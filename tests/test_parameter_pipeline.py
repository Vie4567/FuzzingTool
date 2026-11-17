"""Actual local HTTP through Coordinator; fake LLM responses never make measurements."""

from contextlib import ExitStack
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from src.coordinator import graph
from src.coordinator.llm_logging import invoke_logged
from src.tools.recon_http import ScopedReconTransport


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        query = parse_qs(urlsplit(self.path).query)
        path = urlsplit(self.path).path
        status = 403 if path == '/blocked' else 200
        body = (b'{"result":"filtered selection"}' if 'filter' in query else b'{"result":"all records"}')
        if path != '/search':
            body = b'<html><title>Not found</title>Fallback page</html>'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json' if path == '/search' else 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ParameterPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.requests = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.server.requests.clear()
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {
            'LLM_RESPONSE_LOG_FILE': str(Path(self.temp) / 'llm.jsonl'),
            'LANGSMITH_TRACING': 'false', 'LANGCHAIN_TRACING_V2': 'false',
        }))

    def test_real_requests_and_invocations_count_once_across_pipeline(self):
        def fake_invoke(component):
            return invoke_logged(SimpleNamespace(invoke=lambda _: SimpleNamespace(content='fixture')),
                                 'fixture', component=component, operation='fixture')

        actions = {'after_tech_recon': 'proceed_to_wordlist',
                   'after_wordlist_gen': 'proceed_to_fuzzing', 'after_fuzzing': 'proceed_to_param'}

        def decision(**kw):
            fake_invoke('Coordinator')
            return {'action': actions[kw['decision_point']], 'reasoning': 'fixture'}

        engine = SimpleNamespace(llm=None, make_decision=decision,
                                 reflect_on_session=lambda state: fake_invoke('Coordinator'))

        def recon(target):
            status, _, _ = ScopedReconTransport(target).fetch(target + '/search')
            self.assertEqual(status, 200)
            return {'tech_stack': {}, 'discovered_paths': ['/search']}

        def wordlist(**kw):
            fake_invoke('WordlistGenAgent')
            fake_invoke('WordlistGenAgent')
            return {'wordlist': ['/search']}

        def candidates(target_url, endpoints, **kw):
            return {'param_results': [{'url': target_url + '/search', 'path': '/search',
                                      'result_kind': 'parameter_candidates', 'status_code': None,
                                      'content_length_change': None, 'discovered_params': [
                                          {'name': 'filter', 'method': 'GET'}, {'name': 'ignored', 'method': 'GET'}]}]}

        with ExitStack() as stack:
            stack.enter_context(patch.object(graph, '_get_decision_engine', return_value=engine))
            stack.enter_context(patch.object(graph.TechReconAgent, 'execute', side_effect=recon))
            stack.enter_context(patch.object(graph.WordlistGenAgent, 'execute', side_effect=wordlist))
            stack.enter_context(patch.object(graph.ParamDiscoveryAgent, '_run_param_discovery_internal', side_effect=candidates))
            result = graph.run_pipeline(self.origin, {
                'artifact_root': self.temp,
                'fuzzing_options': {'engine': 'python_http', 'use_pattern_engine': False,
                                    'rate_limit': 100, 'delay_ms': 0, 'max_requests': 5},
                'parameter_options': {'rate_limit': 100, 'max_requests': 40},
                'soft404_options': {'rate_limit': 100},
            })
        self.assertEqual(result['error_log'], [])
        self.assertEqual([p['name'] for p in result['verified_parameters']], ['filter'])
        self.assertEqual([p['name'] for p in result['parameter_candidates']], ['ignored'])
        self.assertEqual(result['llm_call_count'], 6)
        self.assertEqual(result['coordinator_llm_calls'], 4)
        self.assertEqual(result['total_http_requests'], len(self.server.requests))
        self.assertEqual(result['total_http_requests'],
                         1 + result['fuzzing_stats']['total_requests'] + result['parameter_stats']['total_requests']
                         + result['soft404_stats']['total_requests'])
        self.assertTrue(result['telemetry']['http']['count_complete'])
        saved = json.loads(Path(result['artifacts']['result']).read_text(encoding='utf-8'))
        self.assertEqual(saved, result)
        self.assertGreater(len(list(Path(result['artifacts']['directory']).glob('checkpoints/*.json'))), 10)

    def test_parameter_block_prevents_following_soft404_requests(self):
        state = graph.init_state({'target_url': self.origin, 'config': {
            'parameter_options': {'rate_limit': 100}, 'soft404_options': {'rate_limit': 100}}})
        state.update(raw_results=[{'url': self.origin + '/blocked', 'path': '/blocked', 'status_code': 200}],
                     fuzzing_execution={'engine': 'python_http', 'success': True, 'stop_reason': 'completed',
                         'verification_context': {'route': 'direct', 'auth_matches_operator': True,
                                                  'http_method': 'GET', 'rate_limit': 100}})
        candidates = {'param_results': [{'url': self.origin + '/blocked',
                                        'discovered_params': [{'name': 'filter'}]}]}
        with patch.object(graph, '_get_decision_engine', return_value=None), \
                patch.object(graph.ParamDiscoveryAgent, '_run_param_discovery_internal', return_value=deepcopy(candidates)):
            graph.run_param_discovery(state)
            before = list(self.server.requests)
            graph.run_soft404_filter(state)
        self.assertEqual(len(before), 1)
        self.assertEqual(self.server.requests, before)
        self.assertEqual(state['parameter_stop_reason'], 'http_403')
        self.assertEqual(state['soft404_stats']['total_requests'], 0)
        self.assertEqual(state['verified_parameters'], [])


if __name__ == '__main__':
    unittest.main()
