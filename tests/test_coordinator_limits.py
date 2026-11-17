import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.coordinator import graph
from src.coordinator.runtime import runtime_session, check_deadline, PipelineStopped, cap_timeout, observe_response
from src.coordinator.telemetry import telemetry_session, record_http_attempt
from src.coordinator.supervisor import run_pipeline_supervised


def hanging_worker(target, config, directory):
    while True:
        with (Path(directory) / 'heartbeat.txt').open('a') as stream:
            stream.write('tick\n')
        time.sleep(.05)


class CoordinatorLimitsTests(unittest.TestCase):
    def test_shared_budget_does_not_count_denied_dispatch(self):
        with runtime_session({'http_max_requests': 1, 'http_rate_limit': 100}), telemetry_session() as t:
            record_http_attempt()
            with self.assertRaises(PipelineStopped):
                record_http_attempt()
            self.assertEqual(t.snapshot()['http']['total_requests'], 1)

    def test_deadline_and_block_are_terminal(self):
        with runtime_session({'pipeline_timeout_seconds': .01}):
            self.assertLessEqual(cap_timeout(10), .010001)
            time.sleep(.02)
            with self.assertRaises(PipelineStopped):
                check_deadline()
        with runtime_session({}):
            observe_response(429)
            with self.assertRaises(PipelineStopped):
                record_http_attempt()

    def test_real_retry_execution_counter_and_limit(self):
        with tempfile.TemporaryDirectory() as d, patch.object(graph, '_get_decision_engine') as get:
            engine = SimpleNamespace(llm=None, make_decision=lambda **kw: {'action': 'retry_recon'},
                                     reflect_on_session=lambda state: None)
            get.return_value = engine
            with patch.object(graph.TechReconAgent, 'execute', return_value={'tech_stack': {}, 'discovered_paths': ['/']} ) as recon:
                result = graph.run_pipeline('https://example.test', {'artifact_root': d, 'max_retries': 1})
            self.assertEqual(recon.call_count, 2)
            self.assertEqual(result['agent_attempts']['tech_recon'], 2)
            self.assertEqual(result['retry_counts']['tech_recon'], 1)
            self.assertEqual(result['iteration_count'], 2)
            self.assertEqual(result['stop_reason'], 'max_retries')
            self.assertEqual(result['pipeline_status'], 'partial')

    def test_empty_module_result_is_failed_not_success(self):
        state = graph.init_state({'target_url': 'https://example.test', 'config': {}})
        with patch.object(graph, '_get_decision_engine', return_value=None), \
                patch.object(graph.TechReconAgent, 'execute', return_value={}):
            graph.run_tech_recon(state)
        self.assertEqual(state['agent_statuses']['tech_recon'], 'failed')

    def test_configured_retries_survive_default_langgraph_step_limit(self):
        # 11 executions + 11 decisions + administrative nodes exceeds 25.
        with tempfile.TemporaryDirectory() as d, patch.object(graph, '_get_decision_engine') as get:
            get.return_value = SimpleNamespace(llm=None, make_decision=lambda **kw: {'action': 'retry_recon'},
                                              reflect_on_session=lambda state: None)
            with patch.object(graph.TechReconAgent, 'execute', return_value={'tech_stack': {}, 'discovered_paths': ['/']}) as recon:
                result = graph.run_pipeline('https://example.test',
                                            {'artifact_root': d, 'max_retries': 10, 'max_iterations': 20})
            self.assertEqual(recon.call_count, 11)
            self.assertEqual(result['retry_counts']['tech_recon'], 10)
            self.assertEqual(result['iteration_count'], 11)
            self.assertEqual(result['stop_reason'], 'max_retries')
            self.assertEqual(result['error_log'], [])

    def test_wordlist_selection_keeps_operator_order_and_rejects_unsafe_generated_paths(self):
        for mode, expected in [('provided', ['/seed']), ('merge', ['/seed', '/generated']),
                               ('generated', ['/generated', '/last'])]:
            with self.subTest(mode=mode):
                state = graph.init_state({'target_url': 'https://example.test', 'config': {
                    'wordlist': ['/seed'], 'wordlist_mode': mode, 'max_wordlist_entries': 2}})
                output = {'wordlist': ['/generated', 'https://outside.invalid/private', '/last', '/generated']}
                with patch.object(graph, '_get_decision_engine', return_value=SimpleNamespace(llm=None)), \
                        patch.object(graph.WordlistGenAgent, 'execute', return_value=output):
                    result = graph.run_wordlist_gen(state)
                self.assertEqual(result['wordlist'], expected)
                self.assertEqual(result['wordlist_metadata']['rejected_generated_entries'], 1)
                self.assertEqual(result['generated_wordlist'], ['/generated', '/last'])

    def test_bad_input_never_creates_llm(self):
        with tempfile.TemporaryDirectory() as d, patch.object(graph, '_get_decision_engine') as engine:
            result = graph.run_pipeline('https://', {'artifact_root': d})
        engine.assert_not_called()
        self.assertEqual(result['agent_statuses']['validate'], 'failed')

    def test_root_selection_deduplicates_path_aliases_before_limit(self):
        state = graph.init_state({'target_url': 'https://example.test/base', 'config': {
            'wordlist': ['/', '/admin', 'admin', 'login', '/'],
            'wordlist_mode': 'provided', 'max_wordlist_entries': 3}})
        with patch.object(graph, '_get_decision_engine', return_value=SimpleNamespace(llm=None)), \
                patch.object(graph.WordlistGenAgent, 'execute', return_value={'wordlist': ['/generated']}):
            result = graph.run_wordlist_gen(state)
        self.assertEqual(result['wordlist'], ['/', '/admin', 'login'])
        self.assertEqual(result['wordlist_metadata']['selected_count'], 3)
        self.assertEqual(result['wordlist_metadata']['selection_input_count'], 3)

    def test_decision_retry_guard_uses_only_requested_agent_and_configured_limit(self):
        from src.coordinator.decision_engine import DecisionEngine
        engine = object.__new__(DecisionEngine)
        state = {'config': {'max_retries': 1, 'max_llm_calls': 100},
                 'retry_counts': {'tech_recon': 1, 'wordlist_gen': 0}, 'audit_log': [], 'llm_call_count': 60}
        result = engine._validate_decision({'action': 'retry_wordlist'}, 'after_wordlist_gen', state)
        self.assertEqual(result['action'], 'retry_wordlist')
        state['retry_counts']['wordlist_gen'] = 1
        result = engine._validate_decision({'action': 'retry_wordlist'}, 'after_wordlist_gen', state)
        self.assertEqual(result['action'], 'abort_to_report')
        self.assertEqual(state['stop_reason'], 'max_retries')

    def test_supervisor_kills_owned_worker_and_saves_unknown_inflight_counts(self):
        with tempfile.TemporaryDirectory() as d:
            start = time.monotonic()
            result = run_pipeline_supervised('http://127.0.0.1:9',
                {'artifact_root': d, 'pipeline_timeout_seconds': 3}, _worker_target=hanging_worker)
            self.assertLess(time.monotonic()-start, 12)
            self.assertEqual(result['stop_reason'], 'pipeline_deadline')
            self.assertIsNone(result['total_http_requests'])
            files = list(Path(d).glob('pipeline_*/heartbeat.txt'))
            sizes = [p.stat().st_size for p in files]
            time.sleep(.15)
            self.assertEqual(sizes, [p.stat().st_size for p in files])
            self.assertEqual(json.loads(Path(result['artifacts']['result']).read_text(encoding='utf-8')), result)
