"""B4.1 real localhost chain Agent 1 -> 2 -> 3 -> Agent 4; no HTTP mocks, Internet or provider LLM.

Three independent servers (frontend, gateway, unapproved) log every request
they receive. Agent 4 consumes the SharedState that real Agents 1-3 produced.
Set B41_EVIDENCE_DIR to retain evidence for scripts/verify_origin_parameter_evidence.py.
"""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import random
import string
import tempfile
from threading import Lock, Thread
import time
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from src.agents.fuzzer import FuzzingAgent
from src.agents.param_discovery import ParamDiscoveryAgent
from src.agents.tech_recon import TechReconAgent
from src.agents.wordlist_gen import WordlistGenAgent
from src.coordinator.origins import merge_discovery_context, origin_state
from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session
from src.tools.origin_parameters import ParameterProbeTransport
from src.tools.origin_scope import OriginCredentialContext, OriginScopedTransport, OriginScopePolicy

AUTH, COOKIE = 'Bearer b41-local-only-fake', 'sid=b41-local-only-fake'


def utc(): return datetime.now(timezone.utc).isoformat()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def respond(self):
        server, parts = self.server, urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        fault = server.faults.get(parts.path)
        status, mime, body, headers, delay = 200, 'application/json', None, {}, 0
        if parts.path in server.documents:
            body, mime = server.documents[parts.path]
        elif server.role == 'frontend' and parts.path == '/search':
            # Reflects input without using it to select data.
            value = escape(query.get('q', [''])[0])
            body, mime = f'<html><body><h1>Search</h1><p>Results for: {value}</p></body></html>', 'text/html'
        elif server.role == 'frontend' and parts.path == '/app':
            body, mime = '<html><body><div id="root">Application shell</div></body></html>', 'text/html'
        elif server.role == 'frontend' and parts.path == '/account/orders':
            if (self.headers.get('Authorization'), self.headers.get('Cookie')) != (AUTH, COOKIE):
                status, body = 401, json.dumps({'error': 'credential_required'})
            else:
                rows = '' if 'status' in query else '<li>alpha order</li><li>beta order</li>'
                body, mime = f'<html><body><ul>{rows}</ul></body></html>', 'text/html'
        elif server.role == 'frontend' and parts.path == '/slow':
            delay, body = 1.2, json.dumps({'slow': True})
        elif server.role == 'gateway' and parts.path == '/search':
            body = json.dumps({'results': [] if 'q' in query else ['alpha', 'beta']})
        elif server.role == 'gateway' and parts.path == '/v1/products':
            body = json.dumps({'items': [] if 'category' in query else ['kettle', 'lamp']})
        elif server.role == 'gateway' and parts.path == '/v1/echo':
            body = json.dumps({'term': query.get('term', [None])[0]})
        elif server.role == 'gateway' and parts.path == '/v1/noise':
            body = json.dumps({'sample': ''.join(random.choice(string.ascii_lowercase) for _ in range(16))})
        elif server.role == 'gateway' and parts.path == '/v1/strict':
            body = json.dumps({'error': 'unexpected_parameter'} if parts.query else {'ok': True})
        else:
            status, body = 404, json.dumps({'error': 'not_found'})
        if fault and fault.get('when') in query:
            if fault['kind'] == 'status':
                status, headers = fault['status'], {'Retry-After': '30'}
            elif fault['kind'] == 'timeout':
                delay = 1.2
        raw = body.encode()
        auth, cookie = self.headers.get('Authorization'), self.headers.get('Cookie')
        row = {'utc': utc(), 'monotonic': time.monotonic(), 'case_id': server.case_id, 'origin': server.origin,
               'role': server.role, 'phase': server.phase, 'method': self.command, 'path': parts.path,
               'query': parts.query, 'status': status, 'body_sha256': sha256(raw).hexdigest(), 'delay_seconds': delay,
               'body': body if parts.path not in server.documents else None,
               'credential_identity': 'frontend' if (auth, cookie) == (AUTH, COOKIE)
               else 'anonymous' if auth is None and cookie is None else 'unexpected'}
        # Logged on arrival, before any delay, so phase/order match the client.
        with server.lock:
            server.access.append(row)
        time.sleep(delay)
        try:
            self.send_response(status)
            self.send_header('Content-Type', mime)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(raw)
        except (OSError, ConnectionError):
            pass

    do_GET = respond
    do_HEAD = respond
    do_POST = respond


class OriginParameterHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        for role in ('frontend', 'gateway', 'unapproved'):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            server.role, server.lock = role, Lock()
            server.origin = f'http://127.0.0.1:{server.server_port}'
            Thread(target=server.serve_forever, daemon=True).start()
            cls.servers.append(server)
        cls.a, cls.b, cls.c = [s.origin for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown(); server.server_close()

    def setUp(self):
        self.case_id = 'b41_' + self._testMethodName[5:][:40] + '_' + uuid4().hex[:8]
        root = os.getenv('B41_EVIDENCE_DIR')
        if not root:
            tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); root = tmp.name
        self.directory = Path(root).resolve() / self.case_id
        self.directory.mkdir(parents=True)
        html = ('<html><body><form action="/search" method="GET"><input name="q"></form>'
                '<form action="/app" method="GET"><input name="tab"></form>'
                '<form action="/account/orders" method="GET"><input name="status"></form>'
                '<script src="/app.js"></script></body></html>')
        js = '\n'.join(['fetch("/missing", {method:"GET"});', 'fetch("/slow", {method:"GET"});',
                        f'fetch("{self.c}/v1/private", {{method:"GET"}});'])
        def op(*names): return {'get': {'parameters': [{'name': n, 'in': 'query'} for n in names]}}
        schema = json.dumps({'openapi': '3.0.0', 'servers': [{'url': self.b}], 'paths': {
            '/search': op('q'), '/v1/products': op('category', 'sort', 'page', 'debug'),
            '/v1/echo': op('term'), '/v1/noise': op('seed'), '/v1/strict': op('mode')}})
        for server in self.servers:
            server.access, server.faults, server.case_id, server.phase = [], {}, self.case_id, 'recon'
            server.documents = {}
        self.servers[0].documents = {'/': (html, 'text/html'), '/app.js': (js, 'application/javascript')}
        self.servers[1].documents = {'/openapi.json': (schema, 'application/json')}
        def rule(path, params=None):
            row = {'path': path, 'methods': ['GET'], 'operation': 'read_only'}
            if params:
                row['parameters'] = params
            return row
        self.config = {'approved_origins': [self.a, self.b], 'origin_policies': {
            self.a: {'credential_profile': 'frontend', 'rules': [
                rule('/'), rule('/app.js'), rule('/search', ['q']), rule('/app', ['tab']),
                rule('/account/orders', ['status']), rule('/missing'), rule('/slow')]},
            self.b: {'rules': [rule('/openapi.json'), rule('/search', ['q']),
                               rule('/v1/products', ['category', 'sort', 'debug']), rule('/v1/echo', ['term']),
                               rule('/v1/noise', ['seed']), rule('/v1/strict', ['mode'])]}}}
        self.plan = [{'url': self.a + '/', 'kind': 'html'}, {'url': self.a + '/app.js', 'kind': 'javascript'},
                     {'url': self.b + '/openapi.json', 'kind': 'openapi'}]
        self.limits = {'http_max_requests': 200, 'http_rate_limit': 50, 'http_timeout_seconds': .4,
                       'pipeline_timeout_seconds': 90, 'max_retries': 0,
                       'http_origin_max_requests': {self.a: 60, self.b: 80}}
        self.with_credentials = True
        self.scenario = {}
        self.evidence = None

    def start(self):
        self.state = {'target_url': self.a + '/', **origin_state(self.a + '/', self.config)}
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.telemetry = self.stack.enter_context(telemetry_session(max_llm_calls=0))
        self.runtime = self.stack.enter_context(runtime_session(self.limits))
        self.policy = OriginScopePolicy(self.config)
        self.credentials = OriginCredentialContext(self.policy, {self.a: {
            'profile_id': 'frontend', 'headers': {'Authorization': AUTH, 'Cookie': COOKIE}}})

    def chain(self):
        """Real Agents 1-3 over HTTP; their SharedState is Agent 4's only input."""
        self.start()
        transport = OriginScopedTransport(self.a, policy=self.policy, credentials=self.credentials)
        self.llms = [Mock() for _ in range(4)]
        recon = TechReconAgent(llm=self.llms[0]).collect_discovery(self.a + '/', self.plan, transport=transport)
        merge_discovery_context(self.state, recon['discovery_context'])
        WordlistGenAgent(llm=self.llms[1]).generate_from_discovery(
            self.state, max_wordlist_entries=10, artifact_root=self.directory)
        for server in self.servers:
            server.phase = 'dispatch'
        FuzzingAgent(llm=self.llms[2]).dispatch_selected(self.state, transport=transport, artifact_root=self.directory)
        self.state_before = deepcopy(self.state)
        self.runtime_before = self.runtime.snapshot()
        self.access_before = [len(s.access) for s in self.servers]
        for server in self.servers:
            server.phase = 'parameters'

    def agent4(self, credentials=True, **kwargs):
        transport = ParameterProbeTransport(self.a, policy=self.policy,
                                            credentials=self.credentials if credentials else None)
        self.result = ParamDiscoveryAgent(llm=self.llms[3]).verify_origin_parameters(
            self.state, transport=transport, artifact_root=self.directory, **kwargs)
        for llm in self.llms:
            llm.invoke.assert_not_called()
        self.check_invariants()
        return self.result

    def section(self, origin):
        return self.result['origin_contexts'][origin]['context']['parameter_discovery']

    def verdicts(self, origin):
        return {(urlsplit(e['url']).path, c['name']): (c['verification'], c['verification_reason'])
                for e in self.section(origin)['endpoints'] for c in e['candidates'] if c['selected']}

    def probes(self, index):
        return [r for r in self.servers[index].access if r['phase'] == 'parameters']

    def check_invariants(self):
        summary = self.result['parameter_execution']['multi_origin']
        self.assertEqual(len(self.servers[2].access), 0)
        self.assertEqual(self.result['origin_execution_mode'], 'not_enabled_b1')
        self.assertFalse(summary['full_multi_origin_execution_enabled'])
        self.assertEqual(self.result['approved_origins'], [self.a, self.b])
        for index, origin in ((0, self.a), (1, self.b)):
            section, probes = self.section(origin), self.probes(index)
            self.assertEqual(len(section['requests']), len(probes))
            self.assertEqual(section['origin_budget_used'] - section['origin_budget_before'], len(probes))
            for sent, logged in zip(section['requests'], probes):
                self.assertEqual((sent['path'], sent['query']), (logged['path'], logged['query']))
                if sent['status_code'] is None:
                    # Client timed out before the delayed server reply; never fabricated.
                    self.assertGreater(logged['delay_seconds'], self.limits['http_timeout_seconds'])
                    self.assertIsNotNone(sent['error'])
                else:
                    self.assertEqual(sent['status_code'], logged['status'])
                if sent['body_sha256'] is not None and sent['body_complete']:
                    self.assertEqual(sent['body_sha256'], logged['body_sha256'])
            self.assertTrue(all(row['method'] == 'GET' for row in probes))
            expected = 'frontend' if index == 0 else 'anonymous'
            self.assertTrue(all(row['credential_identity'] == expected for row in probes), origin)
            for endpoint in section['endpoints']:
                for candidate in endpoint['candidates']:
                    if candidate['verification'] == 'verified':
                        self.assertEqual(candidate['verification_reason'], 'repeatable_response_effect_vs_negative_controls')
                        self.assertFalse(candidate['verification_evidence']['reflection_detected'])
        total = sum(len(self.probes(i)) for i in (0, 1))
        self.assertEqual(summary['http_dispatches_this_call'], total)
        self.assertEqual(self.runtime.snapshot()['http_dispatches'], sum(len(s.access) for s in self.servers))
        self.assertEqual(self.telemetry.snapshot()['http']['known_requests'], sum(len(s.access) for s in self.servers))
        text = json.dumps(self.result)
        self.assertNotIn('b41-local-only-fake', text)

    def test_real_chain_verifies_only_processed_parameters(self):
        self.chain()
        dispatch = {urlsplit(r['url']).path + '@' + r['origin']: r for e in self.state['origin_contexts'].values()
                    for r in (e.get('context') or {}).get('http_dispatch', {}).get('records', [])}
        self.assertEqual(len(dispatch), 10)
        self.agent4()
        self.assertEqual(self.verdicts(self.a), {
            ('/search', 'q'): ('inconclusive', 'reflected_input_requires_review'),
            ('/app', 'tab'): ('inconclusive', 'no_repeatable_response_effect'),
            ('/account/orders', 'status'): ('verified', 'repeatable_response_effect_vs_negative_controls')})
        self.assertEqual(self.verdicts(self.b), {
            ('/search', 'q'): ('verified', 'repeatable_response_effect_vs_negative_controls'),
            ('/v1/products', 'category'): ('verified', 'repeatable_response_effect_vs_negative_controls'),
            ('/v1/products', 'sort'): ('inconclusive', 'no_repeatable_response_effect'),
            ('/v1/products', 'debug'): ('not_checked', 'sensitive_parameter_or_path_requires_review'),
            ('/v1/echo', 'term'): ('inconclusive', 'reflected_input_requires_review'),
            ('/v1/noise', 'seed'): ('inconclusive', 'unstable_or_query_sensitive_controls'),
            ('/v1/strict', 'mode'): ('inconclusive', 'unstable_or_query_sensitive_controls')})
        excluded = {urlsplit(e['url']).path: e['exclusion_reason'] for e in self.section(self.a)['endpoints'] if not e['eligible']}
        self.assertEqual(excluded, {'/missing': 'source_not_2xx', '/slow': 'source_error_or_timeout'})
        page = next(c for e in self.section(self.b)['endpoints'] if e['url'] == self.b + '/v1/products'
                    for c in e['candidates'] if c['name'] == 'page')
        self.assertEqual((page['selected'], page['verification']), (False, 'not_checked'))
        self.assertEqual([len(self.probes(0)), len(self.probes(1))], [33, 48])
        # Same path on two origins: separate identities and different verdicts.
        ids = {e['url']: e['endpoint_id'] for o in (self.a, self.b) for e in self.section(o)['endpoints']}
        self.assertNotEqual(ids[self.a + '/search'], ids[self.b + '/search'])
        for origin in (self.a, self.b):
            self.assertEqual(self.section(origin)['status'], 'completed')
            for endpoint in self.section(origin)['endpoints']:
                source = next(r for r in self.state_before['origin_contexts'][origin]['endpoints']
                              if r['endpoint_id'] == endpoint['endpoint_id'])
                self.assertEqual(endpoint['provenance'], source['provenance'])
                for candidate in endpoint['candidates']:
                    if candidate['selected']:
                        self.assertTrue(any(p['source'] == 'agent1_reference' and p['evidence_refs']
                                            for p in candidate['provenance']))
        self.scenario['expected_verified'] = sorted(f'{o}{p}?{n}' for o in (self.a, self.b)
                                                    for (p, n), v in self.verdicts(o).items() if v[0] == 'verified')

    def test_global_budget_stops_mid_verification(self):
        self.limits['http_max_requests'] = 3 + 10 + 20
        self.chain()
        self.agent4()
        summary = self.result['parameter_execution']['multi_origin']
        self.assertEqual(summary['stop_reason'], 'http_request_budget')
        self.assertEqual(len(self.probes(0)), 20)
        self.assertEqual(len(self.probes(1)), 0)
        self.assertEqual(self.section(self.a)['status'], 'partial')
        self.assertNotEqual(self.section(self.b)['status'], 'completed')
        for origin in (self.a, self.b):
            for endpoint in self.section(origin)['endpoints']:
                for candidate in endpoint['candidates']:
                    if candidate['verification'] == 'verified':
                        self.assertEqual(len(candidate['verification_evidence']['post_controls']), 3)

    def test_origin_quota_exhaustion_is_local(self):
        self.limits['http_origin_max_requests'] = {self.a: 2 + 5 + 6, self.b: 80}
        self.chain()
        self.agent4()
        self.assertEqual(len(self.probes(0)), 6)
        self.assertEqual(self.section(self.a)['stop_reason'], 'origin_request_budget')
        self.assertEqual(self.section(self.b)['status'], 'completed')
        self.assertEqual(len(self.probes(1)), 48)
        self.assertIsNone(self.runtime.stop_reason)

    def test_429_on_probe_stops_all_origins(self):
        self.chain()
        self.servers[0].faults['/account/orders'] = {'kind': 'status', 'status': 429, 'when': 'status'}
        self.agent4()
        self.assertEqual(self.runtime.stop_reason, 'http_429')
        self.assertEqual(len(self.probes(1)), 0)
        self.assertEqual(self.probes(0)[-1]['status'], 429)
        self.assertNotIn('verified', {v for v, _ in self.verdicts(self.b).values()})
        orders = self.verdicts(self.a)[('/account/orders', 'status')]
        self.assertEqual(orders, ('inconclusive', 'http_429'))

    def test_probe_timeout_is_counted_and_preserves_other_origin(self):
        self.chain()
        self.servers[1].faults['/v1/products'] = {'kind': 'timeout', 'when': 'category'}
        self.agent4()
        self.assertEqual(self.section(self.a)['status'], 'completed')
        self.assertEqual(self.section(self.b)['stop_reason'], 'transport_error')
        timed_out = [r for r in self.section(self.b)['requests'] if r['error']]
        self.assertEqual(len(timed_out), 1)
        self.assertIsNone(timed_out[0]['status_code'])
        self.assertNotEqual(self.verdicts(self.b)[('/v1/products', 'category')][0], 'verified')

    def test_missing_credential_binding_fails_closed_before_attempt(self):
        self.chain()
        self.agent4(credentials=False)
        self.assertEqual(len(self.probes(0)), 0)
        reasons = {e['exclusion_reason'] for e in self.section(self.a)['endpoints'] if e['candidates']}
        self.assertEqual(reasons, {'credential_or_transport_scope_denied'})
        self.assertEqual(len(self.probes(1)), 48)

    def test_tampered_agent3_input_is_not_authority(self):
        self.chain()
        records = self.state['origin_contexts'][self.a]['context']['http_dispatch']['records']
        app = next(r for r in records if r['url'] == self.a + '/app')
        app['url'] = self.a + '/app?tab=admin'
        orders = next(r for r in records if r['url'] == self.a + '/account/orders')
        orders['verified'] = True; orders['verification_status'] = 'verified'
        gateway = self.state['origin_contexts'][self.b]['context']['http_dispatch']['records']
        echo = next(r for r in gateway if r['url'] == self.b + '/v1/echo')
        echo['status_code'] = 200; echo['attempted'] = False
        fake = deepcopy(orders); fake.update(candidate_id='f' * 24, url=self.c + '/v1/private', origin=self.a)
        records.append(fake)
        self.agent4()
        reasons = {e['url']: e['exclusion_reason'] for e in self.section(self.a)['endpoints']}
        self.assertEqual(reasons[self.a + '/app?tab=admin'], 'source_contract_changed')
        self.assertEqual(reasons[self.c + '/v1/private'], 'source_contract_changed')
        self.assertNotIn('/app', {r['path'] for r in self.probes(0)})
        gateway_reasons = {e['url']: e['exclusion_reason'] for e in self.section(self.b)['endpoints']}
        self.assertEqual(gateway_reasons[self.b + '/v1/echo'], 'source_not_observed')
        # A forged verified flag on the source record is ignored; the probe decides.
        self.assertEqual(self.verdicts(self.a)[('/account/orders', 'status')][0], 'verified')
        self.scenario['tampering'] = ['url_changed', 'forged_verified_flag', 'unattempted_200', 'unapproved_origin_record']

    def test_recovery_bound_runtime_and_rerun_fail_closed_without_http(self):
        self.chain()
        self.runtime.recovery = object()
        transport = ParameterProbeTransport(self.a, policy=self.policy, credentials=self.credentials)
        with self.assertRaisesRegex(ValueError, 'parameter_recovery_not_supported_b41'):
            ParamDiscoveryAgent(llm=self.llms[3]).verify_origin_parameters(self.state, transport=transport)
        self.runtime.recovery = None
        self.assertEqual([len(s.access) for s in self.servers], self.access_before)
        self.agent4()
        with self.assertRaisesRegex(ValueError, 'rerun is not enabled'):
            self.agent4()
        self.assertEqual(len(self.probes(0)) + len(self.probes(1)), 81)
        self.scenario['refusals'] = ['recovery_bound', 'rerun']

    def tearDown(self):
        if not hasattr(self, 'result'):
            return
        artifacts = sorted(str(p) for p in self.directory.rglob('result.json'))
        evidence = {'case_id': self.case_id, 'test': self._testMethodName, 'written_at_utc': utc(),
                    'origins': {'frontend': self.a, 'gateway': self.b, 'unapproved': self.c},
                    'config_public': self.config, 'limits': self.limits, 'scenario': self.scenario,
                    'access': {s.role: s.access for s in self.servers},
                    'state_before_agent4': self.state_before, 'state_after_agent4': self.result,
                    'runtime_before_agent4': self.runtime_before, 'runtime_after_agent4': self.runtime.snapshot(),
                    'telemetry': self.telemetry.snapshot(), 'artifact_results': artifacts}
        (self.directory / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
