"""B4.2B real localhost chain Agent 1 -> 2 -> 3 -> Agent 5 per origin; no HTTP mocks, Internet or provider LLM.

Three independent servers (frontend, gateway, unapproved) log every arrival before any delay,
including the served body, so the independent verifier can recompute similarity itself.
Set B42B_EVIDENCE_DIR to retain evidence for scripts/verify_origin_soft404_evidence.py.
"""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
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
from urllib.parse import urlsplit
from uuid import uuid4

from src.agents.fuzzer import FuzzingAgent
from src.agents.soft404_filter import Soft404FilterAgent
from src.agents.tech_recon import TechReconAgent
from src.agents.wordlist_gen import WordlistGenAgent
from src.coordinator.origins import merge_discovery_context, origin_state
from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session
from src.tools.origin_scope import OriginCredentialContext, OriginScopedTransport, OriginScopePolicy
from src.tools.origin_soft404 import Soft404ProbeTransport

AUTH, COOKIE = 'Bearer b42b-local-only-fake', 'sid=b42b-local-only-fake'
SHELL = '<html><body><div id="root">App shell loading</div></body></html>'
TEMPLATE = '<html><body><h1>Docs</h1>' + ''.join(f'<p>Section {i} explains the archive layout in detail.</p>'
                                                for i in range(60)) + '</body></html>'
HELP = '<html><body><h1>Help centre</h1><p>Contact support, reset devices, read guides and manuals.</p></body></html>'
NOT_FOUND = '{"error": "not_found"}'


def utc(): return datetime.now(timezone.utc).isoformat()


def respond(server, path):
    """Deterministic lab semantics shared by the in-process and recovery labs."""
    if path in server.documents:
        return 200, *server.documents[path]
    if server.role == 'frontend':
        if path == '/help':
            return 200, HELP, 'text/html'
        if path.startswith('/docs/'):
            return 200, (TEMPLATE.replace('Section 7 ', 'Section 7 legacy ') if path == '/docs/legacy' else TEMPLATE), 'text/html'
        return 200, SHELL, 'text/html'  # SPA catch-all, including /, /promo and missing controls
    if server.role == 'gateway':
        if path == '/promo':
            return 200, json.dumps({'promo': ['spring', 'summer']}), 'application/json'
        if path == '/v1/products':
            return 200, json.dumps({'items': ['kettle', 'lamp']}), 'application/json'
        if path == '/v1/ghost':
            if server.ghost_gone:
                return 404, NOT_FOUND, 'application/json'
            if getattr(server, 'ghost_once', False):
                server.ghost_gone = True  # graph lab: Agent 3 sees 200 once, Agent 5 then re-measures 404
            return 200, '{"ghost": true}', 'application/json'
        if path == '/v1/secret':
            return 200, '{"secret_listing": ["alpha"]}', 'application/json'
        if path == '/v2/items':
            return 200, json.dumps({'items': ['mug']}), 'application/json'
        if path.startswith('/v2/'):
            return 200, json.dumps({'debug': ''.join(random.choice(string.ascii_lowercase) for _ in range(16))}), 'application/json'
    return 404, NOT_FOUND, 'application/json'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        server, parts = self.server, urlsplit(self.path)
        status, body, mime = respond(server, parts.path)
        fault = server.faults.get(parts.path) or (server.faults.get('controls') if '__sentinel_missing_' in parts.path else None)
        if fault and fault['kind'] == 'block' and server.blocked:
            fault = None  # a block applies once; later rows are ordinary responses
        headers, delay = {}, 0
        if fault and fault['kind'] == 'status':
            status, headers = fault['status'], {'Retry-After': '30'}
        elif fault and fault['kind'] == 'timeout':
            delay = 1.2
        raw = body.encode()
        auth, cookie = self.headers.get('Authorization'), self.headers.get('Cookie')
        row = {'utc': utc(), 'monotonic': time.monotonic(), 'origin': server.origin, 'role': server.role, 'phase': server.phase,
               'method': self.command, 'path': parts.path, 'query': parts.query, 'status': status, 'content_type': mime,
               'body_sha256': sha256(raw).hexdigest(), 'body': body if parts.path not in server.documents else None,
               'delay_seconds': delay, 'fault': fault['kind'] if fault else None,
               'credential_identity': 'frontend' if (auth, cookie) == (AUTH, COOKIE)
               else 'anonymous' if auth is None and cookie is None else 'unexpected'}
        with server.lock:
            server.access.append(row)
            if getattr(server, 'access_path', None):
                with open(server.access_path, 'a', encoding='utf-8') as log:
                    log.write(json.dumps(row) + '\n'); log.flush(); os.fsync(log.fileno())
        if fault and fault['kind'] == 'block' and not server.blocked:
            server.blocked = True; server.arrived.set(); server.release.wait(30)
        time.sleep(delay)
        try:
            self.send_response(status); self.send_header('Content-Type', mime + '; charset=utf-8')
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
        except (OSError, ConnectionError):
            pass


def start_servers():
    servers = []
    for role in ('frontend', 'gateway', 'unapproved'):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        server.role, server.lock = role, Lock()
        server.origin = f'http://127.0.0.1:{server.server_port}'
        Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    return servers


def lab_config(a, b, c):
    """Documents, operator scope and the expected per-origin lab semantics."""
    js = '\n'.join(f'fetch("{p}", {{method:"GET"}});' for p in ('/', '/promo', '/help', '/docs/legacy')) + \
         f'\nfetch("{c}/v1/private", {{method:"GET"}});'
    op = {'get': {}}
    schema = json.dumps({'openapi': '3.0.0', 'servers': [{'url': b}], 'paths': {
        p: op for p in ('/promo', '/v1/products', '/v1/ghost', '/v1/secret', '/v2/items')}})
    rule = lambda path, controls=True: {'path': path, 'methods': ['GET'], 'operation': 'read_only',
                                        **({'soft404_controls': True} if controls else {})}
    scope = {'approved_origins': [a, b], 'origin_policies': {
        a: {'credential_profile': 'frontend', 'rules': [rule('/boot.js', False), rule('/'), rule('/promo'),
                                                       rule('/help'), rule('/docs/legacy')]},
        b: {'rules': [rule('/openapi.json', False), rule('/promo'), rule('/v1/products'), rule('/v1/ghost'),
                      rule('/v2/items'), rule('/v1/secret', False)]}}}
    documents = {'frontend': {'/boot.js': (js, 'application/javascript')}, 'gateway': {'/openapi.json': (schema, 'application/json')}}
    plan = [{'url': a + '/boot.js', 'kind': 'javascript', 'document_url': a + '/'}, {'url': b + '/openapi.json', 'kind': 'openapi'}]
    expected = {
        (a, '/'): ('inconclusive', 'rederived'), (a, '/promo'): ('soft_404', 'rederived'),
        (a, '/help'): ('genuine_distinct', 'metrics_journaled'), (a, '/docs/legacy'): ('soft_404', 'metrics_journaled'),
        (b, '/promo'): ('genuine_distinct', 'metrics_journaled'), (b, '/v1/products'): ('genuine_distinct', 'metrics_journaled'),
        (b, '/v1/ghost'): ('http_404', 'rederived'), (b, '/v2/items'): ('inconclusive', 'metrics_journaled'),
        (b, '/v1/secret'): ('not_checked', None)}
    return scope, documents, plan, expected


class OriginSoft404HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = start_servers()
        cls.a, cls.b, cls.c = [s.origin for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown(); server.server_close()

    def setUp(self):
        self.case_id = 'b42b_' + sha256(self._testMethodName.encode()).hexdigest()[:8] + '_' + uuid4().hex[:6]
        root = os.getenv('B42B_EVIDENCE_DIR')
        if not root:
            tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); root = tmp.name
        self.directory = Path(root).resolve() / self.case_id
        self.directory.mkdir(parents=True)
        self.config, documents, self.plan, self.expected = lab_config(self.a, self.b, self.c)
        for server in self.servers:
            server.access, server.faults, server.phase, server.ghost_gone, server.blocked = [], {}, 'recon', False, False
            server.documents = documents.get(server.role, {})
        self.limits = {'http_max_requests': 200, 'http_rate_limit': 50, 'http_timeout_seconds': .4,
                       'pipeline_timeout_seconds': 90, 'max_retries': 0, 'http_origin_max_requests': {self.a: 40, self.b: 40}}
        self.scenario, self.result = {}, None

    def chain(self):
        self.state = {'target_url': self.a + '/', **origin_state(self.a + '/', self.config)}
        stack = ExitStack(); self.addCleanup(stack.close)
        self.telemetry = stack.enter_context(telemetry_session(max_llm_calls=0))
        self.runtime = stack.enter_context(runtime_session(self.limits))
        self.policy = OriginScopePolicy(self.config)
        self.credentials = OriginCredentialContext(self.policy, {self.a: {'profile_id': 'frontend',
                                                                          'headers': {'Authorization': AUTH, 'Cookie': COOKIE}}})
        transport = OriginScopedTransport(self.a, policy=self.policy, credentials=self.credentials)
        self.llms = [Mock() for _ in range(4)]
        recon = TechReconAgent(llm=self.llms[0]).collect_discovery(self.a + '/', self.plan, transport=transport)
        merge_discovery_context(self.state, recon['discovery_context'])
        WordlistGenAgent(llm=self.llms[1]).generate_from_discovery(self.state, max_wordlist_entries=9, artifact_root=self.directory)
        for server in self.servers:
            server.phase = 'dispatch'
        FuzzingAgent(llm=self.llms[2]).dispatch_selected(self.state, transport=transport, artifact_root=self.directory)
        self.state_before = deepcopy(self.state)
        self.runtime_before = self.runtime.snapshot()
        self.access_before = [len(s.access) for s in self.servers]
        for server in self.servers:
            server.phase, server.ghost_gone = 'soft404', True

    def agent5(self, credentials=True, **kwargs):
        transport = Soft404ProbeTransport(self.a, policy=self.policy, credentials=self.credentials if credentials else None)
        self.result = Soft404FilterAgent(llm=self.llms[3]).verify_origin_soft404(
            self.state, transport=transport, artifact_root=self.directory, **kwargs)
        for llm in self.llms:
            llm.invoke.assert_not_called()
        self.check_invariants()
        return self.result

    def section(self, origin):
        return self.result['origin_contexts'][origin]['context']['soft404']

    def classes(self):
        return {(o, urlsplit(e['url']).path): (e['soft404_classification'], e['evidence_level'])
                for o in (self.a, self.b) for e in self.section(o)['endpoints']}

    def probes(self, index):
        return [r for r in self.servers[index].access if r['phase'] == 'soft404']

    def check_invariants(self):
        summary = self.result['soft404_execution']['multi_origin']
        self.assertEqual(len(self.servers[2].access), 0)
        self.assertEqual(self.result['origin_execution_mode'], 'not_enabled_b1')
        self.assertFalse(summary['full_multi_origin_execution_enabled'])
        for index, origin in ((0, self.a), (1, self.b)):
            section, probes = self.section(origin), self.probes(index)
            self.assertEqual(len(section['requests']), len(probes))
            self.assertEqual(section['origin_budget_used'] - section['origin_budget_before'], len(probes))
            for sent, logged in zip(section['requests'], probes):
                self.assertEqual((sent['path'], sent['query']), (logged['path'], logged['query']))
                if sent['status_code'] is None:
                    self.assertGreater(logged['delay_seconds'], self.limits['http_timeout_seconds'])
                else:
                    self.assertEqual(sent['status_code'], logged['status'])
                if sent['role'] == 'control':
                    self.assertIn('__sentinel_missing_', sent['path'])
            expected = 'frontend' if index == 0 else 'anonymous'
            self.assertTrue(all(r['credential_identity'] == expected for r in probes), origin)
            for endpoint in section['endpoints']:
                self.assertEqual(endpoint['verification_status'], 'not_verified')
                self.assertEqual(endpoint['parameter_context']['authority'], 'context_only')
            self.assertNotIn('/v1/secret', {r['path'] for r in probes})
        total = sum(len(self.probes(i)) for i in (0, 1))
        self.assertEqual(summary['http_dispatches_this_call'], total)
        self.assertEqual(self.runtime.snapshot()['http_dispatches'], sum(len(s.access) for s in self.servers))
        self.assertEqual(self.telemetry.snapshot()['http']['known_requests'], sum(len(s.access) for s in self.servers))
        self.assertNotIn('b42b-local-only-fake', json.dumps(self.result))

    def test_real_chain_classifies_each_origin_with_its_own_controls(self):
        self.chain()
        self.assertEqual(len(self.state['origin_contexts'][self.a]['context']['http_dispatch']['records'])
                         + len(self.state['origin_contexts'][self.b]['context']['http_dispatch']['records']), 9)
        self.agent5()
        self.assertEqual(self.classes(), self.expected)
        self.assertEqual([len(self.probes(0)), len(self.probes(1))], [10, 12])
        secret = next(e for e in self.section(self.b)['endpoints'] if e['url'] == self.b + '/v1/secret')
        self.assertEqual(secret['exclusion_reason'], 'soft404_controls_not_approved')
        # Every control used by an origin came from that origin and the endpoint's own group.
        for origin in (self.a, self.b):
            groups = {g['group_id']: g for g in self.section(origin)['groups']}
            requests = {r['runtime_sequence']: r for r in self.section(origin)['requests']}
            for endpoint in self.section(origin)['endpoints']:
                for seq in (endpoint['verification_evidence'] or {}).get('control_sequences') or []:
                    self.assertEqual((requests[seq]['origin'], requests[seq]['group_id']), (origin, endpoint['group_id']))
                if endpoint['eligible']:
                    self.assertIn(endpoint['group_id'], groups)
        self.scenario['expected'] = {f'{o}{p}': v for (o, p), v in self.expected.items()}

    def test_global_budget_stops_mid_classification(self):
        self.limits['http_max_requests'] = 2 + 9 + 7
        self.chain(); self.agent5()
        self.assertEqual(self.result['soft404_execution']['multi_origin']['stop_reason'], 'http_request_budget')
        self.assertEqual(len(self.probes(0)), 7)
        self.assertEqual(len(self.probes(1)), 0)
        self.assertTrue(all(c not in {'genuine_distinct', 'soft_404', 'http_404'} for (o, _), (c, _) in self.classes().items() if o == self.b))

    def test_origin_quota_exhaustion_is_local(self):
        self.limits['http_origin_max_requests'] = {self.a: 1 + 4 + 4, self.b: 40}
        self.chain(); self.agent5()
        self.assertEqual(len(self.probes(0)), 4)
        self.assertEqual(self.section(self.a)['stop_reason'], 'origin_request_budget')
        self.assertEqual(self.section(self.b)['status'], 'completed')
        self.assertEqual(len(self.probes(1)), 12)
        self.assertIsNone(self.runtime.stop_reason)

    def test_429_on_control_stops_all_origins(self):
        self.chain()
        self.servers[0].faults['controls'] = {'kind': 'status', 'status': 429}
        self.agent5()
        self.assertEqual(self.runtime.stop_reason, 'http_429')
        self.assertEqual(len(self.probes(1)), 0)
        self.assertEqual(self.probes(0)[-1]['status'], 429)
        self.assertFalse({c for c, _ in self.classes().values()} & {'genuine_distinct', 'soft_404', 'http_404'})

    def test_control_timeout_is_counted_and_preserves_other_origin(self):
        self.chain()
        self.servers[1].faults['controls'] = {'kind': 'timeout'}
        self.agent5()
        self.assertEqual(self.section(self.a)['status'], 'completed')
        self.assertEqual(self.section(self.b)['stop_reason'], 'transport_error')
        self.assertEqual(len([r for r in self.section(self.b)['requests'] if r['error']]), 1)
        self.assertFalse({c for (o, _), (c, _) in self.classes().items() if o == self.b} & {'genuine_distinct', 'soft_404', 'http_404'})

    def test_missing_credential_binding_fails_closed_before_attempt(self):
        self.chain(); self.agent5(credentials=False)
        self.assertEqual(len(self.probes(0)), 0)
        reasons = {e['exclusion_reason'] for e in self.section(self.a)['endpoints']}
        self.assertEqual(reasons, {'credential_or_transport_scope_denied'})
        self.assertEqual(len(self.probes(1)), 12)

    def test_parameter_verified_is_context_only(self):
        self.chain()
        promo = next(r for r in self.state['origin_contexts'][self.a]['context']['http_dispatch']['records']
                     if r['url'] == self.a + '/promo')
        # Simulated Agent 4 outcome: a verified parameter must never upgrade the endpoint.
        self.state['origin_contexts'][self.a]['context']['parameter_discovery'] = {'endpoints': [{
            'endpoint_id': promo['candidate_id'], 'candidates': [{'name': 'q', 'verification': 'verified'}]}]}
        self.agent5()
        endpoint = next(e for e in self.section(self.a)['endpoints'] if e['url'] == self.a + '/promo')
        self.assertEqual(endpoint['parameter_context'], {'verified_parameters': ['q'], 'authority': 'context_only'})
        self.assertEqual((endpoint['soft404_classification'], endpoint['verification_status']), ('soft_404', 'not_verified'))
        self.scenario['parameter_context_injected'] = True

    def test_tampered_agent3_input_is_not_authority(self):
        self.chain()
        records = self.state['origin_contexts'][self.a]['context']['http_dispatch']['records']
        help_row = next(r for r in records if r['url'] == self.a + '/help'); help_row['url'] = self.a + '/help?x=1'
        promo = next(r for r in records if r['url'] == self.a + '/promo'); promo['status_code'] = 201
        gateway = self.state['origin_contexts'][self.b]['context']['http_dispatch']['records']
        products = next(r for r in gateway if r['url'] == self.b + '/v1/products'); products['attempted'] = None
        self.agent5()
        reasons = {e['url']: e['exclusion_reason'] for o in (self.a, self.b) for e in self.section(o)['endpoints']}
        self.assertEqual(reasons[self.a + '/help?x=1'], 'source_contract_changed')
        self.assertEqual(reasons[self.a + '/promo'], 'source_not_http_200')
        self.assertEqual(reasons[self.b + '/v1/products'], 'source_not_observed')
        self.assertFalse({'/help', '/promo'} & {r['path'] for r in self.probes(0)})
        self.assertNotIn('/v1/products', {r['path'] for r in self.probes(1)})
        self.scenario['tampering'] = ['url_changed', 'status_201', 'attempted_unknown']

    def test_recovery_without_soft404_context_and_rerun_fail_closed(self):
        self.chain()
        self.runtime.recovery = object()
        transport = Soft404ProbeTransport(self.a, policy=self.policy, credentials=self.credentials)
        with self.assertRaisesRegex(ValueError, 'soft404_recovery_not_supported'):
            Soft404FilterAgent(llm=self.llms[3]).verify_origin_soft404(self.state, transport=transport)
        self.runtime.recovery = None
        self.assertEqual([len(s.access) for s in self.servers], self.access_before)
        self.agent5()
        with self.assertRaisesRegex(ValueError, 'rerun is not enabled'):
            self.agent5()
        self.assertEqual(len(self.probes(0)) + len(self.probes(1)), 22)
        self.scenario['refusals'] = ['recovery_bound_without_soft404', 'rerun']

    def tearDown(self):
        if self.result is None:
            return
        evidence = {'case_id': self.case_id, 'test': self._testMethodName, 'written_at_utc': utc(),
                    'origins': {'frontend': self.a, 'gateway': self.b, 'unapproved': self.c},
                    'config_public': self.config, 'limits': self.limits, 'scenario': self.scenario,
                    'access': {s.role: s.access for s in self.servers},
                    'state_before_agent5': self.state_before, 'state_after_agent5': self.result,
                    'runtime_before_agent5': self.runtime_before, 'runtime_after_agent5': self.runtime.snapshot(),
                    'telemetry': self.telemetry.snapshot(),
                    'artifact_results': sorted(str(p) for p in self.directory.rglob('result.json'))}
        (self.directory / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
