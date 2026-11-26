"""B4.2C real compiled LangGraph on loopback: Coordinator -> Agents 1..5 -> Report -> Reflection.

Three independent servers (frontend, gateway, unapproved) log every arrival (fsync) before any delay.
Agents 4 and 5 send real probes. No HTTP mocks, no Internet, no provider LLM (the decision engine is
replaced by a failing stub), no KnowledgeStore writes. Every run binds a fresh recovery journal so
each request carries a phase. Set B42C_EVIDENCE_DIR to keep evidence for
scripts/verify_origin_full_graph_evidence.py.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
from threading import Event
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import test_origin_soft404_http as b42b
from src.coordinator import graph
from src.coordinator.graph import run_pipeline
from src.coordinator.knowledge_store import KnowledgeStore
from src.coordinator.origin_local import LocalOriginTest
from src.coordinator.origin_report import canonical_digest, resolve

AUTH, COOKIE = b42b.AUTH, b42b.COOKIE
SEARCH = '<html><body><h1>Help centre</h1><p>Matching guides: reset devices and read manuals.</p></body></html>'
AGENTS = ('tech_recon', 'wordlist_gen', 'fuzzing', 'param_disc', 'soft404_filter')
# Compiled LangGraph node names, as recorded by the LangGraph callback (not Python function names).
FULL_TRACE = ['validate_input', 'init_state', 'tech_recon', 'llm_decide_recon', 'gen_words', 'llm_decide_wordlist',
              'fuzzing', 'llm_decide_fuzzing', 'param_disc', 'filter_404', 'report', 'reflection']


def utc(): return datetime.now(timezone.utc).isoformat()
def write(path, value): Path(path).write_text(json.dumps(value, indent=2), encoding='utf-8')
def read(path): return json.loads(Path(path).read_text(encoding='utf-8'))
def journal(directory): return [json.loads(l) for l in (Path(directory) / 'recovery/journal.jsonl').read_text(encoding='utf-8').splitlines()]


def respond(server, path, query):
    """B4.2B lab semantics plus two query-sensitive endpoints for real Agent 4 verdicts (values never reflected)."""
    if server.role == 'frontend' and path == '/help' and 'q' in query:
        return 200, SEARCH, 'text/html'
    if server.role == 'gateway' and path == '/v1/products' and 'category' in query:
        return 200, json.dumps({'items': []}), 'application/json'
    return b42b.respond(server, path)


class Handler(b42b.Handler):
    def do_GET(self):
        server, parts = self.server, urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        status, body, mime = respond(server, parts.path, query)
        fault = server.faults.get(parts.path)
        if fault and fault.get('when') and fault['when'] not in query:
            fault = None
        if fault is None and '__sentinel_missing_' in parts.path:
            fault = server.faults.get('controls')
        headers, delay = {}, 0
        if fault and fault['kind'] == 'status':
            status, headers = fault['status'], {'Retry-After': '30'}
        elif fault and fault['kind'] == 'timeout':
            delay = 1.2
        raw = body.encode()
        auth, cookie = self.headers.get('Authorization'), self.headers.get('Cookie')
        row = {'utc': utc(), 'monotonic': time.monotonic(), 'origin': server.origin, 'role': server.role,
               'method': self.command, 'path': parts.path, 'query': parts.query, 'status': status, 'content_type': mime,
               'body_sha256': sha256(raw).hexdigest(), 'delay_seconds': delay, 'fault': fault['kind'] if fault else None,
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
    servers = b42b.start_servers()
    for server in servers:
        server.RequestHandlerClass = Handler
    return servers


def lab_config(a, b, c):
    """B4.2B scope plus operator-listed parameters on three exact GET rules."""
    scope, documents, plan, expected = b42b.lab_config(a, b, c)
    for rule in scope['origin_policies'][a]['rules']:
        if rule['path'] in ('/help', '/promo'):
            rule['parameters'] = ['q']
    for rule in scope['origin_policies'][b]['rules']:
        if rule['path'] == '/v1/products':
            rule['parameters'] = ['category']
    schema = json.loads(documents['gateway']['/openapi.json'][0])
    schema['paths']['/v1/products'] = {'get': {'parameters': [{'name': 'category', 'in': 'query'}]}}
    documents['gateway']['/openapi.json'] = (json.dumps(schema), 'application/json')
    verdicts = {(a, '/help', 'q'): 'verified', (a, '/promo', 'q'): 'not_verified', (b, '/v1/products', 'category'): 'verified'}
    return scope, documents, plan, expected, verdicts


class FullGraphLab:
    """Shared per-case setup, evidence and invariant checks for in-process and subprocess cases."""
    EVIDENCE = 'B42C_EVIDENCE_DIR'
    kind = 'run'

    @classmethod
    def setUpClass(cls):
        cls.servers = start_servers()
        cls.a, cls.b, cls.c = [s.origin for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown(); server.server_close()

    def setUp(self):
        base = os.getenv(self.EVIDENCE)
        if not base:
            tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); base = tmp.name
        self.case_id = 'b42c_' + sha256(self._testMethodName.encode()).hexdigest()[:8] + '_' + uuid4().hex[:6]
        self.directory = Path(base).resolve() / self.case_id
        self.directory.mkdir(parents=True)
        scope, documents, self.plan, self.expected, self.verdicts = lab_config(self.a, self.b, self.c)
        for server in self.servers:
            server.access, server.faults, server.blocked = [], {}, False
            server.ghost_gone, server.ghost_once = False, True
            server.documents = documents.get(server.role, {})
            server.access_path = self.directory / (server.role + '_access.jsonl'); server.access_path.touch()
            server.arrived, server.release = Event(), Event()
        self.settings = {'target': self.a + '/', 'auth': AUTH, 'cookie': COOKIE,
                         'parameter_verification': True, 'soft404_verification': True,
                         'parameter_max_requests': 200, 'soft404_max_requests': 200,
                         'documents': self.plan, 'quotas': {self.a: 80, self.b: 80},
                         'config': {'multi_origin': scope, 'fuzzing_options': {'engine': 'python_http'}, 'max_retries': 0,
                                    'max_wordlist_entries': 9, 'http_max_requests': 300, 'http_rate_limit': 50,
                                    'http_timeout_seconds': 2, 'pipeline_timeout_seconds': 120,
                                    'artifact_root': str(self.directory), 'max_llm_calls': 1}}
        self.processes, self.process_events, self.result, self.crash_point, self.expect = [], [], None, None, {}

    def tearDown(self):
        for proc, stream in getattr(self, 'processes', []):
            if proc.poll() is None:
                proc.kill(); proc.wait(timeout=10)
            stream.close()
        for server in self.servers:
            if getattr(server, 'release', None):
                server.release.set()
        public = deepcopy(self.settings); public.pop('auth'); public.pop('cookie')
        write(self.directory / 'evidence.json', {
            'case_id': self.case_id, 'test': self._testMethodName, 'kind': self.kind, 'written_at_utc': utc(),
            'origins': {'frontend': self.a, 'gateway': self.b, 'unapproved': self.c}, 'settings_public': public,
            'crash_point': self.crash_point, 'expect': self.expect, 'process_events': self.process_events,
            'expected_classes': {f'{o}{p}': v for (o, p), v in self.expected.items()},
            'expected_verdicts': {f'{o}{p}?{n}': v for (o, p, n), v in self.verdicts.items()},
            'access_files': {s.role: str(s.access_path) for s in self.servers},
            'results': sorted(str(p) for p in self.directory.glob('*_result.json')),
            'denials': sorted(str(p) for p in self.directory.glob('*_denied.json'))})

    # ── in-process run (fresh journal, no resume) ──
    def local(self, **overrides):
        options = {k: self.settings[k] for k in ('parameter_verification', 'soft404_verification',
                                                 'parameter_max_requests', 'soft404_max_requests')}
        options.update(overrides)
        profiles = {self.a: {'profile_id': 'frontend', 'headers': {'Authorization': AUTH, 'Cookie': COOKIE}}}
        return LocalOriginTest(self.settings['target'], scope=self.settings['config']['multi_origin'],
                               documents=self.plan, origin_max_requests=self.settings['quotas'],
                               credential_profiles=profiles, recovery_directory=self.directory / 'recovery', **options)

    def run_graph(self, label='first', **overrides):
        local = self.local(**overrides)
        forbidden = AssertionError('B4.2C lab: LLM provider or KnowledgeStore write attempted')
        with patch.object(graph, '_get_decision_engine', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_lessons', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_session', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_decision_pattern', side_effect=forbidden):
            self.result = run_pipeline(self.settings['target'], self.settings['config'], local_origin_test=local)
        write(self.directory / (label + '_result.json'), self.result)
        return self.result

    # ── shared views ──
    def section(self, origin, key='soft404'):
        return self.result['origin_contexts'][origin]['context'][key]

    def classes(self):
        return {(o, urlsplit(e['url']).path): (e['soft404_classification'], e['evidence_level'])
                for o in (self.a, self.b) for e in self.section(o)['endpoints']}

    def verdict_map(self):
        out = {}
        for o in (self.a, self.b):
            for e in self.section(o, 'parameter_discovery')['endpoints']:
                for c in e['candidates']:
                    if c['selected']:
                        out[(o, urlsplit(e['url']).path, c['name'])] = 'verified' if c['verification'] == 'verified' else 'not_verified'
        return out

    def reservations(self):
        return [e['payload'] for e in journal(self.directory) if e['event'] == 'reserved']

    def phase_rows(self, phase):
        return [r for r in self.reservations() if r['phase'] == phase]

    # ── invariants every case must keep ──
    def check_common(self, *, final=True):
        result, rows = self.result, journal(self.directory)
        reservations = [e['payload'] for e in rows if e['event'] == 'reserved']
        started = {e['payload']['sequence'] for e in rows if e['event'] == 'dispatch_started'}
        self.assertEqual(len(self.servers[2].access), 0, 'unapproved origin received HTTP')
        self.assertTrue(all(r['credential_identity'] == 'frontend' for r in self.servers[0].access))
        self.assertTrue(all(r['credential_identity'] == 'anonymous' for r in self.servers[1].access))
        reserved = Counter((r['origin'], urlsplit(r['url']).path, urlsplit(r['url']).query)
                           for r in reservations if r['sequence'] in started)
        for server in self.servers[:2]:
            for key, count in Counter((server.origin, r['path'], r['query']) for r in server.access).items():
                self.assertLessEqual(count, reserved.get(key, 0), f'server saw more {key} than reservations')
        self.assertEqual(result['origin_execution_mode'], 'not_enabled_b1')
        text = json.dumps(result)
        self.assertNotIn('b42b-local-only-fake', text)
        for key in ('fuzzing_execution', 'parameter_execution', 'soft404_execution'):
            if (result.get(key) or {}).get('multi_origin'):
                self.assertFalse(result[key]['multi_origin']['full_multi_origin_execution_enabled'])
        if not final:
            return
        self.assertEqual(result['runtime']['http_dispatches'], len(reservations))
        self.assertEqual(result['runtime']['http_dispatches_by_origin'], dict(Counter(r['origin'] for r in reservations)))
        points = [d['decision_point'] for d in result['decision_chain']]
        self.assertEqual(len(points), len(set(points)), f'duplicate decisions {points}')
        self.assertTrue(all(d['source'] == 'deterministic_local_test_policy' and d['llm_called'] is False
                            for d in result['decision_chain']))
        report, reflection = result['multi_origin_report'], result['local_reflection']
        self.assertEqual(report['digest'], canonical_digest(report['content']))
        self.assertEqual((reflection['report_digest'], reflection['knowledge_writes'], reflection['lessons'],
                          reflection['llm_called']), (report['digest'], 0, [], False))
        for row in reflection['observations']:
            self.assertEqual(resolve(report['content'], row['report_path']), row['value'])
        content = report['content']
        self.assertEqual([o['origin'] for o in content['approved_origins']], [self.a, self.b])
        self.assertTrue(all(not o['executed'] and o['dispatch_attempts'] == 0 for o in content['discovered_only_origins']))
        self.assertIn(self.c, [o['origin'] for o in content['discovered_only_origins']])
        for origin in content['approved_origins']:
            for key in ('parameters', 'soft404'):
                for e in (origin[key] or {}).get('endpoints', []):
                    self.assertEqual(urlsplit(e['url']).scheme + '://' + urlsplit(e['url']).netloc, origin['origin'])
            for e in (origin['soft404'] or {}).get('endpoints', []):
                self.assertEqual(e['verification_status'], 'not_verified')
                source = next(x for x in self.section(origin['origin'])['endpoints'] if x['endpoint_id'] == e['endpoint_id'])
                self.assertEqual((e['soft404_classification'], e['evidence_level']),
                                 (source['soft404_classification'], source['evidence_level']))
        statuses = result['agent_statuses']
        self.assertEqual({a: content['agents'][a]['status'] for a in AGENTS}, {a: statuses[a] for a in AGENTS})
        if result['pipeline_status'] == 'completed':
            self.assertTrue(result['all_modules_successful'] and result['all_modules_executed'])
            self.assertTrue(all(o['status'] == 'completed' for o in content['approved_origins']))
            self.assertEqual((content['totals']['outcome_unknown'], content['totals']['interrupted_units']), (0, 0))
            self.assertIsNone(content['stop']['global_stop_reason'])
        self.expect['common_checked'] = True


class OriginFullGraphHttpTests(FullGraphLab, unittest.TestCase):
    def test_full_graph_five_agents_report_reflection(self):
        self.run_graph()
        self.check_common()
        trace = [e['node'] for e in self.result['local_origin_execution']['langgraph_trace'] if e['event'] == 'start']
        self.assertEqual(trace, FULL_TRACE)
        self.assertEqual(self.result['local_origin_execution']['graph_integration'], 'local_full_graph_b42c')
        self.assertEqual(self.classes(), self.expected)
        self.assertEqual(self.verdict_map(), self.verdicts)
        for origin in (self.a, self.b):
            self.assertGreater(len(self.section(origin, 'parameter_discovery')['requests']), 0)
            self.assertGreater(len(self.section(origin)['requests']), 0)
        for index in (0, 1):
            self.assertTrue(any(r['query'] and '__sentinel_missing_' not in r['path'] for r in self.servers[index].access),
                            'Agent 4 probes never reached the server')
            self.assertTrue(any('__sentinel_missing_' in r['path'] for r in self.servers[index].access),
                            'Agent 5 controls never reached the server')
        self.assertEqual(sum(len(s.access) for s in self.servers[:2]), self.result['runtime']['http_dispatches'])
        self.assertEqual({p for p in Counter(r['phase'] for r in self.reservations())} >= {'param_disc', 'soft404_filter'}, True)
        self.assertEqual(self.result['pipeline_status'], 'completed')
        self.assertTrue(self.result['all_modules_executed'] and self.result['all_modules_successful'])
        self.assertIsNone(self.result['stop_reason'])
        self.assertEqual(self.result['parameter_execution']['multi_origin']['langgraph_integration'], 'local_full_graph_b42c')
        self.expect.update(pipeline_status='completed', agent4_and_agent5_http=True, trace=FULL_TRACE)

    def test_global_429_in_agent4_stops_all_origins_and_reports(self):
        self.servers[0].faults['/help'] = {'kind': 'status', 'status': 429, 'when': 'q'}
        self.run_graph()
        self.check_common()
        self.assertEqual(self.result['runtime']['stop_reason'], 'http_429')
        self.assertEqual(self.phase_rows('soft404_filter'), [])
        self.assertEqual(self.result['agent_statuses']['soft404_filter'], 'not_started')
        self.assertNotEqual(self.result['pipeline_status'], 'completed')
        self.assertFalse(self.result['all_modules_successful'])
        self.assertEqual(self.result['multi_origin_report']['content']['stop']['global_stop_reason'], 'http_429')
        self.expect.update(global_stop='http_429', agent5_requests=0)

    def test_origin_quota_halt_is_local_and_reported(self):
        self.settings['quotas'][self.a] = 12
        self.run_graph()
        self.check_common()
        self.assertIsNone(self.result['runtime']['stop_reason'])
        self.assertLessEqual(self.result['runtime']['http_dispatches_by_origin'][self.a], 12)
        self.assertGreater(len(self.section(self.b)['requests']), 0, 'gateway Agent 5 must continue')
        self.assertNotEqual(self.result['pipeline_status'], 'completed')
        self.expect.update(local_halt_origin=self.a)

    def test_global_budget_spans_all_agents_without_reset(self):
        self.settings['config']['http_max_requests'] = 60
        self.run_graph()
        self.check_common()
        self.assertEqual(self.result['runtime']['stop_reason'], 'http_request_budget')
        self.assertLessEqual(len(self.reservations()), 60)
        self.assertEqual(sum(len(s.access) for s in self.servers[:2]), len(self.reservations()))
        self.assertNotEqual(self.result['pipeline_status'], 'completed')
        self.expect.update(global_stop='http_request_budget')

    def test_contract_failure_in_agent4_skips_agent5_and_reports(self):
        original = LocalOriginTest.parameters

        def tampered(local, state, agent_class):
            state['origin_policies'] = deepcopy(state['origin_policies'])
            state['origin_policies'][self.b]['rules'] = state['origin_policies'][self.b]['rules'][:-1]
            return original(local, state, agent_class)
        before = None
        with patch.object(LocalOriginTest, 'parameters', tampered):
            self.run_graph()
        self.check_common()
        self.assertEqual(self.result['agent_statuses']['param_disc'], 'failed')
        self.assertEqual(self.result['agent_statuses']['soft404_filter'], 'skipped')
        self.assertEqual(self.result['local_origin_execution']['contract_failures'],
                         {'param_disc': 'parameter_contract_policy_snapshot_mismatch'})
        self.assertEqual((self.phase_rows('param_disc'), self.phase_rows('soft404_filter')), ([], []))
        self.assertNotEqual(self.result['pipeline_status'], 'completed')
        self.expect.update(contract_failure='parameter_contract_policy_snapshot_mismatch')

    def test_unexpected_agent4_error_is_not_masked(self):
        def broken(local, state, agent_class):
            raise ValueError('programming error')
        with patch.object(LocalOriginTest, 'parameters', broken):
            self.run_graph()
        self.assertEqual(self.result['pipeline_status'], 'failed')
        self.assertNotIn('multi_origin_report', self.result)
        self.assertEqual(self.phase_rows('soft404_filter'), [])
        self.expect.update(unmasked_error=True)

    def test_legacy_local_modes_keep_routing_and_never_complete(self):
        modes = {'three': (False, False), 'params': (True, False), 'soft404': (False, True)}
        traces, original, results = {}, self.directory, []
        for name, (params, soft) in modes.items():
            with self.subTest(mode=name):
                self.directory = self.directory.parent / (self.case_id + '_' + name); self.directory.mkdir()
                self.settings['config']['artifact_root'] = str(self.directory)
                for server in self.servers:
                    server.access, server.ghost_gone = [], False
                self.run_graph(parameter_verification=params, soft404_verification=soft)
                results.append(str(self.directory / 'first_result.json'))
                trace = [e['node'] for e in self.result['local_origin_execution']['langgraph_trace'] if e['event'] == 'start']
                traces[name] = trace
                self.assertNotEqual(self.result['pipeline_status'], 'completed')
                self.assertFalse(self.result['all_modules_executed'])
                self.assertNotIn('graph_integration', self.result['local_origin_execution'])
                if not params:
                    self.assertEqual(self.phase_rows('param_disc'), [])
                if not soft:
                    self.assertEqual(self.phase_rows('soft404_filter'), [])
        self.assertNotIn('param_disc', traces['three'])
        self.assertNotIn('filter_404', traces['three'])
        self.assertIn('param_disc', traces['params'])
        self.assertNotIn('param_disc', traces['soft404'])
        self.assertIn('filter_404', traces['soft404'])
        self.directory = original  # evidence.json stays in the case directory
        self.expect.update(legacy_traces=traces, legacy_results=results)


if __name__ == '__main__':
    unittest.main()
