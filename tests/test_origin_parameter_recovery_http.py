"""B4.2A real compiled graph (Agents 1-4) in killed/restarted subprocesses; independent servers.

No HTTP mocks, Internet or provider LLM. Servers log every arrival (fsync) before any
delay. Set B42A_EVIDENCE_DIR to retain evidence for verify_origin_parameter_recovery_evidence.py.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Event, Lock, Thread
import time
import unittest
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from src.coordinator.origin_recovery import digest
from src.coordinator.artifacts import RunArtifacts

AUTH, COOKIE = 'Bearer b42a-local-only-fake', 'sid=b42a-local-only-fake'


def utc(): return datetime.now(timezone.utc).isoformat()
def write(path, value): path.write_text(json.dumps(value, indent=2), encoding='utf-8')
def read(path): return json.loads(Path(path).read_text(encoding='utf-8'))
def journal(directory): return [json.loads(l) for l in (directory / 'recovery/journal.jsonl').read_text(encoding='utf-8').splitlines()]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        server, parts = self.server, urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        status, mime = 200, 'application/json'
        if parts.path in server.documents:
            body, mime = server.documents[parts.path]
        elif server.role == 'frontend' and parts.path == '/search':
            body, mime = f'<html><body><p>Results for: {escape(query.get("q", [""])[0])}</p></body></html>', 'text/html'
        elif server.role == 'frontend' and parts.path == '/account/orders':
            if (self.headers.get('Authorization'), self.headers.get('Cookie')) != (AUTH, COOKIE):
                status, body = 401, '{"error":"credential_required"}'
            else:
                body, mime = '<html><body><ul>' + ('' if 'status' in query else '<li>alpha order</li>') + '</ul></body></html>', 'text/html'
        elif server.role == 'gateway' and parts.path == '/search':
            body = json.dumps({'results': [] if 'q' in query else ['alpha', 'beta']})
        elif server.role == 'gateway' and parts.path == '/v1/products':
            body = json.dumps({'items': [] if 'category' in query else ['kettle', 'lamp']})
        else:
            status, body = 404, '{"error":"not_found"}'
        fault = server.faults.get(parts.path)
        hit = fault and fault['when'] in query
        headers = {}
        if hit and fault['kind'] == 'status':
            status, headers = fault['status'], {'Retry-After': '30'}
        raw = body.encode()
        auth, cookie = self.headers.get('Authorization'), self.headers.get('Cookie')
        row = {'utc': utc(), 'monotonic': time.monotonic(), 'origin': server.origin, 'role': server.role,
               'method': self.command, 'path': parts.path, 'query': parts.query, 'status': status,
               'body_sha256': sha256(raw).hexdigest(), 'body': body if parts.path not in server.documents else None,
               'credential_identity': 'frontend' if (auth, cookie) == (AUTH, COOKIE)
               else 'anonymous' if auth is None and cookie is None else 'unexpected',
               'fault': fault['kind'] if hit else None}
        with server.lock:
            server.access.append(row)
            with open(server.access_path, 'a', encoding='utf-8') as log:
                log.write(json.dumps(row) + '\n'); log.flush(); os.fsync(log.fileno())
        if hit and fault['kind'] == 'block' and not server.blocked:
            server.blocked = True
            server.arrived.set(); server.release.wait(30)
        try:
            self.send_response(status); self.send_header('Content-Type', mime)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
        except (OSError, ConnectionError):
            pass


class OriginParameterRecoveryHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        for role in ('frontend', 'gateway', 'unapproved'):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            server.role, server.origin, server.lock = role, f'http://127.0.0.1:{server.server_port}', Lock()
            Thread(target=server.serve_forever, daemon=True).start()
            cls.servers.append(server)
        cls.a, cls.b, cls.c = [s.origin for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown(); server.server_close()

    def setUp(self):
        base = os.getenv('B42A_EVIDENCE_DIR')
        if not base:
            tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); base = tmp.name
        # Short IDs keep nested checkpoint paths under the Windows MAX_PATH limit;
        # the full test name is recorded in evidence.json.
        self.case_id = 'b42a_' + sha256(self._testMethodName.encode()).hexdigest()[:8] + '_' + uuid4().hex[:6]
        self.directory = Path(base).resolve() / self.case_id
        self.directory.mkdir(parents=True)
        for server in self.servers:
            server.access, server.faults, server.blocked = [], {}, False
            server.access_path = self.directory / (server.role + '_access.jsonl'); server.access_path.touch()
            server.arrived, server.release = Event(), Event()
            server.documents = {}
        self.servers[0].documents = {'/': ('<html><body><form action="/search" method="GET"><input name="q"></form>'
                                           '<form action="/account/orders" method="GET"><input name="status"></form>'
                                           f'<a href="{self.c}/v1/private">x</a></body></html>', 'text/html')}
        op = lambda *names: {'get': {'parameters': [{'name': n, 'in': 'query'} for n in names]}}
        self.servers[1].documents = {'/openapi.json': (json.dumps({'openapi': '3.0.0', 'servers': [{'url': self.b}],
            'paths': {'/search': op('q'), '/v1/products': op('category', 'sort')}}), 'application/json')}
        rule = lambda path, params=None: {'path': path, 'methods': ['GET'], 'operation': 'read_only',
                                          **({'parameters': params} if params else {})}
        scope = {'approved_origins': [self.a, self.b], 'origin_policies': {
            self.a: {'credential_profile': 'frontend', 'rules': [rule('/'), rule('/search', ['q']),
                                                                 rule('/account/orders', ['status'])]},
            self.b: {'rules': [rule('/openapi.json'), rule('/search', ['q']), rule('/v1/products', ['category', 'sort'])]}}}
        self.settings = {'target': self.a + '/', 'auth': AUTH, 'cookie': COOKIE, 'parameter_verification': True,
            'parameter_max_requests': 200,
            'documents': [{'url': self.a + '/', 'kind': 'html'}, {'url': self.b + '/openapi.json', 'kind': 'openapi'}],
            'quotas': {self.a: 40, self.b: 40},
            'config': {'multi_origin': scope, 'fuzzing_options': {'engine': 'python_http'}, 'max_retries': 0,
                       'max_wordlist_entries': 4, 'http_max_requests': 200, 'http_rate_limit': 50,
                       'http_timeout_seconds': 2, 'pipeline_timeout_seconds': 120,
                       'artifact_root': str(self.directory), 'max_llm_calls': 1}}
        self.processes, self.process_events, self.result, self.crash_point = [], [], None, None
        self.expect = {}

    def tearDown(self):
        for proc, stream in self.processes:
            if proc.poll() is None:
                proc.kill(); proc.wait(timeout=10)
            stream.close()
        for server in self.servers:
            server.release.set()
        public = deepcopy(self.settings); public.pop('auth'); public.pop('cookie')
        write(self.directory / 'evidence.json', {'case_id': self.case_id, 'test': self._testMethodName,
            'written_at_utc': utc(), 'origins': {'frontend': self.a, 'gateway': self.b, 'unapproved': self.c},
            'settings_public': public, 'crash_point': self.crash_point, 'expect': self.expect,
            'process_events': self.process_events,
            'access_files': {s.role: str(s.access_path) for s in self.servers},
            'results': sorted(str(p) for p in self.directory.glob('*_result.json')),
            'denials': sorted(str(p) for p in self.directory.glob('*_denied.json'))})

    # ── process control ──
    def worker(self, mode='start', label='first'):
        path = self.directory / (label + '_config.json'); write(path, self.settings)
        stream = open(self.directory / (label + '_stdout.log'), 'w', encoding='utf-8')
        command = [sys.executable, '-B', str(Path(__file__).with_name('origin_parameter_recovery_worker.py')), str(path), mode, label]
        proc = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, cwd=Path(__file__).resolve().parents[1])
        self.processes.append((proc, stream))
        self.process_events.append({'pid': proc.pid, 'mode': mode, 'label': label, 'started_utc': utc()})
        return proc

    def wait_file(self, path, proc, seconds=40):
        deadline = time.monotonic() + seconds
        while not path.exists() and time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(.03)
        self.assertTrue(path.exists(), f'Missing {path.name}; child={proc.poll()}; see {self.directory}')

    def kill(self, proc):
        proc.kill(); proc.wait(timeout=10)  # real TerminateProcess/SIGKILL
        self.process_events.append({'pid': proc.pid, 'hard_killed_utc': utc(), 'exit_code': proc.returncode})
        write(self.directory / 'access_before_resume.json', {s.role: deepcopy(s.access) for s in self.servers})
        shutil.copytree(self.directory / 'recovery', self.directory / 'recovery_before_resume', dirs_exist_ok=True)

    def crash(self, event, *, probe=None, match=None):
        self.settings['barrier'] = {'event': event, 'match': match or {}, **({'probe': probe} if probe else {})}
        self.crash_point = deepcopy(self.settings['barrier'])
        proc = self.worker(); self.wait_file(self.directory / 'first_barrier.json', proc)
        self.kill(proc)

    def run_to_end(self, mode='start', label='first'):
        proc = self.worker(mode, label); proc.wait(timeout=90)
        path = self.directory / (label + '_result.json')
        self.result = read(path) if path.exists() else read(self.directory / (label + '_denied.json'))
        return self.result

    def resume(self):
        return self.run_to_end('resume', 'resume')

    # ── shared assertions ──
    def section(self, origin):
        return self.result['origin_contexts'][origin]['context']['parameter_discovery']

    def verified(self):
        return sorted(f'{o}{urlsplit(e["url"]).path}?{c["name"]}' for o in (self.a, self.b)
                      for e in self.section(o)['endpoints'] for c in e['candidates'] if c['verification'] == 'verified')

    def expected_verified(self):
        return sorted([f'{self.a}/account/orders?status', f'{self.b}/v1/products?category', f'{self.b}/search?q'])

    def probe_reservations(self):
        return [e['payload'] for e in journal(self.directory) if e['event'] == 'reserved' and 'probe' in e['payload']]

    def no_replay_checks(self):
        rows = journal(self.directory)
        reservations = [e['payload'] for e in rows if e['event'] == 'reserved']
        probes = [r for r in reservations if 'probe' in r]
        started = {e['payload']['sequence'] for e in rows if e['event'] == 'dispatch_started'}
        identities = [(r['probe']['unit_id'], r['probe']['ordinal']) for r in probes]
        self.assertEqual(len(identities), len(set(identities)))
        units = {}
        for r in probes:
            units.setdefault((r['origin'], r['probe']['endpoint_id']), set()).add(r['probe']['unit_id'])
        self.assertTrue(all(len(u) == 1 for u in units.values()), 'an endpoint was measured by a second unit')
        reserved_urls = Counter(urlsplit(r['url']).path + '?' + urlsplit(r['url']).query
                                for r in reservations if r['sequence'] in started)
        for server in self.servers[:2]:
            for key, count in Counter(r['path'] + '?' + r['query'] for r in server.access).items():
                self.assertLessEqual(count, reserved_urls.get(key, 0), f'server saw more {key} than reservations')
        self.assertEqual(len(self.servers[2].access), 0)
        self.assertTrue(all(r['credential_identity'] == 'anonymous' for r in self.servers[1].access))
        self.assertTrue(all(r['credential_identity'] == 'frontend' for r in self.servers[0].access))
        self.assertEqual(self.result['runtime']['http_dispatches'], len(reservations))
        self.assertEqual(self.result['runtime']['http_dispatches_by_origin'],
                         dict(Counter(r['origin'] for r in reservations)))
        self.assertLessEqual(sum(len(s.access) for s in self.servers), len(reservations))
        self.assertEqual(self.result['origin_execution_mode'], 'not_enabled_b1')
        self.assertFalse(self.result['all_modules_executed'])
        self.assertEqual(self.result['agent_statuses']['soft404_filter'], 'skipped')
        self.assertNotIn('b42a-local-only-fake', json.dumps(self.result))
        for origin in (self.a, self.b):
            section = self.section(origin)
            self.assertEqual(sorted(r['runtime_sequence'] for r in section['requests']),
                             sorted(r['sequence'] for r in probes if r['origin'] == origin))
        self.assertTrue(set(self.verified()) <= set(self.expected_verified()))
        self.expect['no_replay_checked'] = True

    def interrupted(self):
        return [(o, e) for o in (self.a, self.b) for e in self.section(o)['endpoints'] if e.get('unit_state') == 'interrupted']

    def deny_checks(self, code=None):
        before = read(self.directory / 'access_before_resume.json')
        self.assertEqual(before, {s.role: s.access for s in self.servers}, 'resume sent HTTP although denied')
        text = json.dumps(self.result)
        self.assertTrue(self.result.get('pipeline_status') == 'failed' or 'reason' in self.result)
        if code:
            self.assertIn(code, text)
        self.expect['denied'] = code or True

    # ── cases ──
    def test_clean_run_journals_every_probe_and_verifies(self):
        self.run_to_end()
        self.assertEqual(self.verified(), self.expected_verified())
        rows = journal(self.directory)
        probes = self.probe_reservations()
        measured = {e['payload']['sequence'] for e in rows if e['event'] == 'measurement'}
        self.assertEqual(len(probes), 51)
        self.assertTrue(all(r['sequence'] in measured for r in probes))
        anchored = [e for e in rows if e['event'] == 'checkpoint' and e['payload']['node'] == 'b41_parameters']
        self.assertTrue(any(e['payload']['event'] == 'parameters_unit_measured' for e in anchored))
        self.assertEqual(self.result['agent_statuses']['param_disc'], 'success')
        self.no_replay_checks()
        self.expect['verified'] = self.expected_verified()

    def test_crash_before_first_probe_reservation_runs_units_once(self):
        self.crash('before_reservation', probe={'unit_index': 0, 'ordinal': 1})
        self.assertEqual(len(self.probe_reservations()), 0)
        self.resume()
        self.assertEqual(self.verified(), self.expected_verified())
        self.assertEqual(len(self.probe_reservations()), 51)
        self.assertEqual(self.interrupted(), [])
        self.assertEqual(self.result['recovery']['parameter_outcome_unknown_sequences'], [])
        self.no_replay_checks()

    def interrupted_case(self, event, ordinal, reason):
        self.crash(event, probe={'unit_index': 0, 'ordinal': ordinal})
        before = self.probe_reservations()
        unit = before[0]['probe']['unit_id']
        self.resume()
        self.no_replay_checks()
        interrupted = self.interrupted()
        self.assertEqual(len(interrupted), 1)
        origin, endpoint = interrupted[0]
        self.assertEqual(endpoint['unit_id'], unit)
        self.assertEqual({c['verification_reason'] for c in endpoint['candidates'] if c['selected']}, {reason})
        self.assertTrue(all(c['verification'] == 'inconclusive' for c in endpoint['candidates'] if c['selected']))
        after = self.probe_reservations()
        self.assertEqual([r for r in after if r['probe']['unit_id'] == unit], [r for r in before if r['probe']['unit_id'] == unit])
        self.expect.update(interrupted_unit=unit, interrupted_reason=reason)
        return endpoint

    def test_crash_after_probe_reservation_is_outcome_unknown_not_resent(self):
        self.interrupted_case('reserved', 5, 'probe_outcome_unknown')
        self.assertEqual(len(self.result['recovery']['parameter_outcome_unknown_sequences']), 1)

    def test_crash_after_server_receive_never_replays(self):
        self.servers[0].faults.update({'/search': {'kind': 'block', 'when': 'q'}, '/account/orders': {'kind': 'block', 'when': 'status'}})
        proc = self.worker(); self.assertTrue(self.servers[0].arrived.wait(40), 'probe never reached the server')
        self.crash_point = {'event': 'server_received_probe'}
        self.kill(proc); self.servers[0].release.set()
        self.resume(); self.no_replay_checks()
        self.assertEqual(len(self.interrupted()), 1)
        self.assertEqual(len(self.result['recovery']['parameter_outcome_unknown_sequences']), 1)

    def test_crash_after_response_headers_keeps_status_but_unit_unproven(self):
        self.interrupted_case('response_headers', 6, 'probe_outcome_unknown')

    def test_crash_after_last_measurement_before_checkpoint_is_not_verified(self):
        endpoint = self.interrupted_case('measurement', 11, 'unit_interrupted')
        self.assertEqual(self.result['recovery']['parameter_outcome_unknown_sequences'], [])
        rows = [r for r in self.section(endpoint['origin'])['requests'] if r['unit_id'] == endpoint['unit_id']]
        self.assertEqual(len(rows), 11)
        self.assertTrue(all(r['recovery_state'] == 'result_persisted' for r in rows))

    def test_crash_after_unit_checkpoint_preserves_verdict(self):
        self.crash('checkpoint', match={'node': 'b41_parameters', 'event': 'parameters_unit_measured'})
        done = [r['probe']['unit_id'] for r in self.probe_reservations()]
        self.resume(); self.no_replay_checks()
        self.assertEqual(self.verified(), self.expected_verified())
        self.assertEqual(self.interrupted(), [])
        self.assertTrue(self.result['parameter_execution']['multi_origin']['resumed'])
        self.expect['units_before_resume'] = sorted(set(done))

    def test_crash_between_origins_resumes_only_gateway(self):
        self.crash('checkpoint', match={'node': 'b41_parameters', 'event': 'parameters_origin_measured'})
        before = self.probe_reservations()
        self.assertTrue(before and all(r['origin'] == self.a for r in before))
        self.resume(); self.no_replay_checks()
        self.assertEqual(self.verified(), self.expected_verified())
        after = self.probe_reservations()
        self.assertTrue(all(r['origin'] == self.b for r in after[len(before):]))

    def test_crash_after_parameter_node_checkpoint_reuses_node_without_http(self):
        self.crash('checkpoint', match={'node': 'run_param_discovery', 'event': 'checkpoint'})
        before = read(self.directory / 'access_before_resume.json')
        self.resume(); self.no_replay_checks()
        self.assertEqual(before, {s.role: s.access for s in self.servers})
        self.assertIn('run_param_discovery', self.result['recovery']['reused_nodes'])
        self.assertEqual(self.verified(), self.expected_verified())

    def test_global_stop_in_probe_blocks_resume(self):
        self.servers[0].faults['/account/orders'] = {'kind': 'status', 'status': 429, 'when': 'status'}
        self.crash('stop')
        self.resume(); self.deny_checks('recovery_global_stop')

    def test_phase_cap_is_not_reset_on_resume(self):
        self.settings['parameter_max_requests'] = 15
        self.crash('reserved', probe={'unit_index': 0, 'ordinal': 10})
        self.resume(); self.no_replay_checks()
        self.assertLessEqual(len(self.probe_reservations()), 15)
        self.assertEqual(self.result['parameter_execution']['multi_origin']['phase_max_requests'], 15)

    def rehash(self, rows):
        previous = None
        for seq, row in enumerate(rows, 1):
            row['seq'], row['previous'] = seq, previous
            row.pop('hash', None); row['hash'] = digest(row); previous = row['hash']
        path = self.directory / 'recovery/journal.jsonl'
        path.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
        RunArtifacts._write_json(self.directory / 'recovery/head.json', {'seq': rows[-1]['seq'], 'hash': rows[-1]['hash']})

    def test_consistently_forged_verdict_is_rejected(self):
        self.crash('checkpoint', match={'node': 'b41_parameters', 'event': 'parameters_unit_measured'})
        rows = journal(self.directory)
        entry = next(r for r in reversed(rows) if r['event'] == 'checkpoint' and r['payload']['node'] == 'b41_parameters')
        path = Path(entry['payload']['path']); data = read(path)
        forged = False
        for context in data['origin_contexts'].values():
            for endpoint in ((context.get('context') or {}).get('parameter_discovery') or {}).get('endpoints', []):
                for candidate in endpoint['candidates']:
                    if candidate['selected'] and candidate['verification'] != 'verified' and endpoint.get('unit_state') == 'completed':
                        candidate.update(verification='verified', verification_reason='repeatable_response_effect_vs_negative_controls')
                        forged = True
                    elif candidate['selected'] and candidate['verification'] == 'verified' and not forged:
                        candidate.update(verification='inconclusive', verification_reason='no_repeatable_response_effect')
                        forged = True
        self.assertTrue(forged)
        RunArtifacts._write_json(path, data)
        entry['payload']['sha256'] = sha256(path.read_bytes()).hexdigest()
        self.rehash(rows)
        self.resume(); self.deny_checks('recovery_parameter_verdict_unproven')

    def test_consistently_removed_measurement_is_rejected(self):
        self.crash('checkpoint', match={'node': 'b41_parameters', 'event': 'parameters_unit_measured'})
        rows = journal(self.directory)
        probe_seqs = {r['payload']['sequence'] for r in rows if r['event'] == 'reserved' and 'probe' in r['payload']}
        victim = next(r for r in rows if r['event'] == 'measurement' and r['payload']['sequence'] in probe_seqs)
        rows.remove(victim); self.rehash(rows)
        self.resume(); self.deny_checks('recovery_checkpoint_invalid')

    def test_relabelled_probe_endpoint_identity_is_rejected(self):
        self.crash('checkpoint', match={'node': 'b41_parameters', 'event': 'parameters_origin_measured'})
        rows = journal(self.directory)
        # Re-label a later unit's reservations with the first unit's endpoint (consistent
        # rehash): identity no longer matches the URL the operator scope resolves to.
        probes = [r for r in rows if r['event'] == 'reserved' and 'probe' in r['payload']]
        first = probes[0]['payload']['probe']['endpoint_id']
        other = next((r for r in probes if r['payload']['probe']['endpoint_id'] != first), None)
        self.assertIsNotNone(other)
        for row in probes:
            if row['payload']['probe']['unit_id'] == other['payload']['probe']['unit_id']:
                row['payload']['probe']['endpoint_id'] = first
        self.rehash(rows)
        self.resume(); self.deny_checks('recovery_reservation_identity_invalid')

    def test_resume_without_parameter_context_is_denied(self):
        self.crash('reserved', probe={'unit_index': 0, 'ordinal': 3})
        self.settings['parameter_verification'] = False
        self.resume(); self.deny_checks('recovery_authority_changed')

    def test_resume_with_changed_phase_cap_is_denied(self):
        self.crash('reserved', probe={'unit_index': 0, 'ordinal': 3})
        self.settings['parameter_max_requests'] = 199
        self.resume(); self.deny_checks('recovery_authority_changed')


if __name__ == '__main__':
    unittest.main()
