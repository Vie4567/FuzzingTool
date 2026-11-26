"""B4.2B real compiled graph (Agents 1-3 + 5) in killed/restarted subprocesses; independent servers.

No HTTP mocks, Internet or provider LLM. Servers log each arrival (fsync, with served body) before
any delay. Set B42B_EVIDENCE_DIR to retain evidence for verify_origin_soft404_evidence.py.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Event
import time
import unittest
from urllib.parse import urlsplit
from uuid import uuid4

import test_origin_soft404_http as lab
from src.coordinator.artifacts import RunArtifacts
from src.coordinator.origin_recovery import digest

STRONG = {'genuine_distinct', 'soft_404', 'http_404'}


def utc(): return datetime.now(timezone.utc).isoformat()
def write(path, value): path.write_text(json.dumps(value, indent=2), encoding='utf-8')
def read(path): return json.loads(Path(path).read_text(encoding='utf-8'))
def journal(directory): return [json.loads(l) for l in (directory / 'recovery/journal.jsonl').read_text(encoding='utf-8').splitlines()]


class OriginSoft404RecoveryHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = lab.start_servers()
        cls.a, cls.b, cls.c = [s.origin for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown(); server.server_close()

    def setUp(self):
        base = os.getenv('B42B_EVIDENCE_DIR')
        if not base:
            tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); base = tmp.name
        # Short IDs keep nested checkpoint paths under the Windows MAX_PATH limit.
        self.case_id = 'b42r_' + sha256(self._testMethodName.encode()).hexdigest()[:8] + '_' + uuid4().hex[:6]
        self.directory = Path(base).resolve() / self.case_id
        self.directory.mkdir(parents=True)
        scope, documents, plan, self.expected = lab.lab_config(self.a, self.b, self.c)
        for server in self.servers:
            server.access, server.faults, server.phase, server.blocked = [], {}, 'graph', False
            server.ghost_gone, server.ghost_once = False, True
            server.documents = documents.get(server.role, {})
            server.access_path = self.directory / (server.role + '_access.jsonl'); server.access_path.touch()
            server.arrived, server.release = Event(), Event()
        self.settings = {'target': self.a + '/', 'auth': lab.AUTH, 'cookie': lab.COOKIE,
                         'soft404_verification': True, 'soft404_max_requests': 200, 'parameter_verification': False,
                         'documents': plan, 'quotas': {self.a: 40, self.b: 40},
                         'config': {'multi_origin': scope, 'fuzzing_options': {'engine': 'python_http'}, 'max_retries': 0,
                                    'max_wordlist_entries': 9, 'http_max_requests': 200, 'http_rate_limit': 50,
                                    'http_timeout_seconds': 2, 'pipeline_timeout_seconds': 120,
                                    'artifact_root': str(self.directory), 'max_llm_calls': 1}}
        self.processes, self.process_events, self.result, self.crash_point, self.expect = [], [], None, None, {}

    def tearDown(self):
        for proc, stream in self.processes:
            if proc.poll() is None:
                proc.kill(); proc.wait(timeout=10)
            stream.close()
        for server in self.servers:
            server.release.set()
        public = deepcopy(self.settings); public.pop('auth'); public.pop('cookie')
        write(self.directory / 'evidence.json', {'case_id': self.case_id, 'test': self._testMethodName, 'kind': 'recovery',
            'written_at_utc': utc(), 'origins': {'frontend': self.a, 'gateway': self.b, 'unapproved': self.c},
            'settings_public': public, 'crash_point': self.crash_point, 'expect': self.expect,
            'expected_classes': {f'{o}{p}': v for (o, p), v in self.expected.items()}, 'process_events': self.process_events,
            'access_files': {s.role: str(s.access_path) for s in self.servers},
            'results': sorted(str(p) for p in self.directory.glob('*_result.json')),
            'denials': sorted(str(p) for p in self.directory.glob('*_denied.json'))})

    # ── process control ──
    def worker(self, mode='start', label='first'):
        path = self.directory / (label + '_config.json'); write(path, self.settings)
        stream = open(self.directory / (label + '_stdout.log'), 'w', encoding='utf-8')
        command = [sys.executable, '-B', str(Path(__file__).with_name('origin_soft404_recovery_worker.py')), str(path), mode, label]
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
        return self.result['origin_contexts'][origin]['context']['soft404']

    def classes(self):
        return {(o, urlsplit(e['url']).path): (e['soft404_classification'], e['evidence_level'])
                for o in (self.a, self.b) for e in self.section(o)['endpoints']}

    def soft404_reservations(self):
        return [e['payload'] for e in journal(self.directory) if e['event'] == 'reserved' and 'soft404' in e['payload']]

    def interrupted(self):
        return [(o, e) for o in (self.a, self.b) for e in self.section(o)['endpoints'] if e.get('unit_state') == 'interrupted']

    def no_replay_checks(self):
        rows = journal(self.directory)
        reservations = [e['payload'] for e in rows if e['event'] == 'reserved']
        probes = [r for r in reservations if 'soft404' in r]
        started = {e['payload']['sequence'] for e in rows if e['event'] == 'dispatch_started'}
        identities = [(r['soft404']['unit_id'], r['soft404']['ordinal']) for r in probes]
        self.assertEqual(len(identities), len(set(identities)))
        owners = {}
        for r in probes:
            owners.setdefault((r['origin'], r['soft404']['group_id']), set()).add(r['soft404']['unit_id'])
        self.assertTrue(all(len(u) == 1 for u in owners.values()), 'a group was measured by a second unit')
        reserved = Counter(urlsplit(r['url']).path + '?' + urlsplit(r['url']).query for r in reservations if r['sequence'] in started)
        for server in self.servers[:2]:
            for key, count in Counter(r['path'] + '?' + r['query'] for r in server.access).items():
                self.assertLessEqual(count, reserved.get(key, 0), f'server saw more {key} than reservations')
        self.assertEqual(len(self.servers[2].access), 0)
        self.assertTrue(all(r['credential_identity'] == 'anonymous' for r in self.servers[1].access))
        self.assertTrue(all(r['credential_identity'] == 'frontend' for r in self.servers[0].access))
        self.assertEqual(self.result['runtime']['http_dispatches'], len(reservations))
        self.assertEqual(self.result['runtime']['http_dispatches_by_origin'], dict(Counter(r['origin'] for r in reservations)))
        self.assertEqual(self.result['origin_execution_mode'], 'not_enabled_b1')
        self.assertFalse(self.result['all_modules_executed'])
        self.assertNotIn('b42b-local-only-fake', json.dumps(self.result))
        for origin in (self.a, self.b):
            self.assertEqual(sorted(r['runtime_sequence'] for r in self.section(origin)['requests']),
                             sorted(r['sequence'] for r in probes if r['origin'] == origin))
            for endpoint in self.section(origin)['endpoints']:
                self.assertEqual(endpoint['verification_status'], 'not_verified')
        for key, (cls, level) in self.classes().items():
            if cls in STRONG:
                self.assertEqual((cls, level), self.expected[key], key)
        self.expect['no_replay_checked'] = True

    def deny_checks(self, code=None):
        before = read(self.directory / 'access_before_resume.json')
        self.assertEqual(before, {s.role: s.access for s in self.servers}, 'resume sent HTTP although denied')
        self.assertTrue(self.result.get('pipeline_status') == 'failed' or 'reason' in self.result)
        if code:
            self.assertIn(code, json.dumps(self.result))
        self.expect['denied'] = code or True

    def rehash(self, rows):
        previous = None
        for seq, row in enumerate(rows, 1):
            row['seq'], row['previous'] = seq, previous
            row.pop('hash', None); row['hash'] = digest(row); previous = row['hash']
        path = self.directory / 'recovery/journal.jsonl'
        path.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
        RunArtifacts._write_json(self.directory / 'recovery/head.json', {'seq': rows[-1]['seq'], 'hash': rows[-1]['hash']})

    # ── cases ──
    def test_clean_graph_run_journals_and_classifies(self):
        self.run_to_end()
        self.assertEqual(self.classes(), self.expected)
        rows = journal(self.directory)
        probes = self.soft404_reservations()
        measured = {e['payload']['sequence'] for e in rows if e['event'] == 'measurement'}
        self.assertEqual(len(probes), 22)
        self.assertTrue(all(r['sequence'] in measured for r in probes))
        self.assertEqual(sum(e['event'] == 'soft404_group' for e in rows), 5)
        self.assertEqual(sum(e['event'] == 'soft404_decision' for e in rows), 7)
        self.assertEqual(self.result['agent_statuses']['soft404_filter'], 'success')
        self.no_replay_checks()

    def test_crash_before_first_reservation_runs_groups_once(self):
        self.crash('before_reservation', probe={'unit_index': 0, 'ordinal': 1})
        self.assertEqual(self.soft404_reservations(), [])
        self.resume(); self.no_replay_checks()
        self.assertEqual(self.classes(), self.expected)
        self.assertEqual(self.interrupted(), [])

    def interrupted_case(self, reason, **crash):
        self.crash(**crash)
        before = self.soft404_reservations()
        unit = before[0]['soft404']['unit_id']
        self.resume(); self.no_replay_checks()
        hits = self.interrupted()
        self.assertTrue(hits)
        self.assertEqual({e['unit_id'] for _, e in hits}, {unit})
        self.assertEqual({(e['soft404_classification'], e['classification_reason'], e['evidence_level']) for _, e in hits},
                         {('inconclusive', reason, 'interrupted')})
        after = self.soft404_reservations()
        self.assertEqual([r for r in after if r['soft404']['unit_id'] == unit], [r for r in before if r['soft404']['unit_id'] == unit])
        self.expect.update(interrupted_unit=unit, interrupted_reason=reason)

    def test_crash_after_control_reservation_is_unknown_not_resent(self):
        self.interrupted_case('probe_outcome_unknown', event='reserved', probe={'unit_index': 0, 'ordinal': 2})
        self.assertEqual(len(self.result['recovery']['soft404_outcome_unknown_sequences']), 1)

    def test_crash_after_server_receive_never_replays(self):
        self.servers[0].faults['controls'] = {'kind': 'block'}
        proc = self.worker(); self.assertTrue(self.servers[0].arrived.wait(40), 'control never reached the server')
        self.crash_point = {'event': 'server_received_control'}
        self.kill(proc); self.servers[0].release.set()
        self.resume(); self.no_replay_checks()
        self.assertEqual(len(self.interrupted()) > 0, True)
        self.assertEqual(len(self.result['recovery']['soft404_outcome_unknown_sequences']), 1)

    def test_crash_after_last_control_measurement_is_interrupted(self):
        self.interrupted_case('unit_interrupted', event='measurement', probe={'unit_index': 0, 'ordinal': 3})

    def test_decisions_without_checkpoint_do_not_restore_classification(self):
        self.interrupted_case('unit_interrupted', event='soft404_decision')

    def test_crash_after_group_checkpoint_preserves_classification(self):
        self.crash('checkpoint', match={'node': 'b42b_soft404', 'event': 'soft404_unit_measured'})
        self.resume(); self.no_replay_checks()
        self.assertEqual(self.classes(), self.expected)
        self.assertTrue(self.result['soft404_execution']['multi_origin']['resumed'])

    def test_crash_between_origins_resumes_only_gateway(self):
        self.crash('checkpoint', match={'node': 'b42b_soft404', 'event': 'soft404_origin_measured'})
        before = self.soft404_reservations()
        self.assertTrue(before and all(r['origin'] == self.a for r in before))
        self.resume(); self.no_replay_checks()
        self.assertEqual(self.classes(), self.expected)
        self.assertTrue(all(r['origin'] == self.b for r in self.soft404_reservations()[len(before):]))

    def test_crash_after_soft404_node_checkpoint_reuses_node_without_http(self):
        self.crash('checkpoint', match={'node': 'run_soft404_filter', 'event': 'checkpoint'})
        before = read(self.directory / 'access_before_resume.json')
        self.resume(); self.no_replay_checks()
        self.assertEqual(before, {s.role: s.access for s in self.servers})
        self.assertIn('run_soft404_filter', self.result['recovery']['reused_nodes'])
        self.assertEqual(self.classes(), self.expected)

    def test_global_stop_on_control_blocks_resume(self):
        self.servers[0].faults['controls'] = {'kind': 'status', 'status': 429}
        self.crash('stop')
        self.resume(); self.deny_checks('recovery_global_stop')

    def test_phase_cap_is_not_reset_on_resume(self):
        self.settings['soft404_max_requests'] = 8
        self.crash('reserved', probe={'unit_index': 0, 'ordinal': 2})
        self.resume(); self.no_replay_checks()
        self.assertLessEqual(len(self.soft404_reservations()), 8)
        self.assertEqual(self.result['soft404_execution']['multi_origin']['phase_max_requests'], 8)

    def checkpointed_unit(self):
        self.crash('checkpoint', match={'node': 'b42b_soft404', 'event': 'soft404_unit_measured'})
        return journal(self.directory)

    def test_consistently_forged_classification_is_rejected(self):
        rows = self.checkpointed_unit()
        entry = next(r for r in reversed(rows) if r['event'] == 'checkpoint' and r['payload']['node'] == 'b42b_soft404')
        path = Path(entry['payload']['path']); data = read(path)
        forged = False
        for context in data['origin_contexts'].values():
            for endpoint in ((context.get('context') or {}).get('soft404') or {}).get('endpoints', []):
                if not forged and endpoint.get('unit_state') == 'completed':
                    endpoint['soft404_classification'] = 'soft_404' if endpoint['soft404_classification'] != 'soft_404' else 'genuine_distinct'
                    forged = True
        self.assertTrue(forged)
        RunArtifacts._write_json(path, data)
        entry['payload']['sha256'] = sha256(path.read_bytes()).hexdigest()
        self.rehash(rows)
        self.resume(); self.deny_checks('recovery_soft404_classification_unproven')

    def test_consistently_tampered_metric_is_rejected(self):
        rows = self.checkpointed_unit()
        decision = next(r for r in rows if r['event'] == 'soft404_decision' and r['payload']['metrics'])
        decision['payload']['metrics'][0]['exact_body_match'] = not decision['payload']['metrics'][0]['exact_body_match']
        self.rehash(rows)
        self.resume(); self.deny_checks('recovery_soft404_classification_unproven')

    def test_consistently_removed_decision_is_rejected(self):
        rows = self.checkpointed_unit()
        rows.remove(next(r for r in rows if r['event'] == 'soft404_decision'))
        self.rehash(rows)
        self.resume(); self.deny_checks('recovery_soft404_classification_unproven')

    def test_consistently_removed_measurement_is_rejected(self):
        rows = self.checkpointed_unit()
        probe_seqs = {r['payload']['sequence'] for r in rows if r['event'] == 'reserved' and 'soft404' in r['payload']}
        rows.remove(next(r for r in rows if r['event'] == 'measurement' and r['payload']['sequence'] in probe_seqs))
        self.rehash(rows)
        self.resume(); self.deny_checks('recovery_checkpoint_invalid')

    def test_resume_without_soft404_context_is_denied(self):
        self.crash('reserved', probe={'unit_index': 0, 'ordinal': 2})
        self.settings['soft404_verification'] = False
        self.resume(); self.deny_checks('recovery_authority_changed')

    def test_parameter_and_soft404_local_route_keeps_agent5_independent(self):
        self.settings['parameter_verification'] = True
        self.run_to_end()
        self.assertEqual(self.classes(), self.expected)
        # No `parameters` rules: Agent 4 ran (B4.2A semantics) but had nothing approved to probe.
        for origin in (self.a, self.b):
            section = self.result['origin_contexts'][origin]['context']['parameter_discovery']
            self.assertEqual((section['status'], section['counts']['http_requests']), ('skipped', 0))
        self.assertFalse(any('probe' in e['payload'] for e in journal(self.directory) if e['event'] == 'reserved'))
        self.assertEqual(self.result['local_origin_execution']['mode'], 'localhost_agents_1_to_5')
        self.no_replay_checks()


if __name__ == '__main__':
    unittest.main()
