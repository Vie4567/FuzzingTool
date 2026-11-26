"""B4.2C real compiled graph (Agents 1-5, Report, Reflection) in killed/restarted subprocesses.

Independent loopback servers log every arrival (fsync) before any delay. A real kill (TerminateProcess/
SIGKILL) at journal barriers covers every Agent boundary, Report, Reflection, the final result and a
finished session; finalize_only and already_finished are checked against the server logs. No HTTP
mocks, Internet, provider LLM or KnowledgeStore writes. Set B42C_EVIDENCE_DIR to keep evidence.
"""
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from urllib.parse import urlsplit

from test_origin_full_graph_http import FullGraphLab, journal, read, utc, write
from src.coordinator.artifacts import RunArtifacts
from src.coordinator.origin_recovery import digest
from src.coordinator.origin_report import canonical_digest


class OriginFullGraphRecoveryHttpTests(FullGraphLab, unittest.TestCase):
    kind = 'recovery'

    # ── process control ──
    def worker(self, mode='start', label='first'):
        path = self.directory / (label + '_config.json'); write(path, self.settings)
        stream = open(self.directory / (label + '_stdout.log'), 'w', encoding='utf-8')
        command = [sys.executable, '-B', str(Path(__file__).with_name('origin_full_graph_recovery_worker.py')),
                   str(path), mode, label]
        proc = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, cwd=Path(__file__).resolve().parents[1])
        self.processes.append((proc, stream))
        self.process_events.append({'pid': proc.pid, 'mode': mode, 'label': label, 'started_utc': utc()})
        return proc

    def wait_file(self, path, proc, seconds=60):
        deadline = time.monotonic() + seconds
        while not path.exists() and time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(.03)
        self.assertTrue(path.exists(), f'Missing {path.name}; child={proc.poll()}; see {self.directory}')

    def snapshot(self):
        write(self.directory / 'access_before_resume.json', {s.role: deepcopy(s.access) for s in self.servers})
        shutil.copytree(self.directory / 'recovery', self.directory / 'recovery_before_resume', dirs_exist_ok=True)

    def crash(self, event, *, probe=None, match=None):
        self.settings['barrier'] = {'event': event, 'match': match or {}, **({'probe': probe} if probe else {})}
        self.crash_point = deepcopy(self.settings['barrier'])
        proc = self.worker(); self.wait_file(self.directory / 'first_barrier.json', proc)
        proc.kill(); proc.wait(timeout=10)  # real process termination
        self.process_events.append({'pid': proc.pid, 'hard_killed_utc': utc(), 'exit_code': proc.returncode})
        self.snapshot()
        self.first_reservations = len([e for e in journal(self.directory) if e['event'] == 'reserved'])

    def run_to_end(self, mode='start', label='first'):
        proc = self.worker(mode, label); proc.wait(timeout=120)
        path = self.directory / (label + '_result.json')
        self.result = read(path) if path.exists() else read(self.directory / (label + '_denied.json'))
        return self.result

    def resume(self, label='resume'):
        return self.run_to_end('resume', label)

    def finalize(self, label='finalize'):
        return self.run_to_end('finalize', label)

    # ── shared assertions ──
    def no_new_http(self):
        before = read(self.directory / 'access_before_resume.json')
        self.assertEqual(before, {s.role: s.access for s in self.servers}, 'HTTP sent after the crash point')

    def no_replay(self):
        rows = journal(self.directory)
        reservations = [e['payload'] for e in rows if e['event'] == 'reserved']
        for key in ('probe', 'soft404'):
            ids = [(r[key]['unit_id'], r[key]['ordinal']) for r in reservations if key in r]
            self.assertEqual(len(ids), len(set(ids)), f'{key} identity replayed')
        candidates = [(r['origin'], r['candidate_id']) for r in reservations if r.get('candidate_id')]
        self.assertEqual(len(candidates), len(set(candidates)), 'Agent 3 candidate replayed')
        bound = [e['payload']['reservations'] for e in rows if e['event'] == 'process_bound']
        self.assertEqual(bound, sorted(bound), 'reservation counter decreased across processes')
        self.assertGreaterEqual(self.result['runtime']['http_dispatches'], self.first_reservations)

    def resumed_ok(self, *, http_after=None):
        self.check_common(); self.no_replay()
        self.assertTrue(self.result['recovery']['resumed'])
        self.assertFalse(self.result['recovery']['exactly_once_delivery'])
        if http_after is False:
            self.no_new_http()
        self.expect['resumed_ok'] = True

    def deny_checks(self, code):
        self.no_new_http()
        self.assertTrue(self.result.get('pipeline_status') == 'failed' or 'reason' in self.result)
        self.assertIn(code, json.dumps(self.result))
        self.assertNotEqual(self.result.get('pipeline_status'), 'completed')
        self.expect['denied'] = code

    def report_digest_before(self):
        rows = [e for e in journal(self.directory)
                if e['event'] == 'checkpoint' and e['payload']['node'] == 'generate_report']
        return read(rows[-1]['payload']['path'])['multi_origin_report']['digest']

    def rehash(self, rows):
        previous = None
        for seq, row in enumerate(rows, 1):
            row['seq'], row['previous'] = seq, previous
            row.pop('hash', None); row['hash'] = digest(row); previous = row['hash']
        path = self.directory / 'recovery/journal.jsonl'
        path.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
        RunArtifacts._write_json(self.directory / 'recovery/head.json', {'seq': rows[-1]['seq'], 'hash': rows[-1]['hash']})

    def forge(self, mutate):
        """Consistently rewrite every journal-anchored checkpoint (sha256 + hash chain): only semantics can catch it."""
        rows = journal(self.directory)
        changed = 0
        for row in rows:
            if row['event'] != 'checkpoint':
                continue
            path = Path(row['payload']['path']); data = read(path)
            if mutate(data):
                RunArtifacts._write_json(path, data)
                row['payload']['sha256'] = sha256(path.read_bytes()).hexdigest(); changed += 1
        self.assertGreater(changed, 0)
        self.rehash(rows)
        self.snapshot()

    # ── crash/resume across every boundary ──
    def test_crash_after_agent3_before_agent4_resumes_once(self):
        self.crash('checkpoint', match={'node': 'run_fuzzing', 'event': 'checkpoint'})
        self.assertEqual([r for r in self.reservations() if r['phase'] in ('param_disc', 'soft404_filter')], [])
        self.resume(); self.resumed_ok()
        self.assertIn('run_fuzzing', self.result['recovery']['reused_nodes'])
        self.assertIn('llm_decide_after_wordlist', self.result['recovery']['reused_nodes'])
        self.assertEqual(self.classes(), self.expected); self.assertEqual(self.verdict_map(), self.verdicts)
        self.assertEqual(self.result['pipeline_status'], 'completed')
        self.expect.update(pipeline_status='completed')

    def test_crash_in_agent4_marks_unit_interrupted_never_resent(self):
        self.crash('reserved', probe={'kind': 'probe', 'unit_index': 0, 'ordinal': 2})
        unit = next(r['probe']['unit_id'] for r in self.reservations() if 'probe' in r)
        self.resume(); self.resumed_ok()
        hits = [e for o in (self.a, self.b) for e in self.section(o, 'parameter_discovery')['endpoints']
                if e.get('unit_state') == 'interrupted']
        self.assertEqual({e['unit_id'] for e in hits}, {unit})
        self.assertEqual(len(self.result['recovery']['parameter_outcome_unknown_sequences']), 1)
        self.assertEqual(self.result['agent_statuses']['param_disc'], 'interrupted')
        self.assertEqual(self.result['agent_statuses']['soft404_filter'], 'success')
        self.assertEqual(self.result['pipeline_status'], 'partial')
        self.assertFalse(self.result['all_modules_successful'])
        self.expect.update(pipeline_status='partial', interrupted_unit=unit)

    def test_crash_after_agent4_checkpoint_reuses_agent4(self):
        self.crash('checkpoint', match={'node': 'run_param_discovery', 'event': 'checkpoint'})
        before = len([r for r in self.reservations() if r['phase'] == 'param_disc'])
        self.resume(); self.resumed_ok()
        self.assertIn('run_param_discovery', self.result['recovery']['reused_nodes'])
        self.assertEqual(len([r for r in self.reservations() if r['phase'] == 'param_disc']), before)
        self.assertGreater(len([r for r in self.reservations() if r['phase'] == 'soft404_filter']), 0)
        self.assertEqual(self.result['pipeline_status'], 'completed')
        self.expect.update(pipeline_status='completed')

    def test_crash_in_agent5_marks_group_interrupted(self):
        self.crash('reserved', probe={'kind': 'soft404', 'unit_index': 0, 'ordinal': 2})
        self.resume(); self.resumed_ok()
        hits = [e for o in (self.a, self.b) for e in self.section(o)['endpoints'] if e.get('unit_state') == 'interrupted']
        self.assertTrue(hits)
        self.assertEqual({(e['soft404_classification'], e['evidence_level']) for e in hits}, {('inconclusive', 'interrupted')})
        self.assertEqual(self.result['agent_statuses']['soft404_filter'], 'interrupted')
        self.assertEqual(self.result['pipeline_status'], 'partial')
        self.expect.update(pipeline_status='partial')

    def test_crash_after_agent5_checkpoint_reports_without_http(self):
        self.crash('checkpoint', match={'node': 'run_soft404_filter', 'event': 'checkpoint'})
        self.resume(); self.resumed_ok(http_after=False)
        self.assertIn('run_soft404_filter', self.result['recovery']['reused_nodes'])
        self.assertEqual(self.result['pipeline_status'], 'completed')
        self.expect.update(pipeline_status='completed', zero_http_after_resume=True)

    def test_crash_after_report_recomputes_identical_digest(self):
        self.crash('checkpoint', match={'node': 'generate_report', 'event': 'checkpoint'})
        before = self.report_digest_before()
        self.resume(); self.resumed_ok(http_after=False)
        self.assertEqual(self.result['multi_origin_report']['digest'], before)
        self.assertEqual(self.result['pipeline_status'], 'completed')
        self.expect.update(pipeline_status='completed', zero_http_after_resume=True, report_digest=before)

    def test_crash_after_reflection_finishes_without_http(self):
        self.crash('checkpoint', match={'node': 'post_session_reflection', 'event': 'checkpoint'})
        before = self.report_digest_before()
        self.resume(); self.resumed_ok(http_after=False)
        self.assertEqual(self.result['multi_origin_report']['digest'], before)
        self.expect.update(pipeline_status=self.result['pipeline_status'], zero_http_after_resume=True)

    def test_crash_after_final_result_before_session_finished(self):
        self.crash('checkpoint', match={'node': 'pipeline'})
        before = self.report_digest_before()
        self.resume(); self.resumed_ok(http_after=False)
        self.assertEqual(self.result['multi_origin_report']['digest'], before)
        self.assertEqual(sum(e['event'] == 'session_finished' for e in journal(self.directory)), 1)
        self.expect.update(pipeline_status=self.result['pipeline_status'], zero_http_after_resume=True)

    def test_finished_session_returns_already_finished_without_execution(self):
        self.crash('session_finished')
        journal_bytes = (self.directory / 'recovery/journal.jsonl').read_bytes()
        final = read(next(e for e in reversed(journal(self.directory)) if e['event'] == 'checkpoint')['payload']['path'])
        self.resume(); self.no_new_http()
        self.assertEqual((self.directory / 'recovery/journal.jsonl').read_bytes(), journal_bytes, 'journal appended')
        recovery = self.result['recovery']
        self.assertEqual((recovery['status'], recovery['graph_invoked'], recovery['agents_invoked'], recovery['journal_appended']),
                         ('already_finished', False, False, False))
        self.assertEqual(self.result['pipeline_status'], final['pipeline_status'])
        self.assertEqual(self.result['multi_origin_report'], final['multi_origin_report'])
        self.check_common()
        self.expect.update(already_finished=True, pipeline_status=self.result['pipeline_status'])

    # ── finalize_only ──
    def test_finalize_after_global_stop_preserves_stop_with_zero_http(self):
        self.servers[0].faults['/help'] = {'kind': 'status', 'status': 429, 'when': 'q'}
        self.crash('stop')
        self.resume('denied_resume'); self.deny_checks('recovery_global_stop')
        self.finalize(); self.check_common(); self.no_replay(); self.no_new_http()
        self.assertEqual(self.result['stop_reason'], 'http_429')
        self.assertEqual(self.result['multi_origin_report']['content']['stop']['global_stop_reason'], 'http_429')
        self.assertTrue(self.result['recovery']['finalize_only'])
        self.assertEqual(self.result['agent_statuses']['soft404_filter'], 'not_started')
        self.assertNotEqual(self.result['pipeline_status'], 'completed')
        self.expect.update(finalize_only=True, zero_http_after_resume=True, global_stop='http_429')

    def test_finalize_with_budget_remaining_sends_nothing(self):
        self.crash('reserved', probe={'kind': 'probe', 'unit_index': 0, 'ordinal': 2})
        self.finalize(); self.check_common(); self.no_replay(); self.no_new_http()
        self.assertLess(self.result['runtime']['http_dispatches'], self.settings['config']['http_max_requests'])
        self.assertIsNone(self.result['runtime']['stop_reason'])
        self.assertEqual(self.result['stop_reason'], 'finalize_only')
        self.assertEqual(self.result['agent_statuses']['param_disc'], 'interrupted')
        self.assertEqual(self.result['agent_statuses']['soft404_filter'], 'not_started')
        self.assertNotEqual(self.result['pipeline_status'], 'completed')
        rows = journal(self.directory)
        bound = max(i for i, e in enumerate(rows) if e['event'] == 'process_bound')
        self.assertFalse(any(e['event'] == 'reserved' for e in rows[bound:]), 'finalize reserved a request')
        self.resume('after_finalize'); self.no_new_http()
        self.assertEqual(self.result['recovery']['status'], 'already_finished')
        self.expect.update(finalize_only=True, zero_http_after_resume=True)

    def test_finalize_never_bypasses_integrity(self):
        self.crash('reserved', probe={'kind': 'probe', 'unit_index': 0, 'ordinal': 2})
        last = next(e for e in reversed(journal(self.directory)) if e['event'] == 'checkpoint')
        path = Path(last['payload']['path']); path.write_bytes(path.read_bytes().replace(b'"partial"', b'"complete"', 1) + b' ')
        self.snapshot(); self.expect['tampered_checkpoint'] = last['payload']['node']
        self.finalize(); self.deny_checks('recovery_checkpoint_invalid')

    # ── consistent forgeries ──
    def test_consistently_forged_decision_is_rejected(self):
        self.crash('checkpoint', match={'node': 'run_param_discovery', 'event': 'checkpoint'})

        def mutate(data):
            hit = False
            for row in data.get('decision_chain', []):
                if row['decision_point'] == 'after_fuzzing':
                    row['action'], hit = 'skip_to_filter', True
            return hit
        self.forge(mutate)
        self.resume(); self.deny_checks('recovery_decision_mismatch')

    def test_consistently_forged_report_is_rejected(self):
        self.crash('checkpoint', match={'node': 'post_session_reflection', 'event': 'checkpoint'})

        def mutate(data):
            report = data.get('multi_origin_report')
            if not report:
                return False
            report['content']['totals']['soft404_strong'] += 1
            report['digest'] = canonical_digest(report['content'])  # self-consistent, so only recomputation can catch it
            return True
        self.forge(mutate)
        self.resume(); self.deny_checks('recovery_report_mismatch')


if __name__ == '__main__':
    unittest.main()
