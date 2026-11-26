"""B5 real loopback sessions exported offline.

Sessions come from the real compiled graph (Agents 1-5, Report, Reflection) on three independent
loopback servers that log every arrival (fsync), in-process or in killed/restarted worker processes
(B4.2C lab). The export then runs with socket connect, the decision engine and KnowledgeStore writes
patched to fail; server logs and source hashes are compared before/after. No HTTP mocks, Internet or
provider LLM. Set B5_EVIDENCE_DIR to keep evidence for scripts/verify_origin_report_evidence.py.
"""
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import test_origin_full_graph_http as b42c
import test_origin_full_graph_recovery_http as b42c_recovery
from src.coordinator import graph
from src.coordinator.knowledge_store import KnowledgeStore
from src.coordinator.origin_export import ExportError, export_session

SECRET = 'b42b-local-only-fake'


def journal(directory):
    return [json.loads(l) for l in (Path(directory) / 'recovery/journal.jsonl').read_text(encoding='utf-8').splitlines()]


class ExportLab(b42c.FullGraphLab):
    EVIDENCE = 'B5_EVIDENCE_DIR'

    def setUp(self):
        super().setUp()
        self.exports = []

    def tearDown(self):
        b42c.write(self.directory / 'b5_evidence.json', {'case_id': self.case_id, 'test': self._testMethodName,
                                                         'exports': self.exports})
        super().tearDown()

    def source_hashes(self):
        recovery = self.directory / 'recovery'
        hashes = {name: sha256((recovery / name).read_bytes()).hexdigest() for name in ('journal.jsonl', 'head.json')}
        for event in journal(self.directory):
            if event['event'] == 'checkpoint':
                path = Path(event['payload']['path'])
                hashes[path.resolve().relative_to(self.directory.resolve()).as_posix()] = sha256(path.read_bytes()).hexdigest()
        return hashes

    def export(self, label, *, expect='exported', code=None):
        recovery, out = self.directory / 'recovery', self.directory / ('export_' + label)
        before, rows = self.source_hashes(), {s.role: len(s.access) for s in self.servers}
        forbidden = AssertionError('B5 export attempted network, LLM or KnowledgeStore')
        outcome = ('exported', None)
        with patch('socket.socket.connect', side_effect=forbidden), patch('socket.create_connection', side_effect=forbidden), \
                patch.object(graph, '_get_decision_engine', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_lessons', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_session', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_decision_pattern', side_effect=forbidden):
            try:
                export_session(recovery, out)
            except ExportError as exc:
                outcome = ('refused', exc.code)
        after = self.source_hashes()
        row = {'label': label, 'recovery_dir': str(recovery.resolve()), 'output_dir': str(out.resolve()),
               'expect': expect, 'code': code, 'outcome': list(outcome), 'source_sha256_before': before,
               'source_sha256_after': after, 'server_rows_before_export': rows,
               'server_rows_after_export': {s.role: len(s.access) for s in self.servers}}
        if outcome[0] == 'refused':
            # A later resume appends to the journal: keep the state the refusal was judged on.
            snapshot = self.directory / ('refusal_snapshot_' + label)
            snapshot.mkdir()
            for name in ('journal.jsonl', 'head.json'):
                (snapshot / name).write_bytes((recovery / name).read_bytes())
            row['source_snapshot'] = str(snapshot.resolve())
        self.exports.append(row)
        self.assertEqual(outcome, (expect, code))
        self.assertEqual(after, before, 'export changed journal, head or checkpoints')
        self.assertEqual({s.role: len(s.access) for s in self.servers}, rows, 'export sent HTTP')
        self.assertFalse(list(self.directory.glob('.pending_export_*')))
        if expect != 'exported':
            self.assertFalse(out.exists())
            return None
        env = json.loads((out / 'report.json').read_text(encoding='utf-8'))
        md = (out / 'report.md').read_text(encoding='utf-8')
        self.check_export(env, md)
        return env, md

    def check_export(self, env, md):
        rows = journal(self.directory)
        final = b42c.read(next(e for e in reversed(rows) if e['event'] == 'checkpoint')['payload']['path'])
        report = final['multi_origin_report']
        self.assertEqual((env['report_v1']['content'], env['report_v1']['digest']), (report['content'], report['digest']))
        reservations = [e['payload'] for e in rows if e['event'] == 'reserved']
        starts = {e['payload']['sequence'] for e in rows if e['event'] == 'dispatch_started'}
        heads = {e['payload']['sequence'] for e in rows if e['event'] == 'response_headers'}
        total = env['accounting']['total']
        self.assertEqual((total['reserved'], total['dispatch_started'], total['response_headers']),
                         (len(reservations), len(starts), len(heads)))
        self.assertGreater(next(k for k in env['accounting']['by_kind'] if k['kind'] == 'recon')['reserved'], 0)
        for row in env['accounting']['by_origin']:
            server = next(s for s in self.servers if s.origin == row['origin'])
            self.assertLessEqual(row['response_headers'], len(server.access))
            self.assertLessEqual(len(server.access), row['dispatch_started'])
        self.assertEqual(len(self.servers[2].access), 0)
        self.assertEqual([o['origin'] for o in env['origins']], [self.a, self.b])
        for origin in env['origins']:
            ids = [e['endpoint_id'] for e in origin['endpoints']]
            self.assertEqual(len(ids), len(set(ids)))
            for e in origin['endpoints']:
                self.assertEqual(urlsplit(e['url']).scheme + '://' + urlsplit(e['url']).netloc, origin['origin'])
                self.assertEqual(e['endpoint_verification_status'], 'not_verified')
            source = {(e['url'], e['method']) for e in final['origin_contexts'][origin['origin']]['endpoints']}
            self.assertTrue(source <= {(e['url'], e['method']) for e in origin['endpoints']})
        self.assertIn(self.c, [d['origin'] for d in env['discovered_only_origins']])
        self.assertTrue(all(d['executed'] is False and d['journal_reservations'] == 0 for d in env['discovered_only_origins']))
        self.assertIsNone(env['severity'])
        self.assertEqual(env['session']['gate']['origin_execution_mode'], 'not_enabled_b1')
        for text in (json.dumps(env), md):
            self.assertNotIn(SECRET, text)
            self.assertNotIn(str(self.directory), text)
        if final['telemetry']['http']['count_complete'] is False:
            self.assertIsNone(env['accounting']['telemetry_http']['total_requests'])


class OriginReportExportHttpTests(ExportLab, unittest.TestCase):
    def test_export_completed_full_graph(self):
        self.run_graph(); self.check_common()
        env, md = self.export('first')
        self.assertEqual(env['session']['pipeline_status'], 'completed')
        self.assertEqual(env['accounting']['total']['reserved'], sum(len(s.access) for s in self.servers[:2]))
        self.assertEqual((env['accounting']['total']['attempt_unknown'], env['accounting']['total']['outcome_unknown']), (0, 0))
        legacy = env['accounting']['legacy_report_totals']
        recon = next(k for k in env['accounting']['by_kind'] if k['kind'] == 'recon')['reserved']
        self.assertEqual(legacy['dispatch_attempted'] + legacy['parameter_requests'] + legacy['soft404_requests'] + recon,
                         env['accounting']['total']['reserved'])
        classes = {e['soft404']['classification'] for o in env['origins'] for e in o['endpoints'] if e['soft404']}
        self.assertIn('genuine_distinct', classes)
        again, md2 = self.export('second')
        self.assertEqual(md, md2, 'Markdown is not deterministic on a real session')
        self.assertEqual(env['export_digest'], again['export_digest'])
        out = self.directory / 'export_first'
        snapshot = {p.name: p.read_bytes() for p in out.iterdir()}
        with self.assertRaises(ExportError) as caught:
            export_session(self.directory / 'recovery', out)
        self.assertEqual(caught.exception.code, 'export_output_exists')
        self.assertEqual({p.name: p.read_bytes() for p in out.iterdir()}, snapshot)

    def test_export_partial_global_429(self):
        self.servers[0].faults['/help'] = {'kind': 'status', 'status': 429, 'when': 'q'}
        self.run_graph(); self.check_common()
        env, _ = self.export('first')
        self.assertEqual(env['session']['global_stop_reason'], 'http_429')
        self.assertIn('http_429', env['session']['journal_stop_events'])
        self.assertNotEqual(env['session']['pipeline_status'], 'completed')
        agents = {a['agent']: a['status'] for a in env['agents']}
        self.assertEqual(agents['soft404_filter'], 'not_started')
        self.assertFalse(any(p['phase'] == 'soft404_filter' for p in env['accounting']['by_phase']))

    def test_export_partial_origin_quota_halt(self):
        self.settings['quotas'][self.a] = 12
        self.run_graph(); self.check_common()
        env, _ = self.export('first')
        frontend = env['origins'][0]
        self.assertEqual((frontend['budget']['limit'], frontend['budget']['reserved'], frontend['budget']['remaining']), (12, 12, 0))
        self.assertEqual(frontend['halts']['parameters'], 'origin_request_budget')
        self.assertEqual(frontend['status'], 'partial')
        self.assertEqual(env['origins'][1]['status'], 'completed')

    def test_export_legacy_three_agent_session(self):
        self.run_graph(parameter_verification=False, soft404_verification=False)
        env, _ = self.export('first')
        self.assertEqual(env['session']['mode'], 'localhost_three_agents')
        self.assertNotEqual(env['session']['pipeline_status'], 'completed')
        self.assertTrue(all(e['parameters'] is None and e['soft404'] is None for o in env['origins'] for e in o['endpoints']))
        self.assertEqual({p['phase'] for p in env['accounting']['by_phase']}, {'run_tech_recon', 'fuzzing'})

    def test_export_refuses_tampered_checkpoint(self):
        self.run_graph(); self.check_common()
        event = next(e for e in journal(self.directory) if e['event'] == 'checkpoint' and e['payload']['node'] == 'run_fuzzing')
        path = Path(event['payload']['path'])
        path.write_bytes(path.read_bytes() + b' ')
        self.export('tampered', expect='refused', code='export_checkpoint_invalid')
        path.write_bytes(path.read_bytes()[:-1])
        self.export('restored')


class OriginReportExportRecoveryHttpTests(ExportLab, unittest.TestCase):
    kind = 'recovery'
    _source = b42c_recovery.OriginFullGraphRecoveryHttpTests
    worker, wait_file, snapshot, crash = _source.worker, _source.wait_file, _source.snapshot, _source.crash
    run_to_end, resume, finalize = _source.run_to_end, _source.resume, _source.finalize

    def test_export_after_crash_in_agent4_and_resume(self):
        self.crash('reserved', probe={'kind': 'probe', 'unit_index': 0, 'ordinal': 2})
        self.export('crashed', expect='refused', code='export_session_not_finished')
        self.resume(); self.check_common()
        env, md = self.export('resumed')
        total = env['accounting']['total']
        self.assertEqual((total['attempt_unknown'], total['outcome_unknown']), (1, 1))
        self.assertEqual(env['session']['pipeline_status'], 'partial')
        self.assertTrue(env['recovery']['resumed'])
        self.assertEqual(len(env['recovery']['parameter_outcome_unknown_sequences']), 1)
        self.assertIn('không xác định', md)  # telemetry total stays unknown
        legacy = env['accounting']['legacy_report_totals']['parameter_requests']
        probe = next(k for k in env['accounting']['by_kind'] if k['kind'] == 'parameter_probe')
        self.assertEqual(legacy, probe['reserved'])
        self.assertEqual(probe['dispatch_started'], probe['reserved'] - 1)

    def test_export_after_crash_in_agent5_and_resume(self):
        self.crash('reserved', probe={'kind': 'soft404', 'unit_index': 0, 'ordinal': 2})
        self.resume(); self.check_common()
        env, _ = self.export('resumed')
        interrupted = [e['soft404'] for o in env['origins'] for e in o['endpoints'] if (e['soft404'] or {}).get('unit_state') == 'interrupted']
        self.assertTrue(interrupted)
        self.assertEqual({(s['classification'], s['evidence_basis']) for s in interrupted}, {('inconclusive', 'interrupted')})
        self.assertGreater(env['accounting']['total']['outcome_unknown'], 0)

    def test_export_finalized_after_crash(self):
        self.crash('reserved', probe={'kind': 'probe', 'unit_index': 0, 'ordinal': 2})
        self.finalize(); self.check_common()
        env, _ = self.export('finalized')
        self.assertTrue(env['session']['finalize_only'])
        self.assertTrue(env['recovery']['finalize_only'])
        self.assertNotEqual(env['session']['pipeline_status'], 'completed')
        self.assertEqual(env['session']['stop_reason'], 'finalize_only')

    def test_export_finalized_after_global_stop(self):
        self.servers[0].faults['/help'] = {'kind': 'status', 'status': 429, 'when': 'q'}
        self.crash('stop')
        self.finalize(); self.check_common()
        env, _ = self.export('finalized')
        self.assertEqual(env['session']['global_stop_reason'], 'http_429')
        self.assertTrue(env['session']['finalize_only'])

    def test_export_requires_session_finished(self):
        self.crash('checkpoint', match={'node': 'pipeline'})
        self.export('unsealed', expect='refused', code='export_session_not_finished')
        self.resume(); self.check_common()
        env, _ = self.export('sealed')
        self.assertEqual(env['session']['pipeline_status'], 'completed')
        self.assertEqual(sum(e['event'] == 'session_finished' for e in journal(self.directory)), 1)


if __name__ == '__main__':
    unittest.main()
