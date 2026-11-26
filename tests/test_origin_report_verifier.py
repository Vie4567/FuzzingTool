"""B5 verifier tests: scripts/verify_origin_report_evidence.py run as an independent subprocess.

Evidence is synthesized offline with the B5 unit fixtures (real on-disk sessions, real exports, access
logs derived from the journal). No sockets, HTTP or provider LLM. Covers refusal-only cases and the
refusal negative checks: wrong code, missing refusal evidence, refusal that still produced a report,
an empty case and a false refusal of an eligible session.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlsplit

from test_origin_report_export import A, B, C, make_state, write_session
from src.coordinator.origin_export import ExportError, export_session

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / 'scripts' / 'verify_origin_report_evidence.py'


def journal_hashes(recovery):
    from hashlib import sha256
    root = recovery.parent
    out = {n: sha256((recovery / n).read_bytes()).hexdigest() for n in ('journal.jsonl', 'head.json')}
    for line in (recovery / 'journal.jsonl').read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        if row['event'] == 'checkpoint':
            path = Path(row['payload']['path'])
            out[path.resolve().relative_to(root.resolve()).as_posix()] = sha256(path.read_bytes()).hexdigest()
    return out


class VerifierCases(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def case(self, name, *, finished=True, export=True):
        directory = self.base / 'evidence' / name
        directory.mkdir(parents=True)
        state, rows = make_state()
        recovery = write_session(directory, state, rows, finished=finished)
        access = {}
        for role, origin in (('frontend', A), ('gateway', B), ('unapproved', C)):
            path = directory / f'{role}_access.jsonl'
            lines = [json.dumps({'path': urlsplit(r['url']).path or '/', 'query': urlsplit(r['url']).query})
                     for r in rows if r['origin'] == origin and r['started']]
            path.write_text(''.join(l + '\n' for l in lines), encoding='utf-8')
            access[role] = str(path)
        (directory / 'evidence.json').write_text(json.dumps({'test': name, 'origins': {'frontend': A, 'gateway': B, 'unapproved': C},
                                                             'access_files': access}), encoding='utf-8')
        out = directory / 'export'
        before = journal_hashes(recovery)
        try:
            export_session(recovery, out)
            outcome = ['exported', None]
        except ExportError as exc:
            outcome = ['refused', exc.code]
        row = {'label': name, 'recovery_dir': str(recovery), 'output_dir': str(out), 'expect': outcome[0], 'code': outcome[1],
               'outcome': outcome, 'source_sha256_before': before, 'source_sha256_after': journal_hashes(recovery),
               'server_rows_before_export': {}, 'server_rows_after_export': {}}
        self.write_rows(directory, [row])
        return directory, row

    @staticmethod
    def write_rows(directory, rows):
        (directory / 'b5_evidence.json').write_text(json.dumps({'case_id': directory.name, 'exports': rows}), encoding='utf-8')

    def verify(self, *extra):
        proc = subprocess.run([sys.executable, '-B', '-I', str(VERIFIER), str(self.base / 'evidence'), *extra],
                              capture_output=True, text=True, timeout=300, encoding='utf-8')
        return proc.returncode, json.loads(proc.stdout)

    def test_export_and_refusal_only_cases_pass_with_every_refusal_checked(self):
        self.case('exported')
        _, row = self.case('unfinished', finished=False)
        self.assertEqual(row['outcome'], ['refused', 'export_session_not_finished'])
        code, result = self.verify('--expected-cases', '2')
        self.assertEqual(code, 0, result)
        self.assertEqual((result['exports_checked'], result['refusals_checked']), (1, 1))
        self.assertEqual(result['refusal_reasons'], {'export_session_not_finished': 1})

    def test_refusal_mutations_are_detected(self):
        _, good = self.case('exported')
        directory, refused = self.case('unfinished', finished=False)
        variants = {
            'wrong_code': lambda r: r.update(code='export_journal_invalid', outcome=['refused', 'export_journal_invalid']),
            'missing_refusal_evidence': lambda r: r.pop('outcome'),
            'expectation_not_matching_outcome': lambda r: r.update(code='export_journal_invalid'),
            'source_changed': lambda r: r['source_sha256_after'].update({'journal.jsonl': '0' * 64}),
        }
        for name, mutate in variants.items():
            with self.subTest(mutation=name):
                row = deepcopy(refused); mutate(row); self.write_rows(directory, [row])
                code, result = self.verify()
                self.assertEqual(code, 1, f'{name} not detected: {result}')
        self.write_rows(directory, [refused])
        # refusal that still published a report
        (Path(refused['output_dir'])).mkdir(); (Path(refused['output_dir']) / 'report.json').write_text('{}', encoding='utf-8')
        code, result = self.verify()
        self.assertEqual(code, 1, result)
        (Path(refused['output_dir']) / 'report.json').unlink(); Path(refused['output_dir']).rmdir()
        # empty case: neither an export nor a refusal
        empty = self.base / 'evidence' / 'empty'; empty.mkdir()
        (empty / 'evidence.json').write_text(json.dumps({'origins': {}, 'access_files': {}}), encoding='utf-8')
        self.write_rows(empty, [])
        code, result = self.verify()
        self.assertEqual(code, 1, result)
        self.assertTrue(any('neither' in f[1] for f in result['failed_cases']), result)
        for p in empty.iterdir():
            p.unlink()
        empty.rmdir()
        # false refusal: the session is eligible, but the evidence claims a refusal
        exported_dir = Path(good['recovery_dir']).parent
        fake = dict(good, expect='refused', code='export_session_not_finished', outcome=['refused', 'export_session_not_finished'],
                    output_dir=str(exported_dir / 'never_written'))
        self.write_rows(exported_dir, [fake])
        code, result = self.verify()
        self.assertEqual(code, 1, result)
        self.assertTrue(any('eligible' in f[1] for f in result['failed_cases']), result)

    def test_refusal_snapshot_allows_only_append_only_growth(self):
        directory, refused = self.case('unfinished', finished=False)
        recovery = Path(refused['recovery_dir'])
        snapshot = directory / 'refusal_snapshot'; snapshot.mkdir()
        for name in ('journal.jsonl', 'head.json'):
            (snapshot / name).write_bytes((recovery / name).read_bytes())
        self.write_rows(directory, [dict(refused, source_snapshot=str(snapshot))])
        journal = recovery / 'journal.jsonl'
        original = journal.read_bytes()
        journal.write_bytes(original + b'{"appended": "after refusal"}\n')  # e.g. an operator resume
        code, result = self.verify()
        self.assertEqual(code, 0, result)
        journal.write_bytes(original.replace(b'"GET"', b'"PUT"', 1))  # rewritten, not appended
        code, result = self.verify()
        self.assertEqual(code, 1, result)
        self.assertTrue(any('rewritten' in f[1] for f in result['failed_cases']), result)

    def test_negative_checks_include_refusal_mutations(self):
        self.case('exported')
        self.case('unfinished', finished=False)
        code, result = self.verify('--negative-checks')
        names = {n: ok for n, ok, _ in result['negative_checks']}
        for name in ('refusal_wrong_code', 'refusal_evidence_missing', 'refusal_with_report', 'empty_case',
                     'false_refusal_of_eligible_session', 'refusal_source_rewritten'):
            self.assertTrue(names.get(name), (name, result['negative_checks']))


if __name__ == '__main__':
    unittest.main()
