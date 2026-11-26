"""B5 unit tests for the offline export layer; no sockets, no HTTP, no provider LLM.

Sessions are synthesized on disk with the real contracts: a hash-chained journal and head,
sha256-anchored checkpoints and a Report v1 built by the real `build_report`/`build_reflection`.
Mutations are applied before anchoring (self-consistent hashes), so only semantic checks catch them.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.coordinator import graph, origin_export
from src.coordinator.artifacts import RunArtifacts
from src.coordinator.knowledge_store import KnowledgeStore
from src.coordinator.origin_export import ExportError, export_session, md_cell, render_markdown
from src.coordinator.origin_recovery import RecoveryJournal, digest
from src.coordinator.origin_report import AGENTS, build_reflection, build_report, canonical_digest

A, B, C = 'http://127.0.0.1:41001', 'http://127.0.0.1:41002', 'http://127.0.0.1:41003'
FAKE = 'Bearer b5-local-only-fake'
ROOT = Path(__file__).resolve().parents[1]
POLICIES = {A: {'rules': [{'path': '/help', 'methods': ['GET', 'HEAD'], 'read_only': True, 'parameters': ['q'],
                           'soft404_controls': True}]},
            B: {'rules': [{'path': '/api', 'methods': ['GET'], 'read_only': True, 'soft404_controls': True}]}}


def ident(url, method):
    return sha256((url + '\n' + (method or '')).encode()).hexdigest()[:24]


def observation(url, method, sources):
    origin = url.split('/', 3)[0] + '//' + url.split('/', 3)[2]
    return {'endpoint_id': ident(url, method), 'url': url, 'origin': origin, 'method': method,
            'resource_type': 'frontend_route', 'classification': 'observed', 'evidence_refs': ['ev_1'],
            'verification_status': 'not_verified', 'attempted': None,
            'provenance': [{'source': s, 'source_type': 'html', 'source_url': origin + '/', 'source_sha256': None,
                            'evidence_location': {}, 'evidence_refs': ['ev_' + s], 'classification': 'observed',
                            'confidence': None, 'confidence_basis': None, 'resource_type': 'frontend_route'}
                           for s in sources]}


class Plan:
    """Ordered request plan: every row becomes a reservation (+ optional start/headers/measurement)."""

    def __init__(self):
        self.rows = []

    def add(self, origin, url, method, phase, *, candidate=None, probe=None, soft404=None, status=200,
            started=True, measured=True, error=None):
        seq = len(self.rows) + 1
        self.rows.append({'seq': seq, 'origin': origin, 'url': url, 'method': method, 'phase': phase,
                          'candidate_id': candidate, 'probe': probe, 'soft404': soft404, 'status': status,
                          'started': started, 'measured': measured, 'error': error})
        return seq


def dispatch_counts(records):
    return {'selected': len(records), 'attempted': sum(r['attempted'] is True for r in records),
            'responses': sum(r['status_code'] is not None for r in records),
            'errors': sum(r['attempted'] is True and r['error'] is not None for r in records),
            'unattempted': sum(r['attempted'] is False for r in records), 'timeouts': sum(r['timeout'] for r in records)}


def make_state(*, unknown=False, timeout=False, inject=None):
    plan, contexts = Plan(), {}
    help_, help_q, help_head, api, slow = A + '/help', A + '/help?x=1', A + '/help', B + '/api', B + '/slow'
    plan.add(A, A + '/', 'GET', 'run_tech_recon')
    plan.add(B, B + '/openapi.json', 'GET', 'run_tech_recon')
    endpoints = {A: [observation(help_, 'GET', ['html', 'javascript']), observation(help_q, 'GET', ['html']),
                     observation(help_head, 'HEAD', ['html'])],
                 B: [observation(api, 'GET', ['openapi'])] + ([observation(slow, 'GET', ['openapi'])] if timeout else [])}
    records = {A: [], B: []}
    for origin in (A, B):
        for e in endpoints[origin]:
            slow_row = e['url'] == slow
            seq = plan.add(origin, e['url'], e['method'], 'fuzzing', candidate=e['endpoint_id'],
                           status=None if slow_row else 200,
                           error={'error_type': 'transport_error', 'exception_type': 'TimeoutError', 'count': 1} if slow_row else None)
            records[origin].append({'candidate_id': e['endpoint_id'], 'origin': origin, 'url': e['url'],
                                    'observed_method': e['method'], 'planned_test_method': None, 'execution_method': e['method'],
                                    'evidence_refs': ['ev_1'], 'runtime_sequence': seq, 'attempted': True,
                                    'status_code': None if slow_row else 200, 'retained_body_bytes': 10, 'bytes_received': 10,
                                    'body_complete': not slow_row, 'response_time': .01,
                                    'error': {'error_type': 'transport_error', 'exception_type': 'TimeoutError', 'count': 1} if slow_row else None,
                                    'timeout': slow_row, 'stop_reason': None, 'classification': None if slow_row else 'observed_response',
                                    'verified': None, 'verification_status': 'not_verified', 'recorded_at_utc': 'x'})
    e1 = endpoints[A][0]['endpoint_id']
    unit = 'u' * 32
    p1 = plan.add(A, help_, 'GET', 'param_disc', probe={'version': 1, 'endpoint_id': e1, 'unit_id': unit, 'ordinal': 1,
                                                         'role': 'baseline', 'parameter': None})
    p2 = plan.add(A, help_ + '?q=s1', 'GET', 'param_disc', probe={'version': 1, 'endpoint_id': e1, 'unit_id': unit,
                                                                   'ordinal': 2, 'role': 'candidate', 'parameter': 'q'})
    preqs = [{'runtime_sequence': p1, 'status_code': 200, 'error': None}, {'runtime_sequence': p2, 'status_code': 200, 'error': None}]
    if unknown:
        p3 = plan.add(A, help_ + '?q=s2', 'GET', 'param_disc', started=False, measured=False, status=None,
                      probe={'version': 1, 'endpoint_id': e1, 'unit_id': unit, 'ordinal': 3, 'role': 'candidate', 'parameter': 'q'})
        preqs.append({'runtime_sequence': p3, 'status_code': None, 'error': None, 'attempted': None,
                      'recovery_state': 'outcome_unknown'})
    candidates = [{'name': 'page', 'selected': False, 'selection_reason': 'parameter_not_approved_by_operator', 'verification': 'not_checked',
                   'verification_reason': 'not_selected', 'verification_performed': False,
                   'provenance': [{'source': 'param_assembler_static', 'classification': 'inferred', 'evidence_refs': []}]},
                  {'name': 'q', 'selected': True, 'selection_reason': 'operator_listed_parameter', 'verification': 'verified',
                   'verification_reason': 'repeatable_response_effect_vs_negative_controls', 'verification_performed': True,
                   'provenance': [{'source': 'agent1_reference', 'classification': 'observed', 'evidence_refs': ['ev_1']}]}]
    if inject and inject.get('parameter_name'):
        candidates.append({'name': inject['parameter_name'], 'selected': False, 'selection_reason': 'x', 'verification': 'not_checked',
                           'verification_reason': 'not_selected', 'verification_performed': False, 'provenance': []})

    def pendpoint(e, origin, eligible):
        record = next(r for r in records[origin] if r['candidate_id'] == e['endpoint_id'])
        return {'endpoint_id': e['endpoint_id'], 'origin': origin, 'url': e['url'], 'method': 'GET', 'eligible': eligible,
                'exclusion_reason': None if eligible else 'parameter_probe_not_approved', 'unit_id': unit if eligible else None,
                'unit_state': 'completed' if eligible else None,
                'source_dispatch': {'runtime_sequence': record['runtime_sequence'], 'evidence_refs': ['ev_1']},
                'candidates': deepcopy(candidates) if eligible else []}
    params = {A: [pendpoint(e, A, i == 0) for i, e in enumerate(endpoints[A])], B: [pendpoint(e, B, False) for e in endpoints[B]]}
    # Soft404: A /help genuine_distinct (metrics_journaled), B /api http_404 (rederived); others not_checked.
    soft_rows, sreqs = {A: [], B: []}, {A: [], B: []}
    for origin, cls, level in ((A, 'genuine_distinct', 'metrics_journaled'), (B, 'http_404', 'rederived')):
        sunit = ('s' if origin == A else 't') * 32
        target = endpoints[origin][0]
        controls = [plan.add(origin, origin + '/__sentinel_missing_' + 'a' * 32, 'GET', 'soft404_filter', status=404,
                             soft404={'version': 1, 'unit_id': sunit, 'ordinal': 1, 'role': 'control'})]
        cand = plan.add(origin, target['url'], 'GET', 'soft404_filter',
                        soft404={'version': 1, 'unit_id': sunit, 'ordinal': 2, 'role': 'candidate', 'endpoint_id': target['endpoint_id']})
        sreqs[origin] = [{'runtime_sequence': s, 'status_code': 404 if s in controls else 200, 'error': None} for s in controls + [cand]]
        for i, e in enumerate(endpoints[origin]):
            record = next(r for r in records[origin] if r['candidate_id'] == e['endpoint_id'])
            first = i == 0
            soft_rows[origin].append({'endpoint_id': e['endpoint_id'], 'origin': origin, 'url': e['url'], 'eligible': first,
                                      'exclusion_reason': None if first else 'soft404_controls_not_approved',
                                      'group_id': 'g' * 24 if first else None, 'unit_id': sunit if first else None,
                                      'unit_state': 'completed' if first else None,
                                      'soft404_classification': cls if first else 'not_checked',
                                      'classification_reason': 'measured' if first else 'soft404_controls_not_approved',
                                      'evidence_level': level if first else None, 'verification_status': 'not_verified',
                                      'parameter_context': {'verified_parameters': ['q'] if origin == A and first else [], 'authority': 'context_only'},
                                      'source_dispatch': {'runtime_sequence': record['runtime_sequence'], 'evidence_refs': ['ev_1']},
                                      'verification_evidence': {'candidate_sequence': cand if first else None,
                                                                'control_sequences': controls if first else None}})
    if inject and inject.get('classification_reason'):
        soft_rows[A][1]['classification_reason'] = inject['classification_reason']
    if inject and inject.get('source_url'):
        endpoints[A][1]['provenance'][0]['source_url'] = inject['source_url']
    for origin in (A, B):
        dispatch_status = 'partial' if any(r['error'] for r in records[origin]) else 'completed'
        pr = preqs if origin == A else []
        pc = [c for e in params[origin] for c in e['candidates']]
        contexts[origin] = {
            'status': 'pending', 'agent_statuses': {'tech_recon': 'success', 'wordlist_gen': 'success'},
            'endpoints': endpoints[origin],
            'context': {'schema_version': 1, 'parameters': [], 'forms': [],
                        'source_documents': [{'url': origin + '/', 'collection_status': 'completed'}],
                        'wordlist': {'candidates': [{'endpoint_id': e['endpoint_id'], 'url': e['url'], 'origin': origin, 'method': e['method'],
                                                     'observed': True, 'generated': False, 'selected': True} for e in endpoints[origin]],
                                     'selected_ids': [e['endpoint_id'] for e in endpoints[origin]]},
                        'http_dispatch': {'engine': 'python_http', 'status': dispatch_status,
                                          'stop_reason': 'partial_transport_error' if dispatch_status == 'partial' else 'completed',
                                          'counts': dispatch_counts(records[origin]), 'records': records[origin]},
                        'parameter_discovery': {'schema_version': 1, 'stage': 'B4.1', 'status': 'completed', 'stop_reason': 'completed',
                                                'origin_halt': None, 'endpoints': params[origin], 'requests': pr,
                                                'counts': {'endpoints': len(params[origin]), 'eligible_endpoints': sum(e['eligible'] for e in params[origin]),
                                                           'candidates': len(pc), 'selected': sum(c['selected'] for c in pc),
                                                           'verification_attempted': sum(c['verification_performed'] for c in pc),
                                                           'verified': sum(c['verification'] == 'verified' for c in pc),
                                                           'inconclusive': 0, 'not_checked': sum(c['verification'] == 'not_checked' for c in pc),
                                                           'http_requests': len(pr), 'responses': sum(r['status_code'] is not None for r in pr),
                                                           'errors': 0}},
                        'soft404': {'status': 'completed', 'stop_reason': 'completed', 'origin_halt': None,
                                    'classification_meaning': 'HTTP representation vs approved missing-path controls; not endpoint validity',
                                    'endpoints': soft_rows[origin], 'requests': sreqs[origin],
                                    'counts': {'endpoints': len(soft_rows[origin]), 'http_requests': len(sreqs[origin])}}}}
    contexts[C] = {'status': 'pending', 'agent_statuses': {}, 'endpoints': [observation(C + '/x', 'GET', ['html'])], 'context': None}
    rows = plan.rows
    reserved = len(rows)
    starts = sum(r['started'] for r in rows)
    state = {'session_id': 'session-b5-unit', 'target_url': A + '/', 'stop_reason': None,
             'approved_origins': [A, B], 'origin_policies': deepcopy(POLICIES), 'origin_execution_mode': 'not_enabled_b1',
             'origin_contract_version': 1,
             'config': {'multi_origin': {'approved_origins': [A, B], 'origin_policies': deepcopy(POLICIES)}},
             'discovered_origins': [{'origin': C, 'sources': [{'source': 'html', 'source_url': A + '/', 'evidence_refs': ['ev_1']}]}],
             'origin_contexts': contexts, 'agent_attempts': {a: 1 for a in AGENTS}, 'error_log': [],
             'decision_chain': [{'decision_point': p, 'action': a, 'source': 'deterministic_local_test_policy', 'llm_called': False, 'reason': None}
                                for p, a in (('after_recon', 'proceed_to_wordlist'), ('after_wordlist', 'proceed_to_fuzzing'),
                                             ('after_fuzzing', 'proceed_to_param'))],
             'local_origin_execution': {'mode': 'localhost_agents_1_to_5', 'graph_integration': 'local_full_graph_b42c'},
             'runtime': {'http_dispatches': reserved, 'http_max_requests': 300, 'stop_reason': None,
                         'http_dispatches_by_origin': {o: sum(r['origin'] == o for r in rows) for o in (A, B)},
                         'http_origin_max_requests': {A: 80, B: 80}},
             'telemetry': {'llm': {'attempted': 0, 'succeeded': 0, 'failed': 0, 'in_flight': 0, 'quota_rejections': 0, 'max_calls': 0,
                                   'count_scope': 'x', 'by_component': {}, 'by_phase': {}},
                           'http': {'total_requests': reserved if starts == reserved else None, 'known_requests': starts,
                                    'count_complete': starts == reserved, 'count_scope': 'x',
                                    'by_kind': {'target': starts}, 'by_phase': {}, 'unknown_sources': []}},
             'llm_call_count': 0,
             'recovery': {'version': 1, 'session_id': 'session-b5-unit', 'resumed': unknown, 'replay_policy': 'at_most_once_no_replay_reserved',
                          'exactly_once_delivery': False,
                          'accounting': {'reserved_requests': reserved, 'known_dispatch_starts': starts,
                                         'attempts_unknown': reserved - starts, 'responses_received': sum(r['started'] and r['status'] is not None for r in rows),
                                         'outcome_unknown_requests': sum(not r['measured'] for r in rows),
                                         'checkpoint_journal_sequence': 0, 'global_stop_reason': None}}}
    report = build_report(state, absent={a: ('not_started', None) for a in AGENTS}, invoked={a: True for a in AGENTS},
                          global_stop=None, contract_failures={}, fixed={'tech_recon': 'success', 'wordlist_gen': 'success'})
    state['multi_origin_report'] = {**report, 'status': 'completed', 'mode': {'graph_integration': 'local_full_graph_b42c', 'finalize_only': False}}
    state['agent_statuses'] = {a: report['content']['agents'][a]['status'] for a in AGENTS}
    state['local_reflection'] = build_reflection(report)
    ok = all(o['status'] == 'completed' for o in report['content']['approved_origins'])
    state['pipeline_status'] = 'completed' if ok else 'partial'
    state['all_modules_executed'] = True
    state['all_modules_successful'] = ok
    return state, rows


def chain(events):
    rows, previous = [], None
    for seq, (event, payload) in enumerate(events, 1):
        row = {'seq': seq, 'previous': previous, 'event': event, 'payload': payload, 'pid': 1, 'utc': '2026-11-26T00:00:00+00:00'}
        row['hash'] = digest(row)
        previous = row['hash']
        rows.append(row)
    return rows


def write_session(base, state, rows, *, finished=True, events_hook=None):
    base = Path(base)
    recovery, run = base / 'recovery', base / 'pipeline_20261126T000000Z_unit'
    (run / 'checkpoints').mkdir(parents=True)
    recovery.mkdir()
    (recovery / 'session.lock').write_bytes(b'0')
    config = {'multi_origin': {'approved_origins': [A, B], 'origin_policies': deepcopy(POLICIES)}, 'http_max_requests': 300,
              'http_rate_limit': 50, 'http_timeout_seconds': 2, 'pipeline_timeout_seconds': 120}
    events = [('session', {'version': 1, 'session_id': state['session_id'], 'runtime_id': 'r' * 32,
                           'authority': {'target': A + '/', 'config': config, 'quotas': {A: 80, B: 80},
                                         'parameter_verification': True, 'parameter_max_requests': 200,
                                         'soft404_verification': True, 'soft404_max_requests': 200}}),
              ('process_bound', {'session_id': state['session_id'], 'resume': False, 'reservations': 0})]
    for r in rows:
        reserved = {'url': r['url'], 'method': r['method'], 'candidate_id': r['candidate_id'], 'evidence_refs': ['ev_1'],
                    'origin': r['origin'], 'phase': r['phase'], 'sequence': r['seq'], 'reserved_at_monotonic': float(r['seq'])}
        for key in ('probe', 'soft404'):
            if r[key] is not None:
                reserved[key] = r[key]
        events.append(('reserved', reserved))
        if r['started']:
            events.append(('dispatch_started', {'sequence': r['seq']}))
        if r['started'] and r['status'] is not None:
            events.append(('response_headers', {'sequence': r['seq'], 'status_code': r['status'], 'stop_reason': None}))
        if r['measured']:
            events.append(('measurement', {'sequence': r['seq'], 'status_code': r['status'], 'content_length': 10, 'bytes_received': 10,
                                           'body_complete': r['status'] is not None, 'response_time': .01, 'stop_reason': None,
                                           'error': r['error']}))
    for index, node in enumerate(('generate_report', 'pipeline'), 1):
        path = run / 'checkpoints' / f'{index:04d}_{node}.json'
        path.write_text(json.dumps(state, indent=2), encoding='utf-8')
        events.append(('checkpoint', {'node': node, 'event': 'checkpoint' if node != 'pipeline' else state['pipeline_status'],
                                      'path': str(path), 'sha256': sha256(path.read_bytes()).hexdigest(), 'reservations': len(rows)}))
    if finished:
        events.append(('session_finished', {'pipeline_status': state['pipeline_status']}))
    if events_hook:
        events = events_hook(events)
    journal = chain(events)
    (recovery / 'journal.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in journal), encoding='utf-8')
    RunArtifacts._write_json(recovery / 'head.json', {'seq': journal[-1]['seq'], 'hash': journal[-1]['hash']})
    return recovery


def tree_hashes(base):
    # session.lock carries no evidence (and is byte-locked while a session is owned).
    return {str(p.relative_to(base)): sha256(p.read_bytes()).hexdigest() for p in sorted(Path(base).rglob('*'))
            if p.is_file() and p.name != 'session.lock'}


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.count = 0

    def session(self, mutate=None, *, unknown=False, timeout=False, inject=None, finished=True, events_hook=None, redigest=True):
        state, rows = make_state(unknown=unknown, timeout=timeout, inject=inject)
        if mutate:
            mutate(state)
            if redigest:  # self-consistent forgery: only semantic checks may catch it
                report = state['multi_origin_report']
                report['digest'] = canonical_digest(report['content'])
                state['local_reflection'] = build_reflection(report)
        self.count += 1
        base = self.tmp / f'session{self.count}'
        base.mkdir()
        return write_session(base, state, rows, finished=finished, events_hook=events_hook), state

    def export(self, recovery, name='export'):
        out = recovery.parent / name
        forbidden = AssertionError('B5 export attempted network, LLM or KnowledgeStore')
        with patch('socket.socket.connect', side_effect=forbidden), patch('socket.create_connection', side_effect=forbidden), \
                patch.object(graph, '_get_decision_engine', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_lessons', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_session', side_effect=forbidden), \
                patch.object(KnowledgeStore, 'save_decision_pattern', side_effect=forbidden):
            result = export_session(recovery, out, generated_at='2026-11-26T00:00:00+00:00')
        return result, json.loads((out / 'report.json').read_text(encoding='utf-8')), (out / 'report.md').read_text(encoding='utf-8')

    def refused(self, recovery, code, name='export'):
        before = tree_hashes(recovery.parent)
        with self.assertRaises(ExportError) as caught:
            self.export(recovery, name)
        self.assertEqual(caught.exception.code, code)
        self.assertFalse((recovery.parent / name).exists(), 'refused export left an output')
        self.assertEqual(tree_hashes(recovery.parent), before, 'refused export changed the session')
        self.assertFalse(list(recovery.parent.glob('.pending_export_*')))


class ExportContractTests(Base):
    def test_report_v1_is_kept_verbatim_and_digest_is_not_recomputed(self):
        recovery, state = self.session()
        result, env, md = self.export(recovery)
        self.assertEqual(env['report_v1']['content'], state['multi_origin_report']['content'])
        self.assertEqual(env['report_v1']['digest'], state['multi_origin_report']['digest'])
        self.assertEqual(env['source']['report_digest'], state['multi_origin_report']['digest'])
        body = {k: v for k, v in env.items() if k not in ('export_digest', 'export_meta')}
        self.assertEqual(env['export_digest'], canonical_digest(body))
        self.assertEqual((env['schema'], env['schema_version'], env['severity']), ('multi_origin_report_export', 1, None))
        self.assertEqual(env['session']['gate'], {'origin_execution_mode': 'not_enabled_b1', 'full_multi_origin_execution_enabled': False})
        self.assertEqual(env['source']['final_checkpoint'], 'pipeline_20261126T000000Z_unit/checkpoints/0002_pipeline.json')
        self.assertEqual(env['source']['journal'], 'recovery/journal.jsonl')
        manifest = json.loads((Path(result['output']) / 'manifest.json').read_text(encoding='utf-8'))
        for name in ('report.json', 'report.md'):
            self.assertEqual(manifest['files'][name], sha256((Path(result['output']) / name).read_bytes()).hexdigest())

    def test_per_origin_identity_variants_and_provenance(self):
        recovery, _ = self.session()
        _, env, _ = self.export(recovery)
        a, b = env['origins']
        self.assertEqual([o['origin'] for o in env['origins']], [A, B])
        self.assertTrue(all(e['url'].startswith(A + '/') for e in a['endpoints']))
        self.assertTrue(all(e['url'].startswith(B + '/') for e in b['endpoints']))
        variants = {(e['url'], e['method']) for e in a['endpoints']}
        self.assertEqual(variants, {(A + '/help', 'GET'), (A + '/help?x=1', 'GET'), (A + '/help', 'HEAD')})
        self.assertEqual(a['endpoint_index']['endpoints'], 3)  # two provenance rows, one endpoint
        self.assertEqual(a['endpoint_index']['provenance_references'], 4)
        self.assertEqual(a['endpoint_index']['urls_with_multiple_methods'], 1)
        self.assertEqual(a['endpoint_index']['with_query'], 1)
        self.assertEqual(a['endpoints'][0]['provenance_count'], 2)
        for e in a['endpoints']:
            self.assertEqual(e['endpoint_id'], ident(e['url'], e['method']))
        self.assertEqual(env['discovered_only_origins'][0]['origin'], C)
        self.assertEqual((env['discovered_only_origins'][0]['executed'], env['discovered_only_origins'][0]['journal_reservations']), (False, 0))
        self.assertNotIn(C, [o['origin'] for o in env['origins']])

    def test_accounting_includes_recon_and_separates_events(self):
        recovery, state = self.session(unknown=True, timeout=True)
        _, env, _ = self.export(recovery)
        acc = env['accounting']
        total = acc['total']
        self.assertEqual(total['reserved'], state['runtime']['http_dispatches'])
        self.assertEqual(total['reserved'] - total['dispatch_started'], total['attempt_unknown'])
        self.assertEqual((total['attempt_unknown'], total['outcome_unknown'], total['timeouts'], total['measured_with_error']), (1, 1, 1, 1))
        self.assertEqual(total['response_headers'], total['dispatch_started'] - 1)  # the timeout got no headers
        phases = {p['phase']: p for p in acc['by_phase']}
        self.assertEqual(phases['run_tech_recon']['reserved'], 2)
        self.assertEqual(sum(p['reserved'] for p in acc['by_phase']), total['reserved'])
        self.assertEqual(sum(o['reserved'] for o in acc['by_origin']), total['reserved'])
        legacy = acc['legacy_report_totals']
        self.assertLess(legacy['dispatch_attempted'] + legacy['parameter_requests'] + legacy['soft404_requests'], total['reserved'])
        self.assertIsNone(acc['telemetry_http']['total_requests'])  # unknown stays unknown, never 0
        self.assertFalse(acc['telemetry_http']['count_complete'])
        self.assertEqual(env['session']['pipeline_status'], 'partial')
        self.assertEqual(env['origins'][0]['status'], 'partial')
        self.assertEqual(env['origins'][0]['outcome_unknown_sequences'], acc['unknown_sequences']['outcome_unknown'])

    def test_evidence_levels_and_authority_are_not_upgraded(self):
        recovery, _ = self.session()
        _, env, md = self.export(recovery)
        a, b = env['origins']
        self.assertTrue(all(e['endpoint_verification_status'] == 'not_verified' for o in env['origins'] for e in o['endpoints']))
        q = next(c for c in a['endpoints'][0]['parameters']['candidates'] if c['name'] == 'q')
        self.assertEqual((q['verification'], q['authority'], q['provenance_classes']), ('verified', 'context_only', ['observed_reference']))
        page = next(c for c in a['endpoints'][0]['parameters']['candidates'] if c['name'] == 'page')
        self.assertEqual(page['provenance_classes'], ['inferred_static'])
        soft = a['endpoints'][0]['soft404']
        self.assertEqual((soft['classification'], soft['evidence_basis'], soft['verification_status']),
                         ('genuine_distinct', 'metrics_journaled', 'not_verified'))
        self.assertEqual(b['endpoints'][0]['soft404']['evidence_basis'], 'rederived')
        unchecked = a['endpoints'][1]['soft404']
        self.assertEqual((unchecked['classification'], unchecked['evidence_basis']), ('not_checked', 'not_applicable'))
        self.assertIn('not a vulnerability', env['evidence_vocabulary']['soft404_class']['genuine_distinct'])
        def keys(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    yield k, v
                    yield from keys(v)
            elif isinstance(value, list):
                for v in value:
                    yield from keys(v)
        data = {k: v for k, v in env.items() if k != 'evidence_vocabulary'}  # vocabulary only explains the null
        self.assertEqual([v for k, v in keys(data) if k == 'severity'], [None])
        self.assertEqual(a['endpoints'][0]['dispatch']['evidence'], 'observed_http')

    def test_markdown_is_rendered_from_envelope_and_backed(self):
        recovery, _ = self.session(unknown=True)
        _, env, md = self.export(recovery)
        self.assertEqual(md, render_markdown({k: v for k, v in env.items() if k != 'export_meta'}))
        checked = 0
        for line in md.splitlines():
            if not line.startswith('| `'):
                continue
            cells = [c.strip() for c in re.split(r'(?<!\\)\|', line)[1:-1]]
            self.assertTrue(cells[0].startswith('`'))
        self.assertIn('không xác định', md)  # telemetry total null
        lines = md.splitlines()
        row = next(i for i, line in enumerate(lines) if line.startswith('| `accounting.total` |'))
        header = [c.strip() for c in lines[row - 2].split('|')[2:-1]]
        cells = [c.strip() for c in lines[row].split('|')[2:-1]]
        for key, cell in zip(header, cells):
            self.assertEqual(cell, md_cell(env['accounting']['total'][key.strip('`')])); checked += 1
        self.assertEqual(checked, len(origin_export.KEYS))
        kv = next(line for line in lines if line.endswith('| `accounting.telemetry_http.total_requests` |'))
        self.assertIn('| không xác định |', kv)

    def test_markdown_escapes_untrusted_html_links_and_pipes(self):
        hostile = '<script>alert(1)</script>|[x](javascript:alert(1)) `tick` ![i](http://127.0.0.1:9/i.png)'
        recovery, _ = self.session(inject={'classification_reason': hostile})
        _, env, md = self.export(recovery)
        self.assertEqual(env['origins'][0]['endpoints'][1]['soft404']['classification_reason'], hostile)
        outside = re.sub(r'(`+)(?:(?!\1).)*?\1', '', md)  # strip code spans
        self.assertNotIn('<script', outside)
        self.assertNotIn('](', outside)
        for line in md.splitlines():
            if line.startswith('| ') and hostile[:8] in line.replace('\\|', '|'):
                header = next(l for l in reversed(md[:md.index(line)].splitlines()) if l.startswith('| JSON path'))
                self.assertEqual(len(re.split(r'(?<!\\)\|', line)), len(re.split(r'(?<!\\)\|', header)))

    def test_export_is_deterministic_except_declared_metadata(self):
        recovery, _ = self.session()
        first, env1, md1 = self.export(recovery, 'one')
        with patch.object(origin_export, 'datetime') as clock:
            clock.now.return_value.isoformat.return_value = '2030-01-01T00:00:00+00:00'
            second = export_session(recovery, recovery.parent / 'two')
        env2 = json.loads((recovery.parent / 'two' / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual(md1.encode(), (recovery.parent / 'two' / 'report.md').read_bytes())
        self.assertEqual({k: v for k, v in env1.items() if k != 'export_meta'}, {k: v for k, v in env2.items() if k != 'export_meta'})
        self.assertNotEqual(env1['export_meta'], env2['export_meta'])
        self.assertEqual(first['export_digest'], second['export_digest'])

    def test_export_sends_no_http_llm_or_knowledge_and_imports_no_transport(self):
        recovery, _ = self.session()
        before = tree_hashes(recovery.parent)
        self.export(recovery)  # patches raise on socket connect, decision engine and KnowledgeStore writes
        after = {k: v for k, v in tree_hashes(recovery.parent).items() if not k.startswith('export')}
        self.assertEqual(after, before, 'journal, head or checkpoints changed during export')
        code = ('import sys; import src.coordinator.origin_export; '
                'bad=[m for m in sys.modules if m.startswith(("src.tools", "src.agents", "langchain_openai", "openai", "requests"))]; '
                'print(bad); sys.exit(1 if bad else 0)')
        env = {**os.environ, 'PYTHON_DOTENV_DISABLED': '1'}
        proc = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class RefusalTests(Base):
    def test_unfinished_or_invalid_sessions_are_refused(self):
        cases = {
            'export_session_not_finished': dict(finished=False),
            # session_finished must directly follow the final pipeline checkpoint
            'export_session_finished_invalid': dict(events_hook=lambda ev: ev[:-1] + [('stop', {'reason': 'x'})] + ev[-1:]),
        }
        for code, options in cases.items():
            with self.subTest(code=code):
                recovery, _ = self.session(**options)
                self.refused(recovery, code)

    def test_journal_head_and_checkpoint_integrity(self):
        recovery, _ = self.session()
        path = recovery / 'journal.jsonl'
        lines = path.read_text(encoding='utf-8').splitlines()
        index = next(i for i, line in enumerate(lines) if '"GET"' in line)
        lines[index] = lines[index].replace('"GET"', '"PUT"', 1)
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        self.refused(recovery, 'export_journal_invalid')
        recovery, _ = self.session()
        head = json.loads((recovery / 'head.json').read_text(encoding='utf-8')); head['seq'] -= 1
        (recovery / 'head.json').write_text(json.dumps(head), encoding='utf-8')
        self.refused(recovery, 'export_journal_invalid')
        recovery, _ = self.session()
        final = sorted((recovery.parent / 'pipeline_20261126T000000Z_unit' / 'checkpoints').glob('*pipeline.json'))[0]
        final.write_bytes(final.read_bytes().replace(b'"partial"', b'"completed"', 1) + b' ')
        self.refused(recovery, 'export_checkpoint_invalid')

    def test_checkpoint_outside_session_root_is_refused(self):
        outside = Path(tempfile.mkdtemp()); self.addCleanup(lambda: __import__('shutil').rmtree(outside, ignore_errors=True))

        def hook(events):
            for name, payload in events:
                if name == 'checkpoint' and payload['node'] == 'generate_report':
                    target = outside / 'escaped.json'
                    target.write_bytes(Path(payload['path']).read_bytes())
                    payload['path'] = str(target)
            return events
        recovery, _ = self.session(events_hook=hook)
        self.refused(recovery, 'export_path_escape')

    def test_missing_journal_lock_and_locked_session(self):
        recovery, _ = self.session()
        (recovery / 'journal.jsonl').unlink()
        self.refused(recovery, 'export_journal_missing')
        recovery, _ = self.session()
        (recovery / 'session.lock').unlink()
        self.refused(recovery, 'export_session_lock_missing')
        recovery, _ = self.session()
        holder = RecoveryJournal(recovery, resume=True)
        holder.__enter__()
        try:
            self.refused(recovery, 'export_session_locked')
        finally:
            holder.__exit__(None, None, None)
        single = self.tmp / 'single_target'; single.mkdir(); (single / 'result.json').write_text('{}', encoding='utf-8')
        with self.assertRaises(ExportError) as caught:
            export_session(single, self.tmp / 'single_out')
        self.assertEqual(caught.exception.code, 'export_journal_missing')

    def test_report_digest_must_match_and_is_never_recomputed(self):
        def tamper(state):
            state['multi_origin_report']['content']['totals']['verified_parameters'] += 1
        recovery, _ = self.session(tamper, redigest=False)
        self.refused(recovery, 'export_report_digest_mismatch')

    def test_consistent_forgeries_are_caught_by_semantics(self):
        def first_soft(state):
            return state['multi_origin_report']['content']['approved_origins'][0]['soft404']['endpoints'][0]
        forgeries = {
            'export_report_source_mismatch': lambda s: s['multi_origin_report']['content']['totals'].update(soft404_strong=9),
            'export_status_mismatch': lambda s: s['multi_origin_report']['content']['approved_origins'][0].update(status='failed'),
            'export_endpoint_promoted': lambda s: first_soft(s).update(verification_status='verified'),
        }
        for code, mutate in forgeries.items():
            with self.subTest(code=code):
                recovery, _ = self.session(mutate)
                self.refused(recovery, code)

        def class_upgrade(state):
            row = state['origin_contexts'][A]['context']['soft404']['endpoints'][1]
            row['soft404_classification'] = 'genuine_distinct'
        recovery, _ = self.session(class_upgrade)
        self.refused(recovery, 'export_report_source_mismatch')

    def test_accounting_and_scope_mismatches(self):
        def counter(state): state['runtime']['http_dispatches'] -= 1
        def budget(state): state['runtime']['http_origin_max_requests'][A] = 81
        def telemetry(state): state['telemetry']['http']['total_requests'] = 0
        def recovery_acc(state): state['recovery']['accounting']['outcome_unknown_requests'] = 0
        def scope(state): state['approved_origins'] = [A]
        def gate(state): state['origin_execution_mode'] = 'enabled'
        def cross_origin(state):
            rows = state['origin_contexts'][B]['context']['soft404']['endpoints']
            rows[0]['url'] = A + '/help'
        def duplicate(state):
            endpoints = state['origin_contexts'][A]['endpoints']
            endpoints.append(deepcopy(endpoints[0]))
        def identity(state):
            state['origin_contexts'][A]['endpoints'][2]['method'] = 'GET'
        def unknown_zero(state):
            for row in state['origin_contexts'][A]['context']['parameter_discovery']['requests']:
                row.pop('recovery_state', None)
        def promoted(state):
            state['origin_contexts'][A]['context']['http_dispatch']['records'][0]['verification_status'] = 'verified'
        def authority(state):
            state['origin_contexts'][A]['context']['soft404']['endpoints'][0]['parameter_context']['authority'] = 'verified'
        cases = [('export_accounting_mismatch', counter, {}), ('export_budget_mismatch', budget, {}),
                 ('export_telemetry_mismatch', telemetry, {'unknown': True}),
                 ('export_recovery_accounting_mismatch', recovery_acc, {'unknown': True}),
                 ('export_scope_mismatch', scope, {}), ('export_gate_changed', gate, {}),
                 ('export_report_source_mismatch', cross_origin, {}), ('export_duplicate_endpoint', duplicate, {}),
                 ('export_endpoint_identity_invalid', identity, {}), ('export_accounting_mismatch', unknown_zero, {'unknown': True}),
                 ('export_endpoint_promoted', promoted, {}), ('export_parameter_authority_changed', authority, {})]
        for code, mutate, options in cases:
            with self.subTest(mutation=mutate.__name__):
                recovery, _ = self.session(mutate, **options)
                self.refused(recovery, code)

    def test_malformed_consistent_source_is_a_public_refusal(self):
        def missing_key(state):
            del state['multi_origin_report']['content']['approved_origins'][1]['agents']
        def not_a_number(state):
            state['telemetry']['http']['known_requests'] = float('nan')
        for mutate, options in ((missing_key, {}), (not_a_number, {'unknown': True})):
            with self.subTest(mutation=mutate.__name__):
                state, rows = make_state(**options)
                mutate(state)
                report = state['multi_origin_report']
                if mutate is missing_key:
                    report['digest'] = canonical_digest(report['content'])
                    state['local_reflection'] = {**state['local_reflection'], 'report_digest': report['digest'],
                                                 'observations': [o for o in state['local_reflection']['observations']
                                                                  if not o['report_path'].startswith('approved_origins[1]')]}
                base = self.tmp / ('malformed_' + mutate.__name__); base.mkdir()
                self.refused(write_session(base, state, rows), 'export_source_malformed')

    def test_reservation_to_discovered_or_unapproved_origin_is_refused(self):
        def hook(events):
            for name, payload in events:
                if name == 'reserved' and payload['sequence'] == 1:
                    payload['origin'], payload['url'] = C, C + '/'
            return events
        recovery, _ = self.session(events_hook=hook)
        self.refused(recovery, 'export_unapproved_dispatch')

    def test_reflection_must_be_backed(self):
        # The session hook rebuilds Reflection, so write a session whose Reflection disagrees directly.
        state2, rows = make_state()
        state2['local_reflection']['observations'][0]['value'] = 'forged'
        base = self.tmp / 'reflection'; base.mkdir()
        self.refused(write_session(base, state2, rows), 'export_reflection_mismatch')


class RedactionTests(Base):
    def test_sensitive_exported_value_is_refused_not_written(self):
        recovery, _ = self.session(inject={'source_url': A + '/?access_token=abcdefabcdef'})
        self.refused(recovery, 'export_sensitive_content')

    def test_secret_outside_public_schema_never_reaches_export(self):
        def private(state):
            state['config']['credentials'] = [{'Authorization': FAKE}]
            state['origin_contexts'][A]['private_note'] = FAKE
        recovery, _ = self.session(private)
        result, env, md = self.export(recovery)
        files = [(Path(result['output']) / n).read_text(encoding='utf-8') for n in ('report.json', 'report.md', 'manifest.json')]
        self.assertTrue(all(FAKE not in text and 'b5-local-only-fake' not in text for text in files))
        self.assertTrue(all(not re.search(r'(?<![A-Za-z])[A-Za-z]:[\\/]', text) for text in files), 'absolute path exported')

    def test_absolute_path_in_exported_value_is_refused(self):
        recovery, _ = self.session(inject={'classification_reason': 'C:\\Users\\someone\\leak.txt'})
        self.refused(recovery, 'export_absolute_path')

    def test_r8_redaction_after_digest_changes_report_content(self):
        """R8: Report digest is computed before RunArtifacts redaction; persisted content can then diverge."""
        state, _ = make_state()
        report = state['multi_origin_report']
        # (a) a credential value that is a substring of report data (>= 4 chars, replaced without word boundary)
        saved = RunArtifacts({'credentials': [{'Authorization': 'Bearer help'}]}).public_state(state)['multi_origin_report']
        self.assertNotEqual(saved['content'], report['content'])
        self.assertNotEqual(canonical_digest(saved['content']), saved['digest'])
        # (b) a legitimate-looking static parameter name matching the API-key pattern
        state_b, _ = make_state(inject={'parameter_name': 'api_version_identifier_v2'})
        saved_b = RunArtifacts({}).public_state(state_b)['multi_origin_report']
        self.assertNotEqual(canonical_digest(saved_b['content']), saved_b['digest'])
        # (c) the exporter fails closed on such a persisted report instead of re-digesting it
        def persisted(s):
            s['multi_origin_report'] = RunArtifacts({}).public_state(s)['multi_origin_report']
        recovery, _ = self.session(persisted, inject={'parameter_name': 'api_version_identifier_v2'}, redigest=False)
        self.refused(recovery, 'export_report_digest_mismatch')
        # (d) ordinary content is unchanged by redaction (no false positive in the normal lab vocabulary)
        state_d, _ = make_state()
        saved_d = RunArtifacts({'credentials': [{'Authorization': FAKE}]}).public_state(state_d)['multi_origin_report']
        self.assertEqual(canonical_digest(saved_d['content']), saved_d['digest'])


class WriteTests(Base):
    def test_existing_output_is_never_overwritten(self):
        recovery, _ = self.session()
        out = recovery.parent / 'export'; out.mkdir(); (out / 'keep.txt').write_text('keep', encoding='utf-8')
        with self.assertRaises(ExportError) as caught:
            self.export(recovery)
        self.assertEqual(caught.exception.code, 'export_output_exists')
        self.assertEqual([p.name for p in out.iterdir()], ['keep.txt'])

    def test_output_location_rules(self):
        recovery, _ = self.session()
        for target, code in ((recovery / 'export', 'export_output_inside_session_state'),
                             (recovery.parent / 'pipeline_20261126T000000Z_unit' / 'x', 'export_output_inside_session_state'),
                             (self.tmp / 'missing' / 'export', 'export_output_parent_missing')):
            with self.subTest(code=code, target=target.name):
                with self.assertRaises(ExportError) as caught:
                    export_session(recovery, target)
                self.assertEqual(caught.exception.code, code)
                self.assertFalse(target.exists())

    def test_failure_mid_write_leaves_no_report_and_no_pending_directory(self):
        recovery, _ = self.session()
        before = tree_hashes(recovery.parent)
        real, calls = origin_export._write_bytes, []

        def flaky(path, data):
            calls.append(path.name)
            if len(calls) == 2:
                raise OSError('disk full (simulated)')
            return real(path, data)
        with patch.object(origin_export, '_write_bytes', side_effect=flaky):
            with self.assertRaises(ExportError) as caught:
                export_session(recovery, recovery.parent / 'export')
        self.assertEqual(caught.exception.code, 'export_write_failed')
        self.assertFalse((recovery.parent / 'export').exists())
        self.assertFalse(list(recovery.parent.glob('.pending_export_*')))
        self.assertEqual(tree_hashes(recovery.parent), before)

    def test_source_change_during_export_is_detected(self):
        recovery, _ = self.session()
        real = origin_export._write_bytes

        def meddle(path, data):
            if path.name == 'manifest.json':
                checkpoint = next((recovery.parent / 'pipeline_20261126T000000Z_unit' / 'checkpoints').glob('*report.json'))
                checkpoint.write_bytes(checkpoint.read_bytes() + b' ')
            return real(path, data)
        with patch.object(origin_export, '_write_bytes', side_effect=meddle):
            with self.assertRaises(ExportError) as caught:
                export_session(recovery, recovery.parent / 'export')
        self.assertEqual(caught.exception.code, 'export_source_changed')
        self.assertFalse((recovery.parent / 'export').exists())

    def test_cli_exit_codes(self):
        recovery, _ = self.session()
        script = ROOT / 'scripts' / 'export_origin_report.py'
        env = {**os.environ, 'PYTHON_DOTENV_DISABLED': '1'}
        ok = subprocess.run([sys.executable, '-B', str(script), str(recovery), '--output', str(recovery.parent / 'cli')],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertTrue(json.loads(ok.stdout)['exported'])
        again = subprocess.run([sys.executable, '-B', str(script), str(recovery), '--output', str(recovery.parent / 'cli')],
                               cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual((again.returncode, json.loads(again.stdout)['code']), (2, 'export_output_exists'))
        unfinished, _ = self.session(finished=False)
        refused = subprocess.run([sys.executable, '-B', str(script), str(unfinished)], cwd=ROOT, env=env,
                                 capture_output=True, text=True, timeout=120)
        self.assertEqual((refused.returncode, json.loads(refused.stdout)['code']), (2, 'export_session_not_finished'))


if __name__ == '__main__':
    unittest.main()
