"""B4.2B unit checks: control scope, derivation parity with the real comparator, reconcile; no sockets/LLM."""
from contextlib import ExitStack
from copy import deepcopy
from email.message import EmailMessage
import io
import json
import random
import string
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
from uuid import uuid4

from src.coordinator.origin_recovery import RecoveryDenied
from src.coordinator.origins import endpoint_observation, normalize_origin_config
from src.tools.origin_scope import OriginCredentialContext, OriginScopedTransport, OriginScopePolicy
from src.tools.origin_soft404 import (STRONG, Soft404InconsistentEvidence, Soft404ProbeTransport, _derive_row,
                                      _metric_fields, group_id, reconcile_soft404_recovery)
from src.tools.soft404 import verify_soft404

A = 'http://127.0.0.1:18881'
B = 'http://127.0.0.1:18882'
HEX = uuid4().hex
SHELL = '<html><body><div id="root">App shell loading</div></body></html>'
TEMPLATE = '<html><body><h1>Docs</h1>' + ''.join(f'<p>Section {i} explains the archive layout in detail.</p>'
                                                for i in range(60)) + '</body></html>'
HELP = '<html><body><h1>Help centre</h1><p>Contact support, reset devices, read guides and manuals.</p></body></html>'


def rule(path, *, controls=False, query=''):
    row = {'path': path, 'methods': ['GET'], 'operation': 'read_only'}
    if query:
        row['query'] = query
    if controls:
        row['soft404_controls'] = True
    return row


class _Response:
    def __init__(self, status, body, mime):
        self.code, self._body = status, io.BytesIO(body.encode())
        self.headers = EmailMessage(); self.headers['Content-Type'] = mime + '; charset=utf-8'
        self.length = None

    def read1(self, n): return self._body.read(n)
    read = read1
    def close(self): pass


class FakeServerTransport:
    """In-memory responses with the verify_soft404 transport interface (no sockets)."""

    def __init__(self, routes):
        self.routes, self.requests = routes, []
        self.proxy_profile_id = self.stop_reason = self.dispatch_deadline = self.dispatched_at = None
        self.dispatched = False

    def allows(self, url): return True
    def begin_unit(self): return None
    def public_settings(self): return {}
    def metrics(self): return {}
    def redact(self, value): return value
    def failure(self, exc, measured): return 'transport_error'

    def open(self, request, timeout=10):
        self.dispatched, self.dispatched_at = True, time.perf_counter()
        status, body, mime = self.routes(urlsplit(request.full_url).path)
        return _Response(status, body, mime)

    def record_measurement(self, measured, halt):
        features = measured.get('features') or {}
        path = urlsplit(measured['url']).path
        self.requests.append({'runtime_sequence': len(self.requests) + 1, 'path': path,
                              'role': 'control' if '__sentinel_missing_' in path else 'candidate',
                              'endpoint_id': None if '__sentinel_missing_' in path else measured['url'],
                              'status_code': measured['status_code'], 'content_type': measured['content_type'],
                              'content_length': measured['content_length'], 'body_complete': measured['body_complete'],
                              'body_truncated': measured['body_truncated'], 'body_sha256': measured['body_sha256'],
                              'normalized_sha256': measured.get('normalized_sha256'),
                              'login_or_challenge': bool(features.get('login_or_challenge')),
                              'error': measured.get('error'), 'unit_halt': halt})


def run_group(routes, urls):
    """Real comparator on one group, then the B4.2B derivation over the same evidence."""
    transport = FakeServerTransport(routes)
    result = verify_soft404(A + '/', [{'url': u, 'status_code': 200, 'body_complete': True, 'method': 'GET',
                                       'content_length': 1} for u in urls], transport=transport, rate_limit=100)
    info = (result['baseline']['groups'] or [{}])[0]
    group_metrics = [_metric_fields(c) for c in info.get('control_similarities', [])] or None
    out = {}
    for bucket in ('verified', 'false_positives', 'unverified'):
        for row in result[bucket]:
            metrics = [_metric_fields(c) for c in (row.get('verification_evidence') or {}).get('comparisons', [])] or None
            derived = _derive_row({'url': row['url'], 'endpoint_id': row['url']}, transport.requests, group_metrics, metrics)
            out[urlsplit(row['url']).path] = (row['verification'], derived)
    return out


class Soft404ScopeTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch('socket.create_connection', side_effect=AssertionError('No network')))
        stack.enter_context(patch('socket.socket.connect', side_effect=AssertionError('No network')))
        self.config = {'approved_origins': [A, B], 'origin_policies': {
            A: {'credential_profile': 'frontend', 'rules': [rule('/promo', controls=True), rule('/docs/a.html', controls=True),
                                                           rule('/plain'), rule('/v', controls=True, query='x=1')]},
            B: {'rules': [rule('/v1/items', controls=True)]}}}
        self.policy = OriginScopePolicy(self.config)

    def test_flag_is_explicit_true_get_only_and_absent_by_default(self):
        normalized = normalize_origin_config(self.config)
        self.assertNotIn('soft404_controls', normalized['origin_policies'][A]['rules'][2])
        for bad in (False, 1, 'true', None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_origin_config({'approved_origins': [A], 'origin_policies': {A: {'rules': [
                    {'path': '/p', 'methods': ['GET'], 'operation': 'read_only', 'soft404_controls': bad}]}}})
        with self.assertRaises(ValueError):
            normalize_origin_config({'approved_origins': [A], 'origin_policies': {A: {'rules': [
                {'path': '/p', 'methods': ['HEAD'], 'operation': 'read_only', 'soft404_controls': True}]}}})

    def test_controls_only_same_directory_suffix_query_and_name(self):
        ok = [(A + f'/__sentinel_missing_{HEX}', A + '/promo'), (A + f'/docs/__sentinel_missing_{HEX}.html', A + '/docs/a.html'),
              (A + f'/__sentinel_missing_{HEX}?x=1', A + '/v?x=1'), (B + f'/v1/__sentinel_missing_{HEX}', B + '/v1/items')]
        for url, base in ok:
            with self.subTest(url=url):
                self.assertEqual(self.policy.check_soft404_control(url, 'GET'), base)
        denied = [A + f'/docs/__sentinel_missing_{HEX}', A + f'/docs/__sentinel_missing_{HEX}.php',
                  A + f'/other/__sentinel_missing_{HEX}', A + f'/__sentinel_missing_{HEX}?x=2',
                  A + '/__sentinel_missing_XYZ', A + f'/__sentinel_other_{HEX}', B + f'/__sentinel_missing_{HEX}',
                  'http://127.0.0.1:18883/__sentinel_missing_' + HEX, A + '/promo']
        for url in denied:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.policy.check_soft404_control(url, 'GET')
        for method in ('HEAD', 'POST'):
            with self.subTest(method=method), self.assertRaises(ValueError):
                self.policy.check_soft404_control(A + f'/__sentinel_missing_{HEX}', method)
        with self.assertRaises(ValueError):
            self.policy.check(A + f'/__sentinel_missing_{HEX}', 'GET')  # B1 exact scope unchanged
        with self.assertRaises(ValueError):
            self.policy.check_parameter_probe(A + f'/__sentinel_missing_{HEX}', 'GET')  # B4.1 unchanged

    def test_transport_rechecks_binding_on_approving_rule(self):
        creds = OriginCredentialContext(self.policy, {A: {'profile_id': 'frontend', 'headers': {'Authorization': 'Bearer u'}}})
        Soft404ProbeTransport(A, policy=self.policy, credentials=creds).check_dispatch(A + f'/__sentinel_missing_{HEX}', 'GET')
        with self.assertRaisesRegex(ValueError, 'credential profile is unavailable'):
            Soft404ProbeTransport(A, policy=self.policy).check_dispatch(A + f'/__sentinel_missing_{HEX}', 'GET')
        with self.assertRaises(ValueError):
            OriginScopedTransport(A, policy=self.policy, credentials=creds).check_dispatch(A + f'/__sentinel_missing_{HEX}', 'GET')
        self.assertEqual(Soft404ProbeTransport(A, policy=self.policy).classify(B + f'/v1/__sentinel_missing_{HEX}'), ('control', None))
        self.assertEqual(group_id(B + f'/v1/__sentinel_missing_{HEX}'), group_id(B + '/v1/items'))
        self.assertNotEqual(group_id(A + '/promo'), group_id(B + '/promo'))  # origin is part of the group key

    def test_supplied_transport_owns_network_policy(self):
        with self.assertRaisesRegex(ValueError, 'owns network policy'):
            verify_soft404(A + '/', [], transport=FakeServerTransport(lambda p: (404, '', 'text/html')), headers={'X': '1'})


class Soft404DerivationParityTests(unittest.TestCase):
    """Every strong class the comparator gives must be reproduced; level must reflect the evidence."""

    def test_exact_shell_fallback_is_rederived_soft404_and_root_is_inconclusive(self):
        out = run_group(lambda p: (200, SHELL, 'text/html'), [A + '/', A + '/promo'])
        self.assertEqual(out['/promo'], ('soft_404', ('soft_404', 'matches_stable_missing_path_controls', 'rederived')))
        self.assertEqual(out['/'][0], 'inconclusive')
        self.assertEqual(out['/'][1][2], 'rederived')

    def test_near_duplicate_template_needs_metrics(self):
        routes = lambda p: (200, TEMPLATE.replace('Section 7 ', 'Section 7 legacy ') if p.endswith('/legacy') else TEMPLATE, 'text/html')
        out = run_group(routes, [A + '/docs/legacy'])
        self.assertEqual(out['/docs/legacy'], ('soft_404', ('soft_404', 'matches_stable_missing_path_controls', 'metrics_journaled')))

    def test_distinct_page_is_genuine_metrics_only(self):
        routes = lambda p: (200, HELP, 'text/html') if p == '/help' else (404, '<html><body>Not found here</body></html>', 'text/html')
        out = run_group(routes, [A + '/help'])
        self.assertEqual(out['/help'], ('genuine', ('genuine_distinct', 'distinct_successful_response', 'metrics_journaled')))

    def test_remeasured_404_is_rederived(self):
        out = run_group(lambda p: (404, '{"error":"not_found"}', 'application/json'), [A + '/v1/ghost'])
        self.assertEqual(out['/v1/ghost'], ('http_404', ('http_404', 'remeasured_http_404', 'rederived')))

    def test_unstable_and_empty_controls_are_never_strong(self):
        noisy = lambda p: (200, json.dumps({'debug': ''.join(random.choice(string.ascii_lowercase) for _ in range(16))}),
                           'application/json')
        out = run_group(noisy, [A + '/v2/items'])
        self.assertEqual(out['/v2/items'][0], 'inconclusive')
        self.assertNotIn(out['/v2/items'][1][0], STRONG)
        empty = lambda p: (200, '{"ok":1}', 'application/json') if p == '/x' else (404, '', 'application/json')
        out = run_group(empty, [A + '/x'])
        self.assertEqual(out['/x'], ('inconclusive', ('inconclusive', 'unsafe_or_incomplete_controls', 'rederived')))

    def test_tampered_metric_is_rejected_even_when_digests_decide(self):
        transport = FakeServerTransport(lambda p: (200, SHELL, 'text/html'))
        result = verify_soft404(A + '/', [{'url': A + '/promo', 'status_code': 200, 'body_complete': True, 'method': 'GET',
                                           'content_length': 1}], transport=transport, rate_limit=100)
        row = result['false_positives'][0]
        metrics = [_metric_fields(c) for c in row['verification_evidence']['comparisons']]
        _derive_row({'url': row['url'], 'endpoint_id': row['url']}, transport.requests, None, metrics)  # consistent: ok
        metrics[0]['exact_body_match'] = False  # contradicts equal journaled digests
        with self.assertRaises(Soft404InconsistentEvidence):
            _derive_row({'url': row['url'], 'endpoint_id': row['url']}, transport.requests, None, metrics)

    def test_type_mismatch_with_identical_body_is_not_soft404(self):
        routes = lambda p: (200, SHELL, 'text/plain' if p == '/promo' else 'text/html')
        out = run_group(routes, [A + '/promo'])
        self.assertNotEqual(out['/promo'][0], 'soft_404')
        self.assertNotIn(out['/promo'][1][0], STRONG)


class Lab:
    """Synthetic journal for one Soft404 group: 3 controls + one candidate `/help` on origin A."""

    def __init__(self, policy, *, classification='genuine_distinct'):
        self.unit, self.gid = uuid4().hex, group_id(A + '/help')
        self.endpoint = endpoint_observation(A + '/help', method='GET')['endpoint_id']
        urls = [A + f'/__sentinel_missing_{uuid4().hex}' for _ in range(3)] + [A + '/help']
        bodies = ['n' * 64] * 3 + ['h' * 64]
        self.reservations, self.measurements, self.starts = [], {}, {}
        self.events = [{'event': 'process_bound', 'payload': {}}]
        for ordinal, (url, digest) in enumerate(zip(urls, bodies), 1):
            role = 'candidate' if url.endswith('/help') else 'control'
            row = {'url': url, 'method': 'GET', 'candidate_id': None, 'evidence_refs': [], 'origin': A, 'phase': 'soft404_filter',
                   'sequence': ordinal, 'soft404': {'version': 1, 'stage': 'soft404', 'group_id': self.gid, 'unit_id': self.unit,
                                                    'ordinal': ordinal, 'role': role,
                                                    'endpoint_id': self.endpoint if role == 'candidate' else None}}
            self.reservations.append(row); self.events.append({'event': 'reserved', 'payload': row})
            self.starts[ordinal] = {}
            self.measurements[ordinal] = {'status_code': 404 if role == 'control' else 200, 'content_type': 'text/html',
                                          'content_length': 40 if role == 'control' else 90, 'body_complete': True,
                                          'body_truncated': False, 'body_sha256': digest, 'normalized_sha256': digest,
                                          'login_or_challenge': False, 'error': None, 'unit_halt': None, 'stop_reason': None}
        metric = lambda a, b: {'exact_body_match': False, 'exact_normalized_match': False, 'comparison_limited': False,
                               'content_similarity': .2, 'text_similarity': .2, 'structure_similarity': .5,
                               'length_ratio': min(a, b) / max(1, a, b)}
        self.events.append({'event': 'soft404_group', 'payload': {'unit_id': self.unit, 'group_id': self.gid,
                            'control_sequences': [1, 2, 3], 'control_metrics': None, 'stable': True, 'reason': 'stable'}})
        self.events.append({'event': 'soft404_decision', 'payload': {'unit_id': self.unit, 'endpoint_id': self.endpoint,
                            'candidate_sequence': 4, 'control_sequences': [1, 2, 3], 'metrics': [metric(90, 40)] * 3,
                            'classification': classification, 'reason': 'x'}})
        self.policy = policy
        self.classification = classification

    def saved(self, upto, *, unit_state='completed', classification=None, level='metrics_journaled'):
        rows = []
        for r in self.reservations[:upto]:
            m = self.measurements[r['sequence']]
            rows.append({'runtime_sequence': r['sequence'], 'origin': A, 'path': urlsplit(r['url']).path, 'query': '',
                         **{k: r['soft404'][k] for k in ('group_id', 'unit_id', 'ordinal', 'role', 'endpoint_id')},
                         **{k: m[k] for k in ('status_code', 'content_type', 'body_sha256', 'normalized_sha256', 'body_complete')}})
        endpoint = {'endpoint_id': self.endpoint, 'url': A + '/help', 'eligible': True, 'group_id': self.gid,
                    'unit_id': self.unit if upto else None, 'unit_state': unit_state,
                    'soft404_classification': classification or self.classification, 'evidence_level': level}
        return {'origin_contexts': {A: {'context': {'soft404': {'endpoints': [endpoint], 'requests': rows, 'final': False,
                                                                'status': 'pending'}}}}}

    def reconcile(self, local, saved, cover, events=None):
        state = deepcopy(saved)
        unknown = reconcile_soft404_recovery(local=local, state=state, events=events or self.events,
                                             reservations=self.reservations, starts=self.starts, measurements=self.measurements,
                                             checkpoints=[({'reservations': cover}, saved)], deny=self.deny)
        return unknown, state

    @staticmethod
    def deny(code):
        raise RecoveryDenied(code)


class Soft404ReconcileTests(unittest.TestCase):
    def setUp(self):
        policy = OriginScopePolicy({'approved_origins': [A], 'origin_policies': {A: {'rules': [rule('/help', controls=True)]}}})
        self.local = type('Local', (), {'soft404_transport': Soft404ProbeTransport(A, policy=policy)})()
        self.policy = policy

    def assertDenied(self, code, call):
        with self.assertRaises(RecoveryDenied) as caught:
            call()
        self.assertEqual(str(caught.exception), code)

    def test_completed_group_keeps_metrics_journaled_genuine(self):
        lab = Lab(self.policy)
        unknown, state = lab.reconcile(self.local, lab.saved(4), 4)
        endpoint = state['origin_contexts'][A]['context']['soft404']['endpoints'][0]
        self.assertEqual((unknown, endpoint['soft404_classification'], endpoint['evidence_level']),
                         ([], 'genuine_distinct', 'metrics_journaled'))

    def test_forged_or_inconsistent_classification_is_denied(self):
        lab = Lab(self.policy)
        self.assertDenied('recovery_soft404_classification_unproven',
                          lambda: lab.reconcile(self.local, lab.saved(4, classification='soft_404'), 4))
        lab = Lab(self.policy)
        lab.events[-1]['payload']['metrics'][0] = {**lab.events[-1]['payload']['metrics'][0], 'exact_body_match': True}
        self.assertDenied('recovery_soft404_classification_unproven', lambda: lab.reconcile(self.local, lab.saved(4), 4))
        lab = Lab(self.policy)
        lab.events[-1]['payload']['metrics'][1] = {**lab.events[-1]['payload']['metrics'][1], 'length_ratio': 0.99}
        self.assertDenied('recovery_soft404_classification_unproven', lambda: lab.reconcile(self.local, lab.saved(4), 4))
        lab = Lab(self.policy)
        self.assertDenied('recovery_soft404_classification_unproven',
                          lambda: lab.reconcile(self.local, lab.saved(4), 4, events=lab.events[:-1]))
        lab = Lab(self.policy)
        self.assertDenied('recovery_soft404_classification_unproven',
                          lambda: lab.reconcile(self.local, lab.saved(4, level='rederived'), 4))

    def test_uncheckpointed_group_is_interrupted_and_unknown_preserved(self):
        lab = Lab(self.policy); del lab.measurements[4]
        unknown, state = lab.reconcile(self.local, lab.saved(0, unit_state='not_started', classification='not_checked'), 0)
        section = state['origin_contexts'][A]['context']['soft404']
        endpoint = section['endpoints'][0]
        self.assertEqual(unknown, [4])
        self.assertEqual((endpoint['unit_state'], endpoint['soft404_classification'], endpoint['evidence_level'],
                          endpoint['classification_reason']), ('interrupted', 'inconclusive', 'interrupted', 'probe_outcome_unknown'))
        self.assertEqual(len(section['requests']), 4)
        self.assertEqual(section['requests'][-1]['recovery_state'], 'outcome_unknown')

    def test_replay_identity_and_checkpoint_integrity(self):
        lab = Lab(self.policy); saved = lab.saved(4)
        lab.reservations[2]['soft404']['ordinal'] = 2
        self.assertDenied('recovery_probe_replay_detected', lambda: lab.reconcile(self.local, saved, 4))
        lab = Lab(self.policy); saved = lab.saved(4)
        lab.reservations[0]['soft404']['role'] = 'candidate'
        self.assertDenied('recovery_reservation_identity_invalid', lambda: lab.reconcile(self.local, saved, 4))
        lab = Lab(self.policy); saved = lab.saved(4)
        lab.reservations[1]['url'] = A + f'/other/__sentinel_missing_{uuid4().hex}'
        self.assertDenied('recovery_reservation_identity_invalid', lambda: lab.reconcile(self.local, saved, 4))
        lab = Lab(self.policy); saved = lab.saved(4)
        saved['origin_contexts'][A]['context']['soft404']['requests'].pop()
        self.assertDenied('recovery_checkpoint_invalid', lambda: lab.reconcile(self.local, saved, 4))
        lab = Lab(self.policy)
        no_transport = type('Local', (), {'soft404_transport': None})()
        self.assertDenied('recovery_reservation_identity_invalid', lambda: lab.reconcile(no_transport, lab.saved(4), 4))
        lab = Lab(self.policy)
        self.assertDenied('recovery_soft404_checkpoint_missing', lambda: lab.reconcile(self.local, {'origin_contexts': {}}, 4))

    def test_no_soft404_data_is_legacy_noop(self):
        self.assertEqual(reconcile_soft404_recovery(local=self.local, state={}, events=[], reservations=[], starts={},
                                                    measurements={}, checkpoints=[({'reservations': 0}, {})],
                                                    deny=Lab.deny), [])


if __name__ == '__main__':
    unittest.main()
