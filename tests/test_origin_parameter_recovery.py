"""B4.2A unit checks: probe identity/replay, verdict re-derivation and reconcile states; no sockets/LLM."""
from contextlib import ExitStack
from copy import deepcopy
import unittest
from unittest.mock import patch
from uuid import uuid4

from src.coordinator.origin_recovery import RecoveryDenied
from src.coordinator.origins import endpoint_observation
from src.tools.origin_parameters import ParameterProbeTransport, derive_unit_verdicts, reconcile_probe_recovery
from src.tools.origin_scope import OriginScopePolicy

A = 'http://127.0.0.1:18871'
URL = A + '/search'
ENDPOINT = endpoint_observation(URL, method='GET')['endpoint_id']


def deny(code):
    raise RecoveryDenied(code)


class Lab:
    """Synthetic journal for one endpoint unit with one candidate `q` (B4.1 order)."""

    def __init__(self, *, effect=True, reflected=False):
        self.unit = uuid4().hex
        v1, v2 = 'sentinel_' + uuid4().hex, 'sentinel_' + uuid4().hex
        control = lambda value: f'__sentinel_unknown_{uuid4().hex}={value}'
        self.plan = [('baseline', None, ''), ('baseline', None, ''), ('control', None, control('1')),
                     ('control', None, control('1')), ('candidate', 'q', 'q=' + v1), ('candidate', 'q', 'q=' + v1),
                     ('candidate', 'q', 'q=' + v2), ('candidate', 'q', 'q=' + v2), ('baseline', None, ''),
                     ('control', None, control(v1)), ('control', None, control(v2))]
        self.events, self.reservations, self.starts, self.measurements = [{'event': 'process_bound', 'payload': {}}], [], {}, {}
        for ordinal, (role, parameter, query) in enumerate(self.plan, 1):
            seq = ordinal
            parameter = query.split('=', 1)[0] if role == 'control' else parameter
            row = {'url': URL + ('?' + query if query else ''), 'method': 'GET', 'candidate_id': None,
                   'evidence_refs': [], 'origin': A, 'phase': 'param_disc', 'sequence': seq,
                   'probe': {'version': 1, 'endpoint_id': ENDPOINT, 'unit_id': self.unit, 'ordinal': ordinal,
                             'role': role, 'parameter': parameter}}
            self.reservations.append(row); self.events.append({'event': 'reserved', 'payload': row})
            self.starts[seq] = {'sequence': seq}
            changed = effect and role == 'candidate'
            self.measurements[seq] = {'sequence': seq, 'status_code': 200, 'content_type': 'application/json',
                'normalized_sha256': ('e' if changed else 'b') * 64, 'body_sha256': ('e' if changed else 'b') * 64,
                'body_complete': True, 'body_truncated': False, 'error': None, 'unit_halt': None,
                'value_reflected': reflected if role == 'candidate' else None}

    def entries(self):
        return [{'role': r['probe']['role'], 'parameter': r['probe']['parameter'],
                 'value': None if r['probe']['role'] == 'baseline' else r['url'].rsplit('=', 1)[-1],
                 **self.measurements[r['sequence']]} for r in self.reservations]

    def checkpoint_state(self, upto, *, unit_state='completed', verification='verified'):
        rows = []
        for r in self.reservations[:upto]:
            m = self.measurements[r['sequence']]
            rows.append({'runtime_sequence': r['sequence'], 'origin': A, 'path': '/search',
                         'query': r['url'].split('?', 1)[1] if '?' in r['url'] else '',
                         **{k: r['probe'][k] for k in ('unit_id', 'ordinal', 'role', 'parameter')},
                         **{k: m[k] for k in ('status_code', 'content_type', 'body_sha256', 'normalized_sha256', 'body_complete')}})
        endpoint = {'endpoint_id': ENDPOINT, 'url': URL, 'eligible': True, 'unit_id': self.unit if upto else None,
                    'unit_state': unit_state, 'candidates': [{'name': 'q', 'selected': True, 'verification': verification,
                                                              'verification_reason': 'x', 'verification_evidence': {}}]}
        return {'origin_contexts': {A: {'context': {'parameter_discovery': {
            'endpoints': [endpoint], 'requests': rows, 'final': False, 'status': 'pending'}}}}}

    def reconcile(self, local, saved, cover, **overrides):
        state = deepcopy(saved)
        args = dict(local=local, state=state, events=self.events, reservations=self.reservations,
                    starts=self.starts, measurements=self.measurements,
                    checkpoints=[({'reservations': cover}, saved)], deny=deny)
        args.update(overrides)
        return reconcile_probe_recovery(**args), state


class OriginParameterRecoveryUnitTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch('socket.create_connection', side_effect=AssertionError('No network')))
        stack.enter_context(patch('socket.socket.connect', side_effect=AssertionError('No network')))
        policy = OriginScopePolicy({'approved_origins': [A], 'origin_policies': {A: {'rules': [
            {'path': '/search', 'methods': ['GET'], 'operation': 'read_only', 'parameters': ['q']}]}}})
        self.local = type('Local', (), {'probe_transport': ParameterProbeTransport(A, policy=policy)})()

    # verdict re-derivation
    def test_derivation_matches_b41_rule(self):
        self.assertEqual(derive_unit_verdicts(Lab().entries()), {'q': True})
        self.assertEqual(derive_unit_verdicts(Lab(effect=False).entries()), {'q': False})
        self.assertEqual(derive_unit_verdicts(Lab(reflected=True).entries()), {'q': False})
        lab = Lab(); entries = lab.entries(); entries[2]['normalized_sha256'] = 'c' * 64
        self.assertEqual(derive_unit_verdicts(entries), {'q': False}, 'unstable controls')
        lab = Lab(); entries = lab.entries(); entries[6]['normalized_sha256'] = 'f' * 64
        self.assertEqual(derive_unit_verdicts(entries), {'q': False}, 'unstable repeat')
        lab = Lab(); entries = lab.entries(); entries[9]['normalized_sha256'] = 'e' * 64
        self.assertEqual(derive_unit_verdicts(entries), {'q': False}, 'value-sensitive post control')
        lab = Lab(); entries = lab.entries(); entries[7]['value_reflected'] = None
        self.assertEqual(derive_unit_verdicts(entries), {'q': False}, 'unknown reflection is not proof')
        lab = Lab(); entries = lab.entries()[:10]
        self.assertEqual(derive_unit_verdicts(entries), {'q': False}, 'count-short unit')
        lab = Lab(); entries = lab.entries(); entries[5]['body_complete'] = None
        self.assertEqual(derive_unit_verdicts(entries), {'q': False}, 'missing measurement')
        lab = Lab(); entries = lab.entries(); entries[4]['unit_halt'] = 'redirect_requires_review'
        self.assertEqual(derive_unit_verdicts(entries), {'q': False}, 'local halt is not usable')

    # reconcile happy paths
    def test_completed_unit_keeps_derived_verdict_and_intentional_repeats(self):
        lab = Lab()
        # baseline URL is reserved three times and each sample URL twice: intentional repeats.
        self.assertEqual(sum(r['url'] == URL for r in lab.reservations), 3)
        unknown, state = lab.reconcile(self.local, lab.checkpoint_state(11), 11)
        self.assertEqual(unknown, [])
        endpoint = state['origin_contexts'][A]['context']['parameter_discovery']['endpoints'][0]
        self.assertEqual((endpoint['unit_state'], endpoint['candidates'][0]['verification']), ('completed', 'verified'))

    def test_no_probes_and_no_sections_is_legacy_noop(self):
        self.assertEqual(reconcile_probe_recovery(local=self.local, state={}, events=[], reservations=[],
                                                  starts={}, measurements={}, checkpoints=[({'reservations': 0}, {})],
                                                  deny=deny), [])

    def test_reserved_after_checkpoint_is_interrupted_and_unknown(self):
        lab = Lab(); del lab.measurements[11]
        unknown, state = lab.reconcile(self.local, lab.checkpoint_state(0, unit_state='not_started', verification='not_checked'), 0)
        self.assertEqual(unknown, [11])
        section = state['origin_contexts'][A]['context']['parameter_discovery']
        endpoint = section['endpoints'][0]
        self.assertEqual(endpoint['unit_state'], 'interrupted')
        self.assertEqual((endpoint['candidates'][0]['verification'], endpoint['candidates'][0]['verification_reason']),
                         ('inconclusive', 'probe_outcome_unknown'))
        self.assertEqual(len(section['requests']), 11)
        self.assertEqual(section['requests'][-1]['recovery_state'], 'outcome_unknown')
        self.assertIsNone(section['requests'][-1]['status_code'])
        self.assertEqual((section['status'], section['stop_reason']), ('interrupted', 'upstream_interrupted'))

    def test_fully_measured_but_uncheckpointed_unit_is_never_verified(self):
        lab = Lab()
        unknown, state = lab.reconcile(self.local, lab.checkpoint_state(0, unit_state='not_started', verification='not_checked'), 0)
        endpoint = state['origin_contexts'][A]['context']['parameter_discovery']['endpoints'][0]
        self.assertEqual(unknown, [])
        self.assertEqual((endpoint['unit_state'], endpoint['candidates'][0]['verification_reason']),
                         ('interrupted', 'unit_interrupted'))
        self.assertTrue(all(r['recovery_state'] == 'result_persisted'
                            for r in state['origin_contexts'][A]['context']['parameter_discovery']['requests']))

    # fail-closed
    def assertDenied(self, code, call):
        with self.assertRaises(RecoveryDenied) as caught:
            call()
        self.assertEqual(str(caught.exception), code)

    def test_unproven_or_contradicted_verdicts_are_denied(self):
        lab = Lab(effect=False)
        self.assertDenied('recovery_parameter_verdict_unproven',
                          lambda: lab.reconcile(self.local, lab.checkpoint_state(11), 11))
        lab = Lab()
        self.assertDenied('recovery_parameter_verdict_unproven',
                          lambda: lab.reconcile(self.local, lab.checkpoint_state(11, verification='inconclusive'), 11))
        lab = Lab()
        saved = lab.checkpoint_state(0, unit_state='completed', verification='verified')
        lab.reservations, lab.events = [], lab.events[:1]
        self.assertDenied('recovery_parameter_verdict_unproven', lambda: lab.reconcile(self.local, saved, 0))

    def test_replay_by_identity_and_epoch_is_denied(self):
        lab = Lab(); saved = lab.checkpoint_state(11)
        lab.reservations[5]['probe']['ordinal'] = 5  # duplicate (unit, ordinal)
        self.assertDenied('recovery_probe_replay_detected', lambda: lab.reconcile(self.local, saved, 11))
        lab = Lab(); saved = lab.checkpoint_state(11)
        lab.events.insert(7, {'event': 'process_bound', 'payload': {}})  # unit reopened after a restart
        self.assertDenied('recovery_probe_replay_detected', lambda: lab.reconcile(self.local, saved, 11))
        lab, second = Lab(), Lab()
        for row in second.reservations:  # a second unit measuring the same endpoint again
            row['sequence'] += 11; lab.reservations.append(row); lab.events.append({'event': 'reserved', 'payload': row})
            lab.starts[row['sequence']] = {}; lab.measurements[row['sequence']] = second.measurements[row['sequence'] - 11]
        self.assertDenied('recovery_probe_replay_detected', lambda: lab.reconcile(self.local, lab.checkpoint_state(11), 22))

    def test_identity_must_match_operator_scope_and_url(self):
        lab = Lab(); saved = lab.checkpoint_state(11)
        lab.reservations[4]['probe']['role'] = 'control'
        self.assertDenied('recovery_reservation_identity_invalid', lambda: lab.reconcile(self.local, saved, 11))
        lab = Lab(); saved = lab.checkpoint_state(11)
        lab.reservations[4]['url'] = URL + '?page=sentinel_' + uuid4().hex
        self.assertDenied('recovery_reservation_identity_invalid', lambda: lab.reconcile(self.local, saved, 11))
        lab = Lab(); saved = lab.checkpoint_state(11)
        no_probe = type('Local', (), {'probe_transport': None})()
        self.assertDenied('recovery_reservation_identity_invalid', lambda: lab.reconcile(no_probe, saved, 11))

    def test_checkpoint_rows_must_match_journal_exactly(self):
        lab = Lab(); saved = lab.checkpoint_state(11)
        saved['origin_contexts'][A]['context']['parameter_discovery']['requests'].pop()
        self.assertDenied('recovery_checkpoint_invalid', lambda: lab.reconcile(self.local, saved, 11))
        lab = Lab(); saved = lab.checkpoint_state(11)
        rows = saved['origin_contexts'][A]['context']['parameter_discovery']['requests']; rows.append(deepcopy(rows[-1]))
        self.assertDenied('recovery_checkpoint_invalid', lambda: lab.reconcile(self.local, saved, 11))
        lab = Lab(); saved = lab.checkpoint_state(11)
        saved['origin_contexts'][A]['context']['parameter_discovery']['requests'][3]['body_sha256'] = 'a' * 64
        self.assertDenied('recovery_checkpoint_invalid', lambda: lab.reconcile(self.local, saved, 11))
        lab = Lab(); saved = lab.checkpoint_state(11); del lab.measurements[3]
        self.assertDenied('recovery_checkpoint_invalid', lambda: lab.reconcile(self.local, saved, 11))
        lab = Lab()
        self.assertDenied('recovery_parameter_checkpoint_missing', lambda: lab.reconcile(self.local, {'origin_contexts': {}}, 11))


if __name__ == '__main__':
    unittest.main()
