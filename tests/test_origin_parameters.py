"""B4.1 unit checks: probe scope, transport guards and fail-closed preconditions; no sockets/LLM."""
from contextlib import ExitStack
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from src.coordinator.origins import normalize_origin_config, origin_state
from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session
from src.tools.origin_parameters import ParameterProbeTransport, _source_reason, verify_origin_parameters
from src.tools.origin_scope import OriginCredentialContext, OriginScopedTransport, OriginScopePolicy
from src.tools.parameter_verification import verify_parameters

A = 'http://127.0.0.1:18861'
B = 'http://127.0.0.1:18862'
HEX = uuid4().hex


def rule(path, params=None, query=''):
    row = {'path': path, 'methods': ['GET'], 'operation': 'read_only'}
    if query:
        row['query'] = query
    if params is not None:
        row['parameters'] = params
    return row


class OriginParameterUnitTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('socket.create_connection', side_effect=AssertionError('No network')))
        self.stack.enter_context(patch('socket.socket.connect', side_effect=AssertionError('No network')))
        self.config = {'approved_origins': [A, B], 'origin_policies': {
            A: {'credential_profile': 'frontend', 'rules': [rule('/search', ['q']), rule('/plain')]},
            B: {'rules': [rule('/items', ['category']), rule('/v', ['q'], query='v=1')]}}}
        self.policy = OriginScopePolicy(self.config)

    def test_parameters_field_is_validated_and_optional(self):
        normalized = normalize_origin_config(self.config)
        self.assertNotIn('parameters', normalized['origin_policies'][A]['rules'][1])
        self.assertEqual(normalized['origin_policies'][A]['rules'][0]['parameters'], ['q'])
        for bad in ([], ['q', 'q'], ['bad name'], ['__sentinel_x'], 'q', [1], ['n%d' % i for i in range(33)]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_origin_config({'approved_origins': [A], 'origin_policies': {A: {'rules': [rule('/s', bad)]}}})
        with self.assertRaises(ValueError):
            normalize_origin_config({'approved_origins': [A], 'origin_policies': {A: {'rules': [
                {'path': '/s', 'methods': ['HEAD'], 'operation': 'read_only', 'parameters': ['q']}]}}})

    def test_probe_scope_accepts_only_one_listed_or_control_pair_with_bounded_value(self):
        ok = [(A + '/search?q=sentinel_' + HEX, A + '/search', 'q'), (A + '/search?q=1', A + '/search', 'q'),
              (A + '/search?__sentinel_unknown_' + HEX + '=true', A + '/search', '__sentinel_unknown_' + HEX),
              (B + '/v?v=1&q=false', B + '/v?v=1', 'q')]
        for url, base, name in ok:
            with self.subTest(url=url):
                self.assertEqual(self.policy.check_parameter_probe(url, 'GET'), (base, name))
        denied = [A + '/search?page=1', A + '/search?q=abc', A + '/search?q=1&q=2', A + '/search?q=1;x',
                  A + '/plain?q=1', A + '/other?q=1', B + '/v?q=1', B + '/v?v=2&q=1', A + '/search?q=sentinel_XYZ',
                  B + '/search?q=1', 'http://127.0.0.1:18863/search?q=1', A + '/search?q=1#frag']
        for url in denied:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.policy.check_parameter_probe(url, 'GET')
        for method in ('HEAD', 'POST', 'DELETE'):
            with self.subTest(method=method), self.assertRaises(ValueError):
                self.policy.check_parameter_probe(A + '/search?q=1', method)
        with self.assertRaises(ValueError):
            self.policy.check(A + '/search?q=1', 'GET')  # B1 exact scope is unchanged.

    def test_probe_transport_rechecks_binding_and_plain_transport_stays_exact(self):
        credentials = OriginCredentialContext(self.policy, {A: {'profile_id': 'frontend',
                                                                'headers': {'Authorization': 'Bearer unit-fake'}}})
        probe = ParameterProbeTransport(A, policy=self.policy, credentials=credentials)
        probe.check_dispatch(A + '/search', 'GET')
        probe.check_dispatch(A + '/search?q=2', 'GET')
        with self.assertRaises(ValueError):
            probe.check_dispatch(A + '/search?page=2', 'GET')
        with self.assertRaises(ValueError):
            OriginScopedTransport(A, policy=self.policy, credentials=credentials).check_dispatch(A + '/search?q=2', 'GET')
        unbound = ParameterProbeTransport(A, policy=self.policy)
        with self.assertRaisesRegex(ValueError, 'credential profile is unavailable'):
            unbound.check_dispatch(A + '/search?q=2', 'GET')
        unbound.check_dispatch(B + '/items?category=1', 'GET')

    def test_supplied_transport_owns_network_policy(self):
        probe = ParameterProbeTransport(A, policy=self.policy)
        with self.assertRaisesRegex(ValueError, 'owns network policy'):
            verify_parameters(A + '/', [], transport=probe, headers={'X-Test': '1'})

    def test_source_reason_requires_complete_observed_2xx_get(self):
        good = {'attempted': True, 'classification': 'observed_response', 'execution_method': 'GET',
                'error': None, 'timeout': False, 'status_code': 200, 'body_complete': True}
        self.assertIsNone(_source_reason(good))
        cases = [({'recovery_state': 'outcome_unknown'}, 'source_outcome_unknown'),
                 ({'attempted': None}, 'source_not_observed'), ({'attempted': False}, 'source_not_observed'),
                 ({'error': {'error_type': 'x'}}, 'source_error_or_timeout'), ({'timeout': True}, 'source_error_or_timeout'),
                 ({'classification': None}, 'source_not_observed'), ({'execution_method': 'HEAD'}, 'source_method_not_get'),
                 ({'status_code': 302}, 'source_not_2xx'), ({'status_code': 404}, 'source_not_2xx'),
                 ({'status_code': '200'}, 'source_not_2xx'), ({'body_complete': False}, 'source_body_incomplete')]
        for change, reason in cases:
            with self.subTest(change=change):
                self.assertEqual(_source_reason({**good, **change}), reason)

    def state(self):
        state = {'target_url': A + '/', **origin_state(A + '/', self.config)}
        state['fuzzing_execution'] = {'multi_origin': {'status': 'completed'}}
        return state

    def test_preconditions_fail_closed_before_any_http(self):
        probe = ParameterProbeTransport(A, policy=self.policy)
        names = lambda path: []
        with self.assertRaisesRegex(ValueError, 'shared runtime'):
            verify_origin_parameters(self.state(), transport=probe, static_names_for=names)
        limits = {'http_origin_max_requests': {A: 5, B: 5}}
        with telemetry_session(max_llm_calls=0), runtime_session(limits) as runtime:
            with self.assertRaisesRegex(ValueError, 'probe transport'):
                verify_origin_parameters(self.state(), transport=OriginScopedTransport(A, policy=self.policy),
                                         static_names_for=names)
            legacy = self.state(); legacy['origin_contract_version'] = None
            with self.assertRaisesRegex(ValueError, 'SharedState contract'):
                verify_origin_parameters(legacy, transport=probe, static_names_for=names)
            runtime.recovery = object()
            with self.assertRaisesRegex(ValueError, 'parameter_recovery_not_supported_b41'):
                verify_origin_parameters(self.state(), transport=probe, static_names_for=names)
            runtime.recovery = None
            widened = self.state(); widened['origin_policies'][A]['rules'].append(rule('/admin', ['q']))
            with self.assertRaisesRegex(ValueError, 'policy_snapshot_mismatch'):
                verify_origin_parameters(widened, transport=probe, static_names_for=names)
            missing = self.state(); missing.pop('fuzzing_execution')
            with self.assertRaisesRegex(ValueError, 'B3.1 dispatch'):
                verify_origin_parameters(missing, transport=probe, static_names_for=names)
            for cap in (0, 10001, 1.5, True):
                with self.subTest(cap=cap), self.assertRaises(ValueError):
                    verify_origin_parameters(self.state(), transport=probe, static_names_for=names, max_requests=cap)
            self.assertEqual(runtime.requests, 0)
        with telemetry_session(max_llm_calls=0), runtime_session({}):
            with self.assertRaisesRegex(ValueError, 'per-origin quotas'):
                verify_origin_parameters(self.state(), transport=probe, static_names_for=names)

    def test_no_eligible_endpoints_records_skips_without_http(self):
        probe = ParameterProbeTransport(A, policy=self.policy)
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        with telemetry_session(max_llm_calls=0), runtime_session({'http_origin_max_requests': {A: 5, B: 5}}) as runtime:
            state = self.state()
            result = verify_origin_parameters(state, transport=probe, static_names_for=lambda path: [],
                                              artifact_root=tmp.name)
            self.assertEqual(runtime.requests, 0)
        for origin in (A, B):
            section = result['origin_contexts'][origin]['context']['parameter_discovery']
            self.assertEqual((section['status'], section['stop_reason']), ('skipped', 'no_eligible_endpoints'))
            self.assertEqual(section['counts']['http_requests'], 0)
        summary = result['parameter_execution']['multi_origin']
        self.assertEqual(summary['langgraph_integration'], 'not_enabled_b41')
        self.assertFalse(summary['full_multi_origin_execution_enabled'])
        with self.assertRaisesRegex(ValueError, 'rerun'):
            with telemetry_session(max_llm_calls=0), runtime_session({'http_origin_max_requests': {A: 5, B: 5}}):
                verify_origin_parameters(state, transport=probe, static_names_for=lambda path: [])


if __name__ == '__main__':
    unittest.main()
