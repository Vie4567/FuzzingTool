"""B4.2C unit tests: Report/Reflection contract, status rules, decisions, finalize/contract guards.

No sockets: every network entry point is patched to fail. No provider LLM, no KnowledgeStore.
"""
from copy import deepcopy
import tempfile
import unittest
from unittest.mock import patch

from src.coordinator.origin_local import LocalOriginTest
from src.coordinator.origin_recovery import RecoveryJournal
from src.coordinator.origin_report import (build_reflection, build_report, canonical_digest, global_agent_status,
                                           origin_agent_status, origin_status, resolve)
from src.coordinator.runtime import PipelineStopped, runtime_session

A, B, C = 'http://127.0.0.1:18761', 'http://127.0.0.1:18762', 'http://127.0.0.1:18763'
AGENTS = ('tech_recon', 'wordlist_gen', 'fuzzing', 'param_disc', 'soft404_filter')


def endpoint(origin, path, cls='genuine_distinct', level='metrics_journaled', unit_state='completed', params=()):
    return {'endpoint_id': (origin + path)[-24:], 'url': origin + path, 'eligible': True, 'exclusion_reason': None,
            'group_id': 'g' * 24, 'unit_id': 'u' * 32, 'unit_state': unit_state, 'soft404_classification': cls,
            'classification_reason': 'r', 'evidence_level': level, 'verification_status': 'not_verified',
            'parameter_context': {'verified_parameters': list(params), 'authority': 'context_only'},
            'source_dispatch': {'runtime_sequence': 3, 'evidence_refs': ['ref1']},
            'verification_evidence': {'candidate_sequence': 9, 'control_sequences': [7, 8]},
            'recorded_at_utc': '2026-11-26T00:00:00+00:00'}


def entry(origin, *, soft=None, params=None, dispatch_status='completed', records=None):
    context = {'source_documents': [{'url': origin + '/doc', 'collection_status': 'completed'}],
               'wordlist': {'candidates': [{}, {}], 'selected_ids': ['x']},
               'http_dispatch': {'status': dispatch_status, 'stop_reason': 'completed',
                                 'counts': {'attempted': 2, 'responses': 2},
                                 'records': records if records is not None else [
                                     {'candidate_id': 'x', 'url': origin + '/', 'runtime_sequence': 3, 'attempted': True,
                                      'status_code': 200, 'stop_reason': None, 'response_time': 0.123}]}}
    if params is not None:
        context['parameter_discovery'] = params
    if soft is not None:
        context['soft404'] = soft
    return {'agent_statuses': {'tech_recon': 'success', 'wordlist_gen': 'success'}, 'endpoints': [{}, {}],
            'context': context, 'status': 'partial'}


def section(status='completed', endpoints=(), requests=()):
    return {'status': status, 'stop_reason': 'completed', 'origin_halt': None, 'endpoints': list(endpoints),
            'requests': list(requests), 'counts': {'http_requests': len(requests), 'verified': 0},
            'classification_meaning': 'representation'}


def state(**overrides):
    value = {'approved_origins': [A, B], 'origin_execution_mode': 'not_enabled_b1',
             'discovered_origins': [{'origin': C, 'sources': [{'source': 'js'}]}],
             'origin_contexts': {
                 A: entry(A, params=section(), soft=section(endpoints=[endpoint(A, '/help')])),
                 B: entry(B, params=section(), soft=section(endpoints=[endpoint(B, '/v1/ghost', 'http_404', 'rederived')])),
                 C: {'agent_statuses': {'wordlist_gen': 'success'}, 'endpoints': [{}], 'context': {}, 'status': 'partial'}}}
    value.update(overrides)
    return value


ABSENT = {a: ('skipped', 'not_enabled_in_mode') for a in AGENTS}
INVOKED = {a: True for a in AGENTS}


def report(value=None, **kwargs):
    options = dict(absent=ABSENT, invoked=INVOKED, global_stop=None, contract_failures={})
    options.update(kwargs)
    return build_report(value or state(), **options)


class ReportContractTests(unittest.TestCase):
    def test_digest_is_canonical_and_ignores_volatile_fields(self):
        first = report()
        varied = state()
        for o in (A, B):
            varied['origin_contexts'][o]['context']['http_dispatch']['records'][0]['response_time'] = 9.9
            varied['origin_contexts'][o]['context']['soft404']['endpoints'][0]['recorded_at_utc'] = 'later'
        self.assertEqual(first['digest'], report(varied)['digest'])
        self.assertEqual(first['digest'], canonical_digest(first['content']))
        self.assertEqual(canonical_digest({'b': 1, 'a': [1, 2]}), canonical_digest({'a': [1, 2], 'b': 1}))
        changed = state()
        changed['origin_contexts'][B]['context']['soft404']['endpoints'][0]['soft404_classification'] = 'soft_404'
        self.assertNotEqual(first['digest'], report(changed)['digest'])

    def test_approved_and_discovered_only_origins_are_separate(self):
        content = report()['content']
        self.assertEqual([o['origin'] for o in content['approved_origins']], [A, B])
        self.assertEqual(content['discovered_only_origins'], [{
            'origin': C, 'approved': False, 'executed': False, 'status': 'not_applicable',
            'endpoints_observed': 1, 'source_references': 1, 'dispatch_attempts': 0}])

    def test_origin_isolation_provenance_and_evidence_levels(self):
        content = report()['content']
        for origin in content['approved_origins']:
            for row in origin['soft404']['endpoints']:
                self.assertTrue(row['url'].startswith(origin['origin'] + '/'))
                self.assertEqual(row['verification_status'], 'not_verified')
                self.assertEqual(row['evidence_refs'], ['ref1'])
                self.assertEqual((row['source_runtime_sequence'], row['candidate_sequence']), (3, 9))
        levels = {o['origin']: o['soft404']['endpoints'][0]['evidence_level'] for o in content['approved_origins']}
        self.assertEqual(levels, {A: 'metrics_journaled', B: 'rederived'})
        self.assertEqual(content['totals']['soft404_strong'], 2)
        self.assertEqual(content['totals']['soft404_http_404'], 1)

    def test_verified_parameter_never_verifies_endpoint(self):
        value = state()
        value['origin_contexts'][A]['context']['soft404']['endpoints'] = [endpoint(A, '/help', params=['q'])]
        row = report(value)['content']['approved_origins'][0]['soft404']['endpoints'][0]
        self.assertEqual(row['parameter_context'], {'verified_parameters': ['q'], 'authority': 'context_only'})
        self.assertEqual(row['verification_status'], 'not_verified')

    def test_interrupted_unit_and_unknown_requests_block_completed(self):
        value = state()
        value['origin_contexts'][A]['context']['soft404']['endpoints'][0]['unit_state'] = 'interrupted'
        value['origin_contexts'][B]['context']['parameter_discovery']['requests'] = [
            {'runtime_sequence': 40, 'recovery_state': 'outcome_unknown'}]
        content = report(value)['content']
        self.assertEqual([o['status'] for o in content['approved_origins']], ['interrupted', 'partial'])
        self.assertEqual(content['agents']['soft404_filter']['status'], 'interrupted')
        self.assertEqual((content['totals']['interrupted_units'], content['totals']['outcome_unknown']), (1, 1))

    def test_contract_failure_is_failed_not_skipped(self):
        content = report(contract_failures={'param_disc': 'parameter_contract_policy_snapshot_mismatch'})['content']
        self.assertEqual(content['agents']['param_disc']['status'], 'failed')
        self.assertTrue(all(o['status'] == 'failed' for o in content['approved_origins']))
        self.assertEqual(content['stop']['contract_failures'], {'param_disc': 'parameter_contract_policy_snapshot_mismatch'})

    def test_totals_are_sums_of_origin_sections(self):
        content = report()['content']
        self.assertEqual(content['totals']['dispatch_attempted'],
                         sum(o['dispatch']['counts']['attempted'] for o in content['approved_origins']))
        self.assertEqual(content['gate'], {'origin_execution_mode': 'not_enabled_b1', 'full_multi_origin_execution_enabled': False})


class StatusRuleTests(unittest.TestCase):
    def test_origin_status_precedence(self):
        ok = {a: ('success', None) for a in AGENTS}
        for change, unknown, expected in (({}, [], 'completed'), ({}, [5], 'partial'),
                                          ({'param_disc': ('skipped', 'x')}, [], 'partial'),
                                          ({'param_disc': ('interrupted', 'x'), 'fuzzing': ('partial', 'x')}, [], 'interrupted'),
                                          ({'param_disc': ('interrupted', 'x'), 'fuzzing': ('failed', 'x')}, [], 'failed'),
                                          ({a: ('skipped', 'x') for a in AGENTS}, [], 'skipped')):
            with self.subTest(change=change, unknown=unknown):
                self.assertEqual(origin_status({**ok, **change}, unknown), expected)

    def test_global_agent_status_never_treats_skip_as_success_by_default(self):
        for values, invoked, expected in ((['success', 'success'], True, 'success'), (['success', 'skipped'], True, 'success'),
                                          (['skipped', 'skipped'], True, 'skipped'), (['success', 'interrupted'], True, 'interrupted'),
                                          (['success', 'partial'], True, 'partial'), (['failed', 'not_started'], True, 'failed'),
                                          (['not_started'], True, 'not_started'), (['success'], False, 'not_started')):
            with self.subTest(values=values, invoked=invoked):
                self.assertEqual(global_agent_status(values, invoked, ('not_started', 'x')), expected)

    def test_section_states_map_to_agent_status(self):
        for status, expected in (('completed', 'success'), ('skipped', 'skipped'), ('partial', 'partial'),
                                 ('not_started', 'not_started'), ('interrupted', 'interrupted'), ('running', 'interrupted')):
            with self.subTest(status=status):
                value = entry(A, params=section(status))
                self.assertEqual(origin_agent_status(value, 'param_disc', ('skipped', 'x'))[0], expected)
        self.assertEqual(origin_agent_status(entry(A), 'soft404_filter', ('not_started', 'http_429')), ('not_started', 'http_429'))


class ReflectionTests(unittest.TestCase):
    def test_every_observation_is_backed_by_the_report(self):
        built = report(global_stop='http_429', contract_failures={'param_disc': 'parameter_contract_dispatch_missing'})
        reflection = build_reflection(built)
        self.assertEqual((reflection['knowledge_writes'], reflection['lessons'], reflection['llm_called']), (0, [], False))
        self.assertEqual(reflection['report_digest'], built['digest'])
        self.assertTrue(reflection['observations'])
        for row in reflection['observations']:
            self.assertEqual(resolve(built['content'], row['report_path']), row['value'], row)
        kinds = {r['kind'] for r in reflection['observations']}
        self.assertTrue({'global_stop', 'contract_failure', 'discovered_only_not_executed'} <= kinds)


class LocalDecisionAndGuardTests(unittest.TestCase):
    def setUp(self):
        self.scope = {'approved_origins': [A, B], 'origin_policies': {
            o: {'rules': [{'path': '/', 'methods': ['GET'], 'operation': 'read_only'}]} for o in (A, B)}}

    def local(self, **kwargs):
        return LocalOriginTest(A + '/', scope=self.scope, documents=[{'url': A + '/', 'kind': 'html'}],
                               origin_max_requests={A: 4, B: 4}, **kwargs)

    def facts(self, recon='success', selected=2, responses=3):
        return {'agent_statuses': {'tech_recon': recon}, 'wordlist_metadata': {'multi_origin': {'selected_count': selected}},
                'fuzzing_execution': {'multi_origin': {'counts': {'responses': responses}, 'stop_reason': 'completed'}}}

    def test_decision_table_per_mode(self):
        modes = {'three': {}, 'params': {'parameter_verification': True}, 'soft404': {'soft404_verification': True},
                 'full': {'parameter_verification': True, 'soft404_verification': True}}
        expected = {'three': 'abort_to_report', 'params': 'proceed_to_param', 'soft404': 'skip_to_filter', 'full': 'proceed_to_param'}
        for name, flags in modes.items():
            local = self.local(**flags)
            with self.subTest(mode=name):
                self.assertEqual(local.decision_for(self.facts(), 'after_recon', None), ('proceed_to_wordlist', None))
                self.assertEqual(local.decision_for(self.facts(), 'after_wordlist', None), ('proceed_to_fuzzing', None))
                self.assertEqual(local.decision_for(self.facts(), 'after_fuzzing', None)[0], expected[name])
                self.assertEqual(local.decision_for(self.facts(), 'after_fuzzing', 'http_429'), ('abort_to_report', 'http_429'))
                self.assertEqual(local.decision_for(self.facts(selected=0), 'after_wordlist', None),
                                 ('abort_to_report', 'no_selected_candidates'))
        self.assertEqual(self.local().decision_for(self.facts(), 'after_fuzzing', None), ('abort_to_report', 'local_three_agent_only'))
        self.assertEqual(self.local(parameter_verification=True, soft404_verification=True).decision_for(
            self.facts(responses=0), 'after_fuzzing', None), ('abort_to_report', 'no_target_responses'))

    def test_finalize_only_requires_resume_and_routes_to_report(self):
        with tempfile.TemporaryDirectory() as directory:
            for kwargs in ({'finalize_only': True}, {'finalize_only': 1, 'resume': True, 'recovery_directory': directory}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    self.local(**kwargs)
            local = self.local(finalize_only=True, resume=True, recovery_directory=directory,
                               parameter_verification=True, soft404_verification=True)
            self.assertEqual(local.decision_for(self.facts(), 'after_recon', None, finalize=True), ('abort_to_report', 'finalize_only'))
            self.assertEqual(local.decision_for(self.facts(), 'after_recon', 'http_429', finalize=True), ('abort_to_report', 'http_429'))
            # Recorded decisions are verified with the normal policy, not the finalize route.
            self.assertEqual(local.decision_for(self.facts(), 'after_recon', None), ('proceed_to_wordlist', None))

    def test_closed_transports_refuse_dispatch(self):
        local = self.local(parameter_verification=True, soft404_verification=True)
        local.close_dispatch()
        for transport in (local.transport, local.probe_transport, local.soft404_transport):
            with self.subTest(transport=type(transport).__name__), self.assertRaisesRegex(ValueError, 'finalize_only_no_dispatch'):
                transport.check_dispatch(A + '/', 'GET')

    def test_finalize_journal_refuses_reservation_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = RecoveryJournal(directory)
            journal.finalize_only = True
            with patch.object(journal, 'append', side_effect=AssertionError('journal written')):
                with self.assertRaises(PipelineStopped):
                    journal.reserve(object(), A, {'candidate_id': None}, 'param_disc')

    def test_contract_failure_only_for_listed_preconditions(self):
        local = self.local(parameter_verification=True, soft404_verification=True)

        class Agent:
            error = 'policy_snapshot_mismatch'

            def __init__(self, llm=None): pass

            def verify_origin_parameters(self, *args, **kwargs):
                raise ValueError(Agent.error)

        base = {'agent_statuses': {'param_disc': 'pending'}, 'config': {}, 'approved_origins': [A, B],
                'origin_contexts': {A: {'context': {}}, B: {'context': {}}},
                'local_origin_execution': {'agent_artifacts': {}}, 'audit_log': [], 'error_log': []}
        with runtime_session({'http_max_requests': 5}):
            done = local.parameters(deepcopy(base), Agent)
            self.assertEqual(done['agent_statuses']['param_disc'], 'failed')
            self.assertEqual(done['local_origin_execution']['contract_failures'],
                             {'param_disc': 'parameter_contract_policy_snapshot_mismatch'})
            self.assertEqual(done['local_origin_execution']['routing_skips'], {'soft404_filter': 'upstream_contract_failure'})
            for error in ('parameter_resume_plan_changed', 'parameter_phase_cap_changed', 'something unexpected'):
                Agent.error = error
                with self.subTest(error=error), self.assertRaises(ValueError):
                    local.parameters(deepcopy(base), Agent)


if __name__ == '__main__':
    unittest.main()
