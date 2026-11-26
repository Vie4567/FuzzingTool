"""B3.1 unit tests for reservation and fail-closed dispatch contracts."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from src.agents.fuzzer import FuzzingAgent
from src.coordinator.origins import origin_state,merge_discovery_context
from src.coordinator.runtime import RuntimeBudget,OriginBudgetExhausted,PipelineStopped,runtime_session,http_origin
from src.coordinator.telemetry import record_http_attempt,telemetry_session
from src.tools.origin_scope import OriginScopePolicy,OriginScopedTransport,OriginCredentialContext
from src.tools.recon_discovery import extract_javascript
from src.agents.wordlist_gen import WordlistGenAgent

A='http://front.test'
B='http://api.test'


class OriginDispatchTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.config={'approved_origins':[A,B],'origin_policies':{
            origin:{'rules':[{'path':'/users','methods':['GET'],'operation':'read_only'}]} for origin in (A,B)}}
        self.policy=OriginScopePolicy(self.config)
        self.transport=OriginScopedTransport(A,policy=self.policy)
        self.limits={'http_max_requests':5,'http_rate_limit':10000,'http_origin_max_requests':{A:2,B:2}}
        self.state={'target_url':A+'/',**origin_state(A,self.config)}
        data=extract_javascript(f'fetch("{A}/users", {{method:"GET"}}); fetch("{B}/users", {{method:"GET"}});',A+'/',A+'/app.js')
        merge_discovery_context(self.state,data)
        WordlistGenAgent(llm=Mock()).generate_from_discovery(self.state,max_wordlist_entries=2,
            max_generated_per_origin=0,artifact_root=self.directory.name)
        self.agent=FuzzingAgent(llm=Mock())

    def test_origin_quota_and_telemetry_do_not_count_denials(self):
        with runtime_session(self.limits) as runtime,telemetry_session() as telemetry:
            with http_origin(A):
                record_http_attempt();record_http_attempt()
                with self.assertRaises(OriginBudgetExhausted):record_http_attempt()
            with http_origin(B):record_http_attempt()
            self.assertEqual(runtime.requests,3)
            self.assertEqual(runtime.origin_requests,{A:2,B:1})
            self.assertEqual(telemetry.snapshot()['http']['known_requests'],3)
            self.assertIsNone(runtime.stop_reason)

    def test_global_limit_does_not_reset_on_origin_switch(self):
        with runtime_session({**self.limits,'http_max_requests':1}) as runtime:
            with http_origin(A):record_http_attempt()
            with http_origin(B):
                with self.assertRaises(PipelineStopped):record_http_attempt()
            self.assertEqual(runtime.requests,1)
            self.assertEqual(runtime.stop_reason,'http_request_budget')

    def test_origin_context_is_reset_and_missing_origin_fails_closed(self):
        with runtime_session(self.limits) as runtime:
            with http_origin(A):record_http_attempt()
            with self.assertRaises(OriginBudgetExhausted):record_http_attempt()
            self.assertEqual(runtime.requests,1)

    def test_atomic_quota_reservation_under_concurrency(self):
        runtime=RuntimeBudget({**self.limits,'http_origin_max_requests':{A:3,B:2}})
        def reserve(_):
            try:runtime.reserve_http(origin=A);return True
            except OriginBudgetExhausted:return False
        with ThreadPoolExecutor(max_workers=6) as executor:
            self.assertEqual(sum(executor.map(reserve,range(10))),3)
        self.assertEqual(runtime.requests,3)
        self.assertEqual(runtime.origin_requests[A],3)

    def test_invalid_origin_limits_and_zero_quota(self):
        for limits in ({}, {A:True},{A:-1},{A+'/path':1},{A:1.5}):
            with self.assertRaises(ValueError):RuntimeBudget({'http_origin_max_requests':limits})
        runtime=RuntimeBudget({'http_origin_max_requests':{A:0}})
        with self.assertRaises(OriginBudgetExhausted):runtime.reserve_http(origin=A)
        self.assertEqual(runtime.requests,0)

    def test_legacy_runtime_without_origin_limits_unchanged(self):
        with runtime_session({'http_max_requests':1}) as runtime:
            record_http_attempt()
            self.assertEqual(runtime.requests,1)
            self.assertIsNone(runtime.origin_limits)

    def test_profile_mismatch_is_rejected_at_configuration(self):
        config=deepcopy(self.config);config['origin_policies'][A]['credential_profile']='front'
        policy=OriginScopePolicy(config)
        with self.assertRaises(ValueError):
            OriginCredentialContext(policy,{A:{'profile_id':'wrong','headers':{'Authorization':'Bearer unit-only'}}})

    def test_changed_binding_is_rejected_without_http_or_budget(self):
        config=deepcopy(self.config);config['origin_policies'][A]['credential_profile']='front'
        policy=OriginScopePolicy(config)
        private=OriginCredentialContext(policy,{A:{'profile_id':'front','headers':{'Authorization':'Bearer unit-only'}}})
        transport=OriginScopedTransport(A,policy=policy,credentials=private)
        policy._config['origin_policies'][A]['credential_profile']='other'
        with runtime_session(self.limits) as runtime:
            with self.assertRaises(ValueError):transport.check_dispatch(A+'/users','GET')
            self.assertEqual(runtime.requests,0)

    def test_unsupported_engines_never_call_transport(self):
        with runtime_session(self.limits),patch.object(self.transport,'fetch_result') as fetch:
            for engine in ('ffuf_cli','proxy_http'):
                with self.assertRaises(ValueError):self.agent.dispatch_selected(self.state,transport=self.transport,engine=engine)
            fetch.assert_not_called()

    def test_runtime_and_explicit_per_origin_budget_required(self):
        with self.assertRaises(ValueError):self.agent.dispatch_selected(self.state,transport=self.transport)
        with runtime_session({'http_max_requests':5}):
            with self.assertRaises(ValueError):self.agent.dispatch_selected(self.state,transport=self.transport)

    def test_cross_runtime_checkpoint_resume_fails_closed(self):
        self.state['origin_contexts'][A]['context']['http_dispatch']={'records':[]}
        with runtime_session(self.limits),patch.object(self.transport,'fetch_result') as fetch:
            with self.assertRaises(ValueError):self.agent.dispatch_selected(self.state,transport=self.transport)
            fetch.assert_not_called()

    def test_interrupt_checkpoint_keeps_failed_and_unattempted_records(self):
        with runtime_session(self.limits) as runtime,patch.object(self.transport,'fetch_result',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.agent.dispatch_selected(self.state,transport=self.transport,artifact_root=self.directory.name)
            self.assertEqual(runtime.requests,0)
            self.assertEqual(runtime.stop_reason,'dispatch_interrupted')
        outputs=[json.loads(p.read_text()) for p in Path(self.directory.name).glob('*/result.json')]
        output=next(o for o in outputs if 'fuzzing_execution' in o)
        summary=output['fuzzing_execution']['multi_origin']
        self.assertEqual(summary['status'],'failed')
        self.assertEqual(summary['counts']['attempted'],0)
        self.assertEqual(summary['counts']['unattempted'],2)

    def test_b1_transport_rejects_candidate_private_headers_before_counting(self):
        from urllib.request import Request
        with runtime_session(self.limits) as runtime:
            with self.assertRaises(ValueError):self.transport.open(Request(A+'/users',headers={'Authorization':'Bearer untrusted'}))
            self.assertEqual(runtime.requests,0)

