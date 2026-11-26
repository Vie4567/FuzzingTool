"""Compiled Coordinator/LangGraph -> three real Agents -> loopback HTTP servers."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest

import test_discovery_http_integration as b21
import test_origin_wordlist_http as b22
import test_origin_dispatch_http as b31
from src.coordinator import graph
from src.coordinator.origin_local import LocalOriginTest
from src.coordinator.runtime import current_runtime
from src.coordinator.llm_logging import sanitize_for_log


class OriginGraphHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):b31.OriginDispatchHttpTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):b31.OriginDispatchHttpTests.tearDownClass.__func__(cls)

    reset_transport=b22.OriginWordlistHttpTests.reset_transport

    def setUp(self):
        # Reuse only fixture documents/policies. Close the helper's unused
        # runtime before invoking Coordinator: Coordinator owns the actual one.
        with patch.dict(os.environ,{'B22_EVIDENCE_DIR':''}):
            b22.OriginWordlistHttpTests.setUp(self)
        self.stack.close()
        self.assertIsNone(current_runtime())
        self.case_id=self.case_id.replace('b22_', 'b32a_')
        base=os.getenv('B32A_EVIDENCE_DIR')
        if not base:
            temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);base=temporary.name
        self.directory=Path(base)/self.case_id;self.directory.mkdir(parents=True)
        for server in self.servers:
            server.case_id=self.case_id;server.dispatch_mode=False;server.faults={};server.redirect_target=self.c+'/forbidden'
        self.config={**self.limits,'multi_origin':self.config,'fuzzing_options':{'engine':'python_http'},
                     'max_wordlist_entries':3,'artifact_root':str(self.directory),'max_llm_calls':1}
        self.quota={self.a:8,self.b:8}
        self.calls=[];self.results=[];self.topology=None;self.result=None
        self.after_selection=None
        self.test_complete=False

    def local(self):
        return LocalOriginTest(self.a+'/',scope=self.config['multi_origin'],documents=self.plan,
            origin_max_requests=self.quota,credential_profiles={self.a:{'profile_id':'frontend',
                'headers':{'Authorization':b21.AUTH,'Cookie':b21.COOKIE}}})

    def run_graph(self, local=None):
        local=local or self.local()
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.object(graph,'_get_decision_engine',side_effect=AssertionError('No provider/LLM in local mode')))
            for cls,method,agent in [(graph.TechReconAgent,'collect_discovery','tech_recon'),
                    (graph.WordlistGenAgent,'generate_from_discovery','wordlist_gen'),
                    (graph.FuzzingAgent,'dispatch_selected','fuzzing')]:
                real=getattr(cls,method)
                def observe(*args,_real=real,_agent=agent,**kwargs):
                    budget=current_runtime()
                    call={'agent':_agent,'runtime_instance':id(budget),'before_runtime':budget.snapshot(),
                          'input_state':deepcopy(args[1]) if _agent!='tech_recon' else None}
                    self.calls.append(call)
                    value=_real(*args,**kwargs)
                    call.update(output=deepcopy(value),after_runtime=budget.snapshot())
                    if _agent=='wordlist_gen':
                        for server in self.servers:server.dispatch_mode=True
                        if self.after_selection:self.after_selection(args[1])
                    return value
                stack.enter_context(patch.object(cls,method,autospec=True,side_effect=observe))
            for cls in (graph.ParamDiscoveryAgent,graph.Soft404FilterAgent):
                stack.enter_context(patch.object(cls,'execute',side_effect=AssertionError('B4 unavailable')))
            real_build=graph.build_coordinator_graph
            def build():
                app=real_build()
                # get_graph()'s drawing simulation cannot handle this installed
                # LangGraph version's cyclic root-state graph. Inspect the real
                # builder; execution itself remains app.invoke(), traced by callbacks.
                self.topology={'compiled_type':type(app).__name__, 'nodes':sorted(app.builder.nodes),
                    'edges':sorted([list(e) for e in app.builder.edges]),
                    'branches':{node:{key:branch.ends for key,branch in branches.items()}
                                for node,branches in app.builder.branches.items()}}
                # Must really be a compiled LangGraph, not a sequential test harness.
                self.assertIn('CompiledStateGraph',type(app).__name__)
                return app
            stack.enter_context(patch.object(graph,'build_coordinator_graph',side_effect=build))
            self.result=graph.run_pipeline(self.a+'/',self.config,local_origin_test=local)
        self.results.append(deepcopy(self.result))
        self.assertEqual(len(self.servers[2].access),0)
        self.assertTrue(all(r['credential_identity']=='anonymous' for r in self.servers[1].access))
        self.assertFalse(self.result.get('all_modules_executed'))
        self.assertFalse(self.result.get('all_modules_successful'))
        self.assertNotEqual(self.result['pipeline_status'],'completed')
        self.assertEqual(self.result['llm_call_count'],0)
        self.test_complete=True
        return self.result

    def counts(self):return self.result['fuzzing_execution']['multi_origin']['counts']

    def fault(self,mode,origin=None):
        def alter(state):
            origin_value=origin or self.a
            w=state['origin_contexts'][origin_value]['context']['wordlist']
            selected=next(r for r in w['candidates'] if r['endpoint_id']==w['selected_ids'][0])
            self.servers[0 if origin_value==self.a else 1].faults[selected['url'][len(origin_value):]]=mode
        self.after_selection=alter

    def test_compiled_graph_real_chain_and_checkpoint_identity(self):
        result=self.run_graph()
        self.assertEqual([c['agent'] for c in self.calls],['tech_recon','wordlist_gen','fuzzing'])
        self.assertEqual(len({c['runtime_instance'] for c in self.calls}),1)
        self.assertEqual(result['local_origin_execution']['status'],'completed')
        self.assertEqual(result['pipeline_status'],'partial')
        self.assertEqual(self.counts()['attempted'],3)
        self.assertEqual(result['runtime']['http_dispatches'],7)
        self.assertEqual([r['node'] for r in result['local_origin_execution']['langgraph_trace'] if r['event']=='start'],
            ['validate_input','init_state','tech_recon','llm_decide_recon','gen_words','llm_decide_wordlist',
             'fuzzing','llm_decide_fuzzing','report','reflection'])
        self.assertEqual(result['agent_attempts'],{'tech_recon':1,'wordlist_gen':1,'fuzzing':1})

    def test_global_budget_spans_recon_and_dispatch(self):
        self.config['http_max_requests']=6
        result=self.run_graph()
        self.assertEqual(result['runtime']['http_dispatches'],6)
        self.assertEqual(self.counts()['attempted'],2)
        self.assertEqual(result['stop_reason'],'http_request_budget')

    def test_per_origin_budget_keeps_global_accounting(self):
        self.quota[self.a]=3
        result=self.run_graph()
        self.assertEqual(self.counts()['attempted'],1)
        self.assertEqual(result['runtime']['http_dispatches'],5)
        self.assertEqual(result['runtime']['http_dispatches_by_origin'][self.a],3)
        self.assertEqual(result['stop_reason'],'origin_request_budget')

    def stop_case(self,status,reason):
        self.fault(status)
        result=self.run_graph()
        self.assertEqual(result['stop_reason'],reason)
        self.assertEqual(self.counts()['attempted'],1)
        self.assertEqual(self.counts()['responses'],1)
        self.assertEqual(result['agent_statuses']['fuzzing'],'partial')

    def test_401_stops_before_gateway(self):self.stop_case(401,'http_401')
    def test_403_stops_before_gateway(self):self.stop_case(403,'http_403')
    def test_407_stops_before_gateway(self):self.stop_case(407,'http_407')
    def test_429_stops_before_gateway(self):self.stop_case(429,'http_429')
    def test_retry_after_stops_before_gateway(self):self.stop_case('retry_after','retry_after')

    def test_timeout_keeps_partial_counts_and_checkpoint(self):
        self.config['http_timeout_seconds']=.05
        self.fault('timeout')
        result=self.run_graph()
        self.assertEqual(self.counts()['attempted'],3)
        self.assertEqual(self.counts()['responses'],2)
        self.assertEqual(self.counts()['errors'],1)
        self.assertEqual(result['agent_statuses']['fuzzing'],'partial')

    def test_transport_error_keeps_other_origin_measurements(self):
        self.fault('disconnect')
        self.run_graph()
        self.assertEqual(self.counts()['errors'],1)
        self.assertEqual(self.counts()['responses'],2)

    def test_redirect_never_followed(self):
        self.fault('redirect')
        self.run_graph()
        self.assertEqual(self.counts()['attempted'],3)

    def test_scope_mutation_after_selection_is_rechecked(self):
        self.after_selection=lambda state:state['origin_policies'][self.a].update(rules=[])
        result=self.run_graph()
        self.assertEqual(self.counts()['attempted'],0)
        self.assertEqual(result['runtime']['http_dispatches'],4)

    def test_duplicate_selection_does_not_repeat_dispatch(self):
        def duplicate(state):
            wordlist=state['origin_contexts'][self.a]['context']['wordlist']
            wordlist['selected_ids']+=wordlist['selected_ids']
        self.after_selection=duplicate
        result=self.run_graph()
        self.assertEqual(self.counts()['attempted'],3)
        self.assertEqual(result['agent_attempts']['fuzzing'],1)

    def test_no_selected_endpoints_skips_fuzzing_truthfully(self):
        for origin,policy in self.config['multi_origin']['origin_policies'].items():
            policy['rules']=[r for r in policy['rules'] if origin+r['path'] in {d['url'] for d in self.plan}]
        result=self.run_graph()
        self.assertEqual([c['agent'] for c in self.calls],['tech_recon','wordlist_gen'])
        self.assertEqual(result['agent_statuses']['fuzzing'],'skipped')
        self.assertEqual(result['stop_reason'],'no_selected_candidates')

    def test_rate_limit_is_global_in_compiled_graph(self):
        self.config['http_rate_limit']=10
        result=self.run_graph()
        times=[r['reserved_at_monotonic'] for r in result['runtime']['origin_reservations']]
        self.assertEqual(len(times),7)
        self.assertTrue(all(b-a>=.1 for a,b in zip(times,times[1:])))

    def test_deadline_after_selection_stops_fuzzing_before_http(self):
        import time
        def expire(state):current_runtime().deadline=time.monotonic()-1
        self.after_selection=expire
        result=self.run_graph()
        self.assertEqual(result['stop_reason'],'pipeline_deadline')
        self.assertEqual(result['agent_statuses']['fuzzing'],'skipped')
        self.assertEqual(result['runtime']['http_dispatches'],4)

    def test_same_context_replay_is_denied_without_new_http(self):
        local=self.local();self.run_graph(local)
        before=deepcopy([s.access for s in self.servers])
        result=self.run_graph(local)
        self.assertEqual(result['pipeline_status'],'failed')
        self.assertEqual([s.access for s in self.servers],before)
        self.assertEqual(result['total_http_requests'],0)

    def test_checkpoint_without_private_context_cannot_resume(self):
        result=self.run_graph()
        checkpoint=json.loads(Path(result['artifacts']['checkpoint']).read_text())
        before=deepcopy([s.access for s in self.servers])
        with patch.object(graph,'_get_decision_engine',side_effect=AssertionError('No provider')):
            denied=graph.build_coordinator_graph().invoke(checkpoint)
        self.assertEqual(denied['agent_statuses']['validate'],'failed')
        self.assertEqual(denied['stop_reason'],'multi_origin_execution_not_enabled_b1')
        self.assertEqual([s.access for s in self.servers],before)
        self.denied_resume=denied

    def test_recon_global_stop_skips_downstream_agents(self):
        self.servers[0].mode='blocked'
        result=self.run_graph()
        self.assertEqual([c['agent'] for c in self.calls],['tech_recon'])
        self.assertEqual(result['stop_reason'],'http_403')
        self.assertEqual(result['runtime']['http_dispatches'],1)
        self.assertEqual(result['agent_statuses']['wordlist_gen'],'skipped')
        self.assertEqual(result['agent_statuses']['fuzzing'],'skipped')

    def test_partial_recon_preserves_context_for_downstream_agents(self):
        self.servers[0].mode='disconnect_js'
        result=self.run_graph()
        self.assertEqual([c['agent'] for c in self.calls],['tech_recon','wordlist_gen','fuzzing'])
        self.assertEqual(result['agent_statuses']['tech_recon'],'partial')
        self.assertEqual(result['local_origin_execution']['status'],'partial')
        self.assertGreater(self.counts()['responses'],0)

    def test_production_multi_origin_remains_closed(self):
        with patch.object(graph,'_get_decision_engine',side_effect=AssertionError('No provider')):
            self.result=graph.run_pipeline(self.a+'/',self.config)
        self.results.append(self.result)
        self.assertEqual(self.result['pipeline_status'],'failed')
        self.assertEqual(self.result['stop_reason'],'multi_origin_execution_not_enabled_b1')
        self.assertEqual(sum(len(s.access) for s in self.servers),0)
        self.test_complete=True

    def tearDown(self):
        failed=any(test is self for test,_ in self._outcome.result.failures+self._outcome.result.errors)
        data={'diagnostic_id':self.case_id,'test':self.id().replace('.', '::'),
            'started_at_utc':self.started,'finished_at_utc':datetime.now(timezone.utc).isoformat(),
            'test_outcome':'PASS' if self.test_complete and not failed else 'FAIL',
            'config':self.config,'origin_quotas':self.quota,'documents':self.plan,
            'servers':{s.role:s.origin for s in self.servers},'agent_calls':self.calls,
            'results':self.results,'graph_topology':self.topology,'llm_calls':0,'mock_llm_decisions':0,
            'denied_resume':getattr(self,'denied_resume',None),
            'live_verification':'not_verified'}
        for server in self.servers:
            (self.directory/(server.role+'_access.json')).write_text(json.dumps(server.access,indent=2),encoding='utf-8')
            served={r['path'] for r in server.access if r.get('phase')=='recon' and r['status']==200}
            (self.directory/(server.role+'_served.json')).write_text(json.dumps({server.origin+p:server.documents[p][0] for p in served},indent=2),encoding='utf-8')
        public=sanitize_for_log({'credentials':[b21.AUTH,b21.COOKIE],'payload':data})['payload']
        (self.directory/'evidence.json').write_text(json.dumps(public,indent=2),encoding='utf-8')
