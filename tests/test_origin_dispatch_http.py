"""B3.1 real localhost chain; no HTTP mocks, public Internet or provider LLM."""
from copy import deepcopy
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import tempfile
from threading import Lock, Thread
import time
import unittest
from unittest.mock import Mock, patch

import test_discovery_http_integration as b21
import test_origin_wordlist_http as b22
from src.agents.fuzzer import FuzzingAgent
from src.tools.origin_scope import OriginScopePolicy, OriginCredentialContext, OriginScopedTransport


class DispatchHandler(b21.Handler):
    def do_GET(self):
        received = time.monotonic()
        if not self.server.dispatch_mode:
            super().do_GET()
            self.server.access[-1]['received_at_monotonic'] = received
            self.server.access[-1]['phase'] = 'recon'
            return
        mode = self.server.faults.get(self.path, 'ok')
        status = None if mode in ('timeout','disconnect') else 302 if mode=='redirect' else mode if type(mode) is int else 200
        a,c = self.headers.get('Authorization'),self.headers.get('Cookie')
        row = {'utc':datetime.now(timezone.utc).isoformat(),'diagnostic_id':self.server.case_id,
            'origin':self.server.origin,'path':self.path,'method':self.command,'phase':'dispatch',
            'received_at_monotonic':received,'status':status,'fault':mode,
            'authorization_present':a is not None,'cookie_present':c is not None,
            'credential_identity':'frontend' if (a,c)==(b21.AUTH,b21.COOKIE) else 'anonymous' if a is None and c is None else 'unexpected'}
        with self.server.lock:
            self.server.access.append(row)
        if mode in ('timeout','disconnect'):
            if mode=='timeout':
                time.sleep(.3)
            self.connection.close()
            self.close_connection = True
            return
        body = json.dumps({'lab_role':self.server.role,'request_path':self.path}).encode()
        try:
            self.send_response(status)
            if mode=='redirect':
                self.send_header('Location',self.server.redirect_target)
            if mode=='retry_after' or status==429:
                self.send_header('Retry-After','30')
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            if self.command!='HEAD':
                self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET


class OriginDispatchHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers,cls.workers=[],[]
        for role in ('frontend','gateway','unapproved'):
            server=ThreadingHTTPServer(('127.0.0.1',0),DispatchHandler)
            server.daemon_threads=True
            server.role,server.lock=role,Lock()
            server.origin=f'http://127.0.0.1:{server.server_port}'
            worker=Thread(target=server.serve_forever,daemon=True);worker.start()
            cls.servers.append(server);cls.workers.append(worker)
        cls.a,cls.b,cls.c=[s.origin for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        b21.DiscoveryHttpTests.tearDownClass.__func__(cls)

    reset_transport=b22.OriginWordlistHttpTests.reset_transport

    def setUp(self):
        real_session=b21.runtime_session
        self.closed_origin=None
        if self._testMethodName=='test_connection_refused_counts_attempt_without_server_access':
            with socket.socket() as unused:
                unused.bind(('127.0.0.1',0))
                self.closed_origin=f'http://127.0.0.1:{unused.getsockname()[1]}'
        def configured(options):
            options.update(http_origin_max_requests={self.a:8,self.b:8})
            if self.closed_origin:
                options['http_origin_max_requests'][self.closed_origin]=2
            if self._testMethodName=='test_global_budget_between_origins':
                options['http_max_requests']=6
            if self._testMethodName=='test_per_origin_budget_includes_recon_and_does_not_reset_global':
                options['http_origin_max_requests']={self.a:3,self.b:8}
            if 'timeout' in self._testMethodName:
                options['http_timeout_seconds']=.05
            if self._testMethodName=='test_rate_limit_is_shared_across_recon_and_both_origins':
                options['http_rate_limit']=10
            return real_session(options)
        with patch.object(b21,'runtime_session',side_effect=configured), patch.dict(os.environ,{'B22_EVIDENCE_DIR':''}):
            b22.OriginWordlistHttpTests.setUp(self)
        self.case_id=self.case_id.replace('b22_','b31_')
        root=os.getenv('B31_EVIDENCE_DIR')
        if not root:
            temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=temporary.name
        self.directory=Path(root)/self.case_id;self.directory.mkdir(parents=True)
        for server in self.servers:
            server.case_id=self.case_id;server.dispatch_mode=False;server.faults={};server.redirect_target=self.c+'/must-not-follow'
        self.dispatch_runs=[]
        self.dispatch_before=None
        self.runtime_before=None
        self.http_before_dispatch=None
        self.agent3_llm=Mock()
        self.agent3=FuzzingAgent(llm=self.agent3_llm)
        self.verified=False
        self.scenario={}
        if self.closed_origin:
            from src.coordinator.origins import origin_state
            self.config['approved_origins'].append(self.closed_origin)
            for origin in (self.a,self.b):
                self.config['origin_policies'][origin]['rules']=[
                    {'path':r['url'][len(origin):], 'methods':['GET'],'operation':'read_only'}
                    for r in self.plan if r['url'].startswith(origin+'/')]
            self.config['origin_policies'][self.closed_origin]={'rules':[{'path':'/users','methods':['GET'],'operation':'read_only'}]}
            body,mime=self.servers[0].documents['/app.js']
            self.servers[0].documents['/app.js']=(body+f'\nfetch("{self.closed_origin}/users", {{method:"GET"}});',mime)
            self.state={'target_url':self.a+'/',**origin_state(self.a,self.config)}
            self.reset_transport()
            self.scenario.update(unreachable_origin=self.closed_origin,socket_bound_then_closed=True,no_listener_created=True)

    def prepare(self,k=3):
        b22.OriginWordlistHttpTests.collect(self)
        self.selection=b22.OriginWordlistHttpTests.generate(self,k)
        self.selection_state=deepcopy(self.state)
        self.http_before_dispatch=deepcopy([s.access for s in self.servers])
        self.runtime_before=self.runtime.snapshot()
        for server in self.servers:
            server.dispatch_mode=True

    def selected(self,origin):
        wordlist=self.state['origin_contexts'][origin]['context']['wordlist']
        return [next(r for r in wordlist['candidates'] if r['endpoint_id']==identifier) for identifier in wordlist['selected_ids']]

    def dispatch(self):
        if self.dispatch_before is None:
            self.dispatch_before=deepcopy(self.state)
        result=self.agent3.dispatch_selected(self.state,transport=self.transport,artifact_root=self.directory)
        self.dispatch_runs.append(result)
        self.agent3_llm.invoke.assert_not_called()
        self.assertEqual(self.state['origin_execution_mode'],'not_enabled_b1')
        self.assertEqual(len(self.servers[2].access),0)
        for index,server in enumerate(self.servers):
            expected='frontend' if index==0 else 'anonymous'
            self.assertTrue(all(e['credential_identity']==expected for e in server.access))
        summary=result['fuzzing_execution']['multi_origin']
        self.assertEqual(summary['runtime']['http_dispatches'],self.telemetry.snapshot()['http']['known_requests'])
        self.assertEqual(summary['runtime']['http_dispatches'],self.runtime_before['http_dispatches']+summary['counts']['attempted'])
        self.verified=True
        return summary

    def records(self):
        return [r for entry in self.state['origin_contexts'].values() for r in entry['context']['http_dispatch']['records']]

    def first_path(self):
        from urllib.parse import urlsplit
        row=self.selected(self.a)[0];p=urlsplit(row['url'])
        return p.path+('?' + p.query if p.query else '')

    def test_real_agent_chain_preserves_identity_query_evidence_and_actual_responses(self):
        self.prepare()
        summary=self.dispatch()
        self.assertEqual(summary['status'],'completed')
        self.assertEqual(summary['counts'],{'selected':3,'attempted':3,'responses':3,'errors':0,'unattempted':0,'timeouts':0})
        self.assertEqual({r['origin'] for r in self.records() if r['attempted']},{self.a,self.b})
        for row in self.records():
            self.assertEqual(row['classification'],'observed_response')
            self.assertEqual(row['execution_method'],row['observed_method'])
            self.assertIsNone(row['planned_test_method']);self.assertIsNone(row['verified'])
            self.assertTrue(row['evidence_refs']);self.assertGreater(row['bytes_received'],0)

    def test_global_budget_between_origins(self):
        self.prepare()
        summary=self.dispatch()
        self.assertEqual(summary['stop_reason'],'http_request_budget')
        self.assertEqual(summary['counts']['attempted'],2)
        self.assertEqual(summary['runtime']['http_dispatches'],6)
        self.assertEqual(summary['counts']['unattempted'],1)

    def test_per_origin_budget_includes_recon_and_does_not_reset_global(self):
        self.prepare()
        summary=self.dispatch()
        self.assertEqual(summary['runtime']['http_dispatches_by_origin'][self.a],3)
        self.assertGreater(summary['counts']['responses'],0)
        self.assertTrue(all(not r['attempted'] and r['stop_reason']=='origin_request_budget' for r in self.records() if r['origin']==self.a))
        self.assertIsNone(self.runtime.stop_reason)
        self.assertEqual(self.runtime.requests,4+summary['counts']['attempted'])

    def stop_case(self,mode,reason):
        self.prepare();self.servers[0].faults[self.first_path()]=mode
        summary=self.dispatch()
        self.assertEqual(summary['stop_reason'],reason)
        self.assertEqual(summary['counts']['attempted'],1)
        self.assertEqual(summary['counts']['responses'],1)
        self.assertEqual(summary['counts']['errors'],0)
        self.assertEqual(len([r for r in self.servers[1].access if r.get('phase')=='dispatch']),0)
        self.assertNotEqual(summary['status'],'completed')

    def test_401_stops_all_origins(self): self.stop_case(401,'http_401')
    def test_403_stops_all_origins(self): self.stop_case(403,'http_403')
    def test_407_stops_all_origins(self): self.stop_case(407,'http_407')
    def test_429_retry_after_stops_all_origins(self): self.stop_case(429,'http_429')
    def test_retry_after_on_200_stops_all_origins(self): self.stop_case('retry_after','retry_after')

    def test_timeout_is_an_attempt_and_other_results_are_preserved(self):
        self.prepare();self.servers[0].faults[self.first_path()]='timeout'
        summary=self.dispatch()
        self.assertEqual(summary['counts']['attempted'],3)
        self.assertEqual(summary['counts']['responses'],2)
        self.assertEqual(summary['counts']['errors'],1)
        self.assertEqual(summary['counts']['timeouts'],1)
        self.assertEqual(summary['status'],'partial')

    def test_all_timeouts_fail_without_fabricated_responses(self):
        from urllib.parse import urlsplit
        self.prepare()
        for server in self.servers[:2]:
            for row in self.selected(server.origin):
                p=urlsplit(row['url']);server.faults[p.path+('?' + p.query if p.query else '')]='timeout'
        summary=self.dispatch()
        self.assertEqual(summary['status'],'failed')
        self.assertEqual(summary['counts']['attempted'],3)
        self.assertEqual(summary['counts']['responses'],0)
        self.assertEqual(summary['counts']['timeouts'],3)

    def test_disconnect_counts_attempt_and_preserves_other_origin(self):
        self.prepare();self.servers[0].faults[self.first_path()]='disconnect'
        summary=self.dispatch()
        self.assertEqual(summary['counts']['attempted'],3)
        self.assertEqual(summary['counts']['errors'],1)
        self.assertEqual(summary['status'],'partial')

    def test_connection_refused_counts_attempt_without_server_access(self):
        self.prepare()
        summary=self.dispatch()
        self.assertEqual(summary['counts']['selected'],1)
        self.assertEqual(summary['counts']['attempted'],1)
        self.assertEqual(summary['counts']['responses'],0)
        self.assertEqual(summary['counts']['errors'],1)
        self.assertEqual(sum(len(s.access) for s in self.servers),4)
        self.assertEqual(summary['status'],'failed')

    def test_later_gateway_block_does_not_overwrite_completed_frontend(self):
        from urllib.parse import urlsplit
        self.prepare()
        p=urlsplit(self.selected(self.b)[0]['url'])
        self.servers[1].faults[p.path+('?' + p.query if p.query else '')]=403
        summary=self.dispatch()
        self.assertEqual(summary['stop_reason'],'http_403')
        self.assertEqual(self.state['origin_contexts'][self.a]['context']['http_dispatch']['status'],'completed')
        self.assertEqual(self.state['origin_contexts'][self.b]['context']['http_dispatch']['status'],'partial')

    def test_redirect_is_observed_but_not_followed(self):
        self.prepare();self.servers[0].faults[self.first_path()]='redirect'
        summary=self.dispatch()
        self.assertIn(302,[r['status_code'] for r in self.records()])
        self.assertEqual(summary['counts']['attempted'],3)
        self.assertEqual(len(self.servers[2].access),0)

    def test_duplicate_candidates_and_reordered_repeat_never_rescan(self):
        self.prepare()
        wordlist=self.state['origin_contexts'][self.a]['context']['wordlist']
        wordlist['candidates'].append(deepcopy(self.selected(self.a)[0]))
        wordlist['selected_ids'].append(wordlist['selected_ids'][0])
        self.dispatch()
        count=self.runtime.requests;logs=deepcopy([s.access for s in self.servers])
        for entry in self.state['origin_contexts'].values():
            entry['context']['wordlist']['selected_ids'].reverse()
        summary=self.dispatch()
        self.assertEqual(self.runtime.requests,count)
        self.assertEqual([s.access for s in self.servers],logs)
        self.assertEqual(summary['http_dispatches_this_call'],0)
        self.assertEqual(summary['counts']['attempted'],3)

    def test_url_path_query_or_method_tampering_is_blocked(self):
        self.prepare()
        row=self.selected(self.a)[0]
        row['url']=self.c+'/outside?altered=1'
        summary=self.dispatch()
        self.assertEqual(summary['counts']['attempted'],2)
        self.assertTrue(any(r.get('rejection_reason')=='candidate_identity_changed' for r in self.records()))

    def test_method_and_same_origin_query_tampering_are_blocked(self):
        self.prepare()
        self.selected(self.a)[0]['method']='HEAD'
        self.selected(self.b)[0]['url']+='?changed=1'
        summary=self.dispatch()
        self.assertEqual(summary['counts']['attempted'],1)
        self.assertEqual(summary['counts']['unattempted'],2)
        self.assertFalse(any(r['method']=='HEAD' or 'changed=1' in r['path'] for s in self.servers for r in s.access))

    def test_post_unknown_generated_and_unapproved_snapshots_are_not_authority(self):
        self.prepare()
        for origin,entry in self.state['origin_contexts'].items():
            wordlist=entry['context']['wordlist']
            extra=next(r for r in wordlist['candidates'] if (r['method']=='POST' if origin==self.b else r['method'] is None if origin==self.a else r['method']=='GET'))
            extra.update(selected=True,dispatch_eligible=True)
            wordlist['selected_ids'].append(extra['endpoint_id'])
        summary=self.dispatch()
        self.assertEqual(summary['counts']['attempted'],3)
        self.assertEqual(summary['counts']['unattempted'],3)
        self.assertEqual({r.get('rejection_reason') for r in self.records() if not r['attempted']},
                         {'method_unknown','method_not_read_only','scope_denied'})

    def test_missing_required_credential_fails_closed_before_attempt(self):
        self.prepare()
        policy=OriginScopePolicy(self.config)
        self.transport=OriginScopedTransport(self.a,policy=policy,credentials=OriginCredentialContext(policy))
        summary=self.dispatch()
        self.assertTrue(all(not r['attempted'] for r in self.records() if r['origin']==self.a))
        self.assertGreater(summary['counts']['responses'],0)

    def test_candidate_headers_and_body_cannot_override_credentials(self):
        self.prepare()
        for origin in (self.a,self.b):
            for row in self.selected(origin):
                row.update(headers={'Authorization':'Bearer b31-injected-secret','Cookie':'b31-injected-cookie'},body='write request')
        summary=self.dispatch()
        self.assertEqual(summary['counts']['attempted'],3)
        self.assertNotIn('b31-injected-secret',json.dumps(self.dispatch_runs[-1]))

    def test_policy_changed_after_selection_is_rechecked(self):
        self.prepare()
        self.state['origin_policies'][self.a]['rules']=[]
        summary=self.dispatch()
        self.assertEqual(summary['counts']['attempted'],0)
        self.assertEqual(summary['counts']['errors'],0)
        self.assertEqual(self.runtime.requests,4)

    def test_deadline_stops_every_origin_before_dispatch(self):
        self.prepare()
        self.scenario['deadline_shortened_for_test']=True
        self.runtime.deadline=time.monotonic()+.02
        time.sleep(.03)
        summary=self.dispatch()
        self.assertEqual(summary['stop_reason'],'pipeline_deadline')
        self.assertEqual(summary['counts']['attempted'],0)

    def test_rate_limit_is_shared_across_recon_and_both_origins(self):
        self.prepare();self.dispatch()
        times=[r['reserved_at_monotonic'] for r in self.runtime.origin_reservations]
        self.assertEqual(len(times),7)
        self.assertTrue(all(b-a>=.099 for a,b in zip(times,times[1:])))
        arrivals=sorted(r['received_at_monotonic'] for s in self.servers for r in s.access)
        self.assertTrue(all(received>=reserved for received,reserved in zip(arrivals,times)))

    def tearDown(self):
        failed=any(test is self for test,_ in self._outcome.result.failures+self._outcome.result.errors)
        evidence={'diagnostic_id':self.case_id,'test':self.id().replace('.', '::'),'started_at_utc':self.started,
            'finished_at_utc':datetime.now(timezone.utc).isoformat(),'test_outcome':'PASS' if self.verified and not failed else 'FAIL',
            'config':self.config,'limits':self.limits,'plan':self.plan,'servers':{s.role:s.origin for s in self.servers},
            'agent1_result':self.result,'agent2_results':self.generation_runs,
            'state_before_agent2':self.context_before,'state_after_agent2':getattr(self,'selection_state',None),
            'state_before_dispatch':self.dispatch_before,'runtime_before_dispatch':self.runtime_before,
            'http_before_dispatch':self.http_before_dispatch,'dispatch_runs':self.dispatch_runs,
            'runtime':self.runtime.snapshot(),'telemetry':self.telemetry.snapshot(),'scenario':self.scenario,
            'mock_llm_invocations':self.llm.invoke.call_count+self.agent2_llm.invoke.call_count+self.agent3_llm.invoke.call_count,
            'live_verification':'not_verified','pipeline_gate':'not_enabled_b1'}
        for server in self.servers:
            (self.directory/(server.role+'_access.json')).write_text(json.dumps(server.access,indent=2),encoding='utf-8')
            served={r['path'] for r in server.access if r.get('phase')=='recon' and r['status']==200}
            (self.directory/(server.role+'_served.json')).write_text(json.dumps({server.origin+p:server.documents[p][0] for p in served},indent=2),encoding='utf-8')
        # Transport redaction includes the original fixture credentials even in the missing-binding case.
        from src.coordinator.llm_logging import sanitize_for_log
        public=sanitize_for_log({'credentials':[b21.AUTH,b21.COOKIE],'payload':evidence})['payload']
        self.assertEqual(public['test'],evidence['test'])
        (self.directory/'evidence.json').write_text(json.dumps(public,indent=2),encoding='utf-8')

