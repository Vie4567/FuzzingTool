"""Real compiled graph in killed/restarted subprocesses; independent HTTP servers."""
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Event, Lock, Thread
import time
import unittest
from uuid import uuid4


def utc(): return datetime.now(timezone.utc).isoformat()
def write(path, value): path.write_text(json.dumps(value, indent=2), encoding='utf-8')
def read(path): return json.loads(path.read_text(encoding='utf-8'))


class RecoveryHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        server = self.server
        body, mime = server.documents.get(self.path, ('{"observed":true}', 'application/json'))
        raw = body.encode()
        fault = server.faults.get(self.path)
        status = fault if isinstance(fault, int) else 200
        auth, cookie = self.headers.get('Authorization'), self.headers.get('Cookie')
        row = {'utc': utc(), 'monotonic': time.monotonic(), 'server_pid': os.getpid(),
            'origin': server.origin, 'path': self.path, 'method': self.command, 'status': status,
            'credential_identity': 'frontend' if (auth, cookie) == ('Bearer b32b-local-only-fake', 'sid=b32b-local-only-fake')
                else 'anonymous' if auth is None and cookie is None else 'unexpected',
            'body_sha256': sha256(raw).hexdigest(), 'phase': 'recon' if self.path in server.documents else 'fuzzing',
            'fault': fault}
        with server.lock:
            server.access.append(row)
            with open(server.access_path, 'a', encoding='utf-8') as log:
                log.write(json.dumps(row)+'\n'); log.flush(); os.fsync(log.fileno())
        if fault == 'before_headers':
            server.arrived.set(); server.release.wait(30)
        try:
            self.send_response(status); self.send_header('Content-Type', mime)
            if fault == 'retry_after': self.send_header('Retry-After', '30')
            self.send_header('Content-Length', str(len(raw))); self.end_headers()
            if fault == 'body':
                self.wfile.write(raw[:1]); self.wfile.flush()
                server.arrived.set(); server.release.wait(30)
                self.wfile.write(raw[1:])
            else: self.wfile.write(raw)
        except (OSError, ConnectionError): pass


class OriginRecoveryHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        for role in ('frontend', 'gateway', 'unapproved'):
            server = ThreadingHTTPServer(('127.0.0.1', 0), RecoveryHandler)
            server.daemon_threads = True
            server.role, server.origin = role, f'http://127.0.0.1:{server.server_port}'
            server.lock = Lock()
            worker = Thread(target=server.serve_forever, daemon=True); worker.start()
            cls.servers.append(server)
        cls.a, cls.b, cls.c = [s.origin for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers: server.shutdown(); server.server_close()

    def setUp(self):
        base = os.getenv('B32B_EVIDENCE_DIR')
        if not base:
            tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); base = tmp.name
        self.directory = Path(base).resolve()/('b32b_'+uuid4().hex[:10]); self.directory.mkdir(parents=True)
        self.processes, self.process_events = [], []
        self.test_started = utc()
        for server in self.servers:
            server.access, server.documents, server.faults = [], {}, {}
            server.access_path = self.directory/(server.role+'_access.jsonl'); server.access_path.touch()
            server.arrived, server.release = Event(), Event()
        self.servers[0].documents = {'/': ('<script src="/app.js"></script>', 'text/html'),
            '/app.js': ('\n'.join(['fetch("/a", {method:"GET"});', 'fetch("/b", {method:"GET"});',
                f'fetch("{self.b}/users", {{method:"GET"}});', f'fetch("{self.c}/private", {{method:"GET"}});']), 'application/javascript')}
        self.servers[1].documents = {'/openapi.json': (json.dumps({'openapi':'3.0.0', 'servers':[{'url':self.b}],
            'paths':{'/users':{'get':{}}}}), 'application/json')}
        def rules(paths): return [{'path':p, 'methods':['GET'], 'operation':'read_only'} for p in paths]
        scope = {'approved_origins':[self.a,self.b], 'origin_policies':{
            self.a:{'credential_profile':'frontend','rules':rules(['/','/app.js','/a','/b'])},
            self.b:{'rules':rules(['/openapi.json','/users'])}}}
        self.settings = {'target': self.a+'/', 'documents':[{'url':self.a+'/', 'kind':'html'},
            {'url':self.a+'/app.js','kind':'javascript'},{'url':self.b+'/openapi.json','kind':'openapi'}],
            'quotas':{self.a:5,self.b:3}, 'config':{'multi_origin':scope, 'fuzzing_options':{'engine':'python_http'},
            'max_retries':0,'max_wordlist_entries':3,'http_max_requests':8,'http_rate_limit':20,
            'http_timeout_seconds':3,'pipeline_timeout_seconds':120,'artifact_root':str(self.directory),'max_llm_calls':1}}
        self.original_settings = deepcopy(self.settings)
        self.crash_event = None
        self.expect_denied = False
        self.result = None

    def worker(self, mode='start', label='first'):
        path = self.directory/(label+'_config.json'); write(path, self.settings)
        stream = open(self.directory/(label+'_stdout.log'),'w',encoding='utf-8')
        command = [sys.executable,'-B',str(Path(__file__).with_name('origin_recovery_worker.py')),str(path),mode,label]
        proc = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, cwd=Path(__file__).resolve().parents[1])
        self.processes.append((proc,stream))
        self.process_events.append({'pid':proc.pid,'mode':mode,'label':label,'command':command,'started_utc':utc()})
        return proc

    def wait_file(self, path, proc, seconds=25):
        deadline = time.monotonic()+seconds
        while not path.exists() and time.monotonic()<deadline:
            if proc.poll() is not None: break
            time.sleep(.03)
        self.assertTrue(path.exists(), f'Missing {path.name}; child={proc.poll()}; see {self.directory}')

    def terminate(self, proc):
        proc.kill(); proc.wait(timeout=10)  # Actual TerminateProcess/SIGKILL, no mocked exception.
        self.process_events.append({'pid':proc.pid,'hard_killed_utc':utc(),'exit_code':proc.returncode})
        shutil.copytree(self.directory/'recovery',self.directory/'before',dirs_exist_ok=True)
        saved=self.directory/'before_checkpoints';saved.mkdir(exist_ok=True)
        for row in (json.loads(line) for line in (self.directory/'before/journal.jsonl').read_text().splitlines()):
            if row['event']=='checkpoint':
                shutil.copyfile(row['payload']['path'],saved/(row['payload']['sha256']+'.json'))
        write(self.directory/'access_before.json',{s.role:deepcopy(s.access) for s in self.servers})

    def crash(self, event, match=None, candidate_only=False):
        self.settings['barrier']={'event':event,'match':match or {},'candidate_only':candidate_only}
        self.crash_event=event
        proc=self.worker(); self.wait_file(self.directory/'first_barrier.json',proc)
        self.terminate(proc)

    def resume(self, label='resume'):
        proc=self.worker('resume',label);proc.wait(timeout=30)
        self.assertEqual(proc.returncode,0)
        path=self.directory/(label+'_result.json')
        self.result=read(path) if path.exists() else read(self.directory/(label+'_denied.json'))
        return self.result

    def success_checks(self, *, unknown=0):
        self.assertEqual(len(self.servers[2].access),0)
        self.assertTrue(all(r['credential_identity']=='anonymous' for r in self.servers[1].access))
        self.assertEqual(self.result['runtime']['http_dispatches'],6)
        self.assertEqual(self.result['runtime']['http_dispatches_by_origin'],{self.a:4,self.b:2})
        self.assertNotEqual(self.result['pipeline_status'],'completed')
        self.assertFalse(self.result['all_modules_executed']); self.assertFalse(self.result['all_modules_successful'])
        self.assertEqual(self.result['agent_statuses']['param_disc'],'skipped')
        self.assertEqual(self.result['agent_statuses']['soft404_filter'],'skipped')
        self.assertEqual(len(self.result['recovery']['outcome_unknown_sequences']),unknown)
        self.assertEqual(self.result['agent_attempts'],{'tech_recon':1,'wordlist_gen':1,'fuzzing':1})
        self.assertEqual(self.result['llm_call_count'],0)
        for s in self.servers:
            keys=[(r['path'],r['method']) for r in s.access]
            self.assertEqual(len(keys),len(set(keys)))
        self.assertTrue({'run_tech_recon','run_wordlist_gen'} <= set(self.result['recovery']['reused_nodes']))

    def deny_checks(self):
        self.expect_denied=True
        before=read(self.directory/'access_before.json')
        self.assertEqual(before,{s.role:s.access for s in self.servers})
        self.assertTrue(self.result.get('pipeline_status')=='failed' or 'reason' in self.result)

    def test_crash_before_reservation_resumes_only_unspent_work(self):
        self.crash('before_reservation',candidate_only=True); self.resume(); self.success_checks()

    def test_crash_after_reservation_keeps_spent_budget_and_unknown(self):
        self.crash('reserved',{'sequence':4}); self.resume(); self.success_checks(unknown=1)
        self.assertEqual(sum(len(s.access) for s in self.servers),5)
        self.assertIsNone(self.result['total_http_requests'])

    def test_crash_after_server_receive_never_replays(self):
        self.servers[0].faults.update({'/a':'before_headers','/b':'before_headers'})
        proc=self.worker();self.assertTrue(self.servers[0].arrived.wait(25));self.crash_event='server_received'
        self.terminate(proc);self.servers[0].release.set()
        self.resume();self.success_checks(unknown=1)

    def test_crash_after_response_headers_preserves_status_not_body(self):
        self.crash('response_headers',{'sequence':4});self.resume();self.success_checks(unknown=1)

    def test_crash_after_measurement_recovers_measured_response(self):
        self.crash('measurement',{'sequence':4});self.resume();self.success_checks()

    def test_crash_after_checkpoint_does_not_execute_completed_agents(self):
        self.crash('checkpoint',{'node':'run_fuzzing','event':'checkpoint'})
        self.resume();self.success_checks()
        self.assertIn('run_fuzzing',self.result['recovery']['reused_nodes'])

    def test_crash_gateway_keeps_completed_frontend(self):
        self.crash('reserved',{'sequence':6});self.resume();self.success_checks(unknown=1)
        rows=self.result['origin_contexts'][self.a]['context']['http_dispatch']['records']
        self.assertEqual([r['status_code'] for r in rows],[200,200])

    def test_crash_mid_body_preserves_unknown_and_no_fabricated_bytes(self):
        self.servers[0].faults.update({'/a':'body','/b':'body'})
        proc=self.worker();self.assertTrue(self.servers[0].arrived.wait(25));self.crash_event='body_streaming'
        # Selection ties depend on endpoint IDs/ports. Stall whichever frontend
        # candidate is first, and wait for both the line AND its durable anchor.
        # Seeing a journal line alone is not a committed event.
        deadline=time.monotonic()+2
        anchored=False
        while time.monotonic()<deadline:
            journal=self.directory/'recovery/journal.jsonl'
            try:
                rows=[json.loads(line) for line in journal.read_text().splitlines()]
                head=read(self.directory/'recovery/head.json')
                last=rows[-1]
                anchored=(last['event']=='response_headers' and last['payload']['sequence']==4 and
                    head=={'seq':last['seq'],'hash':last['hash']})
                if anchored:break
            except (OSError,ValueError,IndexError):pass
            time.sleep(.02)
        self.assertTrue(anchored,'Header event must be durably committed before the body crash')
        self.terminate(proc);self.servers[0].release.set();self.resume();self.success_checks(unknown=1)
        row=next(r for r in self.result['origin_contexts'][self.a]['context']['http_dispatch']['records'] if r.get('recovery_state')=='outcome_unknown')
        self.assertEqual(row['status_code'],200);self.assertIsNone(row['bytes_received'])

    def corrupt_checkpoint(self, kind):
        self.crash('reserved',{'sequence':4})
        rows=[json.loads(line) for line in (self.directory/'recovery/journal.jsonl').read_text().splitlines()]
        entry=next(r for r in reversed(rows) if r['event']=='checkpoint')
        path=Path(entry['payload']['path'])
        if kind=='missing': path.rename(path.with_suffix('.removed'))
        elif kind=='malformed': path.write_text('{',encoding='utf-8')
        else:
            data=read(path);data['runtime']['http_dispatches']=0;write(path,data)
        self.resume();self.deny_checks()

    def test_missing_checkpoint_blocks_resume(self):self.corrupt_checkpoint('missing')
    def test_corrupt_checkpoint_blocks_resume(self):self.corrupt_checkpoint('malformed')
    def test_checkpoint_counter_reduction_blocks_resume(self):self.corrupt_checkpoint('counter')

    def test_truncated_journal_blocks_resume(self):
        self.crash('reserved',{'sequence':4})
        path=self.directory/'recovery/journal.jsonl';path.write_bytes(path.read_bytes()[:-15])
        self.resume();self.deny_checks()

    def test_changed_scope_blocks_resume(self):
        self.crash('reserved',{'sequence':4})
        self.settings['config']['multi_origin']['origin_policies'][self.a]['rules'].pop()
        self.resume();self.deny_checks()

    def test_missing_credentials_blocks_resume(self):
        self.crash('reserved',{'sequence':4});self.settings['missing_profile']=True
        self.resume();self.deny_checks()

    def test_changed_binding_blocks_resume(self):
        self.crash('reserved',{'sequence':4})
        self.settings['config']['multi_origin']['origin_policies'][self.a]['credential_profile']='replacement'
        self.settings['profile_id']='replacement';self.resume();self.deny_checks()

    def test_concurrent_resume_is_exclusively_locked(self):
        self.crash('reserved',{'sequence':4})
        self.settings['resume_barrier']={'event':'process_bound','match':{'resume':True}}
        first=self.worker('resume','owner');self.wait_file(self.directory/'owner_barrier.json',first)
        second=self.worker('resume','contender');second.wait(timeout=30)
        denied=read(self.directory/'contender_result.json')
        self.assertIn('recovery_session_locked',json.dumps(denied))
        (self.directory/'owner_release').touch();first.wait(timeout=30)
        self.result=read(self.directory/'owner_result.json');self.success_checks(unknown=1)

    def stop_case(self, fault):
        self.servers[0].faults.update({'/a':fault,'/b':fault})
        self.crash('stop');self.resume();self.deny_checks()

    def test_restart_after_401_is_blocked(self):self.stop_case(401)
    def test_restart_after_403_is_blocked(self):self.stop_case(403)
    def test_restart_after_407_is_blocked(self):self.stop_case(407)
    def test_restart_after_429_is_blocked(self):self.stop_case(429)
    def test_restart_after_retry_after_is_blocked(self):self.stop_case('retry_after')

    def test_exhausted_budget_is_not_reset(self):
        self.settings['config']['http_max_requests']=4
        self.crash('measurement',{'sequence':4});self.resume();self.deny_checks()

    def test_recon_crash_without_discovery_checkpoint_fails_closed(self):
        self.crash('reserved',{'sequence':1});self.resume();self.deny_checks()

    def test_original_deadline_is_not_restarted(self):
        self.settings['config']['pipeline_timeout_seconds']=8
        self.crash('reserved',{'sequence':4})
        time.sleep(8);self.resume();self.deny_checks()

    def test_stop_headers_alone_block_resume_before_stop_event(self):
        self.servers[0].faults.update({'/a':429,'/b':429})
        self.crash('response_headers',{'sequence':4});self.resume();self.deny_checks()

    def test_resume_after_wordlist_checkpoint_does_not_regenerate(self):
        self.crash('checkpoint',{'node':'run_wordlist_gen','event':'checkpoint'})
        self.resume();self.success_checks()

    def test_origin_quota_remains_spent_after_restart(self):
        self.settings['quotas'][self.a]=3
        self.crash('measurement',{'sequence':4});self.resume()
        self.assertEqual(self.result['runtime']['http_dispatches'],5)
        self.assertEqual(self.result['runtime']['http_dispatches_by_origin'],{self.a:3,self.b:2})
        self.assertEqual(self.result['stop_reason'],'origin_request_budget')
        self.assertEqual(len(self.servers[0].access),3)

    def tearDown(self):
        for server in self.servers: server.release.set()
        for proc, stream in self.processes:
            if proc.poll() is None: proc.kill();proc.wait(timeout=10)
            stream.close()
        write(self.directory/'evidence.json',{'test':self._testMethodName,'utc':self.test_started,
            'directory':str(self.directory),'original_settings':self.original_settings,
            'final_settings':self.settings,'processes':self.process_events,'crash_event':self.crash_event,
            'expect_denied':self.expect_denied,'result':self.result,
            'servers':{s.role:{'origin':s.origin,'access':s.access,'documents':s.documents} for s in self.servers}})
