"""B3.1 independent stdlib verifier. No dispatcher imports, HTTP or provider calls.

python -B scripts/verify_origin_dispatch_evidence.py CASE_ROOT
--negative-checks also corrupts temporary copies; originals are never modified.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime,timezone
import json
from pathlib import Path
import shutil
import sys
import tempfile
from urllib.parse import urlsplit

from verify_origin_wordlist_evidence import read,verify_observation,scope_allowed


def counts(records):
    return {'selected':len(records),'attempted':sum(r['attempted'] for r in records),
        'responses':sum(r['status_code'] is not None for r in records),
        'errors':sum(r['attempted'] and r['error'] is not None for r in records),
        'unattempted':sum(not r['attempted'] for r in records),
        'timeouts':sum(r.get('timeout',False) for r in records)}


def outcome(records,global_reason=None):
    c=counts(records)
    reasons=[r['stop_reason'] for r in records if r['stop_reason']]
    assert 'pending' not in reasons, 'Final ledger contains unfinished records'
    if not records:return 'skipped'
    if c['attempted']==c['selected'] and c['responses']==c['attempted'] and not c['errors'] and not reasons and not global_reason:
        return 'completed'
    return 'partial' if c['responses'] else 'failed'


def verify_case(directory):
    data=read(directory/'evidence.json')
    assert data['test_outcome']=='PASS', 'Integration test failed'
    assert data['mock_llm_invocations']==0
    logs={role:read(directory/(role+'_access.json')) for role in data['servers']}
    assert not logs['unapproved'], 'Unapproved origin received HTTP'
    bodies={url:body for role in logs for url,body in read(directory/(role+'_served.json')).items()}
    all_events=[r for events in logs.values() for r in events]
    before=data['http_before_dispatch']
    recon_events=[r for r in all_events if r.get('phase')=='recon']
    sent_events=[r for r in all_events if r.get('phase')=='dispatch']
    assert Counter((r['origin'],r['path'],r['method']) for r in recon_events)==Counter((r['origin'],r['path'],r['method']) for events in before for r in events)
    for role,events in logs.items():
        assert all(r['credential_identity']==('frontend' if role=='frontend' else 'anonymous') for r in events)
        assert all(r['method'] in ('GET','HEAD') for r in events)
    execution=data['agent1_result']['execution']
    assert Counter((r['url'],r['method'],r['status_code']) for r in execution['requests'] if r['attempted'])==Counter((r['origin']+r['path'],r['method'],r['status']) for r in recon_events)
    for observation in data['agent1_result']['discovery_context']['observations']:
        verify_observation(observation,bodies,data['state_before_agent2']['target_url'])
    initial=data['state_after_agent2']
    originals={r['endpoint_id']:r for entry in initial['origin_contexts'].values() for r in entry['endpoints']}
    selections={r['endpoint_id']:r for entry in initial['origin_contexts'].values() for r in entry['context']['wordlist']['candidates']}
    for run in data['agent2_results']:
        assert read(run['artifacts']['result'])==run
        for entry in run['origin_contexts'].values():
            for candidate in entry['context']['wordlist']['candidates']:
                if candidate['selected']:
                    original=originals[candidate['endpoint_id']]
                    assert all(candidate[k]==original[k] for k in ('origin','url','method','evidence_refs','provenance'))
                    assert candidate['attempted'] is None and candidate['verified'] is None
    assert data['dispatch_runs'], 'No Agent 3 artifact'
    last=data['dispatch_runs'][-1]
    for run in data['dispatch_runs']:
        assert read(run['artifacts']['result'])==run, 'Result differs from recorded state'
        checkpoint=read(run['artifacts']['checkpoint'])
        assert checkpoint==run, 'Checkpoint differs from result'
        assert run['origin_execution_mode']=='not_enabled_b1'
        for key in ('approved_origins','origin_policies','discovered_origins'):
            assert run[key]==data['state_before_dispatch'][key]
    all_records=[]
    per_origin={}
    for origin,entry in last['origin_contexts'].items():
        dispatch=entry['context']['http_dispatch']
        records=dispatch['records']
        assert len(records)==len({r['candidate_id'] for r in records})
        selected_ids=set(data['state_before_dispatch']['origin_contexts'][origin]['context']['wordlist']['selected_ids'])
        assert {r['candidate_id'] for r in records}==selected_ids
        assert dispatch['counts']==counts(records)
        assert dispatch['status']==outcome(records)
        assert entry['endpoints']==data['state_before_dispatch']['origin_contexts'][origin]['endpoints']
        assert entry['agent_statuses']['param_disc']==data['state_before_dispatch']['origin_contexts'][origin]['agent_statuses']['param_disc']
        assert entry['agent_statuses']['soft404_filter']==data['state_before_dispatch']['origin_contexts'][origin]['agent_statuses']['soft404_filter']
        for r in records:
            assert r['origin']==origin
            assert r['planned_test_method'] is None and r['verified'] is None and r['verification_status']=='not_verified'
            if r['attempted']:
                source=originals[r['candidate_id']]
                selected=selections[r['candidate_id']]
                assert selected['selected'] and not selected['generated'] and selected['observed']
                assert r['url']==source['url'] and r['evidence_refs']==source['evidence_refs']
                assert r['execution_method']==r['observed_method']==source['method']
                assert scope_allowed({'origin':origin,'url':r['url'],'method':r['execution_method']},data['config'])
                if r['status_code'] is not None: assert r['classification']=='observed_response'
                else: assert r['error'] is not None and r['classification'] is None
            else:
                assert r['status_code'] is None and r['execution_method'] is None
                assert r['bytes_received']==0 and r['stop_reason']
        per_origin[origin]={'counts':dispatch['counts'],'status':dispatch['status'],'stop_reason':dispatch['stop_reason'],
                            'budget_used':dispatch['origin_budget_used'],'budget_limit':dispatch['origin_budget_limit']}
        all_records.extend(records)
    summary=last['fuzzing_execution']['multi_origin']
    runtime=data['runtime']
    before_runtime=data['runtime_before_dispatch']
    assert summary['counts']==counts(all_records)
    assert summary['status']==outcome(all_records,runtime['stop_reason'])
    assert summary['completed']==(summary['status']=='completed') and not summary['full_multi_origin_execution_enabled']
    attempts=[r for r in all_records if r['attempted']]
    assert len(attempts)==len({(r['url'],r['execution_method']) for r in attempts}), 'Duplicate dispatch'
    assert runtime['http_dispatches']==before_runtime['http_dispatches']+len(attempts)==data['telemetry']['http']['known_requests']
    assert runtime['http_dispatches']<=data['limits']['http_max_requests']
    reservations=runtime['origin_reservations']
    assert len(reservations)==runtime['http_dispatches']
    assert [r['sequence'] for r in reservations]==list(range(1,len(reservations)+1))
    interval=1/data['limits']['http_rate_limit']
    assert all(b['reserved_at_monotonic']-a['reserved_at_monotonic']>=interval-.001 for a,b in zip(reservations,reservations[1:])), 'Global rate limit violated'
    for origin,used in runtime['http_dispatches_by_origin'].items():
        expected=sum(r['origin']==origin for r in recon_events)+sum(r['origin']==origin for r in attempts)
        assert used==expected==sum(r['origin']==origin for r in reservations)
        assert used<=runtime['http_origin_max_requests'][origin]
        assert per_origin[origin]['budget_used']==used
    received=Counter((r['origin']+r['path'],r['method']) for r in sent_events)
    accounted_before_server=0
    for r in attempts:
        key=(r['url'],r['execution_method'])
        reservation=reservations[r['runtime_sequence']-1]
        assert reservation['origin']==r['origin']
        if received[key]:
            assert received[key]==1
            server=next(e for e in sent_events if (e['origin']+e['path'],e['method'])==key)
            assert server['received_at_monotonic']>=reservation['reserved_at_monotonic']
            assert r['status_code']==server['status']
            if server['fault']=='timeout': assert r['timeout'] and r['status_code'] is None
            received[key]-=1
        else:
            assert data['scenario'].get('unreachable_origin')==r['origin']
            assert data['scenario']['socket_bound_then_closed'] and data['scenario']['no_listener_created']
            assert r['status_code'] is None and r['error']['error_type']=='transport_error'
            accounted_before_server+=1
    assert not any(received.values()), 'Server received unaccounted request'
    assert len(attempts)==len(sent_events)+accounted_before_server
    restrictions=[r for r in attempts if r['stop_reason'] in {'http_401','http_403','http_407','http_429','retry_after'}]
    if restrictions:
        stop=min(r['runtime_sequence'] for r in restrictions)
        assert not any(r['runtime_sequence']>stop for r in attempts), 'Dispatch continued after global restriction'
    if data['scenario'].get('deadline_shortened_for_test'):
        assert runtime['stop_reason']=='pipeline_deadline' and not attempts
    for candidate in [r for e in last['origin_contexts'].values() for r in e['context']['wordlist']['candidates']]:
        if candidate.get('generated'): assert candidate['attempted'] is None
        assert candidate['verified'] is None
    for file in directory.rglob('*.json'):
        rendered=file.read_text(encoding='utf-8')
        for secret in ('b21-only-local-fake-token','b21-only-local-fake-cookie','b31-injected-secret','b31-injected-cookie'):
            assert secret not in rendered,'Credential leaked'
    return {'diagnostic_id':data['diagnostic_id'],'test':data['test'],'result':'PASS',
        'counts':summary['counts'],'status':summary['status'],'stop_reason':summary['stop_reason'],
        'per_origin':per_origin,'global_budget_used':runtime['http_dispatches'],'global_budget_limit':runtime['http_max_requests'],
        'recon_attempts':before_runtime['http_dispatches'],'server_dispatch_arrivals':len(sent_events),
        'failures_before_server':accounted_before_server,'mock_llm_invocations':data['mock_llm_invocations']}


def negative_checks(source):
    def transform(value,old,new,mutation):
        if isinstance(value,dict):
            result={k:transform(v,old,new,mutation) for k,v in value.items()}
            if result.get('attempted') is True and 'candidate_id' in result:
                if mutation=='method':result['execution_method']='POST'
                if mutation=='status' and result.get('status_code')==200:result['status_code']=201
            if mutation=='counts' and set(result)=={'selected','attempted','responses','errors','unattempted','timeouts'}:
                result['attempted']+=1
            return result
        if isinstance(value,list):return [transform(v,old,new,mutation) for v in value]
        if isinstance(value,str):return value.replace(old,new)
        return value
    checked=[]
    for mutation in ('method','status','counts','unapproved_access'):
        with tempfile.TemporaryDirectory(prefix='b31_verifier_negative_') as temporary:
            copied=Path(temporary)/'case';shutil.copytree(source,copied)
            for file in copied.rglob('*.json'):
                value=transform(read(file),str(source.resolve()),str(copied.resolve()),mutation)
                file.write_text(json.dumps(value),encoding='utf-8')
            if mutation=='unapproved_access':
                (copied/'unapproved_access.json').write_text('[{"method":"GET","path":"/fake"}]')
            try:
                verify_case(copied)
            except AssertionError:
                checked.append({'mutation':mutation,'result':'rejected_as_expected'})
            else:
                raise AssertionError('Verifier accepted corrupt evidence: '+mutation)
    return checked


def main():
    root=Path(sys.argv[1])
    directories=sorted(p.parent for p in root.glob('b31_*/evidence.json'))
    if not directories:raise SystemExit('No B3.1 HTTP evidence found')
    cases=[verify_case(directory) for directory in directories]
    report={'checked_at_utc':datetime.now(timezone.utc).isoformat(),'cases':cases,
        'agent3_attempts':sum(c['counts']['attempted'] for c in cases),
        'agent3_responses':sum(c['counts']['responses'] for c in cases),
        'recon_attempts':sum(c['recon_attempts'] for c in cases),
        'server_dispatch_arrivals':sum(c['server_dispatch_arrivals'] for c in cases),
        'failures_before_server':sum(c['failures_before_server'] for c in cases),
        'mock_llm_invocations':0,'verification_level':'integration_verified','live_verification':'not_verified'}
    if '--negative-checks' in sys.argv:
        source=next((d for d in directories if 'test_real_agent_chain' in read(d/'evidence.json')['test']), None)
        if source is None:
            # Earlier logs redacted dotted unittest IDs as JWT-shaped strings.
            # Their HTTP evidence remains usable; select by actual measured outcome.
            candidate=next(c for c in cases if c['status']=='completed' and c['counts']['responses']==3)
            source=next(d for d in directories if read(d/'evidence.json')['diagnostic_id']==candidate['diagnostic_id'])
        report['negative_checks']=negative_checks(source)
    (root/'independent_verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'}))


if __name__=='__main__':main()
