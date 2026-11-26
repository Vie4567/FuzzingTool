"""Independent B3.2A stdlib verifier: graph callbacks/checkpoints -> HTTP logs.

Does not import Coordinator, Agents, dispatch, runtime or scope implementation.
"""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import tempfile
from urllib.parse import urlsplit

from verify_origin_wordlist_evidence import read, verify_observation, scope_allowed


def counts(rows):
    return {'selected':len(rows),'attempted':sum(r['attempted'] for r in rows),
            'responses':sum(r['status_code'] is not None for r in rows),
            'errors':sum(r['attempted'] and r['error'] is not None for r in rows),
            'unattempted':sum(not r['attempted'] for r in rows),'timeouts':sum(r['timeout'] for r in rows)}


def verify_case(directory):
    data=read(directory/'evidence.json')
    assert data['test_outcome']=='PASS'
    assert data['llm_calls']==data['mock_llm_decisions']==0
    access={role:read(directory/(role+'_access.json')) for role in data['servers']}
    assert not access['unapproved'], 'Unapproved access'
    for role,events in access.items():
        assert all(e['credential_identity']==('frontend' if role=='frontend' else 'anonymous') for e in events)
        assert all(e['method']=='GET' for e in events)
    events=[e for rows in access.values() for e in rows]
    for result in data['results']:
        assert read(result['artifacts']['result'])==result
        assert read(result['artifacts']['checkpoint'])==result
        assert result['pipeline_status']!='completed'
        assert not result.get('all_modules_executed') and not result.get('all_modules_successful')
        assert result['llm_call_count']==0
    primary=next((r for r in data['results'] if 'local_origin_execution' in r),None)
    if primary is None:
        assert not data['agent_calls'] and not events
        assert data['results'][-1]['stop_reason']=='multi_origin_execution_not_enabled_b1'
        return {'test':data['test'],'diagnostic_id':data['diagnostic_id'],'result':'PASS',
                'http_attempts':0,'responses':0,'mode':'production_gate_denied'}
    assert data['graph_topology']['compiled_type']=='CompiledStateGraph'
    assert set(data['graph_topology']['nodes'])=={'validate_input','init_state','tech_recon','gen_words','fuzzing',
        'param_disc','filter_404','report','reflection','llm_decide_recon','llm_decide_wordlist','llm_decide_fuzzing'}
    calls=data['agent_calls']
    assert [c['agent'] for c in calls] in (['tech_recon'],['tech_recon','wordlist_gen'],['tech_recon','wordlist_gen','fuzzing'])
    assert len({c['runtime_instance'] for c in calls})==1, 'Runtime replaced'
    local=primary['local_origin_execution']
    assert primary['origin_execution_mode']=='not_enabled_b1' and not local['full_pipeline_enabled']
    assert primary['approved_origins']==data['config']['multi_origin']['approved_origins']
    assert local['llm_mode']=='disabled_deterministic_routing'
    assert all(d['source']=='deterministic_local_test_policy' and not d['llm_called'] for d in primary['decision_chain'])
    expected=['validate_input','init_state','tech_recon','llm_decide_recon']
    if len(calls)>1:expected+=['gen_words','llm_decide_wordlist']
    if len(calls)>2:expected+=['fuzzing','llm_decide_fuzzing']
    expected+=['report','reflection']
    trace=local['langgraph_trace']
    assert [e['node'] for e in trace if e['event']=='start']==expected
    assert [e['node'] for e in trace if e['event']=='end']==expected
    assert len(trace)==2*len(expected)
    assert all(e['runtime_id']==local['runtime_id'] for e in trace)
    assert all(a['http_dispatches']<=b['http_dispatches'] for a,b in zip(trace,trace[1:]))
    assert primary['agent_attempts']=={c['agent']:1 for c in calls}
    assert all(primary['retry_counts'][c['agent']]==0 for c in calls)
    assert primary['agent_statuses']['param_disc']==primary['agent_statuses']['soft404_filter']=='skipped'
    bodies={url:body for role in access for url,body in read(directory/(role+'_served.json')).items()}
    recon=calls[0]['output']
    for row in recon['discovery_context']['observations']:
        verify_observation(row,bodies,recon['target_url'])
    recon_events=[e for e in events if e['phase']=='recon']
    dispatch_events=[e for e in events if e['phase']=='dispatch']
    assert Counter((r['url'],r['method'],r['status_code']) for r in recon['execution']['requests'] if r['attempted'])==Counter(
        (e['origin']+e['path'],e['method'],e['status']) for e in recon_events)
    for e in recon_events:
        assert e['origin']+e['path'] in [p['url'] for p in data['documents']], 'Unplanned Recon URL'
    assert primary['recon_execution']==recon['execution']
    expected_recon_status='success' if recon['execution']['status']=='completed' else recon['execution']['status']
    assert primary['agent_statuses']['tech_recon']==expected_recon_status
    checkpoints=[read(p) for p in sorted((Path(primary['artifacts']['directory'])/'checkpoints').glob('*.json'))]
    for checkpoint in checkpoints:
        assert not checkpoint.get('all_modules_executed') and not checkpoint.get('all_modules_successful')
        assert checkpoint.get('pipeline_status')!='completed'
    nodes={'tech_recon':'run_tech_recon','wordlist_gen':'run_wordlist_gen','fuzzing':'run_fuzzing'}
    for call in calls:
        agent=call['agent'];node=nodes[agent]
        graph_node={'tech_recon':'tech_recon','wordlist_gen':'gen_words','fuzzing':'fuzzing'}[agent]
        assert next(e for e in trace if e['node']==graph_node and e['event']=='start')['http_dispatches']==call['before_runtime']['http_dispatches']
        assert next(e for e in trace if e['node']==graph_node and e['event']=='end')['http_dispatches']==call['after_runtime']['http_dispatches']
        before=[c for c in checkpoints if c['artifacts']['node']==node and c['artifacts']['event']=='started']
        after=[c for c in checkpoints if c['artifacts']['node']==node and c['artifacts']['event']=='checkpoint']
        assert len(before)==len(after)==1, 'Missing/duplicate node checkpoint'
        end=after[0]
        assert end['runtime']['http_dispatches']==call['after_runtime']['http_dispatches']
        if agent=='tech_recon':assert end['recon_execution']==call['output']['execution']
        if agent=='wordlist_gen':
            assert read(call['output']['artifacts']['result'])==call['output']
            assert end['wordlist_metadata']['multi_origin']==call['output']['wordlist_metadata']['multi_origin']
            assert call['before_runtime']['http_dispatches']==call['after_runtime']['http_dispatches']
            assert call['input_state']['recon_execution']==recon['execution']
        if agent=='fuzzing':
            for origin,entry in end['origin_contexts'].items():
                assert entry['context']['http_dispatch']==primary['origin_contexts'][origin]['context']['http_dispatch']
    ledger=[]
    per_origin={}
    if len(calls)==3:
        word=calls[1]['output'];fuzz=calls[2]
        assert read(word['artifacts']['result'])==word
        assert read(fuzz['output']['artifacts']['result'])==fuzz['output']
        assert read(fuzz['output']['artifacts']['checkpoint'])==fuzz['output']
        observations={r['endpoint_id']:r for e in calls[1]['input_state']['origin_contexts'].values() for r in e['endpoints']}
        selected={r['endpoint_id']:r for e in word['origin_contexts'].values() for r in e['context']['wordlist']['candidates'] if r['selected']}
        for origin,entry in primary['origin_contexts'].items():
            dispatch=entry['context']['http_dispatch'];rows=dispatch['records']
            assert dispatch['counts']==counts(rows)
            assert len(rows)==len({r['candidate_id'] for r in rows})
            assert {r['candidate_id'] for r in rows}==set(fuzz['input_state']['origin_contexts'][origin]['context']['wordlist']['selected_ids'])
            for row in rows:
                assert row['origin']==origin, 'Wrong ledger origin'
                assert row['verified'] is None and row['planned_test_method'] is None
                assert row['verification_status']=='not_verified'
                if row['attempted']:
                    source=observations[row['candidate_id']];candidate=selected[row['candidate_id']]
                    assert row['url']==candidate['url']==source['url']
                    assert row['origin']==candidate['origin']==source['origin']
                    assert row['observed_method']==row['execution_method']==candidate['method']==source['method']
                    assert row['evidence_refs']==candidate['evidence_refs']==source['evidence_refs']
                    assert candidate['provenance']==source['provenance']
                    assert scope_allowed({'origin':origin,'url':row['url'],'method':row['execution_method']},data['config']['multi_origin'])
                    assert scope_allowed({'origin':origin,'url':row['url'],'method':row['execution_method']},primary)
                else:assert row['status_code'] is None and row['execution_method'] is None
            per_origin[origin]={'counts':counts(rows),'status':dispatch['status'],
                'agent_statuses':entry['agent_statuses'],'budget_used':dispatch['origin_budget_used'],
                'budget_limit':dispatch['origin_budget_limit']}
            ledger.extend(rows)
        summary=primary['fuzzing_execution']['multi_origin']
        assert summary['counts']==counts(ledger)
        expected_status='success' if summary['completed'] else summary['status']
        assert primary['agent_statuses']['fuzzing']==expected_status, 'False Agent 3 status'
    else:
        assert not dispatch_events and primary['agent_statuses']['fuzzing']=='skipped'
    assert primary['agent_statuses']['wordlist_gen']==('success' if len(calls)>1 else 'skipped')
    attempts=[r for r in ledger if r['attempted']]
    assert len(attempts)==len({(r['url'],r['execution_method']) for r in attempts})
    assert Counter((r['url'],r['execution_method'],r['status_code']) for r in attempts)==Counter(
        (e['origin']+e['path'],e['method'],e['status']) for e in dispatch_events), 'Ledger/server request mismatch'
    runtime=primary['runtime']
    assert runtime['http_dispatches']==len(events)==primary['total_http_requests']==primary['telemetry']['http']['known_requests']
    assert runtime['http_dispatches']<=data['config']['http_max_requests']
    for origin,used in runtime['http_dispatches_by_origin'].items():
        assert used==sum(e['origin']==origin for e in events)
        assert used<=data['origin_quotas'][origin]
        if origin in per_origin:
            assert per_origin[origin]['budget_used']==used
            assert per_origin[origin]['budget_limit']==data['origin_quotas'][origin]
    reservations=runtime['origin_reservations']
    assert [r['sequence'] for r in reservations]==list(range(1,len(events)+1))
    assert all(b['reserved_at_monotonic']-a['reserved_at_monotonic']>=1/data['config']['http_rate_limit']-1e-7
               for a,b in zip(reservations,reservations[1:])), 'Early rate slot'
    for row in attempts:
        assert reservations[row['runtime_sequence']-1]['origin']==row['origin']
    if data.get('denied_resume'):
        denied=data['denied_resume']
        assert denied['agent_statuses']['validate']=='failed'
        assert denied['stop_reason']=='multi_origin_execution_not_enabled_b1'
    stop_indices=[i for i,e in enumerate(sorted(events,key=lambda e:e['received_at_monotonic']))
        if e['status'] in (401,403,407,429) or e.get('fault')=='retry_after']
    if stop_indices:assert min(stop_indices)==len(events)-1, 'Request after global stop'
    assert local['status']==('completed' if len(calls)==3 and all(primary['agent_statuses'][k]=='success' for k in nodes) else 'partial' if any(e['status'] is not None for e in events) else 'failed')
    for file in directory.rglob('*.json'):
        text=file.read_text(encoding='utf-8')
        assert 'b21-only-local-fake-token' not in text and 'b21-only-local-fake-cookie' not in text
    return {'test':data['test'],'diagnostic_id':data['diagnostic_id'],'result':'PASS',
        'http_attempts':len(events),'responses':sum(e['status'] is not None for e in events),
        'recon_attempts':len(recon_events),
        'selected_candidates':primary.get('wordlist_metadata',{}).get('multi_origin',{}).get('selected_count'),
        'dispatch':counts(ledger) if len(calls)==3 else None,'per_origin':per_origin,
        'pipeline_status':primary['pipeline_status'],'local_status':local['status'],'stop_reason':primary['stop_reason'],
        'graph_nodes_executed':expected}


def negative_checks(source):
    def mutate(value,old,new,kind):
        if isinstance(value,dict):
            result={k:mutate(v,old,new,kind) for k,v in value.items()}
            if kind=='agent_status' and 'agent_statuses' in result and result['agent_statuses'].get('fuzzing')=='success':
                result['agent_statuses']['fuzzing']='skipped'
            if kind=='origin' and 'candidate_id' in result and result.get('attempted'):
                result['origin']='http://127.0.0.1:1'
            return result
        if isinstance(value,list):return [mutate(v,old,new,kind) for v in value]
        if isinstance(value,str):return value.replace(old,new)
        return value
    reports=[]
    for kind in ('agent_status','origin','missing_request','duplicate_request'):
        with tempfile.TemporaryDirectory(prefix='b32a_negative_') as temporary:
            copy=Path(temporary)/'case';shutil.copytree(source,copy)
            for file in copy.rglob('*.json'):
                file.write_text(json.dumps(mutate(read(file),str(source.resolve()),str(copy.resolve()),kind)),encoding='utf-8')
            if kind in ('missing_request','duplicate_request'):
                path=copy/'frontend_access.json';rows=read(path)
                index=next(i for i,r in enumerate(rows) if r['phase']=='dispatch')
                if kind=='missing_request':rows.pop(index)
                else:rows.append(rows[index])
                path.write_text(json.dumps(rows),encoding='utf-8')
            try:verify_case(copy)
            except AssertionError:reports.append({'mutation':kind,'result':'rejected_as_expected'})
            else:raise AssertionError('Corrupt evidence accepted: '+kind)
    return reports


def main():
    root=Path(sys.argv[1]);directories=sorted(p.parent for p in root.glob('b32a_*/evidence.json'))
    assert directories, 'No graph evidence'
    cases=[verify_case(p) for p in directories]
    expected_count=int(sys.argv[sys.argv.index('--expected-cases')+1]) if '--expected-cases' in sys.argv else None
    assert len({c['test'] for c in cases})==len(cases), 'Duplicate case names'
    if expected_count is not None:
        assert len(cases)==expected_count, 'Missing expected HTTP integration cases'
    report={'checked_at_utc':datetime.now(timezone.utc).isoformat(),'cases':cases,
        'cases_checked':len(cases),'expected_cases':expected_count,
        'http_attempts':sum(c['http_attempts'] for c in cases),'responses':sum(c['responses'] for c in cases),
        'real_llm_calls':0,'mock_llm_decisions':0,'verification_level':'integration_verified','live_verification':'not_verified'}
    if '--negative-checks' in sys.argv:
        source=next(p for p in directories if 'test_compiled_graph_real_chain' in read(p/'evidence.json')['test'])
        report['negative_checks']=negative_checks(source)
    (root/'independent_verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'}))


if __name__=='__main__':main()
