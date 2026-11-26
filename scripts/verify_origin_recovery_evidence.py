"""Independent B3.2B evidence verifier: stdlib only, no runtime/Agent imports."""
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from urllib.parse import urlsplit


def read(path): return json.loads(Path(path).read_text(encoding='utf-8'))


def journal(path):
    raw = Path(path).read_bytes()
    assert raw.endswith(b'\n'), 'torn journal'
    return [json.loads(line) for line in raw.splitlines()]


def check_chain(rows, head):
    previous = None
    for seq, row in enumerate(rows, 1):
        plain = {k:v for k,v in row.items() if k!='hash'}
        actual = sha256(json.dumps(plain,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
        assert row['seq']==seq and row['previous']==previous and row['hash']==actual, 'journal altered'
        previous=row['hash']
    assert rows and rows[0]['event']=='session'
    assert head=={'seq':len(rows),'hash':previous}, 'journal/head mismatch'


def verify_case(directory, *, mutation=None):
    directory=Path(directory); case=read(directory/'evidence.json')
    before=journal(directory/'before/journal.jsonl')
    check_chain(before,read(directory/'before/head.json'))
    authority=before[0]['payload']['authority']; session=before[0]['payload']['session_id']
    rows=None
    try:
        rows=journal(directory/'recovery/journal.jsonl')
        if mutation=='ledger':
            next(r for r in rows if r['event']=='reserved')['payload']['sequence']=0
        check_chain(rows,read(directory/'recovery/head.json'))
    except (AssertionError,ValueError):
        assert case['expect_denied'] and mutation is None, 'invalid journal was accepted'
        rows=before
    logs={role:[json.loads(line) for line in (directory/(role+'_access.jsonl')).read_text().splitlines()]
          for role in ('frontend','gateway','unapproved')}
    if mutation=='duplicate': logs['frontend'].append(deepcopy(logs['frontend'][0]))
    result=deepcopy(case['result'])
    if mutation=='counter': result['runtime']['http_dispatches']-=1
    if mutation=='response':
        for entry in result['origin_contexts'].values():
            measured=((entry.get('context') or {}).get('http_dispatch') or {}).get('records',[])
            if measured:
                measured[0]['status_code']=201
                break
    assert not logs['unapproved'], 'unapproved origin received HTTP'
    assert all(r['credential_identity']=='anonymous' for r in logs['gateway']), 'credential crossing'
    assert all(r['credential_identity']=='frontend' for r in logs['frontend'])
    for role, items in logs.items():
        assert items==case['servers'][role]['access'], 'independent server log mismatch'
        keys=[(r['origin'],r['path'],r['method']) for r in items]
        assert len(keys)==len(set(keys)), 'replayed HTTP request'
        for row in items:
            rules=authority['config']['multi_origin']['origin_policies'][row['origin']]['rules']
            parts=urlsplit(row['path'])
            assert any(r['path']==parts.path and r['query']==parts.query and row['method'] in r['methods'] and
                r['operation']=='read_only' for r in rules), 'scope exceeded'
            assert row['method'] in ('GET','HEAD')
    processes=case['processes']
    pids={p['pid'] for p in processes}
    killed=[p for p in processes if 'hard_killed_utc' in p]
    assert killed and killed[0]['exit_code']!=0, 'no hard process termination evidence'
    assert len(pids)>=2 and all(r['server_pid'] not in pids for items in logs.values() for r in items)
    assert any(p.get('mode')=='resume' for p in processes), 'no subprocess restart'
    if case['test']=='test_concurrent_resume_is_exclusively_locked':
        contender=next(p['pid'] for p in processes if p.get('label')=='contender')
        denied=read(directory/'contender_result.json')
        assert any(e.get('error')=='recovery_session_locked' for e in denied['error_log'])
        assert not any(e['pid']==contender and e['event']=='process_bound' for e in rows), 'concurrent owner accepted'
    reservations=[r['payload'] for r in rows if r['event']=='reserved']
    starts={r['payload']['sequence'] for r in rows if r['event']=='dispatch_started'}
    headers={r['payload']['sequence']:r['payload'] for r in rows if r['event']=='response_headers'}
    measurements={r['payload']['sequence']:r['payload'] for r in rows if r['event']=='measurement'}
    assert [r['sequence'] for r in reservations]==list(range(1,len(reservations)+1)), 'quota sequence reset'
    assert len(reservations)<=authority['config']['http_max_requests']
    per_origin=Counter(r['origin'] for r in reservations)
    assert all(n<=authority['quotas'][o] for o,n in per_origin.items()), 'origin budget exceeded'
    times=[r['reserved_at_monotonic'] for r in reservations]
    assert all(b-a>=1/authority['config']['http_rate_limit']-1e-6 for a,b in zip(times,times[1:])), 'rate reset'
    assert all(t<before[0]['payload']['deadline_monotonic'] for t in times), 'deadline reset'
    indexed={}
    for row in reservations:
        parts=urlsplit(row['url']);path=parts.path+('?' + parts.query if parts.query else '')
        key=(row['origin'],path,row['method'])
        assert key not in indexed, 'duplicate reservation for same work'
        indexed[key]=row
    arrived={}
    for items in logs.values():
        for row in items:
            key=(row['origin'],row['path'],row['method'])
            assert key in indexed and indexed[key]['sequence'] in starts, 'HTTP without durable dispatch/reservation'
            arrived[indexed[key]['sequence']]=row
    for seq, h in headers.items():
        assert seq in arrived and arrived[seq]['status']==h['status_code'], 'fabricated response'
    for seq, m in measurements.items():
        assert seq in starts
        if m['status_code'] is not None:
            assert seq in headers and m['status_code']==headers[seq]['status_code']
    # Frozen pre-crash checkpoints survive intentionally corrupted original fixtures.
    for event in before:
        if event['event']!='checkpoint': continue
        ref=event['payload'];raw=(directory/'before_checkpoints'/(ref['sha256']+'.json')).read_bytes()
        assert sha256(raw).hexdigest()==ref['sha256'], 'before-crash checkpoint lost'
    if case['expect_denied']:
        assert logs==read(directory/'access_before.json'), 'denied resume sent HTTP'
        assert result.get('pipeline_status')=='failed' or 'reason' in result
        assert not result.get('all_modules_executed') and result.get('pipeline_status')!='completed'
        reasons={r.get('error') for r in result.get('error_log',[])} | {result.get('reason')}
        assert reasons & {'recovery_authority_changed','recovery_credentials_required','recovery_checkpoint_invalid',
            'recovery_journal_invalid','recovery_global_stop','recovery_deadline_expired','recovery_budget_exhausted',
            'recovery_discovery_checkpoint_missing'}, 'unexpected denial, not a verified recovery guard'
    else:
        assert rows[:len(before)]==before, 'prior journal overwritten'
        assert result['session_id']==session and result['recovery']['session_id']==session
        assert result['runtime']['http_dispatches']==len(reservations), 'spent budget reset'
        assert result['runtime']['http_dispatches_by_origin']==dict(per_origin)
        assert result['pipeline_status']!='completed' and not result['all_modules_executed'] and not result['all_modules_successful']
        assert result['agent_statuses']['param_disc']=='skipped' and result['agent_statuses']['soft404_filter']=='skipped'
        assert result['agent_attempts']=={'tech_recon':1,'wordlist_gen':1,'fuzzing':1}, 'completed Agent executed again'
        assert result['llm_call_count']==0
        assert {'run_tech_recon','run_wordlist_gen'} <= set(result['recovery']['reused_nodes'])
        assert result['local_origin_execution']['full_pipeline_enabled'] is False
        trace=result['local_origin_execution']['langgraph_trace']
        transitions=[e['node'] for e in trace if e['event']=='start']
        assert transitions[-10:]==['validate_input','init_state','tech_recon','llm_decide_recon',
            'gen_words','llm_decide_wordlist','fuzzing','llm_decide_fuzzing','report','reflection'], 'graph routing mismatch'
        assert read(result['artifacts']['checkpoint'])==result, 'result differs from final checkpoint'
        assert read(result['artifacts']['result'])==result, 'result.json differs from returned result'
        all_records=[]
        for origin, entry in result['origin_contexts'].items():
            context=entry.get('context') or {}; wordlist=context.get('wordlist') or {}
            candidates={c['endpoint_id']:c for c in wordlist.get('candidates',[])}
            endpoints={c['endpoint_id']:c for c in entry.get('endpoints',[])}
            for record in (context.get('http_dispatch') or {}).get('records',[]):
                all_records.append(record)
                identifier=record['candidate_id']; c=candidates[identifier];source=endpoints[identifier]
                assert identifier in wordlist['selected_ids'] and source['url']==c['url']==record['url']
                assert source['origin']==c['origin']==record['origin']==origin
                assert source['method']==c['method']==record['observed_method']
                assert source['evidence_refs']==c['evidence_refs']==record['evidence_refs'] and source['provenance']==c['provenance']
                if record['attempted'] is False:
                    assert record['status_code'] is None and record['execution_method'] is None
                    assert not any(r.get('candidate_id')==identifier and r['origin']==origin for r in reservations)
                    continue
                seq=record['runtime_sequence']; r=reservations[seq-1]
                assert r['candidate_id']==identifier and r['origin']==origin
                if record['status_code'] is not None:
                    assert seq in headers and headers[seq]['status_code']==record['status_code'], 'response not measured'
                if seq in measurements:
                    assert record['bytes_received']==measurements[seq]['bytes_received']
                    assert record['body_complete']==measurements[seq]['body_complete']
                else:
                    assert record['recovery_state']=='outcome_unknown' and record['bytes_received'] is None
                    assert record['body_complete'] is None
                assert record['attempted']==(True if seq in starts else None)
                assert record['verified'] is None and record['verification_status']=='not_verified'
        counts=result['fuzzing_execution']['multi_origin']['counts']
        assert counts['selected']==len(all_records)
        assert counts['attempted']==sum(r['attempted'] is True for r in all_records)
        assert counts['responses']==sum(r['status_code'] is not None for r in all_records)
        unknown=[r['runtime_sequence'] for r in all_records if r.get('recovery_state')=='outcome_unknown']
        assert sorted(unknown)==sorted(result['recovery']['outcome_unknown_sequences'])
        if unknown: assert result['agent_statuses']['fuzzing']!='success'
        for e in rows:
            if e['event']=='checkpoint':
                ref=e['payload'];raw=Path(ref['path']).read_bytes()
                assert sha256(raw).hexdigest()==ref['sha256'], 'checkpoint modified'
                saved=json.loads(raw)
                assert saved['runtime']['http_dispatches']==ref['reservations']
        # Preserve every completed pre-crash origin result without rewriting it.
        prior=[]
        for e in before:
            if e['event']=='checkpoint' and e['payload']['node']=='b31_dispatch':
                saved=read(directory/'before_checkpoints'/(e['payload']['sha256']+'.json'))
                prior=[r for c in saved['origin_contexts'].values() for r in ((c.get('context') or {}).get('http_dispatch') or {}).get('records',[]) if r.get('status_code') is not None]
        lookup={(r['origin'],r['candidate_id']):r for r in all_records}
        for r in prior: assert lookup[(r['origin'],r['candidate_id'])]==r, 'completed result was changed'
    # Fake credential values are supplied only inside the worker. None may be persisted.
    for file in directory.rglob('*'):
        if file.is_file() and file.suffix in ('.json','.jsonl','.log'):
            assert 'b32b-local-only-fake' not in file.read_text(encoding='utf-8',errors='replace'), 'credential leak'
    return {'test':case['test'],'directory':str(directory),'status':'PASS','reservations':len(reservations),
        'dispatch_started':len(starts),'responses':len(headers),'measurements':len(measurements),
        'server_arrivals':len(arrived),'by_origin':dict(per_origin),'resume':'blocked' if case['expect_denied'] else 'continued',
        'unknown_outcomes':(result.get('recovery') or {}).get('outcome_unknown_sequences',[]),
        'unresolved_reservations':[r['sequence'] for r in reservations if r['sequence'] not in measurements],
        'blocked_replays':len([r for r in before if r['event']=='reserved' and r['payload'].get('candidate_id')])}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('directory');parser.add_argument('--expected-cases',type=int,required=True)
    parser.add_argument('--negative-checks',action='store_true');args=parser.parse_args()
    root=Path(args.directory);directories=sorted(p.parent for p in root.glob('b32b_*/evidence.json'))
    assert len(directories)==args.expected_cases, 'incomplete case set'
    results=[verify_case(d) for d in directories]
    assert len({r['test'] for r in results})==len(results), 'duplicate test evidence'
    negative={}
    if args.negative_checks:
        case=next(d for d,r in zip(directories,results) if r['resume']=='continued')
        for mutation in ('ledger','duplicate','counter','response'):
            try: verify_case(case,mutation=mutation)
            except AssertionError: negative[mutation]='REJECTED'
            else: raise AssertionError('mutation accepted: '+mutation)
    output={'utc':datetime.now(timezone.utc).isoformat(),'cases':results,'negative_checks':negative,
            'verification':'integration_verified','live_verification':'not_verified'}
    (root/'independent_verification.json').write_text(json.dumps(output,indent=2),encoding='utf-8')
    print(f'{len(results)}/{args.expected_cases} cases PASS; {len(negative)}/4 mutations rejected')


if __name__=='__main__':main()
