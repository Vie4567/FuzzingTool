"""Independent B2.2 artifact verifier: stdlib only, no project imports or I/O to HTTP.

Usage: python -B scripts/verify_origin_wordlist_evidence.py DIAGNOSTIC_CASE_ROOT
This checks actual recorded lab evidence; it never fabricates a successful run.
"""
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import urljoin, urlsplit, urldefrag, parse_qs


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def origin(url):
    p = urlsplit(url)
    return p.scheme+'://'+p.netloc


class HTMLSource(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        line, column = self.getpos()
        self.tags.append((line,column+1,tag,dict(attrs)))


def verify_observation(row, served, document_base):
    text = served[row['source_url']]
    digest = sha256(text.encode('utf-8')).hexdigest()
    assert row['source_sha256']==digest
    location = row['evidence_location']
    reference = 'ev_'+sha256(json.dumps([row['source_url'],digest,location],sort_keys=True).encode()).hexdigest()[:24]
    assert row['evidence_refs']==[reference]
    kind = row['source_type']
    if kind in ('html','form'):
        parser = HTMLSource(text)
        attrs = next(attrs for line,col,tag,attrs in parser.tags
                     if (line,col,tag)==(location['line'],location['column'],location['tag']))
        value = attrs.get(location['attribute']) or row['source_url']
        assert urldefrag(urljoin(row['source_url'],value)).url==row['url']
        if row.get('method'):
            assert row['method']==attrs.get('method','GET').upper()
    elif kind=='javascript':
        snippet = text[location['offset']:location['end_offset']]
        strings = [m.group(2) for m in re.finditer(r'([\'\"])(.*?)\1',snippet)]
        assert any(urljoin(document_base,value)==row['url'] for value in strings)
        if row.get('method'):
            assert re.search(r'method\s*:\s*[\'\"]'+re.escape(row['method'])+r'[\'\"]',snippet)
    elif kind=='openapi':
        schema = json.loads(text)
        keys = [k.replace('~1','/').replace('~0','~') for k in location['json_pointer'].split('/')[1:]]
        value = schema
        for key in keys:
            value = value[key]
        base = schema.get('servers',[{'url':origin(row['source_url'])}])[0]['url'].rstrip('/')
        assert base+keys[1]==row['url'] and keys[2].upper()==row['method']
    else:
        raise AssertionError('Unexpected source type in HTTP evidence')


def scope_allowed(row, config):
    if row['origin'] not in config['approved_origins'] or row['method'] not in ('GET','HEAD'):
        return False
    rules = config['origin_policies'].get(row['origin'],{}).get('rules',[])
    parts = urlsplit(row['url'])
    return any(rule['path']==(parts.path or '/') and rule.get('query','')==parts.query
               and row['method'] in rule['methods'] and rule['operation']=='read_only' for rule in rules)


def metric(selected, eligible, originals):
    return {'selected_count':len(selected),
        'source_provenance_retained':sum(bool(r['provenance'] and r['evidence_refs']) for r in selected),
        'direct_api_references_retained':sum(r['resource_type']=='api_reference' and r['priority']['tier']==1 for r in selected),
        'duplicates':len(selected)-len({r['endpoint_id'] for r in selected}),
        'wrong_origin':sum(r['endpoint_id'] not in originals or originals[r['endpoint_id']]['origin']!=r['origin'] for r in selected),
        'selected_over_eligible':len(selected)/len(eligible) if eligible else None,'llm_invocations':0}


def verify_case(path):
    data = read(path/'evidence.json')
    assert data['test_outcome']=='PASS', 'Lab test did not pass'
    logs = {role:read(path/(role+'_access.json')) for role in data['servers']}
    served = {url:body for role in logs for url,body in read(path/(role+'_served.json')).items()}
    assert not logs['unapproved']
    assert data['http_logs_before_agent2']==list(logs.values()), 'Agent 2 changed HTTP logs'
    accesses = [row for events in logs.values() for row in events]
    planned = {(r['url'],'GET') for r in data['plan']}
    assert all((r['origin']+r['path'],r['method']) in planned for r in accesses)
    assert len(accesses)==len({(r['origin'],r['path']) for r in accesses})
    for role, events in logs.items():
        expected = 'frontend' if role=='frontend' else 'anonymous'
        assert all(e['credential_identity']==expected for e in events)
    execution = data['agent1_result']['execution']
    stats = execution['stats']
    assert len(accesses)==stats['attempted_requests']==data['runtime']['http_dispatches']==data['telemetry']['http']['known_requests']
    assert sum(r['status'] is not None for r in accesses)==stats['responses_received']
    assert data['mock_llm_invocations']==data['telemetry']['llm']['attempted']==0
    events = execution['requests']
    actual = Counter((r['origin']+r['path'],r['method'],r['status']) for r in accesses)
    assert Counter((r['url'],r['method'],r['status_code']) for r in events if r['attempted'])==actual
    for row in data['agent1_result']['discovery_context']['observations']:
        verify_observation(row,served,data['shared_context_before_agent2']['target_url'])
    initial = data['shared_context_before_agent2']
    originals = {r['endpoint_id']:r for entry in initial['origin_contexts'].values() for r in entry['endpoints']}
    for entry in initial['origin_contexts'].values():
        context = entry.get('context') or {}
        for parameter in context.get('parameters', []):
            text = served[parameter['source_url']]
            if parameter['source']=='javascript':
                assert parameter['name'] in parse_qs(urlsplit(parameter['url']).query)
            elif parameter['source']=='html_form':
                assert any(attrs.get('name')==parameter['name'] for _,_,_,attrs in HTMLSource(text).tags)
            elif parameter['source']=='openapi':
                document=json.loads(text)
                keys=[k.replace('~1','/').replace('~0','~') for k in parameter['evidence_location']['json_pointer'].split('/')[1:]]
                operation=document
                for key in keys:
                    operation=operation[key]
                assert any(p['name']==parameter['name'] for p in operation.get('parameters',[]))
            else:
                raise AssertionError('Unverified parameter source')
        for unresolved in context.get('unresolved_references', []):
            assert unresolved['url'] is None and unresolved['origin'] is None
            text=served[unresolved['source_url']]
            assert sha256(text.encode()).hexdigest()==unresolved['source_sha256']
            location=unresolved['evidence_location']
            assert '+' in text[location['offset']:location['end_offset']]
        for document in context.get('source_documents', []):
            if document['collection_status']=='completed':
                assert sha256(served[document['url']].encode()).hexdigest()==document['source_sha256']
    final = read(data['state_artifact'])
    checkpoint = read(final['artifacts']['checkpoint'])
    assert checkpoint==final
    for key in ('approved_origins','origin_policies','discovered_origins','origin_execution_mode'):
        assert final[key]==initial[key]
    artifact_paths = set()
    run_summaries = []
    kind_rank = {'api_reference':0,'frontend_route':1,'unknown':2,'static_asset':3}
    for run in data['generation_runs']:
        assert run['artifacts']['result'] not in artifact_paths
        artifact_paths.add(run['artifacts']['result'])
        assert read(run['artifacts']['result'])==run
        assert read(run['artifacts']['checkpoint'])==run
        assert run['execution_enabled'] is False
        all_rows, counts_by_origin = [], {}
        for key, entry in run['origin_contexts'].items():
            wordlist = entry['context']['wordlist']
            input_context = initial['origin_contexts'][key].get('context') or {}
            for field in ('parameters','forms','source_documents','unresolved_references'):
                records=wordlist['input_context'][field]
                assert len(records)==len(input_context.get(field,[]))
                for record, original in zip(records,input_context.get(field,[])):
                    assert all(original[k]==v for k,v in record.items())
            assert 'raw_javascript' not in wordlist['input_context']
            rows = wordlist['candidates']
            assert len(rows)==len({r['endpoint_id'] for r in rows})
            for row in rows:
                assert row['origin']==key==origin(row['url'])
                assert row['endpoint_id']==sha256((row['url']+'\n'+(row['method'] or '')).encode()).hexdigest()[:24]
                assert row['attempted'] is None and row['verified'] is None and row['verification_status']=='not_verified'
                assert row['dispatch_eligible']==scope_allowed(row,data['config'])
                assert not row['selected'] or row['dispatch_eligible']
                if row['observed']:
                    assert not row['generated']
                    original = originals[row['endpoint_id']]
                    for field in ('url','origin','method','resource_type','evidence_refs','provenance'):
                        assert row[field]==original[field], 'Source contract lost: '+field
                    for provenance in row['provenance']:
                        verify_observation({**provenance,'url':row['url'],'method':row['method']},served,initial['target_url'])
                    direct = any(p.get('source_type') in ('javascript','openapi') and p.get('source_sha256') and p.get('evidence_refs') and p.get('evidence_location') for p in row['provenance'])
                    context = initial['origin_contexts'][key].get('context') or {}
                    priority = {'tier':1 if direct and row['method'] is not None else 2,
                        'reason':'direct_declaration' if direct and row['method'] is not None else 'observed_context',
                        'independent_sources':len({p['source_url'] for p in row['provenance'] if p.get('source_url')}),
                        'parameter_support':sum(p.get('url')==row['url'] and p.get('method')==row['method'] for p in context.get('parameters',[])),
                        'form_support':sum(f.get('action')==row['url'] and f.get('method')==row['method'] for f in context.get('forms',[]))}
                    assert row['priority']==priority
                else:
                    assert row['generated'] and row['method'] is None and not row['selected']
                    assert not row['provenance'] and not row['evidence_refs']
                    for supporting in row['derivation']['supporting_endpoint_ids']:
                        assert originals[supporting]['origin']==key
                    assert row['priority']['tier'] in (3,4)
            selected = sorted([r for r in rows if r['selected']],key=lambda r:r['selection_rank'])
            assert wordlist['selected_ids']==[r['endpoint_id'] for r in selected]
            counts = {'catalog_count':len(rows),'observed_count':sum(r['observed'] for r in rows),
                'unattributed_count':sum(not r['observed'] and not r['generated'] for r in rows),
                'generated_count':sum(r['generated'] for r in rows),'selected_count':len(selected),
                'dispatch_eligible_count':sum(r['dispatch_eligible'] for r in rows)}
            assert counts==wordlist['counts']
            counts_by_origin[key]=counts
            all_rows.extend(rows)
        metadata = run['wordlist_metadata']['multi_origin']
        for field in next(iter(counts_by_origin.values())):
            assert metadata[field]==sum(c[field] for c in counts_by_origin.values())
        assert metadata['llm_invocations']==metadata['http_dispatches']==0
        eligible = [r for r in all_rows if r['dispatch_eligible']]
        def order(r):
            p=r['priority']
            return p['tier'],kind_rank[r['resource_type']],-p['independent_sources'],-p['parameter_support'],-p['form_support'],r['endpoint_id']
        selected = sorted([r for r in all_rows if r['selected']],key=lambda r:r['selection_rank'])
        assert [r['endpoint_id'] for r in selected]==[r['endpoint_id'] for r in sorted(eligible,key=order)[:metadata['selection_limit']]]
        for comparison in data['comparisons']:
            if comparison['catalog_run']!=run['artifacts']['result']:
                continue
            baseline = sorted(eligible,key=lambda r:(urlsplit(r['url']).path.lstrip('/')+('?' + urlsplit(r['url']).query if urlsplit(r['url']).query else ''),r['origin'],r['method']))[:comparison['k']]
            assert comparison['baseline_ids']==[r['endpoint_id'] for r in baseline]
            assert comparison['context_ids']==[r['endpoint_id'] for r in selected]
            assert comparison['baseline']==metric(baseline,eligible,originals)
            assert comparison['context_aware']==metric(selected,eligible,originals)
        run_summaries.append({'result':run['artifacts']['result'],'counts_by_origin':counts_by_origin,'totals':metadata})
    if data['generation_runs']:
        for key,entry in data['generation_runs'][-1]['origin_contexts'].items():
            assert entry['context']['wordlist']==final['origin_contexts'][key]['context']['wordlist']
    for file in path.rglob('*.json'):
        text=file.read_text(encoding='utf-8')
        assert 'b21-only-local-fake-token' not in text and 'b21-only-local-fake-cookie' not in text
    return {'diagnostic_id':data['diagnostic_id'],'test':data['test'],'result':'PASS',
            'http_attempts':len(accesses),'http_responses':stats['responses_received'],
            'agent2_http_dispatches':0,'mock_llm_invocations':0,'generation_runs':run_summaries,
            'comparisons':data['comparisons']}


def main():
    root=Path(sys.argv[1])
    paths=sorted({p.parent for p in root.glob('b22_*/evidence.json')})
    if not paths:
        raise SystemExit('No HTTP integration evidence found')
    cases=[verify_case(path) for path in paths]
    result={'checked_at_utc':datetime.now(timezone.utc).isoformat(),'cases':cases,
            'http_attempts':sum(c['http_attempts'] for c in cases),'http_responses':sum(c['http_responses'] for c in cases),
            'agent2_http_dispatches':0,'mock_llm_invocations':0,'verification_level':'integration_verified',
            'live_verification':'not_verified','scope':'B2.2 Agent1 -> discovery context -> offline Agent2; no candidate dispatch'}
    (root/'independent_verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('http_attempts','http_responses','agent2_http_dispatches','mock_llm_invocations','verification_level')}))


if __name__=='__main__':
    main()
