"""Agent 1 HTTP -> B2.1 SharedState -> real Agent 2 (offline), three servers."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import test_discovery_http_integration as lab
from src.agents.wordlist_gen import WordlistGenAgent
from src.coordinator.artifacts import RunArtifacts
from src.tools.origin_scope import OriginScopePolicy, OriginCredentialContext, OriginScopedTransport


def rows(result):
    return [r for entry in result['origin_contexts'].values() for r in entry['context']['wordlist']['candidates']]


def metrics(selected, pool, eligible_count):
    return {'selected_count':len(selected),
            'source_provenance_retained':sum(bool(r['provenance'] and r['evidence_refs']) for r in selected),
            'direct_api_references_retained':sum(r['resource_type']=='api_reference' and r['priority']['tier']==1 for r in selected),
            'duplicates':len(selected)-len({r['endpoint_id'] for r in selected}),
            'wrong_origin':sum(not any(p['endpoint_id']==r['endpoint_id'] and p['origin']==r['origin'] for p in pool) for r in selected),
            'selected_over_eligible':len(selected)/eligible_count if eligible_count else None,
            'llm_invocations':0}


class OriginWordlistHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lab.DiscoveryHttpTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        lab.DiscoveryHttpTests.tearDownClass.__func__(cls)

    def setUp(self):
        lab.DiscoveryHttpTests.setUp(self)
        self.case_id = self.case_id.replace('b21_', 'b22_')
        for server in self.servers:
            server.case_id = self.case_id
        root = os.getenv('B22_EVIDENCE_DIR')
        self.temporary = None
        if not root:
            self.temporary = tempfile.TemporaryDirectory()
            self.addCleanup(self.temporary.cleanup)
            root = self.temporary.name
        self.directory = Path(root)/self.case_id
        self.directory.mkdir(parents=True)
        self.generation_runs, self.comparisons = [], []
        self.context_before = None
        self.http_before = None
        self.agent2_llm = Mock()
        self.agent2 = WordlistGenAgent(llm=self.agent2_llm)
        body, mime = self.servers[0].documents['/']
        # A second real source for frontend /users helps test origin diversity.
        self.servers[0].documents['/'] = (body+'\n<form action="/users" method="GET"><input name="search"></form>', mime)
        body, mime = self.servers[0].documents['/app.js']
        self.asset_paths = ['/a.js','/b.js','/c.js','/d.js','/e.js','/f.js']
        self.api_paths = ['/v1/orders','/v1/products','/v1/invoices','/v1/accounts','/v1/permissions','/v1/tickets']
        extra = [f'fetch("{p}", {{method:"GET"}});' for p in self.asset_paths]
        extra += [f'fetch("{self.b}{p}", {{method:"GET"}});' for p in self.api_paths]
        self.servers[0].documents['/app.js'] = (body+'\n'+'\n'.join(extra), mime)
        for origin, paths in [(self.a,self.asset_paths+['/users','/v1/items']),
                              (self.b,self.api_paths+['/users','/health'])]:
            self.config['origin_policies'][origin]['rules'].extend(
                {'path':path,'methods':['GET'],'operation':'read_only'} for path in paths)
        self.config['origin_policies'][self.a]['rules'].append(
            {'path':'/api/search','query':'q=book','methods':['GET'],'operation':'read_only'})
        # These are fixture operator policies, set before collection. Generation never changes them.
        from src.coordinator.origins import origin_state
        self.state = {'target_url':self.a+'/', **origin_state(self.a+'/', self.config)}
        self.reset_transport()

    def reset_transport(self):
        policy = OriginScopePolicy(self.config)
        credentials = OriginCredentialContext(policy, {self.a:{'profile_id':'frontend',
            'headers':{'Authorization':lab.AUTH,'Cookie':lab.COOKIE}}})
        self.transport = OriginScopedTransport(self.a, policy=policy, credentials=credentials)

    def collect(self):
        lab.DiscoveryHttpTests.collect(self)
        self.context_before = deepcopy(self.state)
        self.http_before = deepcopy([s.access for s in self.servers])

    def generate(self, k):
        result = self.agent2.generate_from_discovery(self.state, max_wordlist_entries=k,
            max_generated_per_origin=32, allow_generic=True, artifact_root=self.directory)
        self.generation_runs.append(result)
        self.assertEqual(self.http_before, [s.access for s in self.servers])
        self.agent2_llm.invoke.assert_not_called()
        for key in ('approved_origins','origin_policies','discovered_origins','origin_execution_mode'):
            self.assertEqual(self.state[key], self.context_before[key])
        for origin, entry in result['origin_contexts'].items():
            self.assertEqual(entry['context']['wordlist'], self.state['origin_contexts'][origin]['context']['wordlist'])
        return result

    def test_real_chain_and_controlled_legacy_order_comparison_k6_k3(self):
        self.collect()
        for k in (6,3):
            result = self.generate(k)
            pool = rows(result)
            eligible = [r for r in pool if r['dispatch_eligible']]
            # Controlled ablation: same catalog, scope, cap and sources. Only selection ordering changes.
            baseline = sorted(eligible, key=lambda r:(r['url'].split('://',1)[1].split('/',1)[1], r['origin'], r['method']))[:k]
            selected = sorted([r for r in pool if r['selected']], key=lambda r:r['selection_rank'])
            self.assertEqual(len(selected), k)
            self.assertTrue(all(r['resource_type']=='api_reference' for r in selected))
            self.assertIn(self.a, {r['origin'] for r in selected})
            self.assertIn(self.b, {r['origin'] for r in selected})
            for row in selected:
                observed = next(r for r in self.context_before['origin_contexts'][row['origin']]['endpoints'] if r['endpoint_id']==row['endpoint_id'])
                for key in ('url','method','evidence_refs','provenance'):
                    self.assertEqual(row[key], observed[key])
            self.comparisons.append({'k':k, 'design':'legacy_alphabetical_selection_ablation_same_eligible_catalog',
                'catalog_run':result['artifacts']['result'],
                'baseline_ids':[r['endpoint_id'] for r in baseline], 'context_ids':[r['endpoint_id'] for r in selected],
                'baseline':metrics(baseline,pool,len(eligible)), 'context_aware':metrics(selected,pool,len(eligible)),
                'http_discovery_improvement':'not_verified'})
        before = Path(self.generation_runs[0]['artifacts']['result']).read_bytes()
        self.generate(6)
        self.assertEqual(before, Path(self.generation_runs[0]['artifacts']['result']).read_bytes())
        self.assertEqual(len({r['artifacts']['result'] for r in self.generation_runs}), 3)
        lab.DiscoveryHttpTests.check_counts(self, [3,1,0], 4)

    def test_partial_recon_context_remains_usable_without_retry_or_extra_http(self):
        self.servers[0].mode = 'disconnect_js'
        self.collect()
        self.assertEqual(self.result['execution']['status'], 'partial')
        result = self.generate(6)
        self.assertTrue(any(r['selected'] for r in rows(result)))
        self.assertTrue(all(r['method'] in {'GET','HEAD'} for r in rows(result) if r['selected']))
        lab.DiscoveryHttpTests.check_counts(self, [3,1,0], 3)

    def test_discovered_candidates_do_not_enlarge_document_only_scope(self):
        self.config['origin_policies'][self.b]['rules'] = [
            {'path':'/openapi.json','methods':['GET'],'operation':'read_only'}]
        self.state['origin_policies'][self.b]['rules'] = deepcopy(self.config['origin_policies'][self.b]['rules'])
        self.reset_transport()
        self.collect()
        result = self.generate(6)
        gateway = result['origin_contexts'][self.b]['context']['wordlist']['candidates']
        self.assertTrue(gateway)
        self.assertFalse(any(r['dispatch_eligible'] or r['selected'] for r in gateway))
        lab.DiscoveryHttpTests.check_counts(self, [3,1,0], 4)

    def tearDown(self):
        failed = any(test is self for test,_ in self._outcome.result.failures+self._outcome.result.errors)
        evidence = {'diagnostic_id':self.case_id,'test':self.id(),'started_at_utc':self.started,
            'finished_at_utc':datetime.now(timezone.utc).isoformat(),
            'test_outcome':'PASS' if self.checked and not failed else 'FAIL',
            'config':self.config,'plan':self.plan,'limits':self.limits,
            'agent1_result':self.result,'shared_context_before_agent2':self.context_before,
            'http_logs_before_agent2':self.http_before,'generation_runs':self.generation_runs,
            'comparisons':self.comparisons, 'telemetry':self.telemetry.snapshot(),'runtime':self.runtime.snapshot(),
            'servers':{s.role:s.origin for s in self.servers},
            'mock_llm_invocations':self.llm.invoke.call_count+self.agent2_llm.invoke.call_count,
            'internet_verification':'not_verified','pipeline_execution':'not_enabled_b1'}
        for server in self.servers:
            (self.directory/(server.role+'_access.json')).write_text(json.dumps(server.access,indent=2),encoding='utf-8')
            served = {row['path'] for row in server.access if row['status']==200}
            content = {server.origin+path:server.documents[path][0] for path in served if path in server.documents}
            (self.directory/(server.role+'_served.json')).write_text(json.dumps(content,indent=2),encoding='utf-8')
        saved = RunArtifacts({'output_dir':str(self.directory)}).save(self.state,node='b22_chain',event=evidence['test_outcome'])
        evidence['state_artifact'] = saved['artifacts']['result']
        rendered = json.dumps(evidence,indent=2)
        for secret in (lab.AUTH, lab.COOKIE):
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret, json.dumps(saved))
        (self.directory/'evidence.json').write_text(rendered,encoding='utf-8')

