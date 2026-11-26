"""Local graph capability/loopback guards; no HTTP in these unit tests."""
import tempfile
import unittest
from copy import deepcopy
from unittest.mock import patch

from src.coordinator.origin_local import LocalOriginTest, loopback_url
from src.coordinator.runtime import RuntimeBudget
from src.coordinator.validation import validate_pipeline_input

A = 'http://127.0.0.1:18761'
B = 'http://127.0.0.1:18762'


class OriginGraphUnitTests(unittest.TestCase):
    def setUp(self):
        self.scope = {'approved_origins':[A,B], 'origin_policies':{
            o:{'rules':[{'path':'/', 'methods':['GET'], 'operation':'read_only'}]} for o in (A,B)}}
        self.documents = [{'url':A+'/', 'kind':'html'}]
        self.config = {'multi_origin':self.scope, 'fuzzing_options':{'engine':'python_http'}, 'max_retries':0}

    def local(self, **kwargs):
        return LocalOriginTest(A+'/', scope=self.scope, documents=self.documents,
                               origin_max_requests={A:4,B:4}, **kwargs)

    def test_no_dns_names_or_non_loopback_or_ambiguous_ip(self):
        for url in ('https://cab.vn','http://localhost','http://127.1','http://2130706433',
                    'http://127.0.0.1.example.test', 'http://192.168.1.2', 'http://[::ffff:127.0.0.1]'):
            with self.subTest(url=url),self.assertRaises(ValueError):loopback_url(url)
        self.assertEqual(loopback_url('http://[::1]:8000/'), 'http://[::1]:8000/')

    def test_unapproved_and_write_document_plans_are_denied(self):
        self.documents[0]['url']='http://127.0.0.1:9999/'
        with self.assertRaises(ValueError):self.local()
        self.documents[0]={'url':A+'/', 'kind':'html','method':'POST'}
        with self.assertRaises(ValueError):self.local()

    def test_all_approved_origins_must_be_loopback(self):
        self.scope['approved_origins'].append('https://api.example.test')
        with self.assertRaises(ValueError):self.local()

    def test_exact_quotas_required(self):
        for quotas in ({A:1},{A:1,B:True},{A:-1,B:2}):
            with self.assertRaises(ValueError):LocalOriginTest(A+'/',scope=self.scope,
                documents=self.documents,origin_max_requests=quotas)

    def test_proxy_engine_auth_and_provider_configs_fail_closed(self):
        for change in ({'base_url':'http://127.0.0.1:9999'}, {'token':'unit-secret'},
                       {'max_retries':1}, {'run_all_modules':True},
                       {'fuzzing_options':{'engine':'proxy_http'}},
                       {'fuzzing_options':{'engine':'python_http','proxy':'http://127.0.0.1:9999'}}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                target,config=validate_pipeline_input(A+'/',{**self.config,**change})
                self.local().configure(target,config)

    def test_context_cannot_be_reused_and_no_node_without_runtime(self):
        local=self.local();target,config=validate_pipeline_input(A+'/',self.config)
        local.configure(target,config)
        with self.assertRaises(ValueError):local.configure(target,config)
        with self.assertRaises(ValueError):local.enter_node({},'run_tech_recon')

    def test_transport_rechecks_loopback_even_if_policy_is_changed(self):
        local=self.local()
        with patch.object(local.transport._policy,'check') as underlying:
            with self.assertRaises(ValueError):local.transport.check_dispatch('http://example.test/', 'GET')
            underlying.assert_not_called()

    def test_public_profile_labels_are_not_registered_as_secrets(self):
        from src.coordinator.artifacts import RunArtifacts
        self.scope['origin_policies'][A]['credential_profile']='frontend'
        local=self.local(credential_profiles={A:{'profile_id':'frontend',
            'headers':{'Authorization':'Bearer unit-only-secret'}}})
        with tempfile.TemporaryDirectory() as directory:
            writer=RunArtifacts(local.artifact_config({'artifact_root':directory}))
            public=writer.public_state({'source_type':'frontend_route','credential_profile':'frontend',
                                       'reflected':'Bearer unit-only-secret'})
        self.assertEqual(public['source_type'],'frontend_route')
        self.assertEqual(public['credential_profile'],'frontend')
        self.assertNotIn('unit-only-secret',str(public))

    def test_rate_reservation_waits_until_slot_even_if_sleep_returns_early(self):
        clock={'now':0.,'sleeps':0}
        def sleep(delay):
            clock['sleeps']+=1
            clock['now']+=delay-.003 if clock['sleeps']==1 else delay
        with patch('src.coordinator.runtime.time.monotonic',side_effect=lambda:clock['now']), \
             patch('src.coordinator.runtime.time.sleep',side_effect=sleep):
            runtime=RuntimeBudget({'http_rate_limit':10,'http_origin_max_requests':{A:2}})
            runtime.reserve_http(origin=A);runtime.reserve_http(origin=A)
        timestamps=[r['reserved_at_monotonic'] for r in runtime.origin_reservations]
        self.assertGreaterEqual(timestamps[1]-timestamps[0],.1)
        self.assertEqual(runtime.requests,2)
