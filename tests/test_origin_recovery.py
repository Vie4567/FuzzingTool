"""Durability and private recovery guard unit tests, no network or LLM."""
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from src.coordinator.artifacts import ArtifactWriteError
from src.coordinator.artifacts import RunArtifacts
from src.coordinator.origin_recovery import RecoveryJournal, RecoveryDenied
from src.coordinator.runtime import RuntimeBudget
from src.coordinator.origin_local import LocalOriginTest
from src.tools.origin_dispatch import _counts, _outcome

A='http://127.0.0.1:18881'


class OriginRecoveryUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'session'

    def seed(self):
        with RecoveryJournal(self.path) as j:j.append('session',{'version':1})

    def test_missing_session_is_not_created_on_resume(self):
        with self.assertRaisesRegex(RecoveryDenied,'session_missing'):
            with RecoveryJournal(self.path,resume=True):pass
        self.assertFalse(self.path.exists())

    def test_existing_session_cannot_be_replaced_by_new_run(self):
        self.seed();original=(self.path/'journal.jsonl').read_bytes()
        with self.assertRaisesRegex(RecoveryDenied,'already_exists'):
            with RecoveryJournal(self.path):pass
        self.assertEqual((self.path/'journal.jsonl').read_bytes(),original)

    def test_anchor_mismatch_and_complete_line_truncation_fail_closed(self):
        with RecoveryJournal(self.path) as j:
            j.append('session',{'version':1});j.append('process_bound',{'resume':False})
        file=self.path/'journal.jsonl';file.write_bytes(file.read_bytes().splitlines(keepends=True)[0])
        with self.assertRaisesRegex(RecoveryDenied,'journal_invalid'):
            with RecoveryJournal(self.path,resume=True):pass

    def test_invalid_journal_hash_is_rejected(self):
        self.seed();file=self.path/'journal.jsonl'
        file.write_bytes(file.read_bytes().replace(b'"version": 1',b'"version": 2'))
        with self.assertRaisesRegex(RecoveryDenied,'journal_invalid'):
            with RecoveryJournal(self.path,resume=True):pass

    def test_lock_is_released_after_failed_reconciliation(self):
        self.seed();(self.path/'head.json').write_text('{}')
        for _ in range(2):
            with self.assertRaisesRegex(RecoveryDenied,'journal_invalid'):
                with RecoveryJournal(self.path,resume=True):pass

    def test_durable_write_failure_blocks_future_reservations(self):
        runtime=RuntimeBudget({'http_origin_max_requests':{A:2}})
        with RecoveryJournal(self.path) as j:
            j.append('session',{'version':1});j.runtime=runtime;runtime.recovery=j
            with patch('src.coordinator.origin_recovery.RunArtifacts._write_json',side_effect=OSError('unit disk failure')):
                with self.assertRaises(ArtifactWriteError):
                    runtime.reserve_http(origin=A,request={'url':A+'/', 'method':'GET'})
            self.assertEqual(runtime.requests,0)
            self.assertEqual(runtime.stop_reason,'recovery_persistence_error')
            with self.assertRaises(ArtifactWriteError):runtime.reserve_http(origin=A,request={})
        with self.assertRaisesRegex(RecoveryDenied,'journal_invalid'):
            with RecoveryJournal(self.path,resume=True):pass

    def test_reservation_persisted_before_runtime_count_changes(self):
        runtime=RuntimeBudget({'http_origin_max_requests':{A:2}});observed=[]
        with RecoveryJournal(self.path) as j:
            j.append('session',{'version':1});j.runtime=runtime;runtime.recovery=j
            j.barrier=lambda event,payload:observed.append((event,runtime.requests))
            runtime.reserve_http(origin=A,request={'url':A+'/', 'method':'GET'})
            self.assertEqual(observed,[('before_reservation',0),('reserved',0)])
            self.assertEqual(runtime.requests,1)

    def test_unknown_reservation_is_not_reported_as_measured_transport_error(self):
        row={'attempted':None,'status_code':None,'error':None,'timeout':False,
             'stop_reason':'outcome_unknown','recovery_state':'outcome_unknown'}
        counts=_counts([row])
        self.assertEqual((counts['attempted'],counts['responses'],counts['errors'],counts['unattempted']),(0,0,0,0))
        self.assertEqual(counts['attempted_unknown'],1)
        self.assertNotEqual(_outcome([row])[0],'completed')

    def test_resume_requires_private_context_not_config(self):
        scope={'approved_origins':[A],'origin_policies':{A:{'rules':[{'path':'/','methods':['GET'],'operation':'read_only'}]}}}
        with self.assertRaisesRegex(ValueError,'explicit recovery directory'):
            LocalOriginTest(A+'/',scope=scope,documents=[{'url':A+'/', 'kind':'html'}],origin_max_requests={A:1},resume=True)

    def test_journal_append_after_owner_closed_fails(self):
        with RecoveryJournal(self.path) as j:j.append('session',{'version':1})
        with self.assertRaises(ArtifactWriteError):j.append('reserved',{})

    def test_checkpoint_global_stop_is_not_ignored_without_separate_stop_event(self):
        scope={'approved_origins':[A],'origin_policies':{A:{'rules':[{'path':'/','methods':['GET'],'operation':'read_only'}]}}}
        local=LocalOriginTest(A+'/',scope=scope,documents=[{'url':A+'/', 'kind':'html'}],origin_max_requests={A:2})
        config={'multi_origin':local.policy.public_config()}
        runtime=RuntimeBudget({'http_origin_max_requests':{A:2}})
        authority=RecoveryJournal.authority(local,config)
        writer=RunArtifacts({'artifact_root':self.tmp.name})
        state={'session_id':'unit-session','config':config,'runtime':runtime.snapshot(),'origin_contexts':{}}
        state['runtime']['stop_reason']='dispatch_interrupted'
        with RecoveryJournal(self.path) as j:
            j.runtime=runtime
            j.append('session',{'version':1,'session_id':'unit-session','runtime_id':'unit-runtime',
                'authority':authority,'started_wall':time.time(),'started_monotonic':runtime.started,
                'deadline_wall':time.time()+600,'deadline_monotonic':runtime.deadline})
            j.checkpoint(writer.save(state),'run_fuzzing','interrupted')
            with self.assertRaisesRegex(RecoveryDenied,'recovery_global_stop'):
                j._restore(local,runtime,{},authority)
