"""Tests-first regression for confirmed bank0 startup; no validator or transactions."""
import copy
import hashlib
import base64
import json
import io
import time
import tempfile
from unittest import mock
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('queue_supervisor',Path(__file__).with_name('queue_v2_supervisor.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ExecuteReadiness(unittest.TestCase):
    def setUp(self):
        self.before={name:{'owner':'program','executable':False,'data':bytes([i])*8}for i,name in enumerate(('config','issuer','request','queue'))}
        config=b'C'*309
        issuer=b'DYNIS2B1'+bytes(165)+bytes(136)
        self.before['config']['data']=config;self.before['issuer']['data']=issuer
        self.context_digest=bytes([9])*32
        self.consumed=copy.deepcopy(self.before)
        bound=bytearray(issuer);bound[173:181]=(1).to_bytes(8,'big');bound[213:221]=(42).to_bytes(8,'big');bound[221:229]=(342).to_bytes(8,'big');bound[172]=1
        # Enabled belongs to immutable prefix in prepared enrollment as well.
        prepared=bytearray(issuer);prepared[172]=1;self.before['issuer']['data']=bytes(prepared)
        digest=hashlib.sha256(b'part5-synthetic-signed-source-observation'+config[268:300]+issuer[40:72]+self.context_digest+bound[213:221]+issuer[173:181]).digest()
        bound[181:213]=digest;bound[229:261]=config[268:300];bound[261:269]=config[300:308];bound[269:277]=bound[173:181];bound[277:309]=digest
        self.consumed['issuer']['data']=bytes(bound)
        self.consumed['request']['data']=b'consumed'
        self.consumed['queue']['data']=b'oneentry'
        self.states={'before':self.before,'consumed':self.consumed,'context_digest':self.context_digest,'addresses':['a','b','c','d']}
    def snapshot(self,state=None,slot=8):
        return {'context_slot':slot,'accounts':copy.deepcopy(self.before if state is None else state)}
    def ready(self,snapshots,genesis='pinned'):
        return m.execute_snapshot_ready(genesis,'pinned',8,snapshots,self.states)
    def test_confirmed_bank_zero_cannot_launch_runner(self):
        self.assertIsNone(self.ready({'confirmed':{'context_slot':0,'accounts':dict.fromkeys(self.before)},'finalized':self.snapshot()}))
    def test_each_commitment_must_cover_prepare_finalized_slot(self):
        for commitment in ('confirmed','finalized'):
            snapshots={c:self.snapshot()for c in ('confirmed','finalized')};snapshots[commitment]['context_slot']=7
            self.assertIsNone(self.ready(snapshots))
    def test_both_commitments_and_all_four_exact_accounts_required(self):
        self.assertIsNone(self.ready({'confirmed':self.snapshot()}))
        for commitment in ('confirmed','finalized'):
            for name in self.before:
                for field,value in [('data',b'wrong'),('owner','attacker'),('executable',True)]:
                    snapshots={c:self.snapshot()for c in ('confirmed','finalized')};snapshots[commitment]['accounts'][name][field]=value
                    self.assertIsNone(self.ready(snapshots))
    def test_exact_before_pair_releases_runner(self):
        self.assertEqual(self.ready({c:self.snapshot()for c in ('confirmed','finalized')}),'before')
    def test_exact_consumed_pair_allows_zero_execute_reconciliation(self):
        self.assertEqual(self.ready({c:self.snapshot(self.consumed)for c in ('confirmed','finalized')}),'consumed')
    def test_crossed_or_mixed_before_consumed_states_fail_closed(self):
        mixed=copy.deepcopy(self.before);mixed['request']=self.consumed['request']
        self.assertIsNone(self.ready({c:self.snapshot(mixed)for c in ('confirmed','finalized')}))
        self.assertIsNone(self.ready({'confirmed':self.snapshot(self.consumed),'finalized':self.snapshot()}))
    def test_issuer_enrollment_or_any_current_binding_mismatch_is_rejected(self):
        for offset in (40,72,108,140,172,173,181,213,221,229,261,269,277,308):
            changed=copy.deepcopy(self.consumed);data=bytearray(changed['issuer']['data']);data[offset]^=1;changed['issuer']['data']=bytes(data)
            self.assertIsNone(self.ready({c:self.snapshot(changed)for c in ('confirmed','finalized')}),offset)
        changed=copy.deepcopy(self.consumed);data=bytearray(changed['issuer']['data']);data[277]^=1;changed['issuer']['data']=bytes(data)
        self.assertIsNone(self.ready({'confirmed':self.snapshot(self.consumed),'finalized':self.snapshot(changed)}))
    def test_waiter_retries_bank_zero_then_returns_exact_commitment_evidence(self):
        def response(slot,missing):
            values=[]
            for account in self.before.values():
                values.append(None if missing else {'owner':account['owner'],'executable':False,'data':[base64.b64encode(account['data']).decode(),'base64']})
            return io.BytesIO(json.dumps([{'id':0,'result':'pinned'},*({'id':i,'result':{'context':{'slot':slot},'value':values}}for i in (1,2))]).encode())
        opener=mock.Mock();opener.open.side_effect=[response(0,True),response(8,False)]
        validator=mock.Mock();validator.poll.return_value=None
        with mock.patch.object(m.time,'sleep'):
            genesis,mode,evidence=m.execute_readiness(opener,'pinned',8,self.states,time.monotonic()+1,validator)
        self.assertEqual((genesis,mode,evidence['attempts']),('pinned','before',2))
        self.assertEqual(evidence['commitments']['confirmed']['context_slot'],8)
        self.assertEqual(opener.open.call_count,2)
    def test_waiter_timeout_raises_before_a_runner_can_be_started(self):
        opener=mock.Mock();validator=mock.Mock();launched=[]
        with self.assertRaises(TimeoutError):
            m.execute_readiness(opener,'pinned',8,self.states,time.monotonic()-1,validator)
            launched.append(True)
        self.assertEqual(launched,[]);opener.open.assert_not_called()
    def test_consumed_only_gate_rejects_before_and_mixed_modes_before_runner(self):
        for mode in ('before',None,'mixed'):
            with self.assertRaises(ValueError):m.require_consumed_readiness({'reconciliation_only':True},mode)
        self.assertIsNone(m.require_consumed_readiness({'reconciliation_only':True},'consumed'))
        self.assertIsNone(m.require_consumed_readiness({},'before'))
    def test_consumed_only_config_cannot_use_truthy_nonboolean_value(self):
        for value in ('true',1,None):
            with self.assertRaises(ValueError):m.require_consumed_readiness({'reconciliation_only':value},'consumed')
    def test_fresh_reconciliation_report_requires_exact_hashes_and_zero_transactions(self):
        config={'review_assertions':{'expected_consumed_request_sha256':'aa'*32,'expected_one_entry_queue_sha256':'bb'*32}}
        report={'passed':True,'finalized_slot':50,'effect_count':1,'new_execute_transactions':0,'loaded_program':{'elf_match':True},'request_sha256':'aa'*32,'queue_sha256':'bb'*32}
        m.validate_reconciled_report(report,config)
        for field,value in [('request_sha256','cc'*32),('queue_sha256','cc'*32),('new_execute_transactions',1),('effect_count',2),('finalized_slot',True)]:
            changed={**report,field:value}
            with self.assertRaises(ValueError):m.validate_reconciled_report(changed,config)
        for field in ('request_sha256','queue_sha256'):
            changed=dict(report);del changed[field]
            with self.assertRaises(ValueError):m.validate_reconciled_report(changed,config)
    def test_consumed_only_requires_new_reconciliation_report_after_runner_exit(self):
        with tempfile.TemporaryDirectory()as directory:
            private=Path(directory);(private/'execute-report.json').write_text('{"passed":true}')
            with self.assertRaises(ValueError):m.select_runner_report({'reconciliation_only':True},'execute',private)
            (private/'reconciled-report.json').write_text('{"passed":true}')
            self.assertEqual(m.select_runner_report({'reconciliation_only':True},'execute',private),('reconciled-report.json',True))
            self.assertEqual(m.select_runner_report({},'prepare',private),('prepare-report.json',False))
    def test_normal_execute_preserves_report_selection(self):
        with tempfile.TemporaryDirectory()as directory:
            private=Path(directory)
            self.assertEqual(m.select_runner_report({},'execute',private),('execute-report.json',False))
            (private/'reconciled-report.json').write_text('{}')
            self.assertEqual(m.select_runner_report({},'execute',private),('reconciled-report.json',True))
    def test_wrong_genesis_never_releases_runner(self):
        self.assertIsNone(self.ready({c:self.snapshot()for c in ('confirmed','finalized')},'other'))
if __name__=='__main__':unittest.main()
