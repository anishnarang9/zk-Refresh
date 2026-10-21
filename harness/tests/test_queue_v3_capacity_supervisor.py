import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from harness.tests import queue_v3_local_queue_capacity_negative as m


class IntegratedCapacitySupervisorTests(unittest.TestCase):
    def test_integrated_entrypoint_delegates_to_finite_supervisor_without_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'config.json'
            config = dict(schema=m.CONFIG_SCHEMA, scope=m.SCOPE, control_output='/control')
            raw = json.dumps(config).encode(); path.write_bytes(raw)
            pin = {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}
            supervise = Mock(return_value=0)
            with patch.dict(os.environ, P5_V3_QUEUE_CAPACITY_NEGATIVE_SCOPE=m.SCOPE), \
                    patch.object(m, '_validate_config'), patch.object(m, '_require_rust_entrypoint'), \
                    patch.object(m, 'runtime', SimpleNamespace(supervise=supervise), create=True), \
                    patch.object(m, '_write_integration_failure') as blocker:
                self.assertEqual(m.run(config, pin['sha256'], path), 0)
            blocker.assert_not_called()
            supervise.assert_called_once()
            args = supervise.call_args.args
            self.assertEqual(args[:3], (config, pin, 'queue-capacity-negative-report.json'))
            self.assertTrue(callable(args[3]))

    def test_live_replay_retains_private_signed_rpc_transactions_for_external_finalizer(self):
        self.assertTrue(hasattr(m, '_verify_runtime'), 'capacity live RPC verification callback missing')
        from tools.part5 import finalize_v3_queue_capacity_negative as finalizer
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve(); output.chmod(0o700)
            config = dict(rust_config_path='/rust.json', rust_config_sha256='a' * 64)
            report = dict(runner_test=m.RUST_TEST, config_ref={'path':'/rust.json','sha256':'a'*64})
            rows = [{'signature':'signature', 'slot':7}]
            with patch.object(finalizer, 'replay_runtime', return_value=({'projection':True}, rows)) as replay:
                receipt = m._verify_runtime(object(), report, config, output, {'loaded':True}, 123)
            self.assertEqual(json.loads(Path(receipt['path']).read_bytes())['transactions'], rows)
            self.assertEqual(hashlib.sha256(Path(receipt['path']).read_bytes()).hexdigest(), receipt['sha256'])
            self.assertEqual(Path(receipt['path']).stat().st_mode & 0o777, 0o600)
            self.assertEqual((output/'rpc').stat().st_mode & 0o777, 0o700)
            self.assertEqual(replay.call_args.kwargs['runner_pid'], 123)
            self.assertIsNotNone(replay.call_args.kwargs['rpc'])

    def test_runtime_rejects_unbound_rust_config_before_rpc_replay(self):
        self.assertTrue(hasattr(m, '_verify_runtime'), 'capacity live RPC verification callback missing')
        with tempfile.TemporaryDirectory() as directory:
            config = dict(rust_config_path='/rust.json', rust_config_sha256='a'*64)
            for report in ({'runner_test':'wrong'}, {'runner_test':m.RUST_TEST,'config_ref':{}}):
                with self.subTest(report=report), self.assertRaises(ValueError):
                    m._verify_runtime(None, report, config, Path(directory).resolve(), {}, 1)

    def test_signed_credential_validity_bounds_every_declared_request_and_wire(self):
        self.assertTrue(hasattr(m, '_validate_signed_validity'), 'signed capacity validity admission missing')
        from tools.part5 import credential_profile as profile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); root.chmod(0o700)
            def artifact(name, raw):
                path=root/name; path.write_bytes(raw); path.chmod(0o600)
                return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
            der=b'actual pinned signed DER'
            der_ref=artifact('certificate.der',der)
            modulus=artifact('modulus.bin',bytes([0x81])+bytes(255))
            parsed={'not_before':100,'not_after':10000,'variant':0}
            cohort={'schema':'credential-v3-heldout-issuance-cohort-v1','certificates':[
                {'variant':0,'credential_sha256':der_ref['sha256'], 'not_before_unix':100,
                 'not_after_unix':10000,'issuer_hash':'1','policy_hash':'2'}]}
            cohort_ref=artifact('cohort.json',json.dumps(cohort).encode())
            config={'cohort_manifest':cohort_ref['path'],'cohort_manifest_sha256':cohort_ref['sha256']}
            proof_config={'credential_source':{'credential':der_ref,'issuer_modulus':modulus}}
            prepared={'credential_not_after':10000,'request_deadline':9000}
            request=bytearray(2249); request[:8]=b'DYNREQ03';request[183]=1
            request[170:178]=(9000).to_bytes(8,'big')
            request_ref=artifact('request.bin',request)
            wire=(0).to_bytes(32,'big')+(1).to_bytes(32,'big')+(100).to_bytes(32,'big')
            wire+=(10000).to_bytes(32,'big')+bytes(32)+(2).to_bytes(32,'big')+bytes(256)
            wire_ref=artifact('wire.bin',wire)
            row={'request_account':request_ref['path'],'request_sha256':request_ref['sha256'],
                 'full_wire':wire_ref['path'],'full_wire_sha256':wire_ref['sha256']}
            with patch.object(profile,'admit_certificate',return_value=parsed) as admit, \
                    patch.object(profile,'public_bindings',return_value=(1,2)), patch.object(m.time,'time',return_value=1000):
                m._validate_signed_validity(config,prepared,proof_config,[row]*65)
                self.assertEqual(admit.call_args.args[0],der)
                for mutation in ('declared_not_after','deadline','wire','cohort'):
                    with self.subTest(mutation=mutation):
                        wrong=dict(prepared)
                        if mutation=='declared_not_after': wrong['credential_not_after']=20000
                        if mutation=='deadline': wrong['request_deadline']=11000
                        if mutation=='wire':
                            changed=wire[:96]+(20000).to_bytes(32,'big')+wire[128:]
                            new=artifact('changed-wire.bin',changed)
                            changed_row={**row,'full_wire':new['path'],'full_wire_sha256':new['sha256']}
                        else: changed_row=row
                        if mutation=='cohort':
                            cohort['certificates'][0]['not_after_unix']=20000
                            new=artifact('changed-cohort.json',json.dumps(cohort).encode())
                            changed_config={**config,'cohort_manifest':new['path'],'cohort_manifest_sha256':new['sha256']}
                        else: changed_config=config
                        with self.assertRaises(ValueError):
                            m._validate_signed_validity(changed_config,wrong,proof_config,[changed_row]*65)

    def test_owned_lifecycle_preserves_sigint_and_pending_external_finalization(self):
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory).resolve(); artifacts=repo/'artifacts/dynark/part5'
            artifacts.mkdir(parents=True,mode=0o700)
            ledger=repo/'ledger';ledger.mkdir(mode=0o700)
            config=dict(scope=m.SCOPE,output_dir=str(artifacts/'queue-capacity-output'),
                        control_output=str(artifacts/'queue-capacity-control'),ledger=str(ledger),
                        validator='/validator',validator_sha256='a'*64,runner='/runner',runner_sha256='b'*64,
                        expected_elf='/program.so',expected_elf_sha256='c'*64,
                        expected_program='program',expected_genesis='genesis',
                        rust_config_path='/rust.json',rust_config_sha256='d'*64)
            class Proc:
                def __init__(self,pid,code):self.pid=pid;self.code=code
                def poll(self):return self.code
                def wait(self,timeout=None):return self.code
                def send_signal(self,sig):self.code=-sig
            validator,runner=Proc(100,None),Proc(101,0)
            commands=[]
            def spawn(argv,**kwargs):
                commands.append((argv,kwargs['env']))
                if len(commands)==1:return validator
                report=Path(config['output_dir'])/'queue-capacity-negative-report.json'
                report.write_text('{}');report.chmod(0o600)
                return runner
            loaded={'genesis':'genesis','elf_match':True}
            verify=Mock(return_value={'path':'/private/rpc-rechecks.json','sha256':'e'*64})
            with patch.object(m.execute,'REPO',repo),patch.object(m.execute.base,'ports_free'), \
                    patch.object(m.execute.base,'checked',return_value=b'elf'), \
                    patch.object(m.runtime.subprocess,'Popen',side_effect=spawn), \
                    patch.object(m.execute,'wait_loaded_after_start',return_value=loaded), \
                    patch.object(m.execute,'same_loaded'):
                result=m.runtime.supervise(config,{'path':'/config','sha256':'f'*64},
                                           'queue-capacity-negative-report.json',verify)
            self.assertEqual(result,0)
            status=json.loads((Path(config['control_output'])/'status.json').read_bytes())
            self.assertEqual(status['status'],'candidate_verified_pending_external_finalization')
            self.assertEqual(status['validator_cleanup']['exit_code'],-2)
            self.assertFalse(status['validator_cleanup']['graceful'])
            self.assertEqual(status['runner_cleanup']['exit_code'],0)
            self.assertTrue(status['external_finalization_required'])
            self.assertEqual(status['whole_tree_cleanup_authority'],'external bounded_runner')
            self.assertNotIn('--reset',commands[0][0])
            self.assertEqual(commands[1][0][1],m.RUST_TEST)
            self.assertEqual(commands[1][1]['P5_V3_QUEUE_CAPACITY_NEGATIVE_CONFIG_SHA256'],'d'*64)

    def test_prepared_binding_rejects_disconnected_ledger_fixture_and_partial_proofs(self):
        self.assertTrue(hasattr(m,'_validate_prepared_binding'),'prepared capacity clone admission missing')
        from tools.part5 import finalize_v3_queue_capacity_negative as finalizer
        from tools.part5 import prepare_v3_queue_capacity_fixture as producer
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700)
            def write(name,value):
                path=root/name;raw=json.dumps(value).encode();path.write_bytes(raw);path.chmod(0o600)
                return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
            stage_ref=write('baseline.json',{})
            freeze=write('freeze.json',{})
            inputs=[{'request_address':f'request-{j}','action_sha256':f'{j:064x}',
                     'request_account':f'/request-{j}','request_sha256':'b'*64,
                     'full_wire':f'/wire-{j}','full_wire_sha256':'c'*64,
                     'proof_receipt':f'/proof-{j}','proof_receipt_sha256':'d'*64} for j in range(65)]
            source=root/'source'/'ledger'
            stage_config=dict(schema=producer.SCHEMA,phase='stage',ledger=str(source),
                              output_dir=str(root),control_output=str(root),
                              baseline_stage_report=stage_ref,rust_config_path='/stage-rust',rust_config_sha256='e'*64,
                              expected_program='program',expected_genesis='genesis',expected_elf_sha256='f'*64)
            stage_config_ref=write('stage-config.json',stage_config)
            prepared=dict(schema=producer.PREPARATION_SCHEMA,passed=True,request_count=65,queue_empty=True,
                          program='program',genesis='genesis',stage_report_sha256=stage_ref['sha256'],
                          config_ref={'path':'/stage-rust','sha256':'e'*64},
                          inputs=[{**{k:row[k] for k in ('request_address','action_sha256','request_account','request_sha256')},
                                   'finalization':{'signature':f'signature-{j}','slot':j+1}} for j,row in enumerate(inputs)])
            prepared_ref=write('capacity-preparation-report.json',prepared)
            status_ref=write('status.json',{'schema':1,'scope':'part5-v3-queue-capacity-stage',
                'output_dir':str(root),'status':'candidate_verified_pending_external_finalization',
                'candidate_verified':True,'error_type':None,'candidate':prepared_ref,'config_ref':stage_config_ref,
                'runner_cleanup':{'reaped':True,'exit_code':0},'validator_cleanup':{'reaped':True,'exit_code':-2}})
            monitor_ref=write('monitor.json',{});invocation_ref=write('invocation.json',{})
            proof_config_ref=write('proof-config.json',dict(schema=producer.SCHEMA,phase='proofs',
                baseline_stage_report=stage_ref,preparation_report=prepared_ref,stage_config=stage_config_ref,
                stage_status=status_ref,stage_monitor=monitor_ref,stage_invocation=invocation_ref,freeze=freeze))
            fixture=dict(schema=producer.FIXTURE_SCHEMA,program='program',genesis='genesis',genesis_sha256='a'*64,
                elf_sha256='f'*64,stage_report=stage_ref,inputs=inputs,
                request_finalizations=[{'request_address':row['request_address'],'signature':f'signature-{j}','slot':j+1}
                                       for j,row in enumerate(inputs)])
            fixture_ref=write('fixture.json',fixture)
            receipt=dict(schema='part5-v3-queue-capacity-prepared-fixture-v1',config_ref=proof_config_ref,
                fixture_manifest=fixture_ref,preparation_report=prepared_ref,prepared_ledger=str(source),
                stage_config=stage_config_ref,stage_status=status_ref,stage_monitor=monitor_ref,
                stage_invocation=invocation_ref,freeze=freeze,
                proof_receipts=[{'path':row['proof_receipt'],'sha256':row['proof_receipt_sha256']} for row in inputs])
            receipt_ref=write('preparation-receipt.json',receipt)
            config=dict(fixture_manifest=fixture_ref['path'],fixture_manifest_sha256=fixture_ref['sha256'],
                preparation_receipt=receipt_ref['path'],preparation_receipt_sha256=receipt_ref['sha256'],
                stage_report=stage_ref['path'],stage_report_sha256=stage_ref['sha256'],
                stage_config=stage_config_ref['path'],stage_config_sha256=stage_config_ref['sha256'],
                stage_status=status_ref['path'],stage_status_sha256=status_ref['sha256'],
                cohort_freeze=freeze['path'],cohort_freeze_sha256=freeze['sha256'],expected_program='program',
                expected_genesis='genesis',expected_genesis_sha256='a'*64,expected_elf_sha256='f'*64,inputs=inputs)
            clone=dict(preparation_receipt_sha256=receipt_ref['sha256'],fixture_manifest_sha256=fixture_ref['sha256'],
                       stage_report_sha256=stage_ref['sha256'],stage_status_sha256=status_ref['sha256'])
            read_pinned=m._read_pinned
            with patch.object(finalizer,'check_monitor'),patch.object(m,'_validate_signed_validity'), \
                    patch.object(m,'_read_ref',side_effect=lambda ref,cap,label: json.dumps({}).encode()
                                 if label=='capacity proof receipt' else Path(ref['path']).read_bytes()), \
                    patch.object(m,'_read_pinned',side_effect=lambda path,*args,**kwargs: bytes(448)
                                 if str(path).startswith('/wire-') else read_pinned(path,*args,**kwargs)), \
                    patch.object(producer,'check_proof_receipt'), \
                    patch.object(m,'_validate_inputs',return_value=inputs):
                m._validate_prepared_binding(config,clone,source)
                with self.assertRaises(ValueError):m._validate_prepared_binding(config,clone,root/'other'/'ledger')
                changed_stage={**stage_config,'output_dir':str(root/'unmeasured-output')}
                changed_stage_ref=write('disconnected-stage-config.json',changed_stage)
                changed_receipt={**receipt,'stage_config':changed_stage_ref}
                changed_receipt_ref=write('disconnected-prep-receipt.json',changed_receipt)
                changed_config={**config,'stage_config':changed_stage_ref['path'],
                    'stage_config_sha256':changed_stage_ref['sha256'],
                    'preparation_receipt':changed_receipt_ref['path'],
                    'preparation_receipt_sha256':changed_receipt_ref['sha256']}
                with self.assertRaises(ValueError):m._validate_prepared_binding(changed_config,clone,source)
                changed={**clone,'fixture_manifest_sha256':'0'*64}
                with self.assertRaises(ValueError):m._validate_prepared_binding(config,changed,source)
                receipt['proof_receipts']=receipt['proof_receipts'][:1]
                changed_ref=write('partial-receipt.json',receipt)
                changed={**config,'preparation_receipt':changed_ref['path'],
                         'preparation_receipt_sha256':changed_ref['sha256']}
                with self.assertRaises(ValueError):m._validate_prepared_binding(changed,clone,source)


if __name__ == '__main__':
    unittest.main()
