import copy
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import generate_v3_heldout_keys as keys
from tools.part5 import prepare_v3_heldout_context as context
from tools.part5 import prepare_v3_heldout_source as source
from tools.part5.prepare_v3_revocation_cohort import membership_for_pair


class RelationInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.out = self.root / 'out'
        self.rows = []
        for i in range(8):
            self.rows.append(dict(variant=i, issuer_index=i % 4, holder_index=i,
                credential_sha256=f'{i+50:064x}', tbs_sha256=source.digest(bytes([i])*10),
                issuer_public_key_sha256=f'{i%4+1:064x}', holder_public_key_sha256=f'{i+100:064x}',
                aki_sha256=f'{i%4+200:064x}', issuer_hash=str(i%4+1000),
                policy_hash=str(i//4+2000), not_before_unix=100, not_after_unix=200,
                encoder='openssl' if i < 4 else 'cryptography'))
        freeze = dict(schema=keys.FREEZE_SCHEMA, frozen_at_unix_ns=1,
            issuance_tool_sha256=keys.file_sha(keys.ISSUANCE_TOOL),
            key_generation_tool_sha256=keys.file_sha(Path(keys.__file__)),
            identities={role:'a'*64 for role in keys.IDENTITY_ROLES},
            forbidden_public_key_sha256=['b'*64])
        self.freeze = self.write('freeze.json', freeze)
        cohort = dict(schema=context.COHORT_SCHEMA,status='cohort_issued_pending_application_gate',
            keys_generated_after_freeze=True,freeze_sha256=self.freeze['sha256'],
            frozen_at_unix_ns=1,generation_started_unix_ns=2,generation_completed_unix_ns=3,
            counts=dict(issuers=4,holders=8,certificates=8,openssl_issuances=4,policies=2),
            policy_hashes=['2000','2001'],issuer_aki_sha256=sorted({r['aki_sha256'] for r in self.rows}),
            certificates=self.rows)
        self.cohort = self.write('cohort.json',cohort)
        self.cases=[]
        for i,row in enumerate(self.rows):
            other=self.rows[i^4]
            digest=bytes.fromhex(row['tbs_sha256'])
            m=membership_for_pair(digest,bytes.fromhex(other['tbs_sha256']),int.from_bytes(digest[:2],'big')&1023)
            roots={k:f"{m[v]:064x}" for k,v in [('R0','active_root'),('R1','unrelated_root'),('R2','own_revoked_root')]}
            membership=dict(slot=m['slot'],unrelated_slot=m['unrelated_slot'],**roots,
                active_siblings=m['active_siblings'],unrelated_siblings=m['unrelated_siblings'],own_revoked_siblings=m['own_revoked_siblings'])
            ctx=dict(schema=context.CASE_SCHEMA,heldout_acceptance=False,
                frozen_cohort=dict(schema=context.COHORT_SCHEMA,freeze_sha256=self.freeze['sha256'],cohort_receipt_sha256=self.cohort['sha256']),
                target=context._public_certificate(row),unrelated=context._public_certificate(other),membership=membership,
                pair_view=dict(cohort_receipt_sha256='c'*64,membership_sha256='d'*64,stage_context_sha256='e'*64))
            cp=self.write(f'context-{i}.json',ctx)
            case=dict(case_index=i,context=cp)
            for variant,sibling in [('R0','active_siblings'),('R1','unrelated_siblings')]:
                inp={k:'0' for k in ['root','issuerHash','notBefore','notAfter','actionHash','policyHash','layout','slot']}
                inp.update(root=str(int(roots[variant],16)),issuerHash=row['issuer_hash'],policyHash=row['policy_hash'],
                    notBefore='100',notAfter='200',actionHash='123',slot=str(m['slot']))
                for name,n in [('tbs',672),('issuerModulus',17),('issuerSignature',17),('holderSignature',17)]: inp[name]=['0']*n
                inp['siblings']=list(map(str,m[sibling])); inp['pathIndices']=[str((m['slot']>>b)&1) for b in range(10)]
                ip=self.write(f'input-{i}-{variant}.json',inp)
                receipt=dict(schema=source.SCHEMA,variant=variant,case_index=i,target_variant=i,unrelated_variant=i^4,
                    freeze_sha256=self.freeze['sha256'],cohort_receipt_sha256=self.cohort['sha256'],
                    case_context_sha256=cp['sha256'],context_sha256=cp['sha256'],
                    pair_receipt_sha256='c'*64,membership_sha256='d'*64,stage_context_sha256='e'*64,
                    membership_roots=roots,selected_root=roots[variant],action_hash=f'{123:064x}',
                    artifacts_sha256={'input.json':ip['sha256']},proof_created=False,application_effect=False,live_state_authenticated=False,
                    issuer_index=row['issuer_index'],holder_index=row['holder_index'],target_der_sha256=row['credential_sha256'],
                    target_tbs_sha256=row['tbs_sha256'],unrelated_der_sha256=other['credential_sha256'],
                    issuer_public_key_sha256=row['issuer_public_key_sha256'],holder_public_key_sha256=row['holder_public_key_sha256'],
                    stage_report_sha256='1'*64,stage_plan_sha256='2'*64,staged_request_sha256='3'*64,
                    finalized_action_transport_sha256='4'*64,transition_report_sha256=None if variant=='R0' else '5'*64,
                    transition_context_sha256=None if variant=='R0' else '6'*64)
                if variant=='R1':receipt['r0_source_receipt_sha256']=case['R0']['receipt']['sha256']
                case[variant]=dict(receipt=self.write(f'receipt-{i}-{variant}.json',receipt),input=ip)
            self.cases.append(case)
        self.manifest=dict(schema='credential-v3-heldout-relation-inputs-v2',freeze=self.freeze,cohort=self.cohort,cases=self.cases)

    def write(self,name,value):
        p=self.root/name
        raw=source.encoded(value);p.write_bytes(raw);p.chmod(0o600)
        return dict(path=str(p),sha256=source.digest(raw))

    def run_bridge(self):
        pin=self.write('manifest.json',self.manifest)
        tool=importlib.import_module('tools.part5.prepare_v3_heldout_relation_inputs_v2')
        return tool.prepare(Path(pin['path']),pin['sha256'],self.out)

    def test_copies_exact_original_inputs_and_manifest(self):
        self.run_bridge()
        self.assertEqual(os.stat(self.out).st_mode&0o777,0o700)
        expected=[]
        for i,case in enumerate(self.cases):
            for variant,suffix in [('R0',''),('R1','_unrelated_refresh')]:
                name=f'holdout_{i}{suffix}'
                self.assertEqual((self.out/(name+'.input.json')).read_bytes(),Path(case[variant]['input']['path']).read_bytes())
                self.assertEqual(os.stat(self.out/(name+'.input.json')).st_mode&0o777,0o600)
                expected.append(dict(name=name,expect='accept',family='heldout'))
        self.assertEqual(json.loads((self.out/'cases.json').read_bytes()),expected)
        self.assertEqual(len(list(self.out.iterdir())),17)

    def test_rejects_changed_original_input_before_output(self):
        Path(self.cases[0]['R0']['input']['path']).write_bytes(b'{}')
        with self.assertRaises(ValueError):self.run_bridge()
        self.assertFalse(self.out.exists())

    def test_rejects_re_pinned_action_or_non_root_changes(self):
        for field in ['actionHash','holderSignature']:
            with self.subTest(field=field):
                item=self.cases[0]['R1'];original=copy.deepcopy(item)
                inp=json.loads(Path(item['input']['path']).read_bytes())
                inp[field]='124' if field=='actionHash' else ['1']*17
                item['input']=self.write('bad-input.json',inp)
                receipt=json.loads(Path(item['receipt']['path']).read_bytes())
                receipt['artifacts_sha256']['input.json']=item['input']['sha256']
                item['receipt']=self.write('bad-receipt.json',receipt)
                with self.assertRaises(ValueError):self.run_bridge()
                self.assertFalse(self.out.exists())
                item.clear();item.update(original)

    def test_rejects_wrong_external_manifest_pin(self):
        pin=self.write('manifest.json',self.manifest)
        tool=importlib.import_module('tools.part5.prepare_v3_heldout_relation_inputs_v2')
        with self.assertRaises(ValueError):tool.prepare(Path(pin['path']),'0'*64,self.out)
        self.assertFalse(self.out.exists())

    def test_rejects_re_pinned_wrong_r0_link(self):
        item=self.cases[0]['R1']
        receipt=json.loads(Path(item['receipt']['path']).read_bytes())
        receipt['r0_source_receipt_sha256']='0'*64
        item['receipt']=self.write('wrong-link.json',receipt)
        with self.assertRaises(ValueError):self.run_bridge()
        self.assertFalse(self.out.exists())

    def test_rejects_re_pinned_context_root(self):
        case=self.cases[0]
        ctx=json.loads(Path(case['context']['path']).read_bytes())
        ctx['membership']['R1']='0'*64
        case['context']=self.write('wrong-context.json',ctx)
        with self.assertRaises(ValueError):self.run_bridge()
        self.assertFalse(self.out.exists())

    def test_rejects_existing_output_without_touching_it(self):
        self.out.mkdir(mode=0o700)
        sentinel=self.out/'keep';sentinel.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.run_bridge()
        self.assertEqual(sentinel.read_bytes(),b'keep')

    def test_preserves_partial_private_output_when_write_fails(self):
        tool=importlib.import_module('tools.part5.prepare_v3_heldout_relation_inputs_v2')
        original_write=tool._write_new_at
        calls=0
        def fail_after_first_copy(directory_fd, name, raw):
            nonlocal calls
            calls+=1
            if calls==1:
                original_write(directory_fd,name,raw)
                (next(self.root.glob('.v3-heldout-relation-*.pending'))/'keep').write_bytes(b'private evidence')
            else:
                raise OSError('injected publication failure')
        with mock.patch.object(tool,'_write_new_at',side_effect=fail_after_first_copy):
            with self.assertRaisesRegex(OSError,'injected publication failure'):
                self.run_bridge()
        self.assertEqual(calls,2)
        self.assertFalse(self.out.exists())
        staged=next(self.root.glob('.v3-heldout-relation-*.pending'))
        self.assertEqual((staged/'holdout_0.input.json').read_bytes(),
                         Path(self.cases[0]['R0']['input']['path']).read_bytes())
        self.assertEqual((staged/'keep').read_bytes(),b'private evidence')

    def test_rejects_staging_swap_after_private_directory_check(self):
        original_private_dir=source.private_dir
        moved=self.root/'moved-output'
        swapped=False
        def swap_after_check(path, **kwargs):
            nonlocal swapped
            result=original_private_dir(path,**kwargs)
            if Path(path).name.startswith('.v3-heldout-relation-') and not swapped:
                Path(path).rename(moved)
                Path(path).mkdir(mode=0o700)
                (Path(path)/'keep').write_bytes(b'preexisting private data')
                swapped=True
            return result
        with mock.patch.object(source,'private_dir',side_effect=swap_after_check):
            with self.assertRaisesRegex(ValueError,'output directory changed'):
                self.run_bridge()
        self.assertTrue(swapped)
        self.assertFalse(self.out.exists())
        self.assertEqual((next(self.root.glob('.v3-heldout-relation-*.pending'))/'keep').read_bytes(),
                         b'preexisting private data')
        self.assertEqual(list(moved.iterdir()),[])

    def test_rejects_staging_swap_after_first_file_flush(self):
        original_fsync=os.fsync
        moved=self.root/'moved-output'
        swapped=False
        def swap_after_first_flush(fd):
            nonlocal swapped
            original_fsync(fd)
            if not swapped:
                staged=next(self.root.glob('.v3-heldout-relation-*.pending'))
                staged.rename(moved)
                staged.mkdir(mode=0o700)
                (staged/'keep').write_bytes(b'preexisting private data')
                swapped=True
        with mock.patch.object(os,'fsync',side_effect=swap_after_first_flush):
            with self.assertRaisesRegex(ValueError,'output directory changed'):
                self.run_bridge()
        self.assertTrue(swapped)
        self.assertFalse(self.out.exists())
        self.assertEqual((next(self.root.glob('.v3-heldout-relation-*.pending'))/'keep').read_bytes(),
                         b'preexisting private data')
        self.assertEqual((moved/'holdout_0.input.json').read_bytes(),
                         Path(self.cases[0]['R0']['input']['path']).read_bytes())
        self.assertEqual(len(list(moved.iterdir())),1)

    def test_does_not_reserve_exposed_output_before_pinning(self):
        original_mkdir=Path.mkdir
        moved=self.root/'moved-output'
        swapped=False
        def swap_immediately_after_mkdir(path, *args, **kwargs):
            nonlocal swapped
            result=original_mkdir(path,*args,**kwargs)
            if Path(path)==self.out:
                self.out.rename(moved)
                original_mkdir(self.out,mode=0o700)
                swapped=True
            return result
        with mock.patch.object(Path,'mkdir',new=swap_immediately_after_mkdir):
            self.run_bridge()
        self.assertFalse(swapped)
        self.assertFalse(moved.exists())

    def test_atomic_publication_refuses_raced_existing_output(self):
        tool=importlib.import_module('tools.part5.prepare_v3_heldout_relation_inputs_v2')
        original_rename=tool._rename_no_replace
        def race_output_into_place(parent_fd, staged_name, output_name):
            self.out.mkdir(mode=0o700)
            (self.out/'keep').write_bytes(b'preexisting private data')
            original_rename(parent_fd,staged_name,output_name)
        with mock.patch.object(tool,'_rename_no_replace',side_effect=race_output_into_place):
            with self.assertRaises(OSError) as error:
                self.run_bridge()
        self.assertEqual(error.exception.errno,errno.EEXIST)
        self.assertEqual((self.out/'keep').read_bytes(),b'preexisting private data')
        staged=next(self.root.glob('.v3-heldout-relation-*.pending'))
        self.assertEqual(len(list(staged.iterdir())),17)

    def test_rejects_symlink_and_loose_source_permissions(self):
        item=self.cases[0]['R0']
        original=copy.deepcopy(item['input'])
        path=Path(original['path'])
        path.chmod(0o644)
        with self.assertRaises(ValueError):self.run_bridge()
        path.chmod(0o600)
        link=self.root/'linked-input.json';link.symlink_to(path)
        item['input']=dict(path=str(link),sha256=original['sha256'])
        with self.assertRaises(ValueError):self.run_bridge()
        self.assertFalse(self.out.exists())

    def test_rejects_missing_or_duplicate_case(self):
        self.manifest['cases'][-1]=self.manifest['cases'][0]
        with self.assertRaises(ValueError):self.run_bridge()
        self.assertFalse(self.out.exists())


if __name__=='__main__':unittest.main()
