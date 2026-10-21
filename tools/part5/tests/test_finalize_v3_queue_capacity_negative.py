"""Focused replay checks using genuinely signed local refresh transactions."""

import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from harness.tests import queue_v3_capacity_runtime as runtime
from harness.tests import queue_v3_local_queue_capacity_negative as supervisor
from tools.part5 import finalize_v3_queue_capacity_negative as finalizer


def be(value):
    return value.to_bytes(8, "big", signed=True)


def short(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def public_key(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


def signed_data(payer, signer, keys, header, application_indexes, data, program_index, budget_index):
    message = bytes(header) + short(len(keys)) + b"".join(keys) + bytes(32)
    budget_data = b"\x02" + (1_000_000).to_bytes(4, "little")
    budget = bytes([budget_index]) + short(0) + short(len(budget_data)) + budget_data
    application = (bytes([program_index]) + short(len(application_indexes))
                   + bytes(application_indexes) + short(len(data)) + data)
    message += short(2) + budget + application
    signatures = [key.sign(message) for key in (payer, signer)]
    raw = short(2) + b"".join(signatures) + message
    return supervisor.execute.base.b58(signatures[0]), raw


class SignedRefreshCase(unittest.TestCase):
    def setUp(self):
        self.payer = Ed25519PrivateKey.generate()
        self.source = Ed25519PrivateKey.generate()
        self.publisher = Ed25519PrivateKey.generate()
        self.config_key = bytes([21]) * 32
        self.issuer_key = bytes([22]) * 32
        self.head_key = bytes([23]) * 32
        self.program_key = bytes([24]) * 32
        self.budget_key = supervisor.execute.base.key(
            "ComputeBudget111111111111111111111111111111")
        self.system_key = bytes(32)
        self.program = supervisor.execute.base.b58(self.program_key)
        self.config_address = supervisor.execute.base.b58(self.config_key)
        self.issuer_address = supervisor.execute.base.b58(self.issuer_key)
        self.head_address = supervisor.execute.base.b58(self.head_key)
        self.source_address = supervisor.execute.base.b58(public_key(self.source))
        self.publisher_address = supervisor.execute.base.b58(public_key(self.publisher))
        self.root = bytes([31]) * 32
        self.issuer_hash = bytes([32]) * 32
        self.source_digest = bytes([33]) * 32
        self.envelope_digest = bytes([34]) * 32
        config = bytearray(381)
        config[:8] = b"DYNCONF3"
        config[332:364] = self.root
        config[372:380] = be(4)
        config[380] = 1
        issuer = bytearray(374)
        issuer[:8] = b"DYNISS03"
        issuer[8:40] = self.config_key
        issuer[40:72] = self.issuer_hash
        issuer[140:172] = public_key(self.source)
        issuer[172] = 1
        issuer[173:181] = be(1)
        issuer[181:213] = self.source_digest
        issuer[213:221] = be(100)
        issuer[221:229] = be(400)
        issuer[229:261] = self.root
        issuer[269:277] = be(1)
        issuer[277:309] = self.source_digest
        issuer[349:357] = be(4)
        issuer[357] = 1
        issuer[358:366] = be(2)
        issuer[366:374] = be(2)
        head = bytearray(280)
        head[:8] = b"DYNHEAD3"
        head[8:40] = self.config_key
        head[40:72] = self.issuer_key
        head[72:104] = public_key(self.publisher)
        head[104:112] = be(1)
        head[112:144] = self.envelope_digest
        head[176:208] = self.root
        head[216:224] = be(1)
        head[224:256] = self.source_digest
        head[256:264] = be(4)
        head[264:272] = be(2)
        head[272:280] = be(100)
        self.staged = {"config": bytes(config), "issuer": bytes(issuer), "head": bytes(head)}

    def sign_refresh(self, source_data, bind_data, source_slot, bind_slot, observed):
        payer = public_key(self.payer)
        source_key = public_key(self.source)
        publisher_key = public_key(self.publisher)
        source_keys = [payer, source_key, self.issuer_key, self.config_key,
                       self.program_key, self.budget_key]
        source_metas = [(self.source_address, True, False),
                        (self.config_address, False, False),
                        (self.issuer_address, False, True)]
        source_signature, source_raw = signed_data(self.payer, self.source, source_keys,
                                                   (2, 1, 3), (1, 3, 2), source_data, 4, 5)
        checked_source = runtime.signed_transaction(source_raw, source_signature,
                                                    self.program, source_data, source_metas)
        bind_keys = [payer, publisher_key, self.issuer_key, self.head_key, self.config_key,
                     self.system_key, self.program_key, self.budget_key]
        bind_metas = [(self.publisher_address, True, True),
                      (self.config_address, False, False),
                      (self.issuer_address, False, True),
                      (self.head_address, False, True),
                      ("11111111111111111111111111111111", False, False)]
        bind_signature, bind_raw = signed_data(self.payer, self.publisher, bind_keys,
                                               (2, 0, 4), (1, 4, 2, 3, 5), bind_data, 6, 7)
        checked_bind = runtime.signed_transaction(bind_raw, bind_signature,
                                                  self.program, bind_data, bind_metas)
        source_result = {"signature": source_signature, "slot": source_slot,
                         "block_time": observed + 1, "rpc_error": None, "finalized": True}
        bind_result = {"signature": bind_signature, "slot": bind_slot,
                       "block_time": observed + 2, "rpc_error": None, "finalized": True}
        refresh = {"observed_at": observed, "expires_at": observed + 300,
                   "source": source_result.copy(), "bind": bind_result.copy()}
        checked = {"source_data": checked_source, "bind_data": checked_bind,
                   "source_result": source_result, "bind_result": bind_result}
        return refresh, checked

    def make_case(self):
        observed = 200
        sequence = 2
        digest = hashlib.sha256(b"part5-v3-queue-capacity-source-v1" + self.root
                                + self.issuer_hash + self.source_digest + be(sequence)
                                + be(observed)).digest()
        envelope = hashlib.sha256(b"part5-v3-queue-capacity-head-v1" + self.root
                                  + self.envelope_digest + digest + be(observed)).digest()
        source_data = (b"\x51\x03" + be(4) + be(2) + be(1) + be(sequence)
                       + digest + b"\x01" + be(observed) + be(observed + 300))
        bind_data = (b"\x51\x0d\x01" + be(4) + be(2) + self.root + be(0)
                     + be(sequence) + digest + be(1) + self.envelope_digest
                     + be(2) + envelope)
        refresh, checked = self.sign_refresh(source_data, bind_data, 10, 11, observed)
        issuer = bytearray(self.staged["issuer"])
        issuer[173:181] = be(sequence)
        issuer[181:213] = digest
        issuer[213:221] = be(observed)
        issuer[221:229] = be(observed + 300)
        issuer[269:277] = be(sequence)
        issuer[277:309] = digest
        head = bytearray(self.staged["head"])
        head[104:112] = be(2)
        head[112:144] = envelope
        head[144:176] = self.envelope_digest
        head[216:224] = be(sequence)
        head[224:256] = digest
        head[272:280] = be(observed + 2)
        final = {"config": self.staged["config"], "issuer": bytes(issuer), "head": bytes(head)}
        conditions = {"status_active": True, "issuer_active": True, "head_bound": True,
                      "request_live": True, "full_wire_valid": True,
                      "observed_at": observed, "expires_at": observed + 300,
                      "now": 240, "request_deadline": 900}
        fills = []
        executions = []
        for index in range(64):
            slot = 12 + index
            fills.append({"slot": slot, "preconditions": conditions.copy(),
                          "execution_now": 250, "account_slots": {"before": slot,
                                                                   "after": slot}})
            executions.append({"slot": slot, "block_time": 250})
        rejection = {"slot": 76}
        report = {"refresh_transactions": [refresh], "fill_history": fills,
                  "rejected_request": rejection, "preconditions": conditions.copy(),
                  "execution_now": 250, "account_slots": {"before": 76, "after": 76}}
        executions.append({"slot": 76, "block_time": 250})
        return final, report, [checked], executions

    def test_exact_signed_refresh_and_all_fill_clocks_are_accepted(self):
        self.assertTrue(hasattr(finalizer, "check_refresh_history"))
        final, report, signed, executions = self.make_case()
        finalizer.check_refresh_history(self.staged, final, report, signed, executions)

    def test_chained_windows_use_previous_signed_digests(self):
        final, report, signed, executions = self.make_case()
        observed = 300
        digest = hashlib.sha256(b"part5-v3-queue-capacity-source-v1" + self.root
                                + self.issuer_hash + final["issuer"][181:213]
                                + be(3) + be(observed)).digest()
        envelope = hashlib.sha256(b"part5-v3-queue-capacity-head-v1" + self.root
                                  + final["head"][112:144] + digest + be(observed)).digest()
        source = (b"\x51\x03" + be(4) + be(2) + be(2) + be(3)
                  + digest + b"\x01" + be(observed) + be(600))
        bind = (b"\x51\x0d\x01" + be(4) + be(2) + self.root + be(0)
                + be(3) + digest + be(2) + final["head"][112:144] + be(3) + envelope)
        refresh, checked = self.sign_refresh(source, bind, 44, 45, observed)
        report["refresh_transactions"].append(refresh)
        signed.append(checked)
        issuer, head = bytearray(final["issuer"]), bytearray(final["head"])
        issuer[173:181] = issuer[269:277] = be(3)
        issuer[181:213] = issuer[277:309] = digest
        issuer[213:221], issuer[221:229] = be(observed), be(600)
        head[104:112] = be(3)
        head[144:176], head[112:144] = head[112:144], envelope
        head[216:224], head[224:256], head[272:280] = be(3), digest, be(302)
        final = dict(final, issuer=bytes(issuer), head=bytes(head))
        # Move the latter executions beyond the second source/bind pair.
        for index in range(32, 65):
            row = report["fill_history"][index] if index < 64 else report
            transaction = row if index < 64 else report["rejected_request"]
            slot = index + 14
            transaction["slot"] = slot
            row["account_slots"] = {"before": slot, "after": slot}
            row["preconditions"].update(observed_at=300, expires_at=600, now=310)
            row["execution_now"] = 320
            executions[index] = {"slot": slot, "block_time": 320}
        finalizer.check_refresh_history(self.staged, final, report, signed, executions)
        report["fill_history"][32]["preconditions"]["observed_at"] = 200
        with self.assertRaisesRegex(ValueError, "refresh clock"):
            finalizer.check_refresh_history(self.staged, final, report, signed, executions)

    def test_resigned_source_or_head_argument_changes_are_rejected(self):
        self.assertTrue(hasattr(finalizer, "check_refresh_history"))
        final, report, signed, executions = self.make_case()
        source_data = signed[0]["source_data"]
        bind_data = signed[0]["bind_data"]
        for role, position in (("source", 18), ("source", 50), ("source", 66),
                               ("bind", 19), ("bind", 59), ("bind", 131)):
            with self.subTest(role=role, position=position):
                changed_source, changed_bind = bytearray(source_data), bytearray(bind_data)
                target = changed_source if role == "source" else changed_bind
                target[position] ^= 1
                changed_report = copy.deepcopy(report)
                refresh, checked = self.sign_refresh(bytes(changed_source), bytes(changed_bind),
                                                     10, 11, 200)
                changed_report["refresh_transactions"] = [refresh]
                with self.assertRaisesRegex(ValueError, "signed .* refresh arguments"):
                    finalizer.check_refresh_history(self.staged, final, changed_report,
                                                    [checked], executions)

    def test_every_fill_and_rejection_must_use_active_signed_refresh_clock(self):
        self.assertTrue(hasattr(finalizer, "check_refresh_history"))
        final, report, signed, executions = self.make_case()
        for index in (0, 31, 63):
            changed = copy.deepcopy(report)
            changed["fill_history"][index]["preconditions"]["observed_at"] = 201
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "refresh clock"):
                finalizer.check_refresh_history(self.staged, final, changed, signed, executions)
        changed = copy.deepcopy(report)
        changed["fill_history"][63]["execution_now"] = 501
        with self.assertRaisesRegex(ValueError, "refresh clock"):
            finalizer.check_refresh_history(self.staged, final, changed, signed, executions)
        changed = copy.deepcopy(report)
        changed["preconditions"]["expires_at"] = 501
        with self.assertRaisesRegex(ValueError, "refresh clock"):
            finalizer.check_refresh_history(self.staged, final, changed, signed, executions)

    def test_refresh_must_precede_associated_fill_and_match_final_accounts(self):
        self.assertTrue(hasattr(finalizer, "check_refresh_history"))
        final, report, signed, executions = self.make_case()
        changed = copy.deepcopy(report)
        changed["fill_history"][0]["account_slots"]["before"] = 10
        with self.assertRaisesRegex(ValueError, "refresh slot"):
            finalizer.check_refresh_history(self.staged, final, changed, signed, executions)
        changed_final = dict(final)
        changed_head = bytearray(final["head"])
        changed_head[112] ^= 1
        changed_final["head"] = bytes(changed_head)
        with self.assertRaisesRegex(ValueError, "refresh.*final"):
            finalizer.check_refresh_history(self.staged, changed_final, report, signed, executions)


class BoundedProofCase(unittest.TestCase):
    def test_missing_extra_or_empty_bounded_steps_fail_closed(self):
        for bounded in ({}, {'witness': {}}, dict.fromkeys(('witness', 'relation', 'proof', 'adapter', 'extra'), {})):
            with self.subTest(keys=list(bounded)), self.assertRaisesRegex(ValueError, 'exact.*bounded'):
                finalizer.check_bounded_receipts({'bounded': bounded}, {}, 0)

    def make_case(self):
        config = {'output_dir': '/private/capacity'}
        for name in ('proof_runner', 'adapter', 'node', 'witness_js', 'relation_checker', 'bounded_supervisor'):
            config[name] = {'path': '/private/tools/'+name, 'sha256': name}
        receipt = {'tools': {k: config[k] for k in ('proof_runner', 'adapter', 'node', 'witness_js', 'relation_checker')},
                   'packet': {'path': '/private/capacity/proof-00/packet.json', 'sha256': 'packet'}, 'bounded': {}}
        docs = {}
        commands = {
            'witness': [config['node']['path'], config['witness_js']['path'], '/private/capacity/proof-00/training'],
            'relation': [str(Path(finalizer.sys.executable)), '-B', config['relation_checker']['path'], 'check', '/private/capacity/proof-00/training'],
            'proof': [config['proof_runner']['path'], finalizer.fixture.MODE, receipt['packet']['path'], 'packet', '/private/capacity/proof-00/full-proof'],
            'adapter': [config['adapter']['path'], 'private_campaign_final_wire_passes_adapter_and_program_host', '--exact', '--ignored', '--test-threads=1']}
        for name, command in commands.items():
            limits = getattr(finalizer.fixture.proof, {'proof': 'FULL'}.get(name, name.upper())+'_LIMITS')
            monitor = '/private/capacity/supervision/'+name+'-monitor'
            receipt['bounded'][name] = {'path': monitor+'-report.json', 'sha256': name, 'monitor': monitor, 'wall_seconds': 2, 'limits': limits}
            docs[monitor+'/invocation.json'] = {'owner': 'heldout-v3-00-'+('full' if name == 'proof' else name)+'-0123456789', 'argv': command, 'cwd': str(finalizer.REPO), 'storage_roots': [config['output_dir']]}
            docs[monitor+'-report.json'] = {'schema': 1, 'owner': docs[monitor+'/invocation.json']['owner'], 'passed': True, 'exit_code': 0,
                'stop_reason': None, 'runner_error_type': None, 'cleanup_status_unknown': False, 'cleanup_remaining_owned_processes': 0,
                'duration_seconds': 1, 'limits': {'runtime_seconds': limits['runtime_seconds'], 'owned_tree_rss_bytes': limits['rss_bytes'], 'storage_growth_bytes': limits['storage_bytes'], 'poll_seconds': .25},
                'sample_count': 1, 'samples': [{'elapsed_seconds': .5, 'owned_process_count': 1, 'owned_tree_rss_bytes': 1, 'storage_growth_bytes': 1}],
                'sampled_peak_owned_tree_rss_bytes': 1, 'sampled_peak_storage_growth_bytes': 1,
                'environment': {'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1', 'TZ': 'UTC'}}
        return receipt, config, docs

    def check_case(self, receipt, config, docs):
        with patch.object(finalizer.fixture, 'doc', side_effect=lambda pin: docs[pin['path']]), patch.object(finalizer.fixture, 'read'), patch.object(finalizer.fixture, 'ref', side_effect=lambda path: {'path': str(path), 'sha256': 'test'}):
            finalizer.check_bounded_receipts(receipt, config, 0)

    def test_complete_four_process_provenance_passes(self):
        self.check_case(*self.make_case())

    def test_changed_tool_bytes_and_each_missing_step_are_rejected(self):
        receipt, config, docs = self.make_case()
        for name in ('witness', 'relation', 'proof', 'adapter'):
            changed = copy.deepcopy(receipt)
            del changed['bounded'][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'exact.*bounded'):
                self.check_case(changed, config, docs)
        with patch.object(finalizer.fixture, 'read', side_effect=ValueError('tool bytes changed')):
            with self.assertRaisesRegex(ValueError, 'tool bytes changed'):
                finalizer.check_bounded_receipts(receipt, config, 0)

    def test_tool_substitution_rejected(self):
        receipt, config, docs = self.make_case()
        receipt['tools']['node'] = config['adapter']
        with self.assertRaisesRegex(ValueError, 'pinned.*tool'):
            self.check_case(receipt, config, docs)

    def test_command_storage_owner_limits_samples_and_cleanup_are_checked(self):
        for document, key, value in [('invocation', 'argv', []), ('invocation', 'storage_roots', []), ('invocation', 'owner', 'other'),
                ('report', 'sample_count', 0), ('report', 'runner_error_type', 'oops'), ('report', 'cleanup_remaining_owned_processes', False),
                ('report', 'duration_seconds', 0), ('report', 'limits', {}), ('report', 'environment', {})]:
            receipt, config, docs = self.make_case()
            step = receipt['bounded']['witness']
            path = step['monitor']+'/invocation.json' if document == 'invocation' else step['path']
            docs[path][key] = value
            with self.subTest(document=document, key=key), self.assertRaises(ValueError):
                self.check_case(receipt, config, docs)


class CloneOwnerCase(unittest.TestCase):
    def make_case(self):
        root='/private/capacity-clone'
        pin=lambda name: {'path': root+'/'+name.replace('_','-')+'.json', 'sha256': name}
        manifest={name:pin(name) for name in ('clone_config','clone_monitor','clone_invocation','clone_report','proof_monitor','proof_invocation')}
        stage={'ledger':'/private/capacity-stage/ledger'}
        proof={name:pin(name) for name in ('stage_config','stage_status','stage_monitor','stage_invocation','preparation_report','baseline_stage_report')}
        preparation={'fixture_manifest':pin('fixture')}
        config={'ledger':root+'/ledger','clone_receipt':manifest['clone_report']['path'], 'clone_receipt_sha256':manifest['clone_report']['sha256'],
                'preparation_receipt':root+'/preparation.json','preparation_receipt_sha256':'preparation',
                'stage_report_sha256':proof['baseline_stage_report']['sha256'],'stage_status_sha256':proof['stage_status']['sha256'],
                'expected_genesis_sha256':'genesis'}
        rows=[['genesis.bin','file',10,'genesis']]
        digest=hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
        clone_config={**proof,'schema':finalizer.fixture.SCHEMA,'phase':'clone','ledger':config['ledger'],'output_dir':root,
                      'preparation_receipt':{'path':config['preparation_receipt'],'sha256':config['preparation_receipt_sha256']},
                      'proof_monitor':manifest['proof_monitor'],'proof_invocation':manifest['proof_invocation'],'source_tree_sha256':digest}
        limits={'runtime_seconds':3600,'owned_tree_rss_bytes':4294967296,'storage_growth_bytes':1073741824,'poll_seconds':.25}
        report={'schema':'part5-v3-queue-capacity-prepared-ledger-clone-v1','config_ref':manifest['clone_config'],'clone_owner_required':True,
                'cost_included':False,'owner_limits':limits,'source':stage['ledger'],'destination':config['ledger'],'entry_count':1,'tree_sha256':digest,
                'source_stable':True,'copy_identical':True,'excluded_stale_admin_socket':False,'loaded_identity_rechecked_after_restart':False,'application_effect':False,
                'stage_report_sha256':config['stage_report_sha256'],'stage_status_sha256':config['stage_status_sha256'],
                'preparation_receipt_sha256':config['preparation_receipt_sha256'],'fixture_manifest_sha256':preparation['fixture_manifest']['sha256']}
        invocation={'owner':'clone-owner','argv':['/usr/bin/python3',str(Path(finalizer.fixture.__file__)),'--config',manifest['clone_config']['path'],'--config-sha256',manifest['clone_config']['sha256']],
                    'cwd':str(finalizer.REPO),'storage_roots':[root]}
        monitor={'schema':1,'measurement':'bounded_complete_session','passed':True,'exit_code':0,'censored':False,'stop_reason':None,'runner_error_type':None,
                 'cleanup_status_unknown':False,'cleanup_remaining_owned_processes':0,'owner':'clone-owner','limits':limits,'duration_seconds':12,
                 'sample_count':1,'samples':[{'elapsed_seconds':1,'owned_process_count':1,'owned_tree_rss_bytes':1,'storage_growth_bytes':1}],
                 'sampled_peak_owned_tree_rss_bytes':1,'sampled_peak_storage_growth_bytes':1}
        docs={manifest[name]['path']:value for name,value in [('clone_config',clone_config),('clone_report',report),('clone_monitor',monitor),('clone_invocation',invocation)]}
        return manifest,config,preparation,proof,stage,docs,rows

    def check_case(self, case):
        manifest,config,preparation,proof,stage,docs,rows=case
        with patch.object(finalizer.fixture,'doc',side_effect=lambda ref: docs[ref['path']]), patch.object(finalizer.fixture,'inventory',return_value=rows):
            return finalizer.check_clone_owner(manifest,config,preparation,proof,stage)

    def test_verified_clone_external_wall_is_returned(self):
        self.assertEqual(self.check_case(self.make_case())['wall_seconds'],12)

    def test_clone_monitor_requires_named_owner_and_real_numeric_status(self):
        for key,value in [('owner',None),('exit_code',False),('sample_count',True)]:
            case=self.make_case()
            case[5][case[0]['clone_monitor']['path']][key]=value
            if key=='owner':case[5][case[0]['clone_invocation']['path']]['owner']=None
            with self.subTest(key=key),self.assertRaises(ValueError):self.check_case(case)

    def test_missing_clone_refs_and_forged_provenance_are_rejected(self):
        for missing in ('clone_config','clone_monitor','clone_invocation','clone_report'):
            case=self.make_case();del case[0][missing]
            with self.subTest(missing=missing),self.assertRaises(ValueError):self.check_case(case)
        mutations=[('clone_config','phase','proofs'),('clone_config','source_tree_sha256','forged'),
                   ('clone_report','config_ref',{}),('clone_report','owner_limits',{}),('clone_report','source','/other/ledger'),
                   ('clone_report','destination','/other/ledger'),('clone_report','entry_count',0),('clone_report','tree_sha256','forged'),
                   ('clone_report','preparation_receipt_sha256','forged'),('clone_report','cost_included',True),
                   ('clone_monitor','duration_seconds',3601),('clone_monitor','cleanup_remaining_owned_processes',1),
                   ('clone_invocation','argv',[]),('clone_invocation','storage_roots',[])]
        for role,key,value in mutations:
            case=self.make_case();case[5][case[0][role]['path']][key]=value
            with self.subTest(role=role,key=key),self.assertRaises(ValueError):self.check_case(case)


if __name__ == "__main__":
    unittest.main()
