import ast
import hashlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import verify_v3_heldout_acceptance as verifier
from tools.part5 import build_v3_heldout_cohort as cohort_builder
from tools.part5.issue_v3_heldout_certificate import issue_certificate
from tools.part5.generate_v3_heldout_keys import FREEZE_SCHEMA, IDENTITY_ROLES
from tools.part5.prepare_v3_heldout_context import COHORT_SCHEMA
from tools.part5.prepare_v3_revocation_cohort import membership_for_pair
from tools.part5.credential_profile import admit_certificate, public_bindings


def issuer_negative_snapshots(disabled_config, enabled_config):
    disabled = dict(disabled_config)
    active = dict(disabled)
    active['config'] = enabled_config
    prior_config_epoch = int.from_bytes(disabled['config'][372:380], 'big') - 1
    root = enabled_config[332:364]
    root_version = enabled_config[364:372]
    prior_issuer = bytearray(disabled['issuer'])
    prior_issuer[:8] = b'DYNISS03'
    prior_issuer[8:40] = b'K' * 32
    prior_issuer[172] = 1
    prior_issuer[173:181] = (1).to_bytes(8, 'big')
    prior_issuer[181:213] = b'S' * 32
    prior_issuer[213:221] = (100).to_bytes(8, 'big', signed=True)
    prior_issuer[221:229] = (340).to_bytes(8, 'big', signed=True)
    prior_issuer[229:261] = root
    prior_issuer[261:269] = root_version
    prior_issuer[269:277] = (1).to_bytes(8, 'big')
    prior_issuer[277:309] = b'S' * 32
    prior_issuer[309:317] = (1).to_bytes(8, 'big')
    prior_issuer[317:349] = b'E' * 32
    prior_issuer[349:357] = prior_config_epoch.to_bytes(8, 'big')
    prior_issuer[357] = 1
    prior_issuer[358:366] = (2).to_bytes(8, 'big')
    prior_issuer[366:374] = (2).to_bytes(8, 'big')
    disabled['issuer'] = bytes(prior_issuer)
    prior_head = bytearray(disabled['head'])
    prior_head[:8] = b'DYNHEAD3'
    prior_head[8:40] = prior_issuer[8:40]
    prior_head[72:104] = enabled_config[72:104]
    prior_head[104:112] = (1).to_bytes(8, 'big')
    prior_head[112:144] = b'P' * 32
    prior_head[144:176] = bytes(32)
    prior_head[176:208] = root
    prior_head[208:216] = root_version
    prior_head[216:224] = (1).to_bytes(8, 'big')
    prior_head[224:256] = b'S' * 32
    prior_head[256:264] = prior_config_epoch.to_bytes(8, 'big')
    prior_head[264:272] = (2).to_bytes(8, 'big')
    prior_head[272:280] = (100).to_bytes(8, 'big', signed=True)
    disabled['head'] = bytes(prior_head)
    issuer = bytearray(prior_issuer)
    issuer[173:181] = (2).to_bytes(8, 'big')
    issuer[181:213] = b'D' * 32
    issuer[213:221] = (110).to_bytes(8, 'big', signed=True)
    issuer[221:229] = (350).to_bytes(8, 'big', signed=True)
    issuer[269:277] = (2).to_bytes(8, 'big')
    issuer[277:309] = b'D' * 32
    issuer[349:357] = enabled_config[372:380]
    active['issuer'] = bytes(issuer)
    head = bytearray(prior_head)
    head[104:112] = (2).to_bytes(8, 'big')
    head[112:144] = b'Q' * 32
    head[144:176] = b'P' * 32
    head[216:224] = (2).to_bytes(8, 'big')
    head[224:256] = b'D' * 32
    head[256:264] = enabled_config[372:380]
    head[272:280] = (110).to_bytes(8, 'big', signed=True)
    active['head'] = bytes(head)
    before = dict(active)
    issuer[172] = 0
    issuer[357] = 0
    issuer[358:366] = (3).to_bytes(8, 'big')
    before['issuer'] = bytes(issuer)
    return disabled, active, before


class HeldoutAcceptanceVerifierTests(unittest.TestCase):
    def test_disabled_issuer_snapshots_isolate_second_policy_rejection(self):
        disabled_config = {
            name: bytes([index + 1]) * size
            for index, (name, size) in enumerate((
                ('config', 381), ('issuer', 374), ('head', 280),
                ('request', 2249), ('queue', 2090)))
        }
        config = bytearray(disabled_config['config'])
        config[:8] = b'DYNCONF3'
        config[372:380] = (8).to_bytes(8, 'big')
        config[380] = 0
        disabled_config['config'] = bytes(config)
        eligible = dict(disabled_config)
        config[372:380] = (9).to_bytes(8, 'big')
        config[380] = 1
        disabled_config, eligible, before = issuer_negative_snapshots(
            disabled_config, bytes(config))
        result = verifier._verify_disabled_issuer_snapshot_bytes(
            disabled_config, eligible, before, dict(before), 111)
        self.assertEqual(result['issuer_eligibility_epoch_before'], 2)
        self.assertEqual(result['issuer_eligibility_epoch_after'], 3)
        with self.assertRaisesRegex(ValueError, 'issuer eligibility'):
            verifier._verify_disabled_issuer_snapshot_bytes(
                disabled_config, eligible, before, dict(before), 400)
        zero_head_eligible = dict(eligible)
        zero_head_before = dict(before)
        zero_head = bytearray(eligible['head'])
        zero_head[112:144] = bytes(32)
        zero_head_eligible['head'] = bytes(zero_head)
        zero_head_before['head'] = bytes(zero_head)
        with self.assertRaisesRegex(ValueError, 'issuer eligibility'):
            verifier._verify_disabled_issuer_snapshot_bytes(
                disabled_config, zero_head_eligible, zero_head_before,
                dict(zero_head_before), 111)
        altered = dict(before)
        altered['queue'] = b'X' * 2090
        with self.assertRaisesRegex(ValueError, 'failed issuer Execute changed'):
            verifier._verify_disabled_issuer_snapshot_bytes(
                disabled_config, eligible, before, altered, 111)

    def test_disabled_config_snapshots_isolate_policy_rejection(self):
        stage = {
            name: bytes([index + 1]) * size
            for index, (name, size) in enumerate((
                ('config', 381), ('issuer', 374), ('head', 280),
                ('request', 2249), ('queue', 2090)))
        }
        config = bytearray(stage['config'])
        config[:8] = b'DYNCONF3'
        config[372:380] = (7).to_bytes(8, 'big')
        config[380] = 1
        stage['config'] = bytes(config)
        eligible = dict(stage)
        eligible['issuer'] = b'I' * 374
        eligible['head'] = b'H' * 280
        disabled = dict(eligible)
        config[372:380] = (8).to_bytes(8, 'big')
        config[380] = 0
        disabled['config'] = bytes(config)
        result = verifier._verify_disabled_config_snapshot_bytes(
            stage, eligible, disabled, dict(disabled))
        self.assertEqual(result['eligibility_epoch_before'], 7)
        self.assertEqual(result['eligibility_epoch_after'], 8)

        enabled = dict(disabled)
        enabled['config'] = eligible['config']
        with self.assertRaisesRegex(ValueError, 'enabled-to-disabled transition'):
            verifier._verify_disabled_config_snapshot_bytes(
                stage, eligible, enabled, dict(enabled))

        changed_request = dict(disabled)
        changed_request['request'] = b'X' * 2249
        with self.assertRaisesRegex(ValueError, 'failed Execute changed'):
            verifier._verify_disabled_config_snapshot_bytes(
                stage, eligible, disabled, changed_request)

        wrong_clone = dict(eligible)
        wrong_clone['request'] = b'Y' * 2249
        with self.assertRaisesRegex(ValueError, 'staged request'):
            verifier._verify_disabled_config_snapshot_bytes(
                stage, wrong_clone, disabled, dict(disabled))

    def test_r0_clone_verifier_uses_pinned_inventory_after_source_transition(self):
        source = self.root / 'stage-ledger'
        source.mkdir(mode=0o700)
        clone_root = self.root / 'clone'
        clone_root.mkdir(mode=0o700)
        destination = clone_root / 'ledger'
        destination.mkdir(mode=0o700)
        stage = {'config': {'ledger': str(source), 'stage_output': str(self.root)},
                 'config_sha256': 'a' * 64, 'status_sha256': 'b' * 64,
                 'monitor_sha256': 'c' * 64, 'report_sha256': 'd' * 64}
        bundle = {'config': {'path': str(self.root / 'stage-config.json')},
                  'status': {'path': str(self.root / 'stage-status.json')},
                  'monitor': {'path': str(self.root / 'stage-monitor.json')}}
        report = {'schema': 'part5-v3-heldout-r0-ledger-clone-v1',
                  'heldout_acceptance': False,
                  'stage_report_sha256': stage['report_sha256'],
                  'stage_status_sha256': stage['status_sha256'],
                  'stage_monitor_sha256': stage['monitor_sha256'],
                  'source': str(source), 'destination': str(destination),
                  'source_stable': True, 'copy_identical': True,
                  'loaded_identity_rechecked_after_restart': False,
                  'application_effect': False,
                  'excluded_stale_admin_socket': False,
                  'entry_count': 1,
                  'tree_sha256': hashlib.sha256(b'clone-time-inventory').hexdigest()}
        receipt_path = clone_root / 'clone-report.json'
        receipt_raw = (json.dumps(report, sort_keys=True) + '\n').encode()
        receipt_path.write_bytes(receipt_raw)
        receipt_path.chmod(0o600)
        receipt_sha = hashlib.sha256(receipt_raw).hexdigest()
        execution_config = {
            'ledger': str(destination),
            'heldout_r0_clone_report': str(receipt_path),
            'heldout_r0_clone_report_sha256': receipt_sha,
            'prior_stage_config': bundle['config']['path'],
            'prior_stage_config_sha256': stage['config_sha256'],
            'prior_stage_status': bundle['status']['path'],
            'prior_stage_status_sha256': stage['status_sha256'],
            'prior_stage_monitor': bundle['monitor']['path'],
            'prior_stage_monitor_sha256': stage['monitor_sha256'],
            'stage_root': stage['config']['stage_output'],
            'stage_report_sha256': stage['report_sha256']}
        with mock.patch.object(verifier, 'ledger_inventory', return_value=[
                    ['transitioned-source', 'file', 1, 'f' * 64]]) as inventory, \
                mock.patch.object(verifier, 'stale_admin_socket', return_value=True) as stale_socket:
            result = verifier._verify_r0_clone(
                {'receipt': {'path': str(receipt_path), 'sha256': receipt_sha}},
                execution_config, bundle, stage)
            inventory.assert_not_called()
            stale_socket.assert_not_called()
        self.assertEqual(result['destination'], destination)
        self.assertEqual(result['receipt_sha256'], receipt_sha)
        for field, value in (('entry_count', 0), ('entry_count', True),
                             ('tree_sha256', 'not-a-sha')):
            with self.subTest(receipt_field=field, value=value):
                malformed = dict(report, **{field: value})
                malformed_raw = (json.dumps(malformed, sort_keys=True) + '\n').encode()
                receipt_path.write_bytes(malformed_raw)
                receipt_path.chmod(0o600)
                malformed_sha = hashlib.sha256(malformed_raw).hexdigest()
                malformed_config = dict(execution_config,
                    heldout_r0_clone_report_sha256=malformed_sha)
                with self.assertRaisesRegex(ValueError, 'clone receipt required'):
                    verifier._verify_r0_clone(
                        {'receipt': {'path': str(receipt_path), 'sha256': malformed_sha}},
                        malformed_config, bundle, stage)
        receipt_path.write_bytes(receipt_raw)
        receipt_path.chmod(0o600)

    def test_disabled_config_report_requires_real_policy_denial_and_snapshot_pins(self):
        names = ('config', 'issuer', 'head', 'request', 'queue')
        sizes = (381, 374, 280, 2249, 2090)
        stage_accounts = {name: bytes([i + 1]) * size
                          for i, (name, size) in enumerate(zip(names, sizes))}
        active = bytearray(stage_accounts['config'])
        active[:8] = b'DYNCONF3'
        active[372:380] = (2).to_bytes(8, 'big')
        active[380] = 1
        stage_accounts['config'] = bytes(active)
        eligible = dict(stage_accounts)
        before = dict(eligible)
        active[372:380] = (3).to_bytes(8, 'big')
        active[380] = 0
        before['config'] = bytes(active)
        issuer_eligible = dict(before)
        active[372:380] = (4).to_bytes(8, 'big')
        active[380] = 1
        before, issuer_eligible, issuer_before = issuer_negative_snapshots(
            before, bytes(active))
        eligible['issuer'] = before['issuer']
        eligible['head'] = before['head']
        snapshots = {'eligible': eligible, 'before': before, 'after': dict(before),
                     'issuer_eligible': issuer_eligible,
                     'issuer_before': issuer_before, 'issuer_after': dict(issuer_before)}
        invalid_eligible = dict(issuer_eligible)
        invalid_before = dict(issuer_before)
        for group in (invalid_eligible, invalid_before):
            invalid_issuer = bytearray(group['issuer'])
            invalid_issuer[213:221] = (200).to_bytes(8, 'big', signed=True)
            invalid_issuer[221:229] = (100).to_bytes(8, 'big', signed=True)
            group['issuer'] = bytes(invalid_issuer)
        with self.assertRaisesRegex(ValueError, 'issuer eligibility'):
            verifier._verify_disabled_issuer_snapshot_bytes(
                snapshots['after'], invalid_eligible, invalid_before,
                dict(invalid_before), 111)
        refs = {label: {name: {'path': str(self.root / f'{label}-{name}.bin'),
                               'sha256': hashlib.sha256(data).hexdigest()}
                        for name, data in accounts.items()}
                for label, accounts in snapshots.items()}
        scenarios = ('v3-disabled-negative-refresh-source',
                     'v3-disabled-negative-refresh-head',
                     'v3-disabled-negative-disable-config',
                     'v3-disabled-negative-valid-full-execute',
                     'v3-disabled-negative-reenable-config',
                     'v3-disabled-negative-refresh-issuer-source',
                     'v3-disabled-negative-rebind-issuer-head',
                     'v3-disabled-negative-disable-issuer',
                     'v3-disabled-negative-valid-full-execute-issuer')
        txs = [{'scenario': scenario, 'signature': f'sig-{i}',
                'slot': 41 + i, 'customError': 713 if i in (3, 8) else None,
                'err': {'InstructionError': [1, {'Custom': 713}]}
                       if i in (3, 8) else None}
               for i, scenario in enumerate(scenarios)]
        stage_report = {'program': 'P', 'genesis': 'G', 'finalized_slot': 40,
                        **{name: f'address-{name}' for name in names}}
        report = {'schema': 'part5-v3-disabled-config-negative-report-v2',
                  'variant': 3, 'request_slot': 'A', 'passed': True,
                  'program': 'P', 'genesis': 'G', 'loaded_elf_sha256': 'e' * 64,
                  'stage_report_sha256': 'a' * 64,
                  'stage_plan_sha256': 'b' * 64,
                  'full_wire_sha256': 'c' * 64,
                  'clone_receipt_sha256': 'd' * 64,
                  'config_disabled': True, 'execute_rejected': True,
                  'refresh_and_bind_succeeded': True,
                  'disable_changed_only_enabled_and_epoch': True,
                  'accounts_unchanged_after_rejection': True,
                  'issuer_disabled': True,
                  'issuer_execute_rejected': True,
                  'issuer_disable_changed_only_enabled_epoch_status': True,
                  'issuer_accounts_unchanged_after_rejection': True,
                  'expected_custom_error': 713,
                  'addresses': {name: f'address-{name}' for name in names},
                  'source_finalized_slot': 40,
                  'eligible_finalized_slot': 42,
                  'disabled_finalized_slot': 43,
                  'rejected_finalized_slot': 44,
                  'issuer_eligible_finalized_slot': 47,
                  'issuer_disabled_finalized_slot': 48,
                  'issuer_rejected_finalized_slot': 49,
                  'issuer_eligible_clock': 111,
                  'refresh_transaction': {'signature': 'sig-0', 'slot': 41},
                  'bind_transaction': {'signature': 'sig-1', 'slot': 42},
                  'disable_transaction': {'signature': 'sig-2', 'slot': 43,
                                          'finalized_slot': 43},
                  'execute_transaction': {'signature': 'sig-3', 'slot': 44,
                                          'custom_error': 713,
                                          'finalized_slot': 44},
                  'reenable_transaction': {'signature': 'sig-4', 'slot': 45,
                                            'finalized_slot': 45},
                  'issuer_refresh_transaction': {'signature': 'sig-5', 'slot': 46},
                  'issuer_bind_transaction': {'signature': 'sig-6', 'slot': 47,
                                              'finalized_slot': 47},
                  'issuer_disable_transaction': {'signature': 'sig-7', 'slot': 48,
                                                 'finalized_slot': 48},
                  'issuer_execute_transaction': {'signature': 'sig-8', 'slot': 49,
                                                 'custom_error': 713,
                                                 'finalized_slot': 49},
                  'transactions': txs}
        for label, accounts in snapshots.items():
            report[f'{label}_sha256'] = [hashlib.sha256(accounts[name]).hexdigest()
                                         for name in names]
            report[f'{label}_accounts'] = [
                {'name': name, **refs[label][name]} for name in names]
        expected = {'stage_report_sha256': 'a' * 64,
                    'stage_plan_sha256': 'b' * 64,
                    'full_wire_sha256': 'c' * 64,
                    'clone_receipt_sha256': 'd' * 64}
        verifier._verify_disabled_config_report(
            report, 3, stage_report, stage_accounts, 'e' * 64,
            expected, refs, snapshots)
        altered = json.loads(json.dumps(report))
        altered['execute_transaction']['custom_error'] = 714
        with self.assertRaisesRegex(ValueError, 'Policy 713'):
            verifier._verify_disabled_config_report(
                altered, 3, stage_report, stage_accounts, 'e' * 64,
                expected, refs, snapshots)
        altered = json.loads(json.dumps(report))
        altered['before_sha256'][4] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'snapshot hash'):
            verifier._verify_disabled_config_report(
                altered, 3, stage_report, stage_accounts, 'e' * 64,
                expected, refs, snapshots)
        altered = json.loads(json.dumps(report))
        altered['issuer_execute_transaction']['custom_error'] = 714
        with self.assertRaisesRegex(ValueError, 'Policy 713'):
            verifier._verify_disabled_config_report(
                altered, 3, stage_report, stage_accounts, 'e' * 64,
                expected, refs, snapshots)
        altered = json.loads(json.dumps(report))
        altered['issuer_after_sha256'][1] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'snapshot hash'):
            verifier._verify_disabled_config_report(
                altered, 3, stage_report, stage_accounts, 'e' * 64,
                expected, refs, snapshots)
        altered_snapshots = dict(snapshots)
        altered_snapshots['issuer_before'] = dict(issuer_before)
        issuer_bytes = bytearray(issuer_before['issuer'])
        issuer_bytes[170] ^= 1
        altered_snapshots['issuer_before']['issuer'] = bytes(issuer_bytes)
        with self.assertRaisesRegex(ValueError, 'issuer disable'):
            verifier._verify_disabled_config_report(
                report, 3, stage_report, stage_accounts, 'e' * 64,
                expected, refs, altered_snapshots)

    def test_disabled_config_negative_joins_pinned_sidecar_and_rejects_wrong_outer_owner(self):
        names = ('config', 'issuer', 'head', 'request', 'queue')
        sizes = (381, 374, 280, 2249, 2090)
        program, genesis, elf_sha = 'program-id', 'genesis-hash', 'e' * 64
        variant, request_slot = 3, 'A'

        def write_json(path, value):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            raw = (json.dumps(value, sort_keys=True) + '\n').encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

        def write_bytes(path, raw):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(raw)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

        stage_root = self.root / 'stage'
        stage_root.mkdir(mode=0o700)
        source_ledger = self.root / 'source' / 'ledger'
        source_ledger.mkdir(parents=True, mode=0o700)
        clone_root = self.root / 'clone'
        clone_root.mkdir(mode=0o700)
        clone_ledger = clone_root / 'ledger'
        clone_ledger.mkdir(mode=0o700)
        output = self.root / 'negative-output'
        output.mkdir(mode=0o700)
        control = self.root / 'negative-control'
        control.mkdir(mode=0o700)

        stage_accounts = {
            name: bytes([index + 1]) * size
            for index, (name, size) in enumerate(zip(names, sizes))}
        stage_config_bytes = bytearray(stage_accounts['config'])
        stage_config_bytes[:8] = b'DYNCONF3'
        stage_config_bytes[372:380] = (7).to_bytes(8, 'big')
        stage_config_bytes[380] = 1
        stage_accounts['config'] = bytes(stage_config_bytes)
        eligible = dict(stage_accounts)
        eligible['issuer'] = b'I' * sizes[1]
        eligible['head'] = b'H' * sizes[2]
        before = dict(eligible)
        disabled_config = bytearray(eligible['config'])
        disabled_config[372:380] = (8).to_bytes(8, 'big')
        disabled_config[380] = 0
        before['config'] = bytes(disabled_config)
        issuer_eligible = dict(before)
        disabled_config[372:380] = (9).to_bytes(8, 'big')
        disabled_config[380] = 1
        before, issuer_eligible, issuer_before = issuer_negative_snapshots(
            before, bytes(disabled_config))
        eligible['issuer'] = before['issuer']
        eligible['head'] = before['head']
        snapshots = {'eligible': eligible, 'before': before, 'after': dict(before),
                     'issuer_eligible': issuer_eligible,
                     'issuer_before': issuer_before, 'issuer_after': dict(issuer_before)}

        for index, name in enumerate(names):
            (stage_root / f'{name}.bin').write_bytes(stage_accounts[name])
            (stage_root / f'{name}.bin').chmod(0o600)
        stage_plan = {'fixture': 'plan'}
        stage_plan_ref = write_json(stage_root / 'plan.json', stage_plan)
        stage_report = {
            'schema': 'part5-v3-local-stage-v1', 'passed': True,
            'program': program, 'genesis': genesis, 'finalized_slot': 40,
            **{name: f'address-{name}' for name in names}}
        stage_report_ref = write_json(stage_root / 'stage-report.json', stage_report)
        stage_config_path = self.root / 'stage-config.json'
        stage_status_path = self.root / 'stage-status.json'
        stage_monitor_path = self.root / 'stage-monitor.json'
        stage_config_ref = write_json(stage_config_path, {'fixture': 'stage config'})
        stage_status_ref = write_json(stage_status_path, {'fixture': 'stage status'})
        stage_monitor_ref = write_json(stage_monitor_path, {'fixture': 'stage monitor'})
        stage_plan_sha = stage_plan_ref['sha256']
        clone_report = {
            'schema': 'part5-v3-heldout-r0-ledger-clone-v1',
            'heldout_acceptance': False,
            'stage_report_sha256': stage_report_ref['sha256'],
            'stage_status_sha256': stage_status_ref['sha256'],
            'stage_monitor_sha256': stage_monitor_ref['sha256'],
            'source': str(source_ledger), 'destination': str(clone_ledger),
            'source_stable': True, 'copy_identical': True,
            'loaded_identity_rechecked_after_restart': False,
            'application_effect': False, 'excluded_stale_admin_socket': False,
            'entry_count': 1,
            'tree_sha256': hashlib.sha256(b'clone-time-inventory').hexdigest()}
        clone_ref = write_json(clone_root / 'clone-report.json', clone_report)

        root_hex, action_hex = '11' * 32, '22' * 32
        wire = bytearray(448)
        wire[:32] = bytes.fromhex(root_hex)
        wire[128:160] = bytes.fromhex(action_hex)
        full_wire_ref = write_bytes(self.root / 'full-wire.bin', bytes(wire))
        runtime_identity = {
            'program': program, 'programdata': 'programdata-id',
            'elf_sha256': elf_sha, 'program_account_sha256': '1' * 64,
            'programdata_account_sha256': '2' * 64, 'genesis': genesis}
        stage = {
            'report_sha256': stage_report_ref['sha256'],
            'plan_sha256': stage_plan_sha,
            'config_sha256': stage_config_ref['sha256'],
            'status_sha256': stage_status_ref['sha256'],
            'monitor_sha256': stage_monitor_ref['sha256'],
            'config': {'stage_output': str(stage_root), 'ledger': str(source_ledger)},
            'report': stage_report, 'accounts': stage_accounts,
            'runtime_identity': runtime_identity}
        stage_bundle = {
            'report': stage_report_ref, 'plan': stage_plan_ref,
            'config': stage_config_ref, 'status': stage_status_ref,
            'monitor': stage_monitor_ref}

        rust_config_path = self.root / 'negative' / 'rust-config.json'
        wrapper_path = self.root / 'negative' / 'config.json'
        rust_config = {
            'schema': 'part5-v3-disabled-config-negative-config-v1',
            'variant': variant, 'request_slot': request_slot,
            'stage_root': str(stage_root), 'stage_report': stage_report_ref['path'],
            'stage_report_sha256': stage_report_ref['sha256'],
            'stage_plan': stage_plan_ref['path'], 'stage_plan_sha256': stage_plan_sha,
            'ledger': str(clone_ledger),
            'heldout_r0_clone_report': clone_ref['path'],
            'heldout_r0_clone_report_sha256': clone_ref['sha256'],
            'full_wire': full_wire_ref['path'],
            'full_wire_sha256': full_wire_ref['sha256'],
            'expected_program': program, 'expected_genesis': genesis,
            'expected_elf_sha256': elf_sha, 'output_dir': str(output),
            'control_output': str(control), 'runner': '/runner/queue_v3',
            'runner_sha256': '3' * 64}
        rust_config_ref = write_json(rust_config_path, rust_config)
        wrapper = {
            'schema': 'credential-v3-disabled-config-negative-supervisor-v1',
            'scope': 'part5-v3-disabled-config-negative', 'variant': variant,
            'request_slot': request_slot,
            'prior_stage_config': stage_config_ref['path'],
            'prior_stage_config_sha256': stage_config_ref['sha256'],
            'prior_stage_status': stage_status_ref['path'],
            'prior_stage_status_sha256': stage_status_ref['sha256'],
            'prior_stage_monitor': stage_monitor_ref['path'],
            'prior_stage_monitor_sha256': stage_monitor_ref['sha256'],
            'prior_monitor_owner': 'heldout-v03-positive_full-stage',
            'stage_root': str(stage_root),
            'stage_report_sha256': stage_report_ref['sha256'],
            'stage_plan_sha256': stage_plan_sha,
            'ledger': str(clone_ledger),
            'heldout_r0_clone_report': clone_ref['path'],
            'heldout_r0_clone_report_sha256': clone_ref['sha256'],
            'expected_genesis': genesis,
            'runner': rust_config['runner'],
            'runner_sha256': rust_config['runner_sha256'],
            'full_wire': full_wire_ref['path'],
            'full_wire_sha256': full_wire_ref['sha256'],
            'expected_program': program, 'expected_elf_sha256': elf_sha,
            'output_dir': str(output), 'control_output': str(control),
            'rust_config_path': str(rust_config_path),
            'rust_config_sha256': rust_config_ref['sha256'],
            'outer_limits_required': {
                'runtime_seconds': 180, 'rss_bytes': 4294967296,
                'storage_growth_bytes': 268435456}}
        wrapper_ref = write_json(wrapper_path, wrapper)

        rows = {}
        for label, accounts in snapshots.items():
            rows[label] = {}
            for name in names:
                rows[label][name] = write_bytes(
                    output / label / f'{name}.bin', accounts[name])
        transactions = [
            {'scenario': scenario, 'signature': f'sig-{index}', 'slot': 41 + index,
             'customError': 713 if index in (3, 8) else None,
             'err': {'InstructionError': [1, {'Custom': 713}]}
                    if index in (3, 8) else None}
            for index, scenario in enumerate((
                'v3-disabled-negative-refresh-source',
                'v3-disabled-negative-refresh-head',
                'v3-disabled-negative-disable-config',
                'v3-disabled-negative-valid-full-execute',
                'v3-disabled-negative-reenable-config',
                'v3-disabled-negative-refresh-issuer-source',
                'v3-disabled-negative-rebind-issuer-head',
                'v3-disabled-negative-disable-issuer',
                'v3-disabled-negative-valid-full-execute-issuer'))]
        report = {
            'schema': 'part5-v3-disabled-config-negative-report-v2',
            'variant': variant, 'request_slot': request_slot, 'passed': True,
            'program': program, 'genesis': genesis, 'loaded_elf_sha256': elf_sha,
            'stage_report_sha256': stage_report_ref['sha256'],
            'stage_plan_sha256': stage_plan_sha,
            'full_wire_sha256': full_wire_ref['sha256'],
            'clone_receipt_sha256': clone_ref['sha256'],
            'config_disabled': True, 'execute_rejected': True,
            'refresh_and_bind_succeeded': True,
            'disable_changed_only_enabled_and_epoch': True,
            'accounts_unchanged_after_rejection': True,
            'issuer_disabled': True,
            'issuer_execute_rejected': True,
            'issuer_disable_changed_only_enabled_epoch_status': True,
            'issuer_accounts_unchanged_after_rejection': True,
            'expected_custom_error': 713,
            'addresses': {name: stage_report[name] for name in names},
            'source_finalized_slot': 40, 'eligible_finalized_slot': 42,
            'disabled_finalized_slot': 43, 'rejected_finalized_slot': 44,
            'issuer_eligible_finalized_slot': 47,
            'issuer_disabled_finalized_slot': 48,
            'issuer_rejected_finalized_slot': 49,
            'issuer_eligible_clock': 111,
            'refresh_transaction': {'signature': 'sig-0', 'slot': 41},
            'bind_transaction': {'signature': 'sig-1', 'slot': 42},
            'disable_transaction': {'signature': 'sig-2', 'slot': 43,
                                    'finalized_slot': 43},
            'execute_transaction': {'signature': 'sig-3', 'slot': 44,
                                    'custom_error': 713, 'finalized_slot': 44},
            'reenable_transaction': {'signature': 'sig-4', 'slot': 45,
                                     'finalized_slot': 45},
            'issuer_refresh_transaction': {'signature': 'sig-5', 'slot': 46},
            'issuer_bind_transaction': {'signature': 'sig-6', 'slot': 47,
                                        'finalized_slot': 47},
            'issuer_disable_transaction': {'signature': 'sig-7', 'slot': 48,
                                           'finalized_slot': 48},
            'issuer_execute_transaction': {'signature': 'sig-8', 'slot': 49,
                                           'custom_error': 713,
                                           'finalized_slot': 49},
            'transactions': transactions}
        for label, accounts in snapshots.items():
            report[f'{label}_sha256'] = [
                hashlib.sha256(accounts[name]).hexdigest() for name in names]
            report[f'{label}_accounts'] = [
                {'name': name, **rows[label][name]} for name in names]
        report_ref = write_json(output / 'disabled-config-negative-report.json', report)

        loaded_program = {**runtime_identity, 'elf_match': True}
        status = {
            'scope': 'part5-v3-disabled-config-negative', 'status': 'failed',
            'error_type': None, 'effect_verified': True, 'application_effect': False,
            'config_disabled': True, 'execute_rejected': True,
            'accounts_unchanged': True, 'issuer_disabled': True,
            'issuer_execute_rejected': True,
            'issuer_accounts_unchanged': True,
            'ledger_reuse_requires_review': True,
            'report_path': report_ref['path'], 'report_sha256': report_ref['sha256'],
            'config_sha256': wrapper_ref['sha256'],
            'rust_config_path': str(rust_config_path),
            'rust_config_sha256': rust_config_ref['sha256'],
            'validator_cleanup': {'spawned': True, 'reaped': True,
                                  'graceful': False, 'exit_code': -2},
            'runner_cleanup': {'spawned': True, 'reaped': True, 'exit_code': 0},
            'loaded_program': loaded_program}
        status_ref = write_json(self.root / 'negative' / 'status.json', status)
        outer = {
            'schema': 1, 'owner': 'heldout-v03-positive_full-disabled-config-negative',
            'passed': False, 'exit_code': 1, 'stop_reason': None,
            'runner_error_type': None, 'cleanup_remaining_owned_processes': 0,
            'cleanup_status_unknown': False, 'duration_seconds': 4.0,
            'sample_count': 10,
            'limits': {'runtime_seconds': 180, 'owned_tree_rss_bytes': 4294967296,
                       'storage_growth_bytes': 268435456, 'poll_seconds': 0.2}}
        outer_ref = write_json(self.root / 'negative' / 'outer.json', outer)
        report_receipt_ref = write_json(self.root / 'full-proof-receipt.json',
                                         {'fixture': 'full proof receipt'})

        sidecar = {
            'schema': 'credential-v3-heldout-disabled-config-negative-v2',
            'variant': variant,
            'stage_report_sha256': stage_report_ref['sha256'],
            'stage_plan_sha256': stage_plan_sha,
            'r0_source_receipt_sha256': '4' * 64,
            'full_proof_receipt_sha256': report_receipt_ref['sha256'],
            'clone_receipt': clone_ref, 'full_wire': full_wire_ref,
            'config': wrapper_ref, 'rust_config': rust_config_ref,
            'status': status_ref, 'outer': outer_ref, 'report': report_ref,
            'eligible_accounts': rows['eligible'],
            'before_accounts': rows['before'], 'after_accounts': rows['after'],
            'issuer_eligible_accounts': rows['issuer_eligible'],
            'issuer_before_accounts': rows['issuer_before'],
            'issuer_after_accounts': rows['issuer_after']}
        sidecar_path = self.root / 'negative' / 'sidecar.json'
        sidecar_ref = write_json(sidecar_path, sidecar)
        slot = {
            'stage': stage, 'stage_bundle': stage_bundle,
            'r0_sha256': sidecar['r0_source_receipt_sha256'],
            'r0': {'selected_root': root_hex, 'action_hash': action_hex}}
        full_bundle = {
            'result': {'wires': {'full': full_wire_ref}},
            'proof': {'receipt': report_receipt_ref}}
        globals_ = {'freeze': {'identities': {'loaded_elf': elf_sha}}}

        with mock.patch.object(verifier, 'ledger_inventory', return_value=[]), \
                mock.patch.object(verifier, 'stale_admin_socket', return_value=False):
            result = verifier._verify_disabled_config_negative(
                sidecar_ref, variant, globals_, slot, full_bundle, set())
            self.assertTrue(result['verified'])

            bad_outer = dict(outer, owner='wrong-owner')
            bad_outer_ref = write_json(self.root / 'negative' / 'outer.json', bad_outer)
            sidecar['outer'] = bad_outer_ref
            sidecar_ref = write_json(sidecar_path, sidecar)
            with self.assertRaisesRegex(ValueError, 'outer owner'):
                verifier._verify_disabled_config_negative(
                    sidecar_ref, variant, globals_, slot, full_bundle, set())

    def test_anchor_effect_bytes_require_one_request_consume_and_exact_pda_append(self):
        before_request = bytearray(2249)
        before_request[:8] = b'DYNREQ03'
        before_request[183] = 1
        before_queue = bytearray(2090)
        before_queue[:8] = b'DYNQUE03'
        before_queue[8:40] = bytes([3]) * 32
        before_queue[40:42] = (1).to_bytes(2, 'big')
        before_queue[42:74] = bytes([4]) * 32
        request_key = bytes([5]) * 32
        after_request = bytearray(before_request)
        after_request[183] = 2
        after_queue = bytearray(before_queue)
        after_queue[40:42] = (2).to_bytes(2, 'big')
        after_queue[74:106] = request_key

        verifier._verify_single_effect_bytes(
            bytes(before_request), bytes(before_queue), bytes(after_request),
            bytes(after_queue), request_key)

        extra_request_change = bytearray(after_request)
        extra_request_change[200] ^= 1
        with self.assertRaisesRegex(ValueError, 'exactly consume the request'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(before_queue), bytes(extra_request_change),
                bytes(after_queue), request_key)

        extra_queue_change = bytearray(after_queue)
        extra_queue_change[110] ^= 1
        with self.assertRaisesRegex(ValueError, 'append the request PDA exactly once'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(before_queue), bytes(after_request),
                bytes(extra_queue_change), request_key)

    def test_anchor_effect_bytes_reject_wrong_or_duplicate_request_pda(self):
        before_request = bytearray(2249)
        before_request[:8] = b'DYNREQ03'
        before_request[183] = 1
        before_queue = bytearray(2090)
        before_queue[:8] = b'DYNQUE03'
        before_queue[40:42] = (1).to_bytes(2, 'big')
        before_queue[42:74] = bytes([4]) * 32
        request_key = bytes([5]) * 32
        after_request = bytearray(before_request)
        after_request[183] = 2
        after_queue = bytearray(before_queue)
        after_queue[40:42] = (2).to_bytes(2, 'big')
        after_queue[74:106] = bytes([6]) * 32
        with self.assertRaisesRegex(ValueError, 'append the request PDA exactly once'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(before_queue), bytes(after_request),
                bytes(after_queue), request_key)

        duplicate_before_queue = bytearray(before_queue)
        duplicate_before_queue[40:42] = (1).to_bytes(2, 'big')
        duplicate_before_queue[42:74] = request_key
        duplicate_after_queue = bytearray(duplicate_before_queue)
        duplicate_after_queue[40:42] = (2).to_bytes(2, 'big')
        duplicate_after_queue[74:106] = request_key
        with self.assertRaisesRegex(ValueError, 'must not already be present'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(duplicate_before_queue),
                bytes(after_request), bytes(duplicate_after_queue), request_key)

        duplicate_other_queue = bytearray(before_queue)
        duplicate_other_queue[40:42] = (2).to_bytes(2, 'big')
        duplicate_other_queue[74:106] = duplicate_other_queue[42:74]
        duplicate_other_after = bytearray(duplicate_other_queue)
        duplicate_other_after[40:42] = (3).to_bytes(2, 'big')
        duplicate_other_after[106:138] = request_key
        with self.assertRaisesRegex(ValueError, 'canonical bounded encoding'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(duplicate_other_queue),
                bytes(after_request), bytes(duplicate_other_after), request_key)

    def test_config_root_version_uses_program_big_endian_encoding(self):
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        for version in (0, 1, 2):
            config[364:372] = version.to_bytes(8, 'big')
            self.assertEqual(verifier._config_root_version(bytes(config)), version)
        config[364:372] = (1).to_bytes(8, 'little')
        self.assertNotEqual(verifier._config_root_version(bytes(config)), 1)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_proof_runner_manifest_reference_matches_frozen_path_and_hash(self):
        proof_binary = self.root / 'artifacts/dynark/part5/v3-proof-runner-training-010'
        proof_binary.parent.mkdir(parents=True, mode=0o700)
        proof_binary.write_bytes(b'corrected proof runner')
        proof_binary.chmod(0o700)
        proof_sha = hashlib.sha256(proof_binary.read_bytes()).hexdigest()
        frozen_ref = {'path': str(proof_binary), 'sha256': proof_sha}
        proof_ref = dict(frozen_ref)

        self.assertEqual(verifier._validate_proof_runner_reference(
            frozen_ref, proof_ref, {'proof_runner': proof_sha}), frozen_ref)
        self.assertEqual(verifier._artifact(proof_ref)[1], proof_sha)

        alternate_path = self.root / 'alternate-proof-runner'
        alternate_path.write_bytes(proof_binary.read_bytes())
        alternate_path.chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'proof runner reference mismatch'):
            verifier._validate_proof_runner_reference(
                frozen_ref, {'path': str(alternate_path), 'sha256': proof_sha},
                {'proof_runner': proof_sha})
        with self.assertRaisesRegex(ValueError, 'proof runner reference mismatch'):
            verifier._validate_proof_runner_reference(
                frozen_ref, {**proof_ref, 'sha256': '0' * 64},
                {'proof_runner': proof_sha})

    def _parent_observation_fixture(self):
        private = self.root / 'artifacts' / 'dynark' / 'part5' / 'v3-heldout-private-001'
        private.mkdir(parents=True, mode=0o700)
        cohort_root = private / 'v3-heldout-cohort-001'
        cohort_root.mkdir(mode=0o700)
        receipt_path = cohort_root / 'cohort-receipt.json'
        receipt_path.write_bytes(b'{}')
        receipt_path.chmod(0o600)
        cohort_ref = {'path': str(receipt_path),
                      'sha256': hashlib.sha256(b'{}').hexdigest()}
        builder_sha = 'b' * 64
        observer_sha = 'c' * 64
        client_paths = {
            'tools/part5/build_v3_heldout_cohort.py': {'sha256': builder_sha},
            'tools/part5/observe_v3_heldout_cohort.py': {'sha256': observer_sha},
        }
        observation = {
            'schema': 'credential-v3-heldout-cohort-parent-observation-v1',
            'freeze_sha256': 'a' * 64,
            'prior_key_inventory_sha256': 'd' * 64,
            'wall_started_unix_ns': 2000,
            'wall_completed_unix_ns': 5000,
            'monotonic_started_ns': 100,
            'monotonic_completed_ns': 3100,
            'child_exit_code': 0,
            'builder_source_sha256': builder_sha,
            'observer_source_sha256': observer_sha,
            'output_path_sha256': hashlib.sha256(str(cohort_root).encode()).hexdigest(),
            'cohort_receipt_sha256': cohort_ref['sha256'],
            'preexisting_output': False,
            'creation_time_basis': 'observer_parent_started_child_after_freeze',
            'openssl_invocation_observed': False,
        }
        observation_path = private / 'v3-heldout-cohort-observation-001.json'

        def publish():
            raw = json.dumps(observation, sort_keys=True).encode()
            observation_path.write_bytes(raw)
            observation_path.chmod(0o600)
            return {'path': str(observation_path),
                    'sha256': hashlib.sha256(raw).hexdigest()}

        freeze = {'frozen_at_unix_ns': 1000}
        cohort = {'generation_started_unix_ns': 2100,
                  'generation_completed_unix_ns': 4900}
        return (observation, publish, freeze, cohort, cohort_ref,
                client_paths, private)

    def test_parent_observation_requires_frozen_private_chronology(self):
        observation, publish, freeze, cohort, cohort_ref, client_paths, _ = (
            self._parent_observation_fixture())
        with mock.patch.object(verifier, 'ROOT', self.root):
            result = verifier._verify_cohort_parent_observation(
                publish(), freeze, 'a' * 64, cohort, cohort_ref,
                'd' * 64, client_paths)
            self.assertTrue(result['pinned_parent_observation_chronology_consistent'])
            self.assertFalse(result['openssl_invocation_observed'])
            self.assertEqual(result['observation_sha256'],
                             publish()['sha256'])

            for field, value in (
                ('prior_key_inventory_sha256', 'e' * 64),
                ('cohort_receipt_sha256', 'e' * 64),
                ('builder_source_sha256', 'e' * 64),
                ('observer_source_sha256', 'e' * 64),
                ('output_path_sha256', 'e' * 64),
                ('wall_started_unix_ns', 999),
                ('wall_completed_unix_ns', 4800),
                ('monotonic_completed_ns', 99),
                ('preexisting_output', True),
                ('openssl_invocation_observed', True),
                ('child_exit_code', 1),
            ):
                original = observation[field]
                observation[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    verifier._verify_cohort_parent_observation(
                        publish(), freeze, 'a' * 64, cohort, cohort_ref,
                        'd' * 64, client_paths)
                observation[field] = original

            del observation['observer_source_sha256']
            with self.assertRaises(ValueError):
                verifier._verify_cohort_parent_observation(
                    publish(), freeze, 'a' * 64, cohort, cohort_ref,
                    'd' * 64, client_paths)

    def test_parent_observation_rejects_public_or_separate_path(self):
        observation, publish, freeze, cohort, cohort_ref, client_paths, private = (
            self._parent_observation_fixture())
        with mock.patch.object(verifier, 'ROOT', self.root):
            ref = publish()
            path = Path(ref['path'])
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                verifier._verify_cohort_parent_observation(
                    ref, freeze, 'a' * 64, cohort, cohort_ref,
                    'd' * 64, client_paths)
            path.chmod(0o600)
            private.chmod(0o755)
            with self.assertRaises(ValueError):
                verifier._verify_cohort_parent_observation(
                    ref, freeze, 'a' * 64, cohort, cohort_ref,
                    'd' * 64, client_paths)
            private.chmod(0o700)
            outside = self.root / 'outside.json'
            outside.write_bytes(path.read_bytes())
            outside.chmod(0o600)
            outside_ref = {'path': str(outside), 'sha256': ref['sha256']}
            with self.assertRaises(ValueError):
                verifier._verify_cohort_parent_observation(
                    outside_ref, freeze, 'a' * 64, cohort, cohort_ref,
                    'd' * 64, client_paths)
            with self.assertRaises(ValueError):
                verifier._verify_cohort_parent_observation(
                    {'path': 12, 'sha256': ref['sha256']},
                    freeze, 'a' * 64, cohort, cohort_ref,
                    'd' * 64, client_paths)

    def _cohort_provenance_artifacts(self):
        def write(path, value):
            raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

        freeze_path = self.root / 'freeze' / 'freeze.json'
        cohort_path = self.root / 'cohort' / 'cohort-receipt.json'
        identities = {role: f'{index + 1:064x}' for index, role in
                      enumerate(sorted(IDENTITY_ROLES))}
        freeze = {
            'schema': FREEZE_SCHEMA, 'frozen_at_unix_ns': 1000,
            'issuance_tool_sha256': 'a' * 64,
            'key_generation_tool_sha256': 'b' * 64,
            'identities': identities,
            'forbidden_public_key_sha256': ['c' * 64, 'd' * 64],
        }
        freeze_ref = write(freeze_path, freeze)
        inventory = {
            'schema': 'credential-v3-prior-public-key-inventory-v1',
            'observed_at_unix_ns': 900, 'freeze_sha256': freeze_ref['sha256'],
            'public_key_sha256': list(freeze['forbidden_public_key_sha256']),
        }
        inventory_ref = write(freeze_path.parent / 'prior-key-inventory.json', inventory)

        cohort_root, imported_rows, imported_key_rows, _, _ = self._real_import_fixture('cohort')
        self.assertEqual(cohort_path.parent, cohort_root)
        key_rows = []
        key_by_role_index = {}
        for role, count in (('issuer', 4), ('holder', 8)):
            for index in range(count):
                key_row = {
                    'role': role, 'index': index,
                    'public_key_sha256': imported_key_rows[(role, index)]['public_key_sha256'],
                    'generation_started_unix_ns': 2011 + 2 * len(key_rows),
                    'generation_completed_unix_ns': 2012 + 2 * len(key_rows),
                }
                key_rows.append(key_row)
                key_by_role_index[(role, index)] = key_row
        key_receipt = {
            'schema': 'credential-v3-heldout-key-generation-v1',
            'freeze_receipt_sha256': freeze_ref['sha256'],
            'frozen_at_unix_ns': freeze['frozen_at_unix_ns'],
            'identities': identities,
            'issuance_tool_sha256': freeze['issuance_tool_sha256'],
            'key_generation_tool_sha256': freeze['key_generation_tool_sha256'],
            'generation_started_unix_ns': 2010,
            'generation_completed_unix_ns': 2040,
            'counts': {'issuers': 4, 'holders': 8}, 'keys': key_rows,
            'prior_public_key_count': 2,
            'provenance': {'implementation': 'cryptography.rsa.generate_private_key',
                           'cryptography_version': 'test-version', 'backend': 'test-backend',
                           'key_size': 2048, 'public_exponent': 65537,
                           'imported_keys': False, 'certificates_issued': False,
                           'reuse_scope': 'supplied earlier-key inventory and complete new cohort'},
        }
        key_receipt_ref = write(
            cohort_path.parent / 'keys' / 'key-generation-receipt.json', key_receipt)
        rows = []
        for variant in range(8):
            row = dict(imported_rows[variant])
            row.update(issuance_started_unix_ns=2050 + 20 * variant,
                       issuance_completed_unix_ns=2060 + 20 * variant)
            rows.append(row)
        cohort = {
            'generation_started_unix_ns': 2000,
            'generation_completed_unix_ns': 2300,
            'prior_key_inventory_sha256': inventory_ref['sha256'],
            'key_generation_receipt_sha256': key_receipt_ref['sha256'],
            'prior_public_key_count': 2, 'certificates': rows,
        }
        cohort_ref = write(cohort_path, cohort)
        return freeze, freeze_ref, cohort, cohort_ref, {
            variant: row for variant, row in enumerate(rows)}, key_receipt, inventory

    def _real_import_fixture(self, name='import-cohort'):
        cohort_root = self.root / name
        keys_root = cohort_root / 'keys'
        keys_root.mkdir(parents=True, mode=0o700)
        issuer_keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048)
                       for _ in range(4)]
        holder_keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048)
                       for _ in range(8)]
        key_map, rows = {}, {}
        for role, keys in (('issuer', issuer_keys), ('holder', holder_keys)):
            for index, key in enumerate(keys):
                key_map[(role, index)] = key
                path = keys_root / f'{role}-{index}.pem'
                path.write_bytes(key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
                path.chmod(0o600)
        for variant in range(8):
            issuer_index, holder_index = variant % 4, variant
            issuer, holder = issuer_keys[issuer_index], holder_keys[holder_index]
            issuer_digest = self._spki_digest(issuer.public_key())
            params = cohort_builder._certificate_parameters(variant, issuer_digest)
            der = issue_certificate(issuer, holder, params, 'cryptography')
            cert_dir = cohort_root / f'certificate-{variant:02d}'
            cert_dir.mkdir(mode=0o700)
            cert_path = cert_dir / 'credential.der'
            cert_path.write_bytes(der)
            cert_path.chmod(0o600)
            parsed = admit_certificate(der, issuer.public_key().public_numbers().n)
            issuer_hash, policy_hash = public_bindings(
                parsed, issuer.public_key().public_numbers().n)
            rows[variant] = {
                'variant': variant, 'issuer_index': issuer_index,
                'holder_index': holder_index,
                'encoder': 'openssl' if variant < 4 else 'cryptography',
                'credential_sha256': hashlib.sha256(der).hexdigest(),
                'tbs_sha256': hashlib.sha256(parsed['tbs']).hexdigest(),
                'issuer_public_key_sha256': self._spki_digest(issuer.public_key()),
                'holder_public_key_sha256': self._spki_digest(holder.public_key()),
                'issuer_hash': str(issuer_hash), 'policy_hash': str(policy_hash),
                'aki_sha256': hashlib.sha256(parsed['aki']).hexdigest(),
                'organization_sha256': hashlib.sha256(parsed['organization']).hexdigest(),
                'group_sha256': hashlib.sha256(parsed['group']).hexdigest(),
                'serial_hex': parsed['serial'].hex(),
                'not_before_unix': parsed['not_before'],
                'not_after_unix': parsed['not_after'],
            }
        key_rows = {key: {
            'public_key_sha256': self._spki_digest(value.public_key())}
            for key, value in key_map.items()}
        return cohort_root, rows, key_rows, issuer_keys, holder_keys

    @staticmethod
    def _spki_digest(public_key):
        return hashlib.sha256(public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

    def test_independent_cohort_import_parses_all_der_and_imports_all_keys(self):
        cohort_root, rows, key_rows, _, _ = self._real_import_fixture()
        evidence = verifier._verify_cohort_import(
            cohort_root, rows, key_rows, set(), 'a' * 64, 'b' * 64,
            frozen_at_unix_ns=100)
        self.assertEqual(evidence['counts'], {
            'issuer_keys': 4, 'holder_keys': 8, 'certificates': 8})
        self.assertEqual([row['variant'] for row in evidence['certificates']], list(range(8)))
        self.assertTrue(all(row['issuer_signature_verified'] for row in evidence['certificates']))
        self.assertEqual(evidence['creation_time_basis'], 'cohort and key-generation receipt claims only')
        self.assertEqual(evidence['openssl_route_basis'],
                         'freeze-pinned source and receipt encoder labels; invocation not independently observed')
        negative = evidence['local_negative_admission']
        self.assertEqual(negative['scope'], 'local_admission_only')
        self.assertFalse(negative['loaded_execute_observed'])
        self.assertFalse(negative['changed_policy_allowlist_tested'])
        self.assertEqual(negative['counts'], {
            'certificates': 8,
            'malformed_der_rejections': 8,
            'wrong_issuer_key_rejections': 8,
            'tampered_signed_organization_rejections': 8,
            'ineligible_profile_der_rejections': 8,
        })
        self.assertEqual([row['variant'] for row in negative['certificates']], list(range(8)))
        for row in negative['certificates']:
            self.assertEqual(row['malformed_der']['error_category'], 'der_content_exceeds_parent')
            self.assertIn(row['wrong_issuer_key']['error_category'], {
                'rsa_signature_verification_failed', 'noncanonical_rsa_signature'})
            self.assertEqual(row['tampered_signed_organization']['error_category'],
                             'rsa_signature_verification_failed')
            self.assertTrue(row['tampered_signed_organization']['structurally_parseable'])
            ineligible = row['ineligible_profile_der']
            self.assertEqual(ineligible['label'], 'not_before_before_profile_window')
            self.assertTrue(ineligible['issuer_signature_verified'])
            self.assertEqual(ineligible['error_category'], 'utctime_2000-2049_required')
            self.assertNotEqual(ineligible['der_sha256'], row['credential_sha256'])
            self.assertNotEqual(row['malformed_der']['der_sha256'], row['credential_sha256'])
            self.assertNotEqual(row['tampered_signed_organization']['der_sha256'],
                                row['credential_sha256'])
            for case in row.values():
                if isinstance(case, dict):
                    for key, value in case.items():
                        if key.endswith('_sha256'):
                            self.assertRegex(value, r'^[0-9a-f]{64}$')
        serialized = json.dumps(evidence)
        for path in cohort_root.rglob('*'):
            if path.is_file() and path.suffix == '.pem':
                self.assertNotIn(path.read_text(), serialized)
            if path.is_file() and path.suffix == '.der':
                self.assertNotIn(path.read_bytes().hex(), serialized)

    def test_independent_cohort_import_rejects_der_and_key_receipt_mismatch(self):
        cohort_root, rows, key_rows, issuer_keys, _ = self._real_import_fixture('key-mismatch')
        cert_path = cohort_root / 'certificate-03' / 'credential.der'
        cert_path.write_bytes(cert_path.read_bytes()[:-1] + b'\x00')
        with self.assertRaisesRegex(ValueError, 'artifact SHA-256 pin mismatch'):
            verifier._verify_cohort_import(
                cohort_root, rows, key_rows, set(), 'a' * 64, 'b' * 64,
                frozen_at_unix_ns=100)

        cohort_root, rows, key_rows, issuer_keys, _ = self._real_import_fixture('prior-key')
        with self.assertRaisesRegex(ValueError, 'absent from prior inventory'):
            verifier._verify_cohort_import(
                cohort_root, rows, key_rows,
                {key_rows[('issuer', 0)]['public_key_sha256']},
                'a' * 64, 'b' * 64, frozen_at_unix_ns=100)

        cohort_root, rows, key_rows, issuer_keys, _ = self._real_import_fixture('key-mismatch-2')
        pem_path = cohort_root / 'keys' / 'issuer-0.pem'
        pem_path.write_bytes(issuer_keys[1].private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        pem_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'imported key differs from pinned generation receipt'):
            verifier._verify_cohort_import(
                cohort_root, rows, key_rows, set(), 'a' * 64, 'b' * 64,
                frozen_at_unix_ns=100)

    def test_fresh_full_replay_requires_same_statement_and_distinct_proof(self):
        first = self.root / 'first-wire.bin'
        second = self.root / 'replay-wire.bin'
        original = b'a' * 192 + b'b' * 256
        replay = b'a' * 192 + b'c' * 256
        first.write_bytes(original)
        second.write_bytes(replay)
        first.chmod(0o600)
        second.chmod(0o600)
        ref = lambda path: {'path': str(path),
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        verifier._verify_fresh_replay_wires(ref(first), ref(second))
        second.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'distinct randomized proof'):
            verifier._verify_fresh_replay_wires(ref(first), ref(second))
        second.write_bytes(b'z' * 192 + b'c' * 256)
        with self.assertRaisesRegex(ValueError, 'identical six public'):
            verifier._verify_fresh_replay_wires(ref(first), ref(second))

    def _ambiguous_journal_fixture(self):
        def save(name, value):
            path = self.root / name
            path.write_text(json.dumps(value, sort_keys=True) + '\n')
            path.chmod(0o600)
            return {'path': str(path), 'sha256': verifier._sha(path.read_bytes())}
        outer = {'schema': 1, 'passed': True, 'exit_code': 0, 'stop_reason': None,
                 'runner_error_type': None, 'cleanup_remaining_owned_processes': 0,
                 'cleanup_status_unknown': False, 'duration_seconds': 2.5,
                 'sample_count': 3, 'owner': 'heldout-v02-positive_full-ambiguous-restart'}
        config = {'proxy_script_sha256': 'd' * 64, 'proxy_port': 19502}
        sidecar = {'variant': 2, 'stage_report_sha256': '1' * 64,
                   'stage_plan_sha256': '2' * 64, 'r0_source_receipt_sha256': '3' * 64,
                   'full_proof_receipt_sha256': '4' * 64,
                   'replay_proof_receipt_sha256': '5' * 64,
                   'clone_receipt': {'path': str(self.root / 'ambiguous-clone.json'), 'sha256': '6' * 64},
                   'full_wire': {'sha256': '7' * 64}, 'replay_full_wire': {'sha256': '8' * 64},
                   'outer': save('ambiguous-outer.json', outer),
                   'config': save('ambiguous-config.json', config)}
        common = {name: sidecar[name] for name in ('stage_report_sha256',
                  'r0_source_receipt_sha256', 'full_proof_receipt_sha256',
                  'replay_proof_receipt_sha256')}
        common.update(full_wire_sha256='7' * 64, replay_full_wire_sha256='8' * 64)
        clone = {'status': 'passed', 'wall_seconds': 1.25,
                 'inputs': {'stage_report_sha256': sidecar['stage_report_sha256'],
                            'label': 'ambiguous-restart-r0'},
                 'receipt': sidecar['clone_receipt']['path'], 'receipt_sha256': '6' * 64}
        ref = save('ambiguous-sidecar.json', sidecar)
        run = {'status': 'passed', 'wall_seconds': 2.5,
               'inputs': dict(common, variant=2, stage_plan_sha256='2' * 64,
                   clone_receipt_sha256='6' * 64, frozen_elf_sha256='e' * 64,
                   supervisor_script_sha256=verifier._sha((verifier.ROOT /
                       'harness/tests/queue_v3_local_ambiguous_restart.py').read_bytes()),
                   proxy_script_sha256='d' * 64, proxy_port=19502),
               'sidecar': ref['path'], 'sidecar_sha256': ref['sha256'],
               'monitor': sidecar['outer']['path'], 'monitor_sha256': sidecar['outer']['sha256'],
               'monitor_owner': outer['owner']}
        return ({'ambiguous_restart': ref, 'ambiguous_restart_wall_seconds': 3.75},
                {'positive_full:ambiguous-restart-clone': clone,
                 'positive_full:ambiguous-restart': run})

    def test_ambiguous_restart_sidecar_pins_files_and_rejects_semantic_tampering(self):
        from harness.tests.queue_v3_local_ambiguous_restart import expected_reconciled_accounts
        def save(path, value):
            path = self.root / path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value if type(value) is bytes else
                             (json.dumps(value, sort_keys=True) + '\n').encode())
            path.chmod(0o600)
            return {'path': str(path), 'sha256': verifier._sha(path.read_bytes())}
        stage_accounts = {name: bytearray(size) for name, size in zip(verifier.ACCOUNT_NAMES,
                          (381, 374, 280, 2249, 2090))}
        for name, magic in zip(verifier.ACCOUNT_NAMES,
                (b'DYNCONF3', b'DYNISS03', b'DYNHEAD3', b'DYNREQ03', b'DYNQUE03')):
            stage_accounts[name][:8] = magic
        stage_accounts['config'][332:364] = b'R' * 32
        stage_accounts['request'][183] = 1
        stage_accounts = {name: bytes(raw) for name, raw in stage_accounts.items()}
        request = b'Q' * 32
        final = dict(zip(verifier.ACCOUNT_NAMES, expected_reconciled_accounts(
            list(stage_accounts.values()), {'root': b'R' * 32, 'request': request,
                                           'observed_at': 20, 'head_committed_at': 21})))
        pre = {**final, 'request': stage_accounts['request'], 'queue': stage_accounts['queue']}
        identity = {'program': 'program', 'programdata': 'programdata', 'elf_sha256': 'e'*64,
                    'program_account_sha256': 'a'*64, 'programdata_account_sha256': 'b'*64,
                    'genesis': 'genesis'}
        loaded = dict(identity, elf_match=True)
        report = {name: verifier._base58(bytes([index+1])*32)
                  for index, name in enumerate(verifier.ACCOUNT_NAMES)}
        report.update(program='program', genesis='genesis', finalized_slot=1,
                      request=verifier._base58(request))
        context = {'root': (b'R'*32).hex()}
        context_ref = save(Path('context.json'), context)
        limits = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
                  'storage_growth_bytes': 268435456}
        source_refs = {role: save(Path(rel), b'frozen source') for role, rel in (
            ('runner', verifier.QUEUE_RUNNER_REL),
            ('proxy', 'harness/tests/queue_v3_ambiguous_rpc_proxy.py'),
            ('supervisor', 'harness/tests/queue_v3_local_ambiguous_restart.py'))}
        full_wire = save(Path('wire.bin'), b'p'*192+b'a'*256)
        replay_wire = save(Path('replay.bin'), b'p'*192+b'b'*256)
        proof = save(Path('proof.json'), {})
        replay_proof = save(Path('replay-proof.json'), {'fresh': True})
        clone = save(Path('clone.json'), {})
        config = {'schema': 'part5-v3-local-ambiguous-restart-supervisor-v1',
            'scope': 'part5-v3-local-ambiguous-restart', 'outer_limits_required': limits,
            'proxy_script': source_refs['proxy']['path'], 'proxy_script_sha256': source_refs['proxy']['sha256'],
            'proxy_port': 19502, 'expected_program': 'program', 'expected_genesis': 'genesis',
            'expected_elf_sha256': 'e'*64, 'prior_monitor_owner': 'stage-owner',
            'execute_output': str(self.root/'output'), 'control_output': str(self.root/'control'),
            'prior_stage_config': str(self.root/'stage-config.json'), 'prior_stage_config_sha256': '1'*64,
            'prior_stage_status': str(self.root/'stage-status.json'), 'prior_stage_status_sha256': '2'*64,
            'prior_stage_monitor': str(self.root/'stage-monitor.json'), 'prior_stage_monitor_sha256': '3'*64,
            'stage_root': str(self.root/'stage'), 'stage_report_sha256': '4'*64,
            'stage_plan_sha256': '5'*64, 'ledger': str(self.root/'ledger'),
            'heldout_r0_clone_report': clone['path'], 'heldout_r0_clone_report_sha256': clone['sha256'],
            'runner': source_refs['runner']['path'], 'runner_sha256': source_refs['runner']['sha256'],
            'context': context_ref['path'], 'context_sha256': context_ref['sha256'],
            'full_wire': full_wire['path'], 'full_wire_sha256': full_wire['sha256'],
            'replay_full_wire': replay_wire['path'], 'replay_full_wire_sha256': replay_wire['sha256']}
        config_ref = save(Path('config.json'), config)
        outer = {'schema': 1, 'passed': True, 'exit_code': 0, 'stop_reason': None,
                 'runner_error_type': None, 'cleanup_remaining_owned_processes': 0,
                 'cleanup_status_unknown': False, 'duration_seconds': 2.5, 'sample_count': 3,
                 'owner': 'heldout-v02-positive_full-ambiguous-restart',
                 'limits': {'runtime_seconds': 180, 'owned_tree_rss_bytes': 4294967296,
                            'storage_growth_bytes': 268435456, 'poll_seconds': 0.2}}
        proxy = {'schema': 'queue-v3-ambiguous-rpc-proxy-receipt-v1', 'status': 'response_dropped',
                 'target_wire_sha256': full_wire['sha256'], 'transaction_sha256': 'c'*64,
                 'signature': '1'*64, 'matching_submissions': 1, 'duplicate_matching_submissions': 0,
                 'duplicate_rejected': False, 'forward_attempted': 1, 'forwarded': 1,
                 'response_dropped': True}
        proxy_ref = save(Path('control/proxy-receipt.json'), proxy)
        finality = {'schema': 'part5-v3-ambiguous-finality-receipt-v1',
                    'signature': proxy['signature'],
                    'signature_status': {'slot': 4, 'confirmationStatus': 'finalized', 'err': None},
                    'transaction': {'slot': 4, 'meta': {'err': None}, 'signatures': [proxy['signature']]}}
        finality_ref = save(Path('control/finality-receipt.json'), finality)
        pre_finality_ref = save(Path('control/pre-restart-finality-receipt.json'), finality)
        pre_hashes = [verifier._sha(pre[n]) for n in verifier.ACCOUNT_NAMES]
        pre_report = {'schema': 'part5-v3-ambiguous-pre-submit-v1', 'training_only': True,
                      'application_effect': False, 'request_consumed': False, 'finalized_slot': 3,
                      'stage_report_sha256': '4'*64, 'stage_plan_sha256': '5'*64,
                      'wire_sha256': full_wire['sha256'], 'program': 'program', 'genesis': 'genesis',
                      'addresses': {n: report[n] for n in verifier.ACCOUNT_NAMES},
                      'account_sha256': pre_hashes, 'loaded_program': loaded}
        pre_report_ref = save(Path('output/pre-submit-report.json'), pre_report)
        pre_refs = {n: save(Path(f'output/pre-submit-{n}.bin'), pre[n]) for n in verifier.ACCOUNT_NAMES}
        final_refs = {n: save(Path(f'output/final-{n}.bin'), final[n]) for n in verifier.ACCOUNT_NAMES}
        pre_stop_refs = {n: save(Path(f'output/pre-stop-{n}.bin'), final[n]) for n in verifier.ACCOUNT_NAMES}
        status = {name: True for name in ('heldout_acceptance', 'proxy_receipt_verified',
            'expected_transport_failure', 'restart_identity_verified', 'signature_finalized_success',
            'five_account_reconciliation_verified', 'prepositive_snapshot_saved_by_runner',
            'cleanup_verified', 'request_consumed', 'application_effect')}
        status.update({name: config[name] for name in ('expected_program', 'expected_genesis',
            'expected_elf_sha256', 'stage_report_sha256', 'stage_plan_sha256',
            'heldout_r0_clone_report_sha256', 'runner_sha256', 'proxy_script_sha256',
            'context_sha256', 'full_wire_sha256', 'replay_full_wire_sha256')})
        status.update(schema=1, scope=config['scope'], status='passed', config_sha256=config_ref['sha256'],
            outer_limits_required=limits, proof_mode='Full', effect_outcome='reconciled_by_deterministic_transition',
            effect_count=1, queue_appends=1, runner_exit_code=101,
            ledger_path_sha256=verifier._sha(config['ledger'].encode()),
            loaded_program_before=loaded, loaded_program_after=loaded, proxy_receipt_sha256=proxy_ref['sha256'],
            transaction_sha256=proxy['transaction_sha256'], signature_sha256=verifier._sha(proxy['signature'].encode()),
            matching_submissions=1, retry_count=0, proxy_status='response_dropped',
            pre_submit_report_sha256=pre_report_ref['sha256'], pre_submit_account_sha256=pre_hashes,
            initial_account_sha256=[verifier._sha(stage_accounts[n]) for n in verifier.ACCOUNT_NAMES],
            final_account_sha256=[final_refs[n]['sha256'] for n in verifier.ACCOUNT_NAMES],
            final_account_paths=[final_refs[n]['path'] for n in verifier.ACCOUNT_NAMES],
            finality_receipt_path=finality_ref['path'], finality_receipt_sha256=finality_ref['sha256'],
            initial_finalized_slot=2, pre_submit_finalized_slot=3, signature_finalized_slot=4,
            finalized_accounts_slot=5)
        status.update(pre_restart_signature_finalized_success=True,
            pre_stop_accounts_reconciliation_verified=True, restart_accounts_persisted=True,
            pre_restart_signature_finalized_slot=4, pre_stop_accounts_slot=5,
            pre_restart_finality_receipt_path=pre_finality_ref['path'],
            pre_restart_finality_receipt_sha256=pre_finality_ref['sha256'],
            pre_stop_account_sha256=[pre_stop_refs[n]['sha256'] for n in verifier.ACCOUNT_NAMES],
            pre_stop_account_paths=[pre_stop_refs[n]['path'] for n in verifier.ACCOUNT_NAMES],
            pre_restart_finality_elapsed_seconds=0.5, pre_stop_accounts_elapsed_seconds=0.6,
            first_validator_stop_elapsed_seconds=0.7, restart_identity_elapsed_seconds=0.8,
            post_restart_finality_elapsed_seconds=0.9, final_accounts_elapsed_seconds=1.0,
            elapsed_seconds=1.1)
        for name in ('proxy_cleanup', 'first_validator_cleanup', 'final_validator_cleanup'):
            status[name] = {'spawned': True, 'reaped': True, 'graceful': True, 'exit_code': 0}
        genesis = save(Path('ledger/genesis.bin'), b'pinned genesis')
        status.update(first_validator_stop_mode='clean_zero', final_validator_stop_mode='clean_zero',
                      ledger_genesis_sha256_before_stop=genesis['sha256'],
                      ledger_genesis_sha256_after_stop=genesis['sha256'])
        save(Path('control/runner.stdout.log'), b'Error: RPC sendTransaction transport failed\n')
        save(Path('control/runner.stderr.log'), b'')
        status_ref = save(Path('control/status.json'), status)
        sidecar = {'schema': 'credential-v3-heldout-ambiguous-restart-v1', 'variant': 2,
            'stage_report_sha256': '4'*64, 'stage_plan_sha256': '5'*64, 'r0_source_receipt_sha256': '6'*64,
            'full_proof_receipt_sha256': proof['sha256'], 'replay_proof_receipt_sha256': replay_proof['sha256'],
            'clone_receipt': clone, 'full_wire': full_wire, 'replay_full_wire': replay_wire,
            'config': config_ref, 'status': status_ref, 'outer': save(Path('outer.json'), outer),
            'proxy_receipt': proxy_ref, 'finality_receipt': finality_ref, 'pre_submit_report': pre_report_ref,
            'pre_submit_accounts': pre_refs, 'final_accounts': final_refs,
            'pre_restart_finality_receipt': pre_finality_ref, 'pre_stop_accounts': pre_stop_refs}
        slot = {'stage': {'report': report, 'report_sha256': '4'*64, 'plan_sha256': '5'*64,
                         'monitor_owner': 'stage-owner', 'runtime_identity': identity,
                         'accounts': stage_accounts, 'config': {'context': context_ref['path']}},
                'stage_bundle': {}, 'r0_sha256': '6'*64,
                'r0': {'selected_root': context['root'], 'action_hash': '7'*64},
                'case_stage_context': context, 'case_stage_context_sha256': context_ref['sha256']}
        bundle = {'result': {'wires': {'full': full_wire, 'replay_full': replay_wire}},
                  'proof': {'receipt': proof}, 'replay_proof': {'receipt': replay_proof}}
        globals_ = {'freeze': {'identities': {'loaded_elf': 'e'*64}}, 'frozen_bundles': {'registry': [
            {'path': str(Path(ref['path']).relative_to(self.root)), 'artifact': ref}
            for ref in source_refs.values()]}}
        def verify(value):
            return verifier._verify_ambiguous_restart(save(Path('sidecar.json'), value), 2,
                globals_, slot, bundle, set())
        with mock.patch.object(verifier, 'ROOT', self.root), \
             mock.patch.object(verifier, '_verify_wire'), \
             mock.patch.object(verifier, '_private_directory', side_effect=lambda path, label: Path(path)), \
             mock.patch.object(verifier, '_verify_r0_clone', return_value={
                 'destination': self.root/'ledger', 'receipt_sha256': clone['sha256']}):
            result = verify(sidecar)
            self.assertEqual(result['effect_count'], 1)
            self.assertEqual(result['signature_finalization_evidence'], 'pinned local RPC observation')
            for missing in ('pre_restart_finality_receipt', 'pre_stop_accounts'):
                changed = dict(sidecar)
                del changed[missing]
                with self.subTest(missing=missing), self.assertRaises(ValueError):
                    verify(changed)
            for field, value in (
                    ('pre_restart_signature_finalized_slot', 3),
                    ('pre_stop_accounts_slot', 6),
                    ('first_validator_stop_elapsed_seconds', 0.4),
                    ('restart_identity_elapsed_seconds', float('nan')),
                    ('pre_stop_account_sha256', ['f'*64]*5),
                    ('pre_restart_finality_receipt_sha256', 'f'*64)):
                changed = dict(sidecar, status=save(Path('control/status.json'),
                                                   dict(status, **{field: value})))
                with self.subTest(pre_stop_field=field), self.assertRaises(ValueError):
                    verify(changed)
            sidecar['status'] = save(Path('control/status.json'), status)
            altered_finality = json.loads(json.dumps(finality))
            altered_finality['signature_status']['slot'] = 5
            altered_finality['transaction']['slot'] = 5
            altered_ref = save(Path('control/pre-restart-finality-receipt.json'), altered_finality)
            changed = dict(sidecar, pre_restart_finality_receipt=altered_ref,
                status=save(Path('control/status.json'), dict(status,
                    pre_restart_finality_receipt_sha256=altered_ref['sha256'],
                    pre_restart_signature_finalized_slot=5)))
            with self.assertRaisesRegex(ValueError, 'pre-stop finality receipt'):
                verify(changed)
            sidecar['pre_restart_finality_receipt'] = save(
                Path('control/pre-restart-finality-receipt.json'), finality)
            sidecar['status'] = save(Path('control/status.json'), status)
            altered_pre = save(Path('output/pre-stop-request.bin'), pre['request'])
            changed = dict(sidecar, pre_stop_accounts={**pre_stop_refs, 'request': altered_pre})
            changed_status = dict(status,
                pre_stop_account_sha256=[changed['pre_stop_accounts'][n]['sha256']
                                        for n in verifier.ACCOUNT_NAMES])
            changed['status'] = save(Path('control/status.json'), changed_status)
            with self.assertRaises(ValueError):
                verify(changed)
            pre_stop_refs['request'] = save(Path('output/pre-stop-request.bin'), final['request'])
            sidecar['status'] = save(Path('control/status.json'), status)
            stdout_path = self.root / 'control/runner.stdout.log'
            stderr_path = self.root / 'control/runner.stderr.log'
            self.assertEqual(result['runner_stdout_sha256'], verifier._sha(
                b'Error: RPC sendTransaction transport failed\n'))
            self.assertEqual(result['runner_stderr_sha256'], verifier._sha(b''))
            stdout_path.write_bytes(b'')
            stderr_path.write_bytes(b'Error: RPC sendTransaction transport failed\n')
            stderr_only = verify(sidecar)
            self.assertEqual(stderr_only['effect_count'], 1)
            self.assertEqual(stderr_only['runner_stdout_sha256'], verifier._sha(b''))
            self.assertEqual(stderr_only['runner_stderr_sha256'], verifier._sha(
                b'Error: RPC sendTransaction transport failed\n'))
            for raw in (b'unrelated failure', b'x' * 65537):
                stdout_path.write_bytes(b'')
                stderr_path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'runner log'):
                    verify(sidecar)
            stdout_path.write_bytes(b'Error: RPC sendTransaction transport failed\n')
            stderr_path.write_bytes(b'')
            stdout_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'owner-only'):
                verify(sidecar)
            stdout_path.chmod(0o600)
            stdout_path.write_bytes(b'')
            stderr_path.write_bytes(b'Error: RPC sendTransaction transport failed\n')
            stderr_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'owner-only'):
                verify(sidecar)
            stderr_path.chmod(0o600)
            for field, value in (('signature_sha256', 'f'*64), ('signature_finalized_slot', 2),
                    ('effect_count', 2), ('final_account_sha256', ['f'*64]*5),
                    ('first_validator_stop_mode', 'interrupted_sigint'),
                    ('ledger_genesis_sha256_after_stop', 'f'*64)):
                with self.subTest(status_field=field):
                    altered = dict(status, **{field: value})
                    changed = dict(sidecar, status=save(Path('control/status.json'), altered))
                    with self.assertRaises(ValueError):
                        verify(changed)
            sidecar['status'] = save(Path('control/status.json'), status)
            changed = dict(sidecar, proxy_receipt=save(Path('control/proxy-receipt.json'),
                                                       dict(proxy, forwarded=2)))
            with self.assertRaises(ValueError):
                verify(changed)
            sidecar['proxy_receipt'] = save(Path('control/proxy-receipt.json'), proxy)
            for field, value in (('signature', '2'*64), ('confirmationStatus', 'confirmed'),
                    ('status_err', 'failure'), ('status_slot', 5), ('transaction_slot', 5),
                    ('transaction_err', 'failure'), ('signatures', ['2'*64]), ('extra', True)):
                with self.subTest(finality_field=field):
                    altered = json.loads(json.dumps(finality))
                    if field in ('signature', 'extra'):
                        altered[field] = value
                    elif field in ('confirmationStatus', 'status_err', 'status_slot'):
                        key = {'status_err': 'err', 'status_slot': 'slot'}.get(field, field)
                        altered['signature_status'][key] = value
                    elif field == 'transaction_err':
                        altered['transaction']['meta']['err'] = value
                    else:
                        key = 'slot' if field == 'transaction_slot' else field
                        altered['transaction'][key] = value
                    altered_ref = save(Path('control/finality-receipt.json'), altered)
                    altered_status = dict(status, finality_receipt_sha256=altered_ref['sha256'])
                    changed = dict(sidecar, finality_receipt=altered_ref,
                                   status=save(Path('control/status.json'), altered_status))
                    with self.assertRaisesRegex(ValueError, 'finality receipt'):
                        verify(changed)
            sidecar['finality_receipt'] = save(Path('control/finality-receipt.json'), finality)
            sidecar['status'] = save(Path('control/status.json'), status)
            missing_finality = dict(sidecar)
            del missing_finality['finality_receipt']
            with self.assertRaisesRegex(ValueError, 'sidecar must pin'):
                verify(missing_finality)
            changed = dict(sidecar, unexpected=True)
            with self.assertRaisesRegex(ValueError, 'sidecar must pin'):
                verify(changed)
            for name in ('first_validator_cleanup', 'final_validator_cleanup'):
                status[name] = {'spawned': True, 'reaped': True, 'graceful': False, 'exit_code': -2}
                status[name.replace('_cleanup', '_stop_mode')] = 'interrupted_sigint'
            sidecar['status'] = save(Path('control/status.json'), status)
            self.assertEqual(verify(sidecar)['effect_count'], 1)
            status['first_validator_cleanup']['exit_code'] = -9
            sidecar['status'] = save(Path('control/status.json'), status)
            with self.assertRaisesRegex(ValueError, 'shutdown'):
                verify(sidecar)

    def test_ambiguous_restart_journal_rejects_missing_or_repointed_evidence(self):
        case, steps = self._ambiguous_journal_fixture()
        verifier._verify_ambiguous_restart_journal(case, steps, 2, 'e' * 64)
        for mutation in ('missing', 'owner', 'wire', 'proof', 'clone', 'sidecar', 'wall', 'elf'):
            broken = json.loads(json.dumps(steps))
            with self.subTest(mutation=mutation):
                run = broken['positive_full:ambiguous-restart']
                if mutation == 'missing':
                    del broken['positive_full:ambiguous-restart']
                elif mutation == 'owner':
                    run['monitor_owner'] = 'wrong'
                elif mutation == 'wire':
                    run['inputs']['replay_full_wire_sha256'] = 'f' * 64
                elif mutation == 'proof':
                    run['inputs']['replay_proof_receipt_sha256'] = 'f' * 64
                elif mutation == 'clone':
                    broken['positive_full:ambiguous-restart-clone']['receipt_sha256'] = 'f' * 64
                elif mutation == 'sidecar':
                    run['sidecar_sha256'] = 'f' * 64
                elif mutation == 'wall':
                    run['wall_seconds'] = float('nan')
                elif mutation == 'elf':
                    run['inputs']['frozen_elf_sha256'] = 'f' * 64
                with self.assertRaises(ValueError):
                    verifier._verify_ambiguous_restart_journal(case, broken, 2, 'e' * 64)
        with self.assertRaises(ValueError):
            verifier._verify_ambiguous_restart_journal(
                dict(case, ambiguous_restart_wall_seconds=True), steps, 2, 'e' * 64)

    def test_early_ambiguous_clone_is_proof_independent_but_negative_step_is_proof_bound(self):
        case, steps = self._ambiguous_journal_fixture()
        clone = steps['positive_full:ambiguous-restart-clone']
        self.assertEqual(clone['inputs'], {
            'stage_report_sha256': '1' * 64,
            'label': 'ambiguous-restart-r0'})
        verifier._verify_ambiguous_restart_journal(case, steps, 2, 'e' * 64)

        broken = json.loads(json.dumps(steps))
        broken['positive_full:ambiguous-restart-clone']['inputs'][
            'full_proof_receipt_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'exact clone, proof, sidecar and monitor'):
            verifier._verify_ambiguous_restart_journal(case, broken, 2, 'e' * 64)

        broken = json.loads(json.dumps(steps))
        broken['positive_full:ambiguous-restart']['inputs'][
            'full_proof_receipt_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'exact clone, proof, sidecar and monitor'):
            verifier._verify_ambiguous_restart_journal(case, broken, 2, 'e' * 64)

    def test_positive_full_clones_must_complete_between_stage_and_transition(self):
        steps = {
            'positive_full:stage': {'status': 'passed', 'started_monotonic': 1.0,
                                    'completed_monotonic': 2.0},
            'positive_full:transition': {'status': 'passed', 'started_monotonic': 3.0,
                                         'completed_monotonic': 4.0}}
        clone_names = ('positive_full:r0-clone', 'positive_full:disabled-config-clone',
                       'positive_full:ambiguous-restart-clone')
        for index, name in enumerate(clone_names):
            steps[name] = {'status': 'passed', 'started_monotonic': 2.1 + index * 0.2,
                           'completed_monotonic': 2.2 + index * 0.2}

        verifier._verify_positive_full_clone_order(steps)
        for name in clone_names:
            with self.subTest(clone=name, reversal='before-stage'):
                broken = json.loads(json.dumps(steps))
                broken[name]['started_monotonic'] = 1.9
                broken[name]['completed_monotonic'] = 2.1
                with self.assertRaisesRegex(ValueError, 'after Full staging'):
                    verifier._verify_positive_full_clone_order(broken)
            with self.subTest(clone=name, reversal='after-transition-start'):
                broken = json.loads(json.dumps(steps))
                broken[name]['started_monotonic'] = 3.1
                broken[name]['completed_monotonic'] = 3.2
                with self.assertRaisesRegex(ValueError, 'before transition'):
                    verifier._verify_positive_full_clone_order(broken)

        for field, value in (('started_monotonic', float('nan')),
                             ('completed_monotonic', float('inf'))):
            with self.subTest(field=field):
                broken = json.loads(json.dumps(steps))
                broken['positive_full:r0-clone'][field] = value
                with self.assertRaisesRegex(ValueError, 'finite monotonic timestamps'):
                    verifier._verify_positive_full_clone_order(broken)
        broken = json.loads(json.dumps(steps))
        del broken['positive_full:disabled-config-clone']['completed_monotonic']
        with self.assertRaisesRegex(ValueError, 'finite monotonic timestamps'):
            verifier._verify_positive_full_clone_order(broken)

    def test_ambiguous_restart_journal_allows_job_overhead_above_outer_duration(self):
        case, steps = self._ambiguous_journal_fixture()
        steps['positive_full:ambiguous-restart']['wall_seconds'] = 3.0
        case['ambiguous_restart_wall_seconds'] = 4.25
        verifier._verify_ambiguous_restart_journal(case, steps, 2, 'e' * 64)
        steps['positive_full:ambiguous-restart']['wall_seconds'] = 2.0
        case['ambiguous_restart_wall_seconds'] = 3.25
        with self.assertRaisesRegex(ValueError, 'exact clone, proof, sidecar and monitor'):
            verifier._verify_ambiguous_restart_journal(case, steps, 2, 'e' * 64)

    def test_ambiguous_restart_account_bytes_reject_extra_effects_or_policy_changes(self):
        from harness.tests.queue_v3_local_ambiguous_restart import expected_reconciled_accounts
        stage = {name: bytearray(size) for name, size in zip(verifier.ACCOUNT_NAMES,
                    (381, 374, 280, 2249, 2090))}
        for name, magic in zip(verifier.ACCOUNT_NAMES,
                (b'DYNCONF3', b'DYNISS03', b'DYNHEAD3', b'DYNREQ03', b'DYNQUE03')):
            stage[name][:8] = magic
        stage['config'][332:364] = b'R' * 32
        stage['issuer'][213:221] = (10).to_bytes(8, 'big', signed=True)
        stage['head'][272:280] = (10).to_bytes(8, 'big', signed=True)
        stage['request'][183] = 1
        stage = {name: bytes(raw) for name, raw in stage.items()}
        request = b'Q' * 32
        after = expected_reconciled_accounts(list(stage.values()), {
            'root': b'R' * 32, 'request': request, 'observed_at': 20, 'head_committed_at': 21})
        final = dict(zip(verifier.ACCOUNT_NAMES, after))
        pre = {**final, 'request': stage['request'], 'queue': stage['queue']}
        verifier._verify_ambiguous_account_transition(stage, pre, final, request)
        for label, name, offset in (('pre', 'config', 380), ('pre', 'issuer', 172),
                ('pre', 'issuer', 181), ('pre', 'head', 112), ('pre', 'request', 183),
                ('final', 'config', 380), ('final', 'issuer', 172), ('final', 'head', 112),
                ('final', 'request', 183), ('final', 'queue', 41), ('final', 'queue', 74)):
            with self.subTest(label=label, name=name, offset=offset):
                changed = dict(pre if label == 'pre' else final)
                raw = bytearray(changed[name]); raw[offset] ^= 1; changed[name] = bytes(raw)
                with self.assertRaises(ValueError):
                    verifier._verify_ambiguous_account_transition(stage,
                        changed if label == 'pre' else pre,
                        changed if label == 'final' else final, request)
        with self.assertRaises(ValueError):
            verifier._verify_ambiguous_account_transition(stage, pre, final, b'Z' * 32)

    def test_case_run_manifest_and_journal_must_join_frozen_evidence(self):
        globals_ = {name: {'pinned': name} for name in (
            'frozen_files', 'frozen_bundles', 'source_files', 'proof_inputs',
            'application_source_manifest', 'application_source_files',
            'cohort_observation')}
        globals_['frozen_files'] = {'loaded_elf': {'sha256': 'e' * 64}}
        runner_path = str(verifier.ROOT / verifier.QUEUE_RUNNER_REL)
        globals_['frozen_bundles'] = {'registry': [{
            'path': verifier.QUEUE_RUNNER_REL,
            'artifact': {'path': runner_path, 'sha256': 'd' * 64}}],
            'client': []}
        run = {'schema': 'credential-v3-heldout-case-run-v1', 'variant': 2,
               'freeze_sha256': 'a' * 64, 'cohort_sha256': 'b' * 64,
               'runner': runner_path, 'runner_sha256': 'd' * 64, **globals_}
        run_path = self.root / 'case-02.json'
        run_raw = (json.dumps(run, sort_keys=True, indent=2) + '\n').encode()
        run_path.write_bytes(run_raw)
        run_path.chmod(0o600)
        canonical = hashlib.sha256((json.dumps(run, sort_keys=True,
            separators=(',', ':')) + '\n').encode()).hexdigest()
        outer_path = self.root / 'disabled-outer.json'
        outer_path.write_bytes((json.dumps({
            'owner': 'heldout-v02-positive_full-disabled-config-negative'},
            sort_keys=True) + '\n').encode())
        outer_path.chmod(0o600)
        outer_sha = hashlib.sha256(outer_path.read_bytes()).hexdigest()
        sidecar_path = self.root / 'disabled-sidecar.json'
        sidecar = {'variant': 2, 'stage_report_sha256': '1' * 64,
                   'stage_plan_sha256': '2' * 64,
                   'r0_source_receipt_sha256': '3' * 64,
                   'full_proof_receipt_sha256': '4' * 64,
                   'full_wire': {'sha256': '5' * 64},
                   'outer': {'path': str(outer_path), 'sha256': outer_sha},
                   'clone_receipt': {'path': str(self.root / 'disabled-clone.json'),
                                     'sha256': '6' * 64}}
        sidecar_raw = (json.dumps(sidecar, sort_keys=True) + '\n').encode()
        sidecar_path.write_bytes(sidecar_raw)
        sidecar_path.chmod(0o600)
        sidecar_sha = hashlib.sha256(sidecar_raw).hexdigest()
        journal_path = self.root / 'run-journal.json'
        journal = {'schema': 'credential-v3-heldout-case-run-journal-v1',
                   'manifest_sha256': canonical, 'steps': {
                       'positive_full:proof-full-fresh-replay': {'status': 'passed'},
                       'positive_full:disabled-config-clone': {
                           'status': 'passed', 'wall_seconds': 1.25,
                           'inputs': {'stage_report_sha256': '1' * 64,
                                      'label': 'disabled-config-r0'},
                           'receipt': sidecar['clone_receipt']['path'],
                           'receipt_sha256': sidecar['clone_receipt']['sha256']},
                       'positive_full:disabled-config-negative': {
                           'status': 'passed', 'wall_seconds': 2.5,
                           'inputs': {'variant': 2,
                                      'stage_report_sha256': '1' * 64,
                                      'stage_plan_sha256': '2' * 64,
                                      'source_receipt_sha256': '3' * 64,
                                      'proof_receipt_sha256': '4' * 64,
                                      'full_wire_sha256': '5' * 64,
                                      'clone_receipt_sha256': '6' * 64,
                                      'frozen_elf_sha256': 'e' * 64},
                           'sidecar': str(sidecar_path),
                           'sidecar_sha256': sidecar_sha,
                           'monitor': str(outer_path),
                           'monitor_sha256': outer_sha,
                           'monitor_owner': 'heldout-v02-positive_full-disabled-config-negative'}}}
        ambiguous_case, ambiguous_steps = self._ambiguous_journal_fixture()
        journal['steps'].update(ambiguous_steps)
        journal['steps'].update({
            'positive_full:stage': {'status': 'passed', 'started_monotonic': 1.0,
                                    'completed_monotonic': 2.0},
            'positive_full:r0-clone': {'status': 'passed', 'started_monotonic': 2.1,
                                       'completed_monotonic': 2.2},
            'positive_full:transition': {'status': 'passed', 'started_monotonic': 2.7,
                                         'completed_monotonic': 3.0}})
        journal['steps']['positive_full:disabled-config-clone'].update(
            started_monotonic=2.3, completed_monotonic=2.4)
        journal['steps']['positive_full:ambiguous-restart-clone'].update(
            started_monotonic=2.5, completed_monotonic=2.6)
        journal_raw = (json.dumps(journal, sort_keys=True) + '\n').encode()
        journal_path.write_bytes(journal_raw)
        journal_path.chmod(0o600)
        ref = lambda path: {'path': str(path),
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        case = {**ambiguous_case, 'run_manifest': ref(run_path), 'run_journal': ref(journal_path),
                'disabled_config_negative_wall_seconds': 3.75,
                'disabled_config_negative': ref(sidecar_path)}
        verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        wrong_monitor = json.loads(json.dumps(journal))
        wrong_monitor['steps']['positive_full:disabled-config-negative'][
            'monitor_sha256'] = 'f' * 64
        journal_path.write_bytes((json.dumps(wrong_monitor, sort_keys=True) + '\n').encode())
        case['run_journal'] = ref(journal_path)
        with self.assertRaisesRegex(ValueError, 'disabled-config journal evidence'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        wrong_monitor['steps']['positive_full:disabled-config-negative'][
            'monitor_sha256'] = outer_sha
        wrong_monitor['steps']['positive_full:disabled-config-negative'][
            'monitor_owner'] = 'wrong-owner'
        journal_path.write_bytes((json.dumps(wrong_monitor, sort_keys=True) + '\n').encode())
        case['run_journal'] = ref(journal_path)
        with self.assertRaisesRegex(ValueError, 'disabled-config journal evidence'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        journal_path.write_bytes(journal_raw)
        case['run_journal'] = ref(journal_path)
        wrong_sidecar = json.loads(json.dumps(journal))
        wrong_sidecar['steps']['positive_full:disabled-config-negative'][
            'sidecar_sha256'] = 'f' * 64
        journal_path.write_bytes((json.dumps(wrong_sidecar, sort_keys=True) + '\n').encode())
        case['run_journal'] = ref(journal_path)
        with self.assertRaisesRegex(ValueError, 'disabled-config journal evidence'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        journal_path.write_bytes(journal_raw)
        case['run_journal'] = ref(journal_path)
        wrong_cost = dict(case, disabled_config_negative_wall_seconds=3.7)
        with self.assertRaisesRegex(ValueError, 'disabled-config wall cost'):
            verifier._verify_case_run_provenance(
                wrong_cost, 2, globals_, 'a' * 64, 'b' * 64)
        missing_negative = json.loads(json.dumps(journal))
        del missing_negative['steps']['positive_full:disabled-config-negative']
        journal_path.write_bytes((json.dumps(missing_negative, sort_keys=True) + '\n').encode())
        case['run_journal'] = ref(journal_path)
        with self.assertRaisesRegex(ValueError, 'disabled-config'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        journal_path.write_bytes(journal_raw)
        case['run_journal'] = ref(journal_path)
        altered = dict(run, cohort_observation={'pinned': 'other-observation'})
        run_path.write_bytes((json.dumps(altered, sort_keys=True, indent=2) + '\n').encode())
        case['run_manifest'] = ref(run_path)
        with self.assertRaisesRegex(ValueError, 'cohort_observation'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        altered = dict(run, runner_sha256='e' * 64)
        run_path.write_bytes((json.dumps(altered, sort_keys=True, indent=2) + '\n').encode())
        case['run_manifest'] = ref(run_path)
        with self.assertRaisesRegex(ValueError, 'queue runner'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        run_path.write_bytes(run_raw)
        case['run_manifest'] = ref(run_path)
        journal['manifest_sha256'] = 'c' * 64
        journal_path.write_bytes((json.dumps(journal, sort_keys=True) + '\n').encode())
        case['run_journal'] = ref(journal_path)
        with self.assertRaisesRegex(ValueError, 'journal.*manifest'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)

    def test_manifest_reader_returns_exact_input_digest(self):
        raw = b'{"schema":"input"}\n'
        path = self.root / 'manifest.json'
        path.write_bytes(raw)
        manifest, digest = verifier._read_json_path(path)
        self.assertEqual(manifest, {'schema': 'input'})
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_missing_case_evidence_fails_closed(self):
        manifest = {
            'schema': verifier.MANIFEST_SCHEMA,
            'freeze_receipt': {'path': str(self.root / 'missing-freeze.json'),
                               'sha256': 'a' * 64},
            'cohort_receipt': {'path': str(self.root / 'missing-cohort.json'),
                               'sha256': 'b' * 64},
            'frozen_files': {},
            'source_files': {},
            'cases': [],
        }
        manifest_path = self.root / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'eight heldout cases'):
            verifier.verify_manifest(manifest_path)

    def test_offline_context_and_pair_receipts_cannot_claim_authentication(self):
        context = {'heldout_acceptance': False,
                   'authenticated': {'registry_history': False,
                                     'live_state': False,
                                     'current_head': False,
                                     'finalized_account_batch': False}}
        pair = {'heldout_acceptance': False, 'allocation_authorized': False,
                'registry_history_authenticated': False,
                'live_state_authenticated': False}
        verifier._verify_offline_provenance_flags(context, pair)
        context['authenticated']['current_head'] = True
        with self.assertRaisesRegex(ValueError, 'offline context'):
            verifier._verify_offline_provenance_flags(context, pair)
        context['authenticated']['current_head'] = False
        pair['allocation_authorized'] = True
        with self.assertRaisesRegex(ValueError, 'pair receipt'):
            verifier._verify_offline_provenance_flags(context, pair)

    def test_current_head_evidence_is_derived_from_signed_history_and_finalized_bytes(self):
        root = '11' * 32
        source_digest = '22' * 32
        publisher_digest = '33' * 32
        history_sha = '44' * 32
        report_sha = '55' * 32
        history = {'checkpoints': [{'source': {'observation': {'sequence': 2}},
                                    'publisher': {
                                        'root': list(bytes.fromhex(root)),
                                        'root_version': 1,
                                        'source_head': {'sequence': 2,
                                                        'digest': list(bytes.fromhex(source_digest))},
                                        'publication_sequence': 2,
                                        'publisher_key': list(bytes([0x66]) * 32),
                                        'previous_publication_digest': list(bytes(32))}}]}
        chain = {'source_sha256': source_digest,
                 'publisher_sha256': publisher_digest}
        head = bytearray(280)
        head[:8] = b'DYNHEAD3'
        head[72:104] = bytes([0x66]) * 32
        head[104:112] = (2).to_bytes(8, 'big')
        head[112:144] = bytes.fromhex(publisher_digest)
        head[144:176] = bytes(32)
        head[176:208] = bytes.fromhex(root)
        head[208:216] = (1).to_bytes(8, 'big')
        head[216:224] = (2).to_bytes(8, 'big')
        head[224:256] = bytes.fromhex(source_digest)
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[332:364] = bytes.fromhex(root)
        config[364:372] = (1).to_bytes(8, 'big')
        accounts = {'head': bytes(head), 'config': bytes(config)}
        report = {'source_head_digest': source_digest,
                  'publisher_envelope_digest': publisher_digest}

        evidence = verifier._derive_current_head_evidence(
            history=history, history_sha256=history_sha, chain=chain,
            accounts=accounts, expected_root=root, report=report,
            report_sha256=report_sha, label='R1')

        self.assertEqual(evidence['root'], root)
        self.assertEqual(evidence['root_version'], 1)
        self.assertEqual(evidence['source_sequence'], 2)
        self.assertEqual(evidence['source_digest'], source_digest)
        self.assertEqual(evidence['publisher_sequence'], 2)
        self.assertEqual(evidence['publisher_digest'], publisher_digest)
        self.assertEqual(evidence['history_sha256'], history_sha)
        self.assertEqual(evidence['report_sha256'], report_sha)
        self.assertEqual(evidence['finalized_head_account_sha256'],
                         hashlib.sha256(bytes(head)).hexdigest())
        self.assertFalse(evidence['independent_production_freshness'])

    def test_current_head_evidence_rejects_mutated_finalized_head_fields(self):
        root = '11' * 32
        source_digest = '22' * 32
        publisher_digest = '33' * 32
        history = {'checkpoints': [{'source': {'observation': {'sequence': 2}},
                                    'publisher': {
                                        'root': list(bytes.fromhex(root)),
                                        'root_version': 1,
                                        'source_head': {'sequence': 2,
                                                        'digest': list(bytes.fromhex(source_digest))},
                                        'publication_sequence': 2,
                                        'publisher_key': list(bytes([0x66]) * 32),
                                        'previous_publication_digest': list(bytes(32))}}]}
        chain = {'source_sha256': source_digest,
                 'publisher_sha256': publisher_digest}
        head = bytearray(280)
        head[:8] = b'DYNHEAD3'
        head[72:104] = bytes([0x66]) * 32
        head[104:112] = (2).to_bytes(8, 'big')
        head[112:144] = bytes.fromhex(publisher_digest)
        head[144:176] = bytes(32)
        head[176:208] = bytes.fromhex(root)
        head[208:216] = (1).to_bytes(8, 'big')
        head[216:224] = (2).to_bytes(8, 'big')
        head[224:256] = bytes.fromhex(source_digest)
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[332:364] = bytes.fromhex(root)
        config[364:372] = (1).to_bytes(8, 'big')
        report = {'source_head_digest': source_digest,
                  'publisher_envelope_digest': publisher_digest}

        mutations = (
            ('head root version', 'head', 208, b'\x02'),
            ('head publisher sequence', 'head', 104, b'\x03'),
            ('head source sequence', 'head', 216, b'\x03'),
            ('head source digest', 'head', 224, b'\x99'),
            ('head publisher digest', 'head', 112, b'\x99'),
            ('head publisher identity', 'head', 72, b'\x99'),
            ('config root version', 'config', 364, b'\x02'),
            ('config root', 'config', 332, b'\x99'),
        )
        for label, account_name, offset, replacement in mutations:
            with self.subTest(field=label):
                mutated = bytearray(head if account_name == 'head' else config)
                mutated[offset:offset + len(replacement)] = replacement
                accounts = {'head': bytes(head), 'config': bytes(config)}
                accounts[account_name] = bytes(mutated)
                with self.assertRaises(ValueError):
                    verifier._derive_current_head_evidence(
                        history=history, history_sha256='44' * 32, chain=chain,
                        accounts=accounts,
                        expected_root=root, report=report,
                        report_sha256='55' * 32, label='R1')

    def test_branch_passes_globals_and_slot_data_to_proof_validator(self):
        tree = ast.parse(inspect.getsource(verifier._verify_branch))
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)
                 and node.func.id == '_validate_proof_bundle']
        self.assertEqual(len(calls), 1)
        self.assertEqual([ast.unparse(arg) for arg in calls[0].args], [
            "bundle['proof']", 'branch', 'case', 'globals_', 'slot_data',
            "result_bundle['wires']"])

    def test_proof_case_label_matches_heldout_runner_prefix(self):
        self.assertEqual(verifier._proof_case_label({'variant': 3}, 'unrelated_compare'),
                         'heldout_v03_unrelated_compare')

    def test_proof_supervisor_caps_accept_helper_poll_interval(self):
        limits = {'runtime_seconds': 600, 'rss_bytes': 4 * 1024**3,
                  'storage_bytes': 512 * 1024**2}
        outer = {'limits': {'runtime_seconds': 600,
                            'owned_tree_rss_bytes': 4 * 1024**3,
                            'storage_growth_bytes': 512 * 1024**2,
                            'poll_seconds': 0.25}}
        self.assertTrue(verifier._proof_outer_limits_match(outer, limits))
        outer['limits']['poll_seconds'] = 0.2
        self.assertFalse(verifier._proof_outer_limits_match(outer, limits))

    def test_reviewed_execute_status_accepts_verified_sigint_stop(self):
        status = {'scope': 'part5-v3-local-execute', 'status': 'failed',
                  'error_type': None, 'effect_verified': True,
                  'application_effect': True, 'effect_count': 1,
                  'execute_report_sha256': 'a' * 64,
                  'validator_cleanup': {'spawned': True, 'reaped': True,
                                        'graceful': False, 'exit_code': -2},
                  'runner_cleanup': {'spawned': True, 'reaped': True,
                                     'exit_code': 0}}
        verifier._verify_reviewed_local_status(
            status, scope='part5-v3-local-execute', verified_field='effect_verified',
            report_field='execute_report_sha256', report_sha256='a' * 64,
            application_effect=True, effect_count=1)
        status['validator_cleanup']['exit_code'] = 0
        with self.assertRaisesRegex(ValueError, 'reviewed stop'):
            verifier._verify_reviewed_local_status(
                status, scope='part5-v3-local-execute', verified_field='effect_verified',
                report_field='execute_report_sha256', report_sha256='a' * 64,
                application_effect=True, effect_count=1)

    def test_report_identity_joins_producer_report_summary_to_status_runtime(self):
        elf_sha256 = 'a' * 64
        program = 'program-address'
        genesis = 'genesis-hash'
        report = {
            'program': program,
            'genesis': genesis,
            'loaded_program': {
                'elf_match': True, 'elf_sha256': elf_sha256,
                'loader': 'BPFLoaderUpgradeab1e11111111111111111111111',
                'local_bytes': 123, 'remote_bytes': 123,
            },
        }
        status = {'loaded_program': {
            'elf_match': True, 'elf_sha256': elf_sha256,
            'program': program, 'programdata': 'programdata-address',
            'loader': 'BPFLoaderUpgradeab1e11111111111111111111111',
            'elf_bytes': 123,
            'program_account_sha256': 'b' * 64,
            'programdata_account_sha256': 'c' * 64,
            'genesis': genesis,
        }}

        identity_verifier = getattr(verifier, '_verify_report_runtime_identity', None)
        self.assertIsNotNone(identity_verifier,
                             'runtime identity join must be independently testable')
        config = {'expected_genesis': genesis}
        identity = identity_verifier(
            report, status, config, elf_sha256,
            expected_program=program, expected_genesis=genesis)

        self.assertEqual(identity['program'], program)
        self.assertEqual(identity['genesis'], genesis)
        with self.assertRaisesRegex(ValueError, 'runtime identity'):
            identity_verifier(
                report, status, config, elf_sha256,
                expected_program=program, expected_genesis='other-genesis')
        status['loaded_program']['program'] = 'other-program'
        with self.assertRaisesRegex(ValueError, 'runtime identity'):
            identity_verifier(
                report, status, config, elf_sha256,
                expected_program=program, expected_genesis=genesis)

    def test_exporter_source_and_ordinary_adapter_have_distinct_role_pins(self):
        source_hashes = {'exporter': 'd' * 64}
        proof_hashes = {'exporter': 'd' * 64, 'adapter_binary': '5' * 64}
        frozen_hashes = {'ordinary_adapter': '5' * 64}
        verifier._verify_exporter_adapter_roles(source_hashes, proof_hashes,
                                                frozen_hashes)
        proof_hashes['exporter'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'exporter'):
            verifier._verify_exporter_adapter_roles(source_hashes, proof_hashes,
                                                    frozen_hashes)

    def test_proof_packet_and_report_must_share_exact_application_stage_pins(self):
        stage_pins = {name: f'{index + 1:064x}' for index, name in enumerate(
            verifier.PROOF_STAGE_PIN_FIELDS)}
        packet = {
            'schema': 'credential-v3-request-bound-anchor-v1',
            'synthetic_only': False, 'application_verified': False,
            'cohort': 'request-bound-training-v1',
            'proof_source_identity': 'f' * 64,
            'application_stage': stage_pins,
            'pairs': [{'name': 'request_bound_training',
                       'base': {'input_path': '/tmp/base/input.json',
                                'input_sha256': 'a' * 64,
                                'public_path': '/tmp/base/public.json',
                                'public_sha256': 'b' * 64,
                                'wtns_path': '/tmp/base/output.wtns',
                                'wtns_sha256': 'c' * 64,
                                'issuer_version': 1, 'policy_version': 1,
                                'allocation_epoch': 1, 'root_version': 0},
                       'near': {'input_path': '/tmp/near/input.json',
                                'input_sha256': 'd' * 64,
                                'public_path': '/tmp/near/public.json',
                                'public_sha256': 'e' * 64,
                                'wtns_path': '/tmp/near/output.wtns',
                                'wtns_sha256': 'f' * 64,
                                'issuer_version': 1, 'policy_version': 1,
                                'allocation_epoch': 1, 'root_version': 1}}],
        }
        packet.update({name: f'{index + 100:064x}' for index, name in enumerate(
            verifier.PACKET_IDENTITY_FIELDS)})
        report = {
            'schema': 'credential-v3-matched-k1-proof-v1', 'passed': True,
            'application_verified': False, 'setup_executed': False,
            'private_cache_persisted': False, 'qualification_extras_executed': False,
            'old_base_full_rejected_at_near_publics': True,
            'application_stage_pins_authority':
                'caller-supplied; external finalized-state verification required',
            'application_stage_pins': stage_pins,
            'package_digest': packet['package_digest'],
            'proof_binary_sha256': '1' * 64,
            'ordinary_vk_file_sha256': '2' * 64,
            'setup_manifest_sha256': '3' * 64,
            'proof_source_identity': packet['proof_source_identity'],
            'packet_sha256': '4' * 64,
            'mode': 'matched-full-k1',
            'counts': {'proofs': 2, 'positive_checks': 2,
                       'altered_public_checks': 12, 'cross_root_checks': 2,
                       'ordinary_checks': 16},
        }
        packet_fields = {name: packet[name] for name in verifier.PACKET_IDENTITY_FIELDS}
        packet_kinds = {'input.json': 'input', 'public.json': 'public',
                        'output.wtns': 'wtns'}
        artifact_refs = {
            f'{side}/{kind}': {'path': value[f'{packet_kind}_path'],
                               'sha256': value[f'{packet_kind}_sha256']}
            for side, value in (('base', packet['pairs'][0]['base']),
                                ('near', packet['pairs'][0]['near']))
            for kind, packet_kind in packet_kinds.items()
        }
        report_identities = {name: report[name] for name in (
            'package_digest', 'proof_binary_sha256', 'ordinary_vk_file_sha256',
            'setup_manifest_sha256', 'proof_source_identity')}
        verifier._validate_packet_and_proof_report(
            packet, report, packet_sha256='4' * 64, proof_mode='matched-full-k1',
            stage_pins=stage_pins, packet_fields=packet_fields,
            artifact_refs=artifact_refs,
            report_identities=report_identities,
            proof_counts=report['counts'])
        report['application_stage_pins'] = dict(stage_pins, base_root='e' * 64)
        with self.assertRaisesRegex(ValueError, 'stage pins'):
            verifier._validate_packet_and_proof_report(
                packet, report, packet_sha256='4' * 64, proof_mode='matched-full-k1',
                stage_pins=stage_pins, packet_fields=packet_fields,
                artifact_refs=artifact_refs,
                report_identities=report_identities,
                proof_counts=report['counts'])

    def test_cohort_requires_four_issuers_eight_layouts_and_exactly_four_openssl(self):
        freeze = {
            'schema': FREEZE_SCHEMA,
            'frozen_at_unix_ns': 100,
            'identities': {role: f'{index + 1:064x}'
                           for index, role in enumerate(sorted(IDENTITY_ROLES))},
        }
        rows = [{
            'variant': variant,
            'issuer_index': variant % 4,
            'holder_index': variant,
            'credential_sha256': f'{variant + 101:064x}',
            'tbs_sha256': f'{variant + 201:064x}',
            'issuer_public_key_sha256': f'{variant % 4 + 301:064x}',
            'holder_public_key_sha256': f'{variant + 401:064x}',
            'aki_sha256': f'{variant % 4 + 501:064x}',
            'issuer_hash': str(1000 + variant % 4),
            'policy_hash': str(2000 + variant // 4),
            'encoder': 'openssl' if variant < 4 else 'cryptography',
            'not_before_unix': 1_700_000_000,
            'not_after_unix': 1_800_000_000,
        } for variant in range(8)]
        cohort = {
            'schema': COHORT_SCHEMA,
            'status': 'cohort_issued_pending_application_gate',
            'keys_generated_after_freeze': True,
            'freeze_sha256': 'a' * 64,
            'frozen_at_unix_ns': 100,
            'generation_started_unix_ns': 101,
            'generation_completed_unix_ns': 102,
            'counts': {'issuers': 4, 'holders': 8, 'certificates': 8,
                       'openssl_issuances': 4, 'policies': 2},
            'policy_hashes': ['2000', '2001'],
            'issuer_aki_sha256': sorted({row['aki_sha256'] for row in rows}),
            'identities': freeze['identities'],
            'certificates': rows,
        }
        accepted = verifier._case_cohort(freeze, 'a' * 64, cohort, 'b' * 64)
        self.assertEqual(set(accepted), set(range(8)))
        cohort['certificates'][4]['encoder'] = 'openssl'
        with self.assertRaisesRegex(ValueError, 'OpenSSL'):
            verifier._case_cohort(freeze, 'a' * 64, cohort, 'b' * 64)

    def test_cohort_generation_provenance_joins_inventory_keys_times_and_serials(self):
        (freeze, freeze_ref, cohort, cohort_ref, by_variant,
         key_receipt, inventory) = self._cohort_provenance_artifacts()
        result = verifier._verify_cohort_generation_provenance(
            freeze, freeze_ref['sha256'], cohort, by_variant,
            freeze_ref, cohort_ref)
        self.assertEqual(result['prior_key_inventory_sha256'],
                         cohort['prior_key_inventory_sha256'])
        self.assertEqual(result['key_generation_receipt_sha256'],
                         cohort['key_generation_receipt_sha256'])
        evidence = result['cohort_import_evidence']
        self.assertEqual(evidence['cohort_receipt_sha256'], cohort_ref['sha256'])
        self.assertEqual(evidence['counts']['certificates'], 8)
        self.assertEqual(evidence['creation_time_basis'],
                         'cohort and key-generation receipt claims only')

        by_variant[3]['serial_hex'] = (1 << 120).to_bytes(16, 'big').hex()
        with self.assertRaisesRegex(ValueError, 'serial sequence'):
            verifier._verify_cohort_generation_provenance(
                freeze, freeze_ref['sha256'], cohort, by_variant,
                freeze_ref, cohort_ref)
        by_variant[3]['serial_hex'] = ((1 << 120) + 4).to_bytes(16, 'big').hex()
        by_variant[2]['issuance_started_unix_ns'] = 2039
        with self.assertRaisesRegex(ValueError, 'issuance must follow key generation'):
            verifier._verify_cohort_generation_provenance(
                freeze, freeze_ref['sha256'], cohort, by_variant,
                freeze_ref, cohort_ref)

        by_variant[2]['issuance_started_unix_ns'] = 2090
        original_issuer_key = by_variant[0]['issuer_public_key_sha256']
        by_variant[0]['issuer_public_key_sha256'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'match the pinned key-generation receipt'):
            verifier._verify_cohort_generation_provenance(
                freeze, freeze_ref['sha256'], cohort, by_variant,
                freeze_ref, cohort_ref)
        by_variant[0]['issuer_public_key_sha256'] = original_issuer_key

        key_receipt['keys'][0]['public_key_sha256'] = inventory['public_key_sha256'][0]
        key_path = Path(cohort_ref['path']).parent / 'keys' / 'key-generation-receipt.json'
        key_raw = json.dumps(key_receipt, sort_keys=True, separators=(',', ':')).encode()
        key_path.write_bytes(key_raw)
        key_path.chmod(0o600)
        cohort['key_generation_receipt_sha256'] = hashlib.sha256(key_raw).hexdigest()
        cohort_path = Path(cohort_ref['path'])
        cohort_raw = json.dumps(cohort, sort_keys=True, separators=(',', ':')).encode()
        cohort_path.write_bytes(cohort_raw)
        cohort_path.chmod(0o600)
        cohort_ref['sha256'] = hashlib.sha256(cohort_raw).hexdigest()
        with self.assertRaisesRegex(ValueError, 'absent from prior inventory'):
            verifier._verify_cohort_generation_provenance(
                freeze, freeze_ref['sha256'], cohort, by_variant,
                freeze_ref, cohort_ref)

    def test_anchor_transaction_receipt_must_show_stale_r0_rejection(self):
        rows = [
            {'scenario': 'v3-observe-signed-current-status', 'customError': None,
             'err': None},
            {'scenario': 'v3-bind-current-branch-head', 'customError': None,
             'err': None},
            {'scenario': 'v3-stale-R0-full', 'customError': 713,
             'err': {'InstructionError': [1, {'Custom': 713}]}},
            {'scenario': 'v3-anchor-wrong-action', 'customError': 712,
             'err': {'InstructionError': [1, {'Custom': 712}]}},
            {'scenario': 'v3-anchor-invalid-proof', 'customError': 714,
             'err': {'InstructionError': [1, {'Custom': 714}]}},
            {'scenario': 'v3-valid-anchor-R1', 'customError': None, 'err': None},
            {'scenario': 'v3-anchor-replay', 'customError': 707,
             'err': {'InstructionError': [1, {'Custom': 707}]}},
        ]
        expected = [(row['scenario'], row['customError']) for row in rows]
        verifier._txs(rows, expected, 'Anchor')
        rows[2] = dict(rows[2], customError=None, err=None)
        with self.assertRaisesRegex(ValueError, 'transaction outcome mismatch'):
            verifier._txs(rows, expected, 'Anchor')

    def test_full_a_transaction_receipt_matches_execute_report_order_and_codes(self):
        rows = [
            {'scenario': 'v3-refresh-active-source', 'customError': None,
             'err': None},
            {'scenario': 'v3-bind-refreshed-head', 'customError': None,
             'err': None},
            {'scenario': 'v3-wrong-issuer', 'customError': 713,
             'err': {'InstructionError': [1, {'Custom': 713}]}},
            {'scenario': 'v3-wrong-policy', 'customError': 713,
             'err': {'InstructionError': [1, {'Custom': 713}]}},
            {'scenario': 'v3-wrong-action', 'customError': 712,
             'err': {'InstructionError': [1, {'Custom': 712}]}},
            {'scenario': 'v3-invalid-proof', 'customError': 714,
             'err': {'InstructionError': [1, {'Custom': 714}]}},
            {'scenario': 'v3-execute-readonly-request', 'customError': 711,
             'err': {'InstructionError': [1, {'Custom': 711}]}},
            {'scenario': 'v3-execute-missing-final-account', 'customError': 709,
             'err': {'InstructionError': [1, {'Custom': 709}]}},
            {'scenario': 'v3-execute-system-program-as-issuer', 'customError': 710,
             'err': {'InstructionError': [1, {'Custom': 710}]}},
            {'scenario': 'v3-execute-wrong-account-order', 'customError': 701,
             'err': {'InstructionError': [1, {'Custom': 701}]}},
            {'scenario': 'v3-valid-full-execute', 'customError': None,
             'err': None},
            {'scenario': 'v3-replay-new-transaction', 'customError': 707,
             'err': {'InstructionError': [1, {'Custom': 707}]}},
        ]
        snapshots = {'before_sha256': [f'{n:064x}' for n in range(1, 6)],
                     'after_sha256': [f'{n:064x}' for n in range(1, 6)]}
        verifier._verify_full_transactions(rows, snapshots)
        with self.assertRaisesRegex(ValueError, 'transaction outcome mismatch'):
            verifier._verify_full_transactions(rows[1:] + rows[:1], snapshots)
        rows[6]['err'] = {'InstructionError': [1, {'Custom': 710}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[6]['err'] = {'InstructionError': [1, {'Custom': 711}]}
        rows[2]['err'] = {'InstructionError': [1, {'Custom': 714}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[2]['err'] = {'InstructionError': [1, {'Custom': 713}]}
        rows[7]['err'] = {'InstructionError': [1, {'Custom': 710}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[7]['err'] = {'InstructionError': [1, {'Custom': 709}]}
        rows[8]['err'] = {'InstructionError': [1, {'Custom': 709}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[8]['err'] = {'InstructionError': [1, {'Custom': 710}]}
        rows[9]['err'] = {'InstructionError': [1, {'Custom': 709}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[9]['err'] = {'InstructionError': [1, {'Custom': 701}]}
        snapshots['after_sha256'][0] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'preserve all five accounts'):
            verifier._verify_full_transactions(rows, snapshots)

    def test_full_a_rejection_hashes_must_match_pinned_account_bytes(self):
        finalized = {name: f'final-{name}'.encode()
                     for name in ('config', 'issuer', 'head', 'request', 'queue')}
        staged = {name: f'stage-{name}'.encode()
                  for name in ('config', 'issuer', 'head', 'request', 'queue')}
        expected = [hashlib.sha256(finalized[name]).hexdigest()
                    for name in ('config', 'issuer', 'head')]
        expected.extend(hashlib.sha256(staged[name]).hexdigest()
                        for name in ('request', 'queue'))
        report = {'before_sha256': expected[:], 'after_sha256': expected[:]}

        verifier._verify_full_rejection_account_hashes(report, finalized, staged)

        report['before_sha256'][0] = hashlib.sha256(b'tampered').hexdigest()
        report['after_sha256'][0] = report['before_sha256'][0]
        with self.assertRaisesRegex(ValueError, 'pinned finalized/staged account bytes'):
            verifier._verify_full_rejection_account_hashes(report, finalized, staged)

    def test_stage_receipt_requires_pre_enrollment_create_rejection_before_enrollment(self):
        rows = [
            {'scenario': 'v3-initialize', 'customError': None, 'err': None},
            {'scenario': 'v3-pre-enrollment-create', 'customError': 710,
             'err': {'InstructionError': [1, {'Custom': 710}]}},
            {'scenario': 'v3-enroll', 'customError': None, 'err': None},
            {'scenario': 'v3-create', 'customError': None, 'err': None},
        ]
        verifier._verify_pre_enrollment_create(rows, True)
        reordered = rows[:]
        reordered[1], reordered[2] = reordered[2], reordered[1]
        with self.assertRaisesRegex(ValueError, 'pre-enrollment Create must fail before enrollment'):
            verifier._verify_pre_enrollment_create(reordered, True)
        with self.assertRaisesRegex(ValueError, 'request PDA absent'):
            verifier._verify_pre_enrollment_create(rows, False)
        rows[1]['customError'] = 713
        rows[1]['err'] = {'InstructionError': [1, {'Custom': 713}]}
        with self.assertRaisesRegex(ValueError, 'pre-enrollment Create error mismatch'):
            verifier._verify_pre_enrollment_create(rows, True)

    def test_own_leaf_absence_is_rebuilt_from_pair_membership(self):
        own, unrelated = b't' * 32, b'u' * 32
        slot = 73
        membership = membership_for_pair(own, unrelated, slot)
        membership.update(issuer_hash=1200, policy_hash=2300)
        case = {
            'target': {'tbs_sha256': own.hex(), 'issuer_hash': '1200',
                       'policy_hash': '2300'},
            'unrelated': {'tbs_sha256': unrelated.hex()},
            'membership': membership,
            'roots': {'R0': f"{membership['active_root']:064x}",
                      'R1': f"{membership['unrelated_root']:064x}",
                      'R2': f"{membership['own_revoked_root']:064x}"},
        }
        verifier._verify_leaf_absent(case)
        case['roots']['R2'] = case['roots']['R1']
        with self.assertRaisesRegex(ValueError, 'active from finalized R2'):
            verifier._verify_leaf_absent(case)

    def test_current_r2_witness_receipt_rejects_generic_failure(self):
        receipt = {'schema': 'part5-v3-r2-active-witness-rejection-v1',
                   'outcome': 'generator_failed'}
        with mock.patch.object(verifier, '_json', return_value=(receipt, 'a' * 64)):
            with self.assertRaisesRegex(ValueError, 'separate generator and R1CS outcomes'):
                verifier._verify_current_r2_witness_rejection(
                    {'path': '/unused/receipt.json', 'sha256': 'a' * 64}, {}, {}, {}, {})

    def test_current_r2_witness_receipt_rejects_old_r1_proof_rejection_only(self):
        receipt = {'schema': 'part5-v3-r2-active-witness-rejection-v1',
                   'outcome': 'old_r1_proof_rejected_at_r2'}
        with mock.patch.object(verifier, '_json', return_value=(receipt, 'b' * 64)):
            with self.assertRaisesRegex(ValueError, 'separate generator and R1CS outcomes'):
                verifier._verify_current_r2_witness_rejection(
                    {'path': '/unused/receipt.json', 'sha256': 'b' * 64}, {}, {}, {}, {})

    def test_current_r2_receipt_requires_independent_generator_and_relation_supervisors(self):
        receipt = {'schema': 'part5-v3-r2-active-witness-rejection-v1',
                   'outcome': 'generator_rejected_plus_counterfactual_r1cs_unsatisfied',
                   'generator_attempt': {'exit_code': 1}}
        with mock.patch.object(verifier, '_json', return_value=(receipt, 'c' * 64)):
            with self.assertRaisesRegex(ValueError, 'separate generator and R1CS outcomes'):
                verifier._verify_current_r2_witness_rejection(
                    {'path': '/unused/receipt.json', 'sha256': 'c' * 64}, {}, {}, {}, {})

    def test_current_r2_receipt_accepts_only_cross_pinned_counterfactual_row(self):
        def write(path, raw):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

        def json_ref(name, value):
            return write(self.root / name, verifier._canonical_json(value))

        r1_root, r2_root = f'{1:064x}', f'{2:064x}'
        action_hash = f'{8:064x}'
        own_siblings = [40 + index for index in range(10)]
        base_input = {'root': str(int(r1_root, 16)),
                      'siblings': [str(3 + index) for index in range(10)],
                      'issuerHash': '4', 'notBefore': '5', 'notAfter': '6',
                      'actionHash': str(int(action_hash, 16)), 'policyHash': '9'}
        candidate_input = dict(base_input, root=str(int(r2_root, 16)),
                               siblings=[str(value) for value in own_siblings])
        base_input_ref = json_ref('base-input.json', base_input)
        candidate_input_ref = json_ref('candidate-input.json', candidate_input)

        coordinates = list(range(1, 752))
        coordinates_raw = b''.join(value.to_bytes(4, 'little') for value in coordinates)
        coordinates_ref = write(self.root / 'input-coordinates.bin', coordinates_raw)
        values = [0] * 784796
        values[0] = 1
        values[1:7] = [int(base_input[name]) for name in (
            'root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash')]
        for index, wire in enumerate(coordinates[731:741]):
            values[wire] = int(base_input['siblings'][index])

        def wtns_bytes(assignment):
            fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            header = ((32).to_bytes(4, 'little') + fr.to_bytes(32, 'little')
                      + len(assignment).to_bytes(4, 'little'))
            section1 = (1).to_bytes(4, 'little') + len(header).to_bytes(8, 'little') + header
            data = b''.join(value.to_bytes(32, 'little') for value in assignment)
            section2 = (2).to_bytes(4, 'little') + len(data).to_bytes(8, 'little') + data
            return b'wtns' + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little') + section1 + section2

        base_witness_ref = write(self.root / 'base.wtns', wtns_bytes(values))
        patched_values = list(values)
        patched_values[1] = int(r2_root, 16)
        for index, wire in enumerate(coordinates[731:741]):
            patched_values[wire] = own_siblings[index]
        patched_witness_ref = write(self.root / 'patched.wtns', wtns_bytes(patched_values))
        receipt_hashes = {
            'candidate_input_sha256': candidate_input_ref['sha256'],
            'witness_sha256': patched_witness_ref['sha256'],
            'base_r1_witness_sha256': base_witness_ref['sha256'],
            'r1cs_sha256': 'e' * 64,
            'relation_checker_sha256': 'd' * 64,
        }
        relation_result = {
            'schema': 'part5-v3-r2-active-witness-r1cs-result-v1',
            'status': 'unsatisfied', 'scan': 'first_unsatisfied_row',
            'constraint_row': 73,
            'expected_public': [candidate_input[name] for name in (
                'root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash')],
            **receipt_hashes,
        }
        result_ref = json_ref('r1cs-result.json', relation_result)
        witness_limits = {'runtime_seconds': 300, 'rss_bytes': 4 * 1024**3,
                          'storage_bytes': 512 * 1024**2}
        relation_limits = {'runtime_seconds': 600, 'rss_bytes': 4 * 1024**3,
                           'storage_bytes': 512 * 1024**2}

        def outer_ref(name, exit_code, limits):
            outer = {'schema': 1, 'passed': exit_code == 0, 'exit_code': exit_code,
                     'stop_reason': None, 'runner_error_type': None,
                     'cleanup_remaining_owned_processes': 0,
                     'cleanup_status_unknown': False,
                     'duration_seconds': 1.0, 'sample_count': 1,
                     'limits': {'runtime_seconds': limits['runtime_seconds'],
                                'owned_tree_rss_bytes': limits['rss_bytes'],
                                'storage_growth_bytes': limits['storage_bytes'],
                                'poll_seconds': verifier.PROOF_POLL_SECONDS}}
            outer['owner'] = name.replace('.json', '-owner')
            return json_ref(name, outer)

        generator_ref = outer_ref('generator-outer.json', 2, witness_limits)
        relation_ref = outer_ref('relation-outer.json', 0, relation_limits)
        candidate_dir = self.root / 'candidate'
        candidate_dir.mkdir()
        # Move the candidate artifact into its actual generator input directory.
        candidate_input_ref = write(candidate_dir / 'input.json',
                                    verifier._canonical_json(candidate_input))
        candidate_input_ref['sha256'] = hashlib.sha256(
            verifier._canonical_json(candidate_input)).hexdigest()
        relation_dir = self.root / 'relation'
        relation_dir.mkdir()
        result_ref = json_ref('relation/r1cs-result.json', relation_result)
        generator_monitor = self.root / 'generator-monitor'
        relation_monitor = self.root / 'relation-monitor'
        generator_monitor.mkdir()
        relation_monitor.mkdir()
        generator_argv = ['/frozen/node', '/frozen/witness.cjs', str(candidate_dir)]
        relation_argv = [sys.executable, '-B',
                         str(verifier.ROOT / 'tools/part5/check_v3_r2_counterfactual.py'),
                         '--candidate-input', candidate_input_ref['path'],
                         '--candidate-input-sha256', candidate_input_ref['sha256'],
                         '--witness', str(self.root / 'patched.wtns'),
                         '--witness-sha256', patched_witness_ref['sha256'],
                         '--base-r1-witness', str(self.root / 'base.wtns'),
                         '--base-r1-witness-sha256', base_witness_ref['sha256'],
                         '--r1cs', '/frozen/r1cs', '--r1cs-sha256', 'e' * 64,
                         '--relation-checker', '/frozen/relation.py',
                         '--relation-checker-sha256', 'd' * 64,
                         '--output', result_ref['path']]

        def invocation_ref(path, owner, argv, roots):
            return json_ref(path, {'owner': owner, 'argv': argv, 'cwd': str(verifier.ROOT),
                                   'started_at_utc': '2026-10-17T12:00:00Z',
                                   'storage_roots': roots})

        generator_invocation_ref = invocation_ref(
            'generator-monitor/invocation.json', 'generator-outer-owner', generator_argv,
            [str(generator_monitor), str(candidate_dir)])
        relation_invocation_ref = invocation_ref(
            'relation-monitor/invocation.json', 'relation-outer-owner', relation_argv,
            [str(relation_monitor), str(relation_dir)])
        receipt = {
            'schema': 'part5-v3-r2-active-witness-rejection-v1',
            'outcome': 'generator_rejected_plus_counterfactual_r1cs_unsatisfied',
            'r2_root': r2_root, 'base_r1_root': r1_root,
            'own_revoked_siblings_sha256': verifier._sha(verifier._canonical_json(own_siblings)),
            'base_r1_input_sha256': base_input_ref['sha256'],
            'candidate_input_sha256': candidate_input_ref['sha256'],
            'base_r1_input_ref': base_input_ref,
            'candidate_input_ref': candidate_input_ref,
            'generator_invocation_ref': generator_invocation_ref,
            'relation_invocation_ref': relation_invocation_ref,
            'input_coordinates_ref': coordinates_ref,
            'input_coordinates_sha256': coordinates_ref['sha256'],
            'target_credential_sha256': 'a' * 64, 'target_tbs_sha256': 'b' * 64,
            'action_hash': action_hash, 'witness_generator_sha256': 'g' * 64,
            'relation_checker_sha256': 'd' * 64, 'r1cs_sha256': 'e' * 64,
            'bounded_supervisor_sha256': 'f' * 64,
            'generator_attempt': {'exit_code': 2, 'output_wtns_present': False,
                                  'input_sha256': candidate_input_ref['sha256'],
                                  'supervisor_ref': generator_ref,
                                  'supervisor_limits': witness_limits},
            'counterfactual_assignment': {
                'label': 'counterfactual_r1_wtns_with_r2_public_root_and_revoked_siblings',
                'base_r1_witness_ref': base_witness_ref,
                'base_r1_witness_sha256': base_witness_ref['sha256'],
                'patched_witness_ref': patched_witness_ref,
                'patched_witness_sha256': patched_witness_ref['sha256']},
            'r1cs_result': relation_result, 'r1cs_result_ref': result_ref,
            'relation_supervisor': {'ref': relation_ref, 'limits': relation_limits,
                                    'exit_code': 0},
        }
        receipt_ref = json_ref('receipt.json', receipt)
        case = {'roots': {'R1': r1_root, 'R2': r2_root},
                'membership': {'own_revoked_siblings': own_siblings},
                'target': {'credential_sha256': 'a' * 64, 'tbs_sha256': 'b' * 64}}
        slot_data = {'r1_input': base_input,
                     'r1_input_sha256': base_input_ref['sha256'],
                     'r1': {'action_hash': action_hash}}
        globals_ = {
            'freeze': {'identities': {'witness_executable': 'c' * 64, 'r1cs': 'e' * 64}},
            'proof_inputs': {'witness_js': 'g' * 64, 'relation_checker': 'd' * 64,
                             'bounded_supervisor': 'f' * 64},
            'proof_input_paths': {'node': Path('/frozen/node'),
                                  'witness_js': Path('/frozen/witness.cjs'),
                                  'relation_checker': Path('/frozen/relation.py')},
            'frozen_paths': {'r1cs': Path('/frozen/r1cs')},
            'packet_template': {'input_map_sha256': coordinates_ref['sha256']},
        }
        result = verifier._verify_current_r2_witness_rejection(
            receipt_ref, case, globals_, slot_data,
            {'artifacts': {'near/output.wtns': base_witness_ref}})
        self.assertEqual(result['r1cs_constraint_row'], 73)
        self.assertEqual(result['generator_output_absence_scope'],
                         'present-time only; not historical proof')

        bad_invocation = {'owner': 'generator-outer-owner', 'argv': generator_argv[:-1]
                          + ['/wrong/candidate'], 'cwd': str(verifier.ROOT),
                          'started_at_utc': '2026-10-17T12:00:00Z',
                          'storage_roots': [str(generator_monitor), str(candidate_dir)]}
        receipt['generator_invocation_ref'] = json_ref(
            'generator-monitor/invocation.json', bad_invocation)
        receipt_ref = json_ref('receipt.json', receipt)
        with self.assertRaisesRegex(ValueError, 'exact argv, cwd, owner, and storage roots'):
            verifier._verify_current_r2_witness_rejection(
                receipt_ref, case, globals_, slot_data,
                {'artifacts': {'near/output.wtns': base_witness_ref}})

        receipt['r2_root'] = r1_root
        receipt['generator_invocation_ref'] = generator_invocation_ref
        receipt_ref = json_ref('receipt.json', receipt)
        with self.assertRaisesRegex(ValueError, 'membership, target, and C action'):
            verifier._verify_current_r2_witness_rejection(
                receipt_ref, case, globals_, slot_data,
                {'artifacts': {'near/output.wtns': base_witness_ref}})

    def test_four_outcomes_map_to_three_request_identities(self):
        branches = {
            'full': {'finalized_request_sha256': 'a' * 64,
                     'request_account_sha256': '1' * 64,
                     'action_hash': '1' * 64},
            'unrelated_full': {'finalized_request_sha256': 'b' * 64,
                               'request_account_sha256': '2' * 64,
                               'action_hash': '2' * 64,
                               'current_root': 'R1'},
            'anchor': {'finalized_request_sha256': 'b' * 64,
                       'request_account_sha256': '2' * 64,
                       'action_hash': '2' * 64,
                       'current_root': 'R1'},
            'own_revocation': {'finalized_request_sha256': 'd' * 64,
                               'request_account_sha256': '3' * 64,
                               'action_hash': '3' * 64},
        }
        finalized, accounts = set(), set()
        result = verifier._validate_request_triads(branches, finalized, accounts)
        self.assertEqual(result, {'A': 'a' * 64, 'B': 'b' * 64, 'C': 'd' * 64})
        self.assertEqual(len(finalized), 3)
        self.assertEqual(len(accounts), 3)
        branches['anchor'] = dict(branches['anchor'], finalized_request_sha256='e' * 64)
        with self.assertRaisesRegex(ValueError, 'share exact request B'):
            verifier._validate_request_triads(branches, set(), set())
        branches['anchor'] = dict(branches['unrelated_full'])
        branches['full']['action_hash'] = '2' * 64
        with self.assertRaisesRegex(ValueError, 'distinct action hashes'):
            verifier._validate_request_triads(branches, set(), set())

    def test_outer_allows_only_uncensored_expected_sigint_exit(self):
        path = self.root / 'outer.json'
        outer = {
            'schema': 1, 'passed': False, 'exit_code': 1,
            'stop_reason': None, 'runner_error_type': None,
            'cleanup_remaining_owned_processes': 0,
            'cleanup_status_unknown': False,
            'duration_seconds': 1.0, 'sample_count': 2,
        }
        path.write_text(json.dumps(outer))
        path.chmod(0o600)
        ref = {'path': str(path), 'sha256': verifier._sha(path.read_bytes())}
        self.assertEqual(verifier._outer(ref, 'transition')['exit_code'], 1)
        outer['stop_reason'] = 'runtime_limit'
        path.write_text(json.dumps(outer))
        ref['sha256'] = verifier._sha(path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'complete uncensored outer session'):
            verifier._outer(ref, 'transition')




if __name__ == '__main__':
    unittest.main()
