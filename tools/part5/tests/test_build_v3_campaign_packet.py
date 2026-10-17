import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import build_v3_campaign_packet as tool


class CampaignPacketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.stage, self.transition, self.cohort = [self.directory(n) for n in ('stage', 'transition', 'cohort')]
        self.context = dict(root_sequence=[f'{i + 1:064x}' for i in range(11)],
                            issuer_hash=f'{2:064x}', policy_id=f'{3:064x}',
                            not_before=100, not_after=200,
                            initial_allocations=dict(cohort_receipt_sha256='a' * 64,
                                membership_sha256='b' * 64, root_sequence_sha256='c' * 64))
        self.context_path = self.root / 'context.json'
        self.save(self.context_path, self.context)
        self.save(self.cohort / 'cohort-receipt.json', dict(freeze_receipt_sha256='d' * 64))
        self.plan = dict(root=list(bytes.fromhex(self.context['root_sequence'][0])), program=[0] * 32, genesis=[0] * 32)
        self.save(self.stage / 'plan.json', self.plan)
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[136:168] = (3).to_bytes(32, 'big')
        config[332:364] = (1).to_bytes(32, 'big')
        request = bytearray(2249)
        request[:8] = b'DYNREQ03'
        request[104:136] = (2).to_bytes(32, 'big')
        request[169] = 1
        request[177] = 1
        request[182:185] = bytes([2, 1, 2])
        self.config, self.request = bytes(config), bytes(request)
        for directory in (self.stage, self.transition):
            for name, data in zip(('config', 'issuer', 'head', 'request', 'queue'),
                                  (self.config, b'issuer', b'head', self.request, b'queue')):
                self.save(directory / (name + '.bin'), data)
            self.save(directory / 'signed-history.json', {})
        self.save(self.stage / 'initial-allocations.json', self.context['initial_allocations'])
        self.staged = dict(schema='part5-v3-campaign-stage-v1', passed=True,
            training_only=True, registry_history_authenticated=True,
            allocation_history_authenticated=True, upstream_source_authentication=True,
            upstream_publisher_authentication=True, application_effect=False, proof_created=False,
            program='1' * 32, genesis='1' * 32, loaded_program=dict(
                elf_match=True, elf_sha256='e' * 64, loader='upgradeable',
                local_bytes=4096, remote_bytes=4096),
            request='1' * 32, finalized_slot=10,
            plan_sha256=self.sha(self.stage / 'plan.json'),
            signed_history_sha256=self.sha(self.stage / 'signed-history.json'),
            initial_allocations_sha256=self.sha(self.stage / 'initial-allocations.json'),
            account_sha256=[self.sha(self.stage / (n + '.bin')) for n in ('config', 'issuer', 'head', 'request', 'queue')])
        self.save(self.stage / 'stage-report.json', self.staged)
        self.old = self.root / 'old.json'
        self.save(self.old, {k: 'x' for k in ('package_digest', 'setup_manifest_path',
            'setup_manifest_sha256', 'package_check_path', 'package_check_sha256',
            'r1cs_path', 'wasm_path', 'profile_path', 'input_map_path', 'input_map_sha256')})
        self.fixtures = []
        for i in range(11):
            directory = self.directory(f'r{i}')
            row = [str(i + 1), '2', '100', '200', tool.action(self.config, self.request, self.plan), '3']
            self.save(directory / 'public.json', row)
            self.save(directory / 'input.json', dict(zip(('root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash'), row)))
            self.save(directory / 'output.wtns', b'witness')
            self.fixtures.append(directory)

    def directory(self, name):
        path = self.root / name
        path.mkdir(mode=0o700)
        return path

    def save(self, path, data):
        path.write_bytes(data if isinstance(data, bytes) else tool.encoded(data))
        path.chmod(0o600)

    def sha(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def transition_report(self, count):
        config = bytearray(self.config)
        config[332:364] = (count + 1).to_bytes(32, 'big')
        self.save(self.transition / 'config.bin', bytes(config))
        pins = list(self.staged['account_sha256'])
        pins[0] = self.sha(self.transition / 'config.bin')
        report = dict(self.staged, schema='part5-v3-campaign-transition-v1',
            target_count=count, request_unconsumed=True, account_sha256=pins,
            context_sha256=self.sha(self.context_path),
            root_sequence_sha256=self.context['initial_allocations']['root_sequence_sha256'],
            stage_report_sha256=self.sha(self.stage / 'stage-report.json'),
            stage_plan_sha256=self.sha(self.stage / 'plan.json'),
            base_finalized_slot=10, finalized_slot=10 + count,
            base_root=self.context['root_sequence'][0], current_root=self.context['root_sequence'][count],
            checkpoints=[dict(account_sha256=pins, finalized_slot=11 + i) for i in range(count)])
        report['loaded_program'] = self.staged['loaded_program'].copy()
        self.save(self.transition / 'transition-report.json', report)
        return report

    def build(self, count, coalesced=False, fixtures=None):
        with mock.patch.object(tool, 'derive', return_value=self.context), \
             mock.patch.object(tool, 'checked_history') as history:
            selected = fixtures if fixtures is not None else (
                self.fixtures[count:count + 1] if coalesced else self.fixtures[:count + 1])
            packet = tool.build(self.stage, self.transition if count else self.stage,
                self.cohort, self.context_path, selected, self.old, count, coalesced)
            self.assertEqual(history.call_count, 2 if count else 1)
            return packet

    def test_exact_registered_prefixes_and_coalesced(self):
        for count in tool.COUNTS:
            if count:
                self.transition_report(count)
            for coalesced in (False, True):
                with self.subTest(count=count, coalesced=coalesced):
                    packet = self.build(count, coalesced)
                    self.assertFalse(packet['application_verified'])
                    self.assertEqual(packet['application_stage']['near_root'], str(count + 1))
                    if coalesced:
                        self.assertEqual(packet['final']['root_version'], count)
                        self.assertNotIn('pairs', packet)
                    else:
                        self.assertEqual(len(packet['pairs']), max(count, 1))
                        self.assertEqual(packet['pairs'][-1]['name'], f'request_bound_training_r{count}')
                        self.assertEqual(packet['pairs'][-1]['near']['root_version'], count)

    def test_transition_pins_rejected(self):
        for key in ('context_sha256', 'root_sequence_sha256', 'initial_allocations_sha256',
                    'loaded_program', 'base_finalized_slot', 'account_sha256'):
            report = self.transition_report(1)
            report[key] = None
            self.save(self.transition / 'transition-report.json', report)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.build(1)

    def test_transition_loaded_elf_and_size_must_match_stage(self):
        for key, value in (('elf_sha256', '0' * 64), ('remote_bytes', 4095)):
            report = self.transition_report(1)
            report['loaded_program'][key] = value
            self.save(self.transition / 'transition-report.json', report)
            with self.subTest(key=key), self.assertRaisesRegex(
                    ValueError, 'signed current campaign transition'):
                self.build(1)

    def test_public_action_cannot_drift_together(self):
        for i in range(2):
            path = self.fixtures[i] / 'public.json'
            row = json.loads(path.read_bytes())
            row[4] = '42'
            self.save(path, row)
        self.transition_report(1)
        with self.assertRaisesRegex(ValueError, 'public root prefix'):
            self.build(1)

    def test_private_input_must_match_public(self):
        path = self.fixtures[0] / 'input.json'
        row = json.loads(path.read_bytes())
        row['actionHash'] = '42'
        self.save(path, row)
        with self.assertRaisesRegex(ValueError, 'public/input'):
            self.build(0)

    def test_coalesced_requires_final_private_fixture(self):
        self.transition_report(2)
        (self.fixtures[2] / 'output.wtns').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'owner-only'):
            self.build(2, True)

    def test_coalesced_k5_accepts_only_final_fixture(self):
        self.transition_report(5)
        packet = self.build(5, True, self.fixtures[5:6])
        self.assertEqual(packet['final']['root_version'], 5)
        self.assertEqual(packet['application_stage']['base_root'], str(1))
        self.assertEqual(packet['application_stage']['near_root'], str(6))
        self.assertNotIn('pairs', packet)

    def test_coalesced_rejects_hidden_extra_fixture(self):
        self.transition_report(5)
        with self.assertRaisesRegex(ValueError, 'registered complete checkpoint prefix'):
            self.build(5, True, self.fixtures[4:6])

    def test_zero_requires_exact_stage(self):
        with self.assertRaisesRegex(ValueError, 'zero-update'):
            tool.build(self.stage, self.transition, self.cohort, self.context_path,
                       self.fixtures[:1], self.old, 0)

    def test_missing_checkpoint_rejected(self):
        report = self.transition_report(2)
        report['checkpoints'].pop()
        self.save(self.transition / 'transition-report.json', report)
        with self.assertRaises(ValueError):
            self.build(2)


if __name__ == '__main__':
    unittest.main()
