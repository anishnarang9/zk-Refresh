import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.part5 import generate_v3_heldout_keys as keygen
from tools.part5 import observe_v3_heldout_cohort as tool


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.parent.chmod(0o700)
        self.part5 = self.parent / 'private-part5-root'
        self.part5.mkdir(mode=0o700)
        self.private_parent = self.part5 / 'v3-heldout-private-test'
        self.private_parent.mkdir(mode=0o700)
        self.part5_patch = mock.patch.object(tool, 'PART5_OUTPUT_ROOT', self.part5)
        self.part5_patch.start()
        self.addCleanup(self.part5_patch.stop)
        self.freeze = self.parent / 'freeze.json'
        self.inventory = self.parent / 'prior-key-inventory.json'
        self.output = self.private_parent / 'cohort'
        self.observation = self.private_parent / 'observation.json'
        self.freeze_value = {
            'schema': keygen.FREEZE_SCHEMA,
            'frozen_at_unix_ns': 100,
            'identities': {name: 'a' * 64 for name in keygen.IDENTITY_ROLES},
        }
        self.freeze.write_text(json.dumps(self.freeze_value))
        self.freeze.chmod(0o600)
        self.inventory.write_text('{}')
        self.inventory.chmod(0o600)
        self.freeze_sha = hashlib.sha256(self.freeze.read_bytes()).hexdigest()
        self.inventory_sha = hashlib.sha256(self.inventory.read_bytes()).hexdigest()

    def args(self):
        return tool.ObserverInputs(
            freeze=self.freeze, freeze_sha256=self.freeze_sha,
            prior_key_inventory=self.inventory,
            prior_key_inventory_sha256=self.inventory_sha,
            output=self.output, observation=self.observation)

    def child_success(self, command, **kwargs):
        self.assertEqual(command[:4], [tool.sys.executable, '-B', '-m',
                                       'tools.part5.build_v3_heldout_cohort'])
        self.assertEqual(command[4:], [
            '--freeze', str(self.freeze), '--freeze-sha256', self.freeze_sha,
            '--prior-key-inventory', str(self.inventory),
            '--prior-key-inventory-sha256', self.inventory_sha,
            '--output', str(self.output),
        ])
        self.assertEqual(kwargs['stdout'], tool.subprocess.DEVNULL)
        self.assertEqual(kwargs['stderr'], tool.subprocess.DEVNULL)
        self.assertEqual(kwargs['timeout'], tool.CHILD_TIMEOUT_SECONDS)
        self.assertEqual(kwargs['env']['TMPDIR'], str(Path(kwargs['env']['TMPDIR'])))
        self.assertEqual(Path(kwargs['env']['TMPDIR']).stat().st_mode & 0o777, 0o700)
        self.output.mkdir(mode=0o700)
        certs = [{
            'variant': i,
            'holder_index': i,
            'issuer_index': i % 4,
            'encoder': 'openssl' if i < 4 else 'cryptography',
            'issuance_started_unix_ns': 120 + i * 5,
            'issuance_completed_unix_ns': 122 + i * 5,
        } for i in range(8)]
        receipt = {
            'schema': tool.COHORT_SCHEMA,
            'status': 'cohort_issued_pending_application_gate',
            'keys_generated_after_freeze': True,
            'freeze_sha256': self.freeze_sha,
            'prior_key_inventory_sha256': self.inventory_sha,
            'frozen_at_unix_ns': 100,
            'identities': self.freeze_value['identities'],
            'generation_started_unix_ns': 110,
            'generation_completed_unix_ns': 180,
            'counts': {'issuers': 4, 'holders': 8, 'certificates': 8,
                       'openssl_issuances': 4, 'policies': 2},
            'certificates': certs,
        }
        receipt_path = self.output / tool.COHORT_RECEIPT
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o600)
        return mock.Mock(returncode=0)

    def test_records_parent_timing_and_independently_hashed_success(self):
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run', side_effect=self.child_success) as run, \
             mock.patch.object(tool.time, 'time_ns', side_effect=[101, 202]), \
             mock.patch.object(tool.time, 'monotonic_ns', side_effect=[11, 22]):
            result = tool.observe(self.args())

        run.assert_called_once()
        observation = json.loads(self.observation.read_text())
        raw_receipt = (self.output / tool.COHORT_RECEIPT).read_bytes()
        self.assertEqual(result, observation)
        self.assertEqual(observation['freeze_sha256'], self.freeze_sha)
        self.assertEqual(observation['cohort_receipt_sha256'], hashlib.sha256(raw_receipt).hexdigest())
        self.assertEqual(observation['child_exit_code'], 0)
        self.assertEqual(observation['wall_started_unix_ns'], 101)
        self.assertEqual(observation['wall_completed_unix_ns'], 202)
        self.assertEqual(observation['monotonic_started_ns'], 11)
        self.assertEqual(observation['monotonic_completed_ns'], 22)
        self.assertEqual(observation['creation_time_basis'],
                         'observer_parent_started_child_after_freeze')
        self.assertFalse(observation['openssl_invocation_observed'])
        self.assertFalse(observation['preexisting_output'])
        self.assertEqual(observation['output_path_sha256'],
                         hashlib.sha256(str(self.output).encode()).hexdigest())
        self.assertNotIn('output_path', observation)
        self.assertEqual(observation['builder_source_sha256'], tool._builder_source_sha256())
        self.assertEqual(observation['observer_source_sha256'], tool._observer_source_sha256())
        self.assertEqual(self.observation.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.observation.parent.stat().st_mode & 0o777, 0o700)

    def test_nonzero_child_does_not_publish_observation(self):
        def partial_child(command, **kwargs):
            self.output.mkdir(mode=0o700)
            receipt = self.output / tool.COHORT_RECEIPT
            receipt.write_text('partial evidence')
            receipt.chmod(0o600)
            return mock.Mock(returncode=7)

        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run', side_effect=partial_child), \
             mock.patch.object(tool.time, 'time_ns', side_effect=[101, 202]), \
             mock.patch.object(tool.time, 'monotonic_ns', side_effect=[11, 22]):
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(self.args())
        self.assertFalse(self.observation.exists())
        self.assertEqual((self.output / tool.COHORT_RECEIPT).read_text(), 'partial evidence')

    def test_invalid_success_receipt_does_not_publish_observation(self):
        def invalid_child(command, **kwargs):
            self.output.mkdir(mode=0o700)
            receipt_path = self.output / tool.COHORT_RECEIPT
            receipt_path.write_text(json.dumps({
                'schema': tool.COHORT_SCHEMA,
                'status': 'cohort_issued_pending_application_gate',
                'keys_generated_after_freeze': True,
                'freeze_sha256': '0' * 64,
                'prior_key_inventory_sha256': self.inventory_sha,
                'frozen_at_unix_ns': 100,
                'identities': self.freeze_value['identities'],
                'generation_started_unix_ns': 110,
                'generation_completed_unix_ns': 180,
                'counts': {'issuers': 4, 'holders': 8, 'certificates': 8,
                           'openssl_issuances': 4, 'policies': 2},
                'certificates': [{'encoder': 'openssl'}] * 8,
            }))
            receipt_path.chmod(0o600)
            return mock.Mock(returncode=0)

        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run', side_effect=invalid_child), \
             mock.patch.object(tool.time, 'time_ns', side_effect=[101, 202]), \
             mock.patch.object(tool.time, 'monotonic_ns', side_effect=[11, 22]):
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(self.args())
        self.assertFalse(self.observation.exists())
        self.assertTrue((self.output / tool.COHORT_RECEIPT).exists())

    def test_rejects_existing_observation_and_freeze_before_launch(self):
        self.observation.symlink_to(self.freeze)
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(self.args())
        run.assert_not_called()

    def test_rejects_preexisting_output_without_removing_its_receipt(self):
        self.output.mkdir(mode=0o700)
        receipt = self.output / tool.COHORT_RECEIPT
        receipt.write_text('preexisting')
        receipt.chmod(0o600)
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(self.args())
        run.assert_not_called()
        self.assertEqual(receipt.read_text(), 'preexisting')

    def test_parent_wall_clock_must_follow_freeze_before_launch(self):
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run') as run, \
             mock.patch.object(tool.time, 'time_ns', return_value=100), \
             mock.patch.object(tool.time, 'monotonic_ns', return_value=11):
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(self.args())
        run.assert_not_called()
        self.assertFalse(self.observation.exists())

    def test_parent_must_be_reserved_direct_child_outside_training_008(self):
        reserved = self.part5 / 'v3-matrix-training-008'
        reserved.mkdir(mode=0o700)
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(tool.ObserverInputs(
                    self.freeze, self.freeze_sha, self.inventory, self.inventory_sha,
                    reserved / 'cohort', reserved / 'observation.json'))
        run.assert_not_called()

    def test_parent_must_be_fresh_and_empty(self):
        (self.private_parent / 'stale-marker').write_text('prior use')
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(self.args())
        run.assert_not_called()

    def test_receipt_must_match_pins_status_counts_and_parent_interval(self):
        mutations = {
            'inventory': lambda r: r.update(prior_key_inventory_sha256='0' * 64),
            'freeze_time': lambda r: r.update(frozen_at_unix_ns=99),
            'identities': lambda r: r.update(identities={}),
            'status': lambda r: r.update(status='accepted'),
            'fresh_keys': lambda r: r.update(keys_generated_after_freeze=False),
            'issuer_count': lambda r: r['counts'].update(issuers=3),
            'holder_count': lambda r: r['counts'].update(holders=7),
            'certificate_count': lambda r: r['counts'].update(certificates=7),
            'openssl_count': lambda r: r['counts'].update(openssl_issuances=3),
            'pre_interval_generation': lambda r: r.update(generation_started_unix_ns=99),
            'post_interval_completion': lambda r: r.update(generation_completed_unix_ns=203),
        }
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run') as run, \
             mock.patch.object(tool.time, 'time_ns', side_effect=[101, 202] * len(mutations)), \
             mock.patch.object(tool.time, 'monotonic_ns', side_effect=[11, 22] * len(mutations)):
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    case_parent = self.part5 / f'v3-heldout-private-{name}'
                    case_parent.mkdir(mode=0o700)
                    self.output = case_parent / 'cohort'
                    self.observation = case_parent / 'observation.json'

                    def invalid_receipt(command, **kwargs):
                        self.child_success(command, **kwargs)
                        receipt_path = self.output / tool.COHORT_RECEIPT
                        receipt = json.loads(receipt_path.read_text())
                        mutate(receipt)
                        receipt_path.write_text(json.dumps(receipt))
                        receipt_path.chmod(0o600)
                        return mock.Mock(returncode=0)

                    run.side_effect = invalid_receipt
                    with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                        tool.observe(self.args())
                    self.assertFalse(self.observation.exists())
                    self.assertTrue((self.output / tool.COHORT_RECEIPT).exists())

    def test_certificate_rows_must_bind_layout_encoder_and_ordered_times(self):
        mutations = {
            'duplicate_variant': lambda r: r['certificates'][7].update(
                variant=0, issuer_index=0, encoder='openssl'),
            'duplicate_holder': lambda r: r['certificates'][7].update(holder_index=0),
            'wrong_issuer': lambda r: r['certificates'][4].update(issuer_index=1),
            'wrong_encoder': lambda r: r['certificates'][0].update(encoder='cryptography'),
            'before_parent_start': lambda r: r['certificates'][0].update(
                issuance_started_unix_ns=100),
            'after_parent_end': lambda r: r['certificates'][7].update(
                issuance_completed_unix_ns=203),
            'reversed_issue_order': lambda r: r['certificates'][1].update(
                issuance_started_unix_ns=119, issuance_completed_unix_ns=121),
        }
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run') as run, \
             mock.patch.object(tool.time, 'time_ns', side_effect=[101, 202] * len(mutations)), \
             mock.patch.object(tool.time, 'monotonic_ns', side_effect=[11, 22] * len(mutations)):
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    case_parent = self.part5 / f'v3-heldout-private-rows-{name}'
                    case_parent.mkdir(mode=0o700)
                    self.output = case_parent / 'cohort'
                    self.observation = case_parent / 'observation.json'

                    def invalid_rows(command, **kwargs):
                        self.child_success(command, **kwargs)
                        receipt_path = self.output / tool.COHORT_RECEIPT
                        receipt = json.loads(receipt_path.read_text())
                        mutate(receipt)
                        receipt_path.write_text(json.dumps(receipt))
                        receipt_path.chmod(0o600)
                        return mock.Mock(returncode=0)

                    run.side_effect = invalid_rows
                    with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                        tool.observe(self.args())
                    self.assertFalse(self.observation.exists())
                    self.assertTrue((self.output / tool.COHORT_RECEIPT).exists())

    def test_builder_source_change_during_child_rejects_observation(self):
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run', side_effect=self.child_success), \
             mock.patch.object(tool, '_builder_source_sha256', side_effect=['a' * 64, 'b' * 64]), \
             mock.patch.object(tool.time, 'time_ns', side_effect=[101, 202]), \
             mock.patch.object(tool.time, 'monotonic_ns', side_effect=[11, 22]):
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(self.args())
        self.assertFalse(self.observation.exists())
        self.assertTrue((self.output / tool.COHORT_RECEIPT).exists())

    def test_oversized_freeze_is_rejected_before_child_launch(self):
        self.freeze.write_bytes(b'{' + b' ' * (64 * 1024) + b'}')
        self.freeze.chmod(0o600)
        self.freeze_sha = hashlib.sha256(self.freeze.read_bytes()).hexdigest()
        with mock.patch.object(tool.keygen, '_ignored', return_value=True), \
             mock.patch.object(tool.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'heldout observation failed'):
                tool.observe(self.args())
        run.assert_not_called()

    def test_direct_script_help_loads_without_module_path_setup(self):
        result = subprocess.run(
            [sys.executable, '-B', 'tools/part5/observe_v3_heldout_cohort.py', '--help'],
            cwd=tool.ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--observation', result.stdout)


if __name__ == '__main__':
    unittest.main()
