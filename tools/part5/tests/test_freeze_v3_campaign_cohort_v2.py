import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import freeze_v3_campaign_cohort_v2 as tool


class CampaignFreezeV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.part5 = self.root / 'artifacts/dynark/part5'
        self.part5.mkdir(parents=True)
        self.output_root = self.part5
        self.output = self.output_root / 'v3-heldout-freeze-v2-001'

        patches = (
            mock.patch.object(tool, 'ROOT', self.root),
            mock.patch.object(tool, 'PART5', self.output_root),
            mock.patch.object(tool.prior_freeze, 'ROOT', self.root),
            mock.patch.object(tool.prior_freeze, 'PART5', self.part5),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

        self.identities = {
            role: hashlib.sha256(role.encode()).hexdigest()
            for role in tool.preflight_v2.IDENTITY_ROLES
        }
        self.preflight = {
            'schema': tool.preflight_v2.PREFLIGHT_SCHEMA,
            'preflight_passed': True,
            'freeze_published': False,
            'identities': self.identities,
            **{
                field: self.identities[role]
                for field, role in tool.preflight_v2.DIRECT_IDENTITY_ROLES.items()
            },
        }
        self.inputs = {
            'package_pins_path': self.root / 'pins.json',
            'package_pins_sha256': 'a' * 64,
            'prepare_status': self.root / 'prepare.json',
            'application_source_manifest': self.root / 'source-manifest.json',
            'application_elf': self.root / 'program.so',
            'proof_binary': self.root / 'proof-runner',
            'proof_binary_sha256': self.identities['proof_binary'],
            'input_preparer': self.root / 'prepare-v3.py',
            'input_preparer_sha256': self.identities['input_preparer'],
            'client_source': self.root / 'client.py',
            'adapter_binary': self.root / 'adapter',
        }
        self.key_source = {
            'path': 'artifacts/dynark/part5/earlier.pem',
            'sha256': 'e' * 64,
            'public_key_sha256': 'f' * 64,
        }

    def test_freeze_publishes_packet_boundary_and_owner_only_key_inventory(self):
        with (mock.patch.object(tool.preflight_v2, 'preflight',
                                side_effect=[self.preflight, self.preflight]) as preflight,
              mock.patch.object(tool.prior_freeze, 'prior_keys',
                                return_value=([self.key_source['public_key_sha256']],
                                              [self.key_source]))):
            receipt = tool.freeze(self.output, **self.inputs)

        self.assertEqual(preflight.call_count, 2)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        boundary_path = self.output / 'freeze.json'
        inventory_path = self.output / 'prior-key-inventory.json'
        self.assertEqual(boundary_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(inventory_path.stat().st_mode & 0o777, 0o600)

        boundary_raw = boundary_path.read_bytes()
        boundary = json.loads(boundary_raw)
        self.assertEqual(set(boundary), {'schema', *tool.PACKET_BOUNDARY_FIELDS})
        self.assertEqual(boundary['schema'], 'credential-v3-frozen-holdout-boundary-v2')
        self.assertGreater(boundary['frozen_at_unix_ns'], 0)
        for field in tool.PACKET_BOUNDARY_FIELDS - {'frozen_at_unix_ns'}:
            self.assertEqual(boundary[field], self.preflight[field])
        self.assertEqual(receipt['freeze_sha256'], hashlib.sha256(boundary_raw).hexdigest())

        inventory_raw = inventory_path.read_bytes()
        inventory = json.loads(inventory_raw)
        self.assertEqual(inventory['schema'], tool.INVENTORY_SCHEMA)
        self.assertEqual(inventory['freeze_sha256'], receipt['freeze_sha256'])
        self.assertEqual(inventory['public_key_sha256'],
                         [self.key_source['public_key_sha256']])
        self.assertEqual(inventory['sources'], [self.key_source])
        self.assertNotIn(b'BEGIN ', boundary_raw + inventory_raw)
        self.assertEqual(receipt['prior_key_inventory_sha256'],
                         hashlib.sha256(inventory_raw).hexdigest())

    def test_changed_v2_preflight_identity_aborts_without_publication(self):
        changed = dict(self.preflight)
        changed['application_elf_sha256'] = '0' * 64
        changed['identities'] = dict(self.identities, application_elf='0' * 64)
        with (mock.patch.object(tool.preflight_v2, 'preflight',
                                side_effect=[self.preflight, changed]),
              mock.patch.object(tool.prior_freeze, 'prior_keys',
                                return_value=(['f' * 64], [self.key_source])),
              self.assertRaisesRegex(ValueError, 'preflight inputs changed')):
            tool.freeze(self.output, **self.inputs)
        self.assertFalse(self.output.exists())

    def test_failed_v2_preflight_never_publishes_a_freeze(self):
        failed = dict(self.preflight, preflight_passed=False)
        with (mock.patch.object(tool.preflight_v2, 'preflight', return_value=failed),
              self.assertRaisesRegex(ValueError, 'successful v2 heldout preflight')):
            tool.freeze(self.output, **self.inputs)
        self.assertFalse(self.output.exists())

    def test_changed_prior_key_inventory_aborts_without_publication(self):
        with (mock.patch.object(tool.preflight_v2, 'preflight',
                                side_effect=[self.preflight, self.preflight]),
              mock.patch.object(tool.prior_freeze, 'prior_keys',
                                side_effect=[(['f' * 64], [self.key_source]),
                                             (['0' * 64], [dict(
                                                 self.key_source,
                                                 public_key_sha256='0' * 64)])]),
              self.assertRaisesRegex(ValueError, 'prior RSA inventory changed')):
            tool.freeze(self.output, **self.inputs)
        self.assertFalse(self.output.exists())

    def test_empty_prior_key_inventory_is_rejected(self):
        with (mock.patch.object(tool.preflight_v2, 'preflight', return_value=self.preflight),
              mock.patch.object(tool.prior_freeze, 'prior_keys', return_value=([], [])),
              self.assertRaisesRegex(ValueError, 'earlier RSA key inventory required')):
            tool.freeze(self.output, **self.inputs)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved(self):
        self.output.mkdir(mode=0o700)
        sentinel = self.output / 'keep'
        sentinel.write_text('preserve')
        with self.assertRaises(ValueError):
            tool.freeze(self.output, **self.inputs)
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_parent_fsync_failure_preserves_published_freeze_as_evidence(self):
        parent_info = self.output_root.stat()
        real_fsync = os.fsync

        def fail_results_parent(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (parent_info.st_dev, parent_info.st_ino):
                raise OSError('injected parent fsync failure')
            return real_fsync(fd)

        with mock.patch.object(tool.os, 'fsync', side_effect=fail_results_parent):
            with self.assertRaisesRegex(OSError, 'injected parent fsync failure'):
                tool._publish_pair(self.output, b'{"freeze":true}\n',
                                   b'{"inventory":true}\n')

        self.assertTrue(self.output.is_dir())
        self.assertEqual((self.output / 'freeze.json').read_bytes(),
                         b'{"freeze":true}\n')
        self.assertEqual((self.output / 'prior-key-inventory.json').read_bytes(),
                         b'{"inventory":true}\n')
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def test_freeze_marker_failure_preserves_inventory_as_partial_evidence(self):
        inventory_raw = b'{"inventory":true}\n'
        with mock.patch.object(tool, '_publish_freeze_marker',
                               side_effect=OSError('injected freeze marker failure')):
            with self.assertRaisesRegex(OSError, 'injected freeze marker failure'):
                tool._publish_pair(self.output, b'freeze', inventory_raw)

        self.assertTrue(self.output.is_dir())
        self.assertEqual((self.output / 'prior-key-inventory.json').read_bytes(),
                         inventory_raw)
        self.assertFalse((self.output / 'freeze.json').exists())

    def test_destination_race_never_replaces_competing_output(self):
        real_mkdir = os.mkdir
        sentinel = self.output_root / 'competing-output-inode'

        def create_competing_output(name, mode=0o777, *, dir_fd=None):
            self.assertEqual(name, self.output.name)
            real_mkdir(self.output, mode)
            info = self.output.stat()
            sentinel.write_text(f'{info.st_dev}:{info.st_ino}')
            raise FileExistsError('destination created by competing writer')

        with mock.patch.object(tool.os, 'mkdir', side_effect=create_competing_output):
            with self.assertRaisesRegex(FileExistsError, 'competing writer'):
                tool._publish_pair(self.output, b'freeze', b'inventory')

        info = self.output.stat()
        self.assertEqual(sentinel.read_text(), f'{info.st_dev}:{info.st_ino}')
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertFalse((self.output / 'prior-key-inventory.json').exists())
        self.assertFalse((self.output / 'freeze.json').exists())

    def test_cli_help_is_available_from_another_working_directory(self):
        import subprocess
        import sys

        script = Path(tool.__file__).resolve()
        result = subprocess.run([sys.executable, str(script), '--help'],
                                cwd=self.root, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn('--package-pins-sha256', result.stdout.decode())
        self.assertIn('--output-dir', result.stdout.decode())


if __name__ == '__main__':
    unittest.main()
