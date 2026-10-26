"""Synthetic manifest creation only; no loaded execution or acceptance."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import create_v3_heldout_negative_cohort_manifest as tool
from tools.part5.tests.test_verify_v3_heldout_negative_cohort import _cohort


class CreateNegativeManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manifest = _cohort(self.root)
        self.inputs = {key: value for key, value in self.manifest.items() if key != 'schema'}
        self.output = self.root / 'prospective-manifest.json'

    def test_real_child_validation_owner_only_exact_schema_and_path_free_result(self):
        with patch.object(tool.verifier, 'validate_manifest', wraps=tool.verifier.validate_manifest) as validate:
            facts = tool.create_manifest(**self.inputs, output=self.output)
        validate.assert_called_once()
        self.assertEqual(json.loads(self.output.read_bytes()), self.manifest)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(facts['manifest_sha256'], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertFalse(facts['loaded_run_established'])
        self.assertFalse(facts['heldout_acceptance_established'])
        self.assertNotIn(str(self.root), json.dumps(facts))
        self.assertTrue(tool.verifier.verify_file(self.output, facts['manifest_sha256'])['report_consistent'])

    def test_external_pins_cardinality_extra_fields_and_bad_sources_fail_without_output(self):
        mutations = [lambda x: x['expired_status_reports'].pop(),
                     lambda x: x['expired_status_reports'].reverse(),
                     lambda x: x['expired_status_reports'][0].update(extra=True),
                     lambda x: x['expired_status_reports'][0].pop('expected_identities'),
                     lambda x: x['expired_status_reports'][0]['expected_identities'].update(genesis='b' * 64),
                     lambda x: x['queue_capacity_reports'].clear(),
                     lambda x: x['common_identities'].update(extra='a' * 64),
                     lambda x: x['expired_status_reports'][0].update(sha256='b' * 64),
                     lambda x: x['expired_status_reports'][0].update(path='relative.json')]
        for index, mutation in enumerate(mutations):
            inputs = copy.deepcopy(self.inputs)
            mutation(inputs)
            with self.subTest(index=index), self.assertRaises(ValueError):
                tool.create_manifest(**inputs, output=self.output)
            self.assertFalse(self.output.exists())

    def test_existing_symlink_and_parent_symlink_outputs_rejected(self):
        self.output.write_text('preserve')
        with self.assertRaises(ValueError):
            tool.create_manifest(**self.inputs, output=self.output)
        self.assertEqual(self.output.read_text(), 'preserve')
        self.output.unlink()
        self.output.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError):
            tool.create_manifest(**self.inputs, output=self.output)
        self.output.unlink()
        parent_link = self.root / 'parent-link'
        parent_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            tool.create_manifest(**self.inputs, output=parent_link / 'manifest.json')

    def test_exclusive_creation_at_write(self):
        original = tool.verifier.validate_manifest
        def competing_writer(manifest):
            facts = original(manifest)
            self.output.write_text('competing-owner')
            return facts
        with patch.object(tool.verifier, 'validate_manifest', side_effect=competing_writer):
            with self.assertRaises(FileExistsError):
                tool.create_manifest(**self.inputs, output=self.output)
        self.assertEqual(self.output.read_text(), 'competing-owner')

    def test_strict_byte_pinned_inputs_file(self):
        path = self.root / 'external-pins.json'
        path.write_text(json.dumps(self.inputs))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        tool.create_from_file(path, digest, self.output)
        self.output.unlink()
        with self.assertRaises(ValueError):
            tool.create_from_file(path, 'b' * 64, self.output)
        for raw in ('{"common_identities":1,"common_identities":2}', '{"extra":NaN}'):
            path.write_text(raw)
            with self.assertRaises(ValueError):
                tool.create_from_file(path, hashlib.sha256(path.read_bytes()).hexdigest(), self.output)
        bad = {**self.inputs, 'extra': True}
        path.write_text(json.dumps(bad))
        with self.assertRaises(ValueError):
            tool.create_from_file(path, hashlib.sha256(path.read_bytes()).hexdigest(), self.output)
        self.assertFalse(self.output.exists())

    def test_cli_errors_do_not_echo_private_paths(self):
        args = ['create', '--inputs', '/PRIVATE/input', '--inputs-sha256', 'a' * 64,
                '--output', '/PRIVATE/output']
        with patch('sys.argv', args), patch.object(tool, 'create_from_file',
                side_effect=ValueError('/PRIVATE/secret')):
            with self.assertRaises(SystemExit) as raised:
                tool.main()
        self.assertNotIn('PRIVATE', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
