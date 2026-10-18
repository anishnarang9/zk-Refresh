import argparse
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tools.part5 import create_v3_heldout_assignments_manifest_v2 as tool


class HeldoutAssignmentsManifestV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='v3-heldout-assignments-v2-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.report_path = self.root / 'report.json'
        self.output_path = self.root / 'assignments.json'
        # Exercise real file protection/hash reads with tiny WTNS fixture bodies.
        # The header and report retain the production assignment census.
        self.assertEqual(tool.WTNS_BYTES, 76 + 784796 * 32)
        patch = mock.patch.object(tool, 'WTNS_BYTES', 76 + 7 * 32)
        patch.start()
        self.addCleanup(patch.stop)
        self.report = self.make_report()
        self.write_json(self.report_path, self.report)
        self.args = argparse.Namespace(
            suite_report=str(self.report_path),
            suite_sha256=hashlib.sha256(self.report_path.read_bytes()).hexdigest(),
            output=str(self.output_path))

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, sort_keys=True) + '\n')
        path.chmod(0o600)

    @staticmethod
    def wtns_bytes(public_values):
        count = tool.ASSIGNMENT_COUNT
        fields = [1, *(int(value) for value in public_values)]
        header = (b'wtns' + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little')
                  + (1).to_bytes(4, 'little') + (40).to_bytes(8, 'little')
                  + (32).to_bytes(4, 'little')
                  + tool.FIELD_MODULUS.to_bytes(32, 'little')
                  + count.to_bytes(4, 'little') + (2).to_bytes(4, 'little')
                  + (count * 32).to_bytes(8, 'little'))
        prefix = header + b''.join(value.to_bytes(32, 'little') for value in fields)
        return prefix, tool.WTNS_BYTES

    @staticmethod
    def accepted_names():
        return [name for i in range(8) for name in
                (f'holdout_{i}', f'holdout_{i}_unrelated_refresh')]

    def write_case_artifacts(self, name, public_values):
        witness_path = self.root / f'{name}.wtns'
        public_path = self.root / f'{name}-public.json'
        prefix, witness_size = self.wtns_bytes(public_values)
        with witness_path.open('xb') as stream:
            stream.write(prefix)
            stream.truncate(witness_size)
        witness_path.chmod(0o600)
        self.write_json(public_path, public_values)

    def make_report(self):
        accepted = self.accepted_names()
        cases = []
        for pair in range(8):
            names = (f'holdout_{pair}', f'holdout_{pair}_unrelated_refresh')
            for index, name in enumerate(names):
                public_values = [str(pair + (100 if index else 10)), '2', '3', '4', '5', '6']
                self.write_case_artifacts(name, public_values)
        for name in accepted:
            cases.append({
                'name': name,
                'expected': 'accept',
                'family': 'positive',
                'witness_elapsed_ms': 1.0,
                'validation': {
                    'satisfied': True,
                    'constraints_checked': tool.ROWS,
                    'assignment_fields': tool.ASSIGNMENT_COUNT,
                    'matrix_entries': tool.ENTRIES,
                    'max_row_terms': 10,
                },
                'passed': True,
                'complete_relation_check_ms': 1.0,
            })
        for i in range(2):
            cases.append({
                'name': f'reject_{i}',
                'expected': 'reject',
                'family': 'negative',
                'witness_elapsed_ms': 1.0,
                'rejection': 'circuit_assertion',
                'passed': True,
            })
        return {
            'schema': tool.SUITE_SCHEMA,
            'passed': True,
            'r1cs_sha256': tool.R1CS_SHA256,
            'wasm_sha256': tool.WASM_SHA256,
            'host_admission_bypassed': True,
            'setup_or_proofs_executed': False,
            'outputs_private': True,
            'cases': cases,
            'accepted_count': 16,
            'rejected_count': 2,
        }

    def test_valid_suite_writes_exact_private_setup_manifest(self):
        result = tool.create(self.args)
        raw = self.output_path.read_bytes()
        manifest = json.loads(raw)

        self.assertEqual(hashlib.sha256(raw).hexdigest(), result)
        self.assertEqual(stat.S_IMODE(self.output_path.stat().st_mode), 0o600)
        self.assertEqual(set(manifest), {
            'schema', 'synthetic_only', 'accepted_suite_path',
            'accepted_suite_sha256', 'assignments'})
        self.assertEqual(manifest['schema'], tool.ASSIGNMENTS_SCHEMA)
        self.assertIs(manifest['synthetic_only'], True)
        self.assertEqual(manifest['accepted_suite_path'], str(self.report_path))
        self.assertEqual(manifest['accepted_suite_sha256'], self.args.suite_sha256)
        self.assertEqual([case['name'] for case in manifest['assignments']],
                         self.accepted_names())
        self.assertEqual(set(manifest['assignments'][0]), {
            'name', 'wtns_path', 'wtns_sha256', 'public_path', 'public_sha256'})
        for assignment in manifest['assignments']:
            for path_key, hash_key in (('wtns_path', 'wtns_sha256'),
                                       ('public_path', 'public_sha256')):
                artifact = Path(assignment[path_key])
                self.assertEqual(artifact.parent, self.root)
                self.assertEqual(assignment[hash_key],
                                 hashlib.sha256(artifact.read_bytes()).hexdigest())

    def test_wrong_suite_hash_is_rejected_without_output(self):
        self.args.suite_sha256 = '0' * 64
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_missing_accepted_case_is_rejected(self):
        self.report['cases'] = self.report['cases'][1:]
        self.write_json(self.report_path, self.report)
        self.args.suite_sha256 = hashlib.sha256(self.report_path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_extra_suite_field_is_rejected(self):
        self.report['unexpected'] = 'must not silently enter a new pin'
        self.write_json(self.report_path, self.report)
        self.args.suite_sha256 = hashlib.sha256(self.report_path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_extra_case_field_is_rejected(self):
        self.report['cases'][0]['unexpected'] = 'unreviewed case metadata'
        self.write_json(self.report_path, self.report)
        self.args.suite_sha256 = hashlib.sha256(self.report_path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_stale_compiled_artifact_pin_is_rejected(self):
        for key in ('r1cs_sha256', 'wasm_sha256'):
            with self.subTest(key=key):
                self.report[key] = '0' * 64
                self.write_json(self.report_path, self.report)
                self.args.suite_sha256 = hashlib.sha256(
                    self.report_path.read_bytes()).hexdigest()
                with self.assertRaises(ValueError):
                    tool.create(self.args)
                self.assertFalse(self.output_path.exists())
                self.report[key] = tool.R1CS_SHA256 if key == 'r1cs_sha256' else tool.WASM_SHA256

    def test_public_values_must_match_witness_public_coordinates(self):
        public_path = self.root / 'holdout_0-public.json'
        self.write_json(public_path, ['999', '2', '3', '4', '5', '6'])
        self.args.suite_sha256 = hashlib.sha256(self.report_path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_symlink_case_artifact_is_rejected(self):
        artifact = self.root / 'holdout_0.wtns'
        replacement = self.root / 'replacement.wtns'
        artifact.rename(replacement)
        artifact.symlink_to(replacement)
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_output_outside_fresh_suite_root_is_rejected(self):
        self.args.output = str(self.root.parent / 'assignments-outside.json')
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(Path(self.args.output).exists())

    def test_non_private_suite_root_is_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_existing_output_is_never_overwritten(self):
        self.output_path.write_bytes(b'keep')
        with self.assertRaises((ValueError, FileExistsError)):
            tool.create(self.args)
        self.assertEqual(self.output_path.read_bytes(), b'keep')

    def repin_report(self):
        self.write_json(self.report_path, self.report)
        self.args.suite_sha256 = hashlib.sha256(self.report_path.read_bytes()).hexdigest()

    def test_incomplete_or_noninteger_relation_census_is_rejected(self):
        for key, value in (('satisfied', False), ('constraints_checked', 793680),
                           ('assignment_fields', 784795), ('matrix_entries', 4257582),
                           ('max_row_terms', 4097), ('constraints_checked', True)):
            with self.subTest(key=key, value=value):
                original = self.report['cases'][0]['validation'][key]
                self.report['cases'][0]['validation'][key] = value
                self.repin_report()
                with self.assertRaises(ValueError):
                    tool.create(self.args)
                self.assertFalse(self.output_path.exists())
                self.report['cases'][0]['validation'][key] = original

    def test_training_or_duplicate_or_extra_heldout_name_is_rejected(self):
        for name in ('credential_0', 'holdout_1', 'holdout_8'):
            with self.subTest(name=name):
                self.report['cases'][0]['name'] = name
                self.repin_report()
                with self.assertRaises(ValueError):
                    tool.create(self.args)
                self.assertFalse(self.output_path.exists())

    def test_invalid_report_context_or_counts_is_rejected(self):
        for key, value in (('passed', False), ('host_admission_bypassed', False),
                           ('setup_or_proofs_executed', True), ('outputs_private', False),
                           ('accepted_count', 18), ('accepted_count', True),
                           ('rejected_count', -1), ('rejected_count', 0)):
            with self.subTest(key=key):
                original = self.report[key]
                self.report[key] = value
                self.repin_report()
                with self.assertRaises(ValueError):
                    tool.create(self.args)
                self.assertFalse(self.output_path.exists())
                self.report[key] = original

    def test_noncanonical_header_or_constant_coordinate_is_rejected(self):
        path = self.root / 'holdout_0.wtns'
        original = path.read_bytes()
        for offset in (0, 4, 8, 12, 16, 24, 28, 60, 64, 68, 76):
            with self.subTest(offset=offset):
                corrupted = bytearray(original)
                corrupted[offset] ^= 1
                path.write_bytes(corrupted)
                with self.assertRaises(ValueError):
                    tool.create(self.args)
                self.assertFalse(self.output_path.exists())
        path.write_bytes(original)

    def test_noncanonical_or_out_of_field_public_is_rejected(self):
        path = self.root / 'holdout_0-public.json'
        for value in ('01', '-1', str(tool.FIELD_MODULUS), 1):
            with self.subTest(value=value):
                self.write_json(path, [value, '2', '3', '4', '5', '6'])
                with self.assertRaises(ValueError):
                    tool.create(self.args)
                self.assertFalse(self.output_path.exists())

    def test_pairs_require_changed_root_and_identical_other_public_fields(self):
        for public in (['10', '2', '3', '4', '5', '6'],
                       ['100', '7', '3', '4', '5', '6']):
            with self.subTest(public=public):
                for path in (self.root / 'holdout_0_unrelated_refresh.wtns',
                             self.root / 'holdout_0_unrelated_refresh-public.json'):
                    path.unlink()
                self.write_case_artifacts('holdout_0_unrelated_refresh', public)
                with self.assertRaises(ValueError):
                    tool.create(self.args)
                self.assertFalse(self.output_path.exists())

    def test_wrong_size_or_nonprivate_artifact_is_rejected(self):
        for name in ('holdout_0.wtns', 'holdout_0-public.json', 'report.json'):
            with self.subTest(name=name):
                path = self.root / name
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    tool.create(self.args)
                self.assertFalse(self.output_path.exists())
                path.chmod(0o600)
        path = self.root / 'holdout_0.wtns'
        with path.open('ab') as target:
            target.write(b'X')
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_hardlinked_artifacts_are_rejected(self):
        path = self.root / 'holdout_0_unrelated_refresh.wtns'
        path.unlink()
        path.hardlink_to(self.root / 'holdout_0.wtns')
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_external_hardlink_alias_is_rejected(self):
        alias = self.root / 'external-alias.wtns'
        alias.hardlink_to(self.root / 'holdout_0.wtns')
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())

    def test_duplicate_report_json_field_is_rejected(self):
        raw = self.report_path.read_bytes()
        self.report_path.write_bytes(b'{"schema":"duplicate",' + raw[1:])
        self.args.suite_sha256 = hashlib.sha256(self.report_path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertFalse(self.output_path.exists())


if __name__ == '__main__':
    unittest.main()
