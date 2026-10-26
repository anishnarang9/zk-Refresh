import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.part5 import export_v3_proof_package_summary as tool


def _fixture(root):
    witness = {
        'schema': 'credential-v3-bounded-witness-qualification-v1',
        'passed': True,
        'r1cs_sha256': 'a' * 64,
        'wasm_sha256': 'b' * 64,
        'host_admission_bypassed': True,
        'setup_or_proofs_executed': False,
        'outputs_private': True,
        'accepted_count': 1,
        'rejected_count': 1,
        'cases': [
            {'passed': True, 'name': 'credential_private_case',
             'expected': 'accept', 'witness_elapsed_ms': 100.0,
             'raw_witness': 'PRIVATE-WITNESS-SENTINEL'},
            {'passed': True, 'name': 'other_case', 'expected': 'reject',
             'witness_elapsed_ms': 2.0},
        ],
    }
    identity = {
        'circuit': '1' * 64,
        'engine_extended_vk': '2' * 64,
        'matrix': '3' * 64,
        'package': '4' * 64,
        'pk': '5' * 64,
    }
    suite_raw = json.dumps(witness, sort_keys=True).encode()
    setup = {
        'schema': 'credential-v3-bounded-setup-v1',
        'accepted_suite_path': '/private/user/path/report.json',
        'accepted_suite_sha256': hashlib.sha256(suite_raw).hexdigest(),
        'admitted': False,
        'development_only': True,
        'six_field_adapter_qualified': False,
        'secret_scalars_written': False,
        'assignment_fields': 11,
        'constraints': 12,
        'matrix_entries': 13,
        'instance_fields_including_one': 7,
        'ordinary_vk_ic_count': 7,
        'curve': 'bn254',
        'domain': 1024,
        'reduction': 'modulus',
        'identity': identity,
        'circuit_source_identity': '6' * 64,
        'binary_sha256': '7' * 64,
        'launcher_src_sha256': '8' * 64,
        'package_lock_sha256': '9' * 64,
        'profile_sha256': 'a' * 64,
        'public_schema_sha256': 'b' * 64,
        'semantic_schema_sha256': 'c' * 64,
        'r1cs_sha256': witness['r1cs_sha256'],
        'wasm_sha256': witness['wasm_sha256'],
        'ordinary_vk_file_sha256': 'd' * 64,
        'pk_file_sha256': 'e' * 64,
        'provenance': 'LOCAL-PROVENANCE-SENTINEL',
        'ordered_public_inputs': ['private input labels'],
        'elapsed_ms': 1.5,
    }
    package = {
        'schema': 'credential-v3-bounded-public-package-check-v1',
        'passed': True,
        'admitted': False,
        'development_only': True,
        'six_field_adapter_qualified': False,
        'setup_or_proofs_executed': False,
        'single_shared_package': True,
        'public_package_loads': 1,
        'accepted_complete_assignments': 1,
        'root_refresh_pairs': 2,
        'assignment_fields': setup['assignment_fields'],
        'constraints': setup['constraints'],
        'matrix_entries': setup['matrix_entries'],
        'ordinary_vk_ic_count': setup['ordinary_vk_ic_count'],
        'identity': identity.copy(),
        'ordinary_vk_file_sha256': setup['ordinary_vk_file_sha256'],
        'public_schema_sha256': setup['public_schema_sha256'],
        'semantic_schema_sha256': setup['semantic_schema_sha256'],
        'elapsed_ms': 8.0,
    }
    witness_path = root / 'witness-report.json'
    setup_path = root / 'setup-manifest.json'
    package_path = root / 'package-check.json'
    witness_path.write_bytes(suite_raw)
    setup_path.write_text(json.dumps(setup), encoding='utf-8')
    package_path.write_text(json.dumps(package), encoding='utf-8')
    return witness_path, setup_path, package_path, witness, setup, package


class ProofPackageSummaryTests(unittest.TestCase):
    def test_exports_linked_hashes_counts_gates_and_identity_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness, setup, package, wdoc, sdoc, _ = _fixture(root)
            output = root / 'public-summary.json'

            summary = tool.export_summary(witness, setup, package, output)

            self.assertEqual(json.loads(output.read_text()), summary)
            self.assertEqual(summary['schema'], tool.SUMMARY_SCHEMA)
            self.assertEqual(summary['qualification']['case_count'], 2)
            self.assertEqual(summary['qualification']['accepted_count'], 1)
            self.assertEqual(summary['qualification']['rejected_count'], 1)
            self.assertTrue(summary['qualification']['passed'])
            self.assertTrue(summary['setup']['development_only'])
            self.assertFalse(summary['setup']['admitted'])
            self.assertFalse(summary['setup']['six_field_adapter_qualified'])
            self.assertTrue(summary['package_check']['development_only'])
            self.assertFalse(summary['package_check']['admitted'])
            self.assertFalse(summary['package_check']['six_field_adapter_qualified'])
            self.assertEqual(summary['source_identity']['identity'], sdoc['identity'])
            self.assertEqual(summary['source_identity']['r1cs_sha256'], wdoc['r1cs_sha256'])
            self.assertEqual(summary['source_identity']['wasm_sha256'], wdoc['wasm_sha256'])
            self.assertEqual(summary['inputs']['witness_report_sha256'],
                             hashlib.sha256(witness.read_bytes()).hexdigest())
            self.assertEqual(summary['inputs']['setup_manifest_sha256'],
                             hashlib.sha256(setup.read_bytes()).hexdigest())
            self.assertEqual(summary['inputs']['package_check_report_sha256'],
                             hashlib.sha256(package.read_bytes()).hexdigest())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_does_not_export_paths_provenance_case_details_or_private_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness, setup, package, *_ = _fixture(root)
            output = root / 'public-summary.json'

            tool.export_summary(witness, setup, package, output)
            exported = output.read_text()

            for private_marker in (
                    '/private/user/path', 'LOCAL-PROVENANCE-SENTINEL',
                    'credential_private_case', 'PRIVATE-WITNESS-SENTINEL',
                    'witness_elapsed_ms', 'ordered_public_inputs'):
                self.assertNotIn(private_marker, exported)
            self.assertNotIn('accepted_suite_path', exported)
            self.assertNotIn('provenance', exported)

    def test_rejects_mismatched_report_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness, setup, package, *_ = _fixture(root)
            package_doc = json.loads(package.read_text())
            package_doc['identity']['package'] = 'f' * 64
            package.write_text(json.dumps(package_doc), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'identity hashes differ'):
                tool.export_summary(witness, setup, package,
                                    root / 'identity-mismatch.json')

            package_doc['identity']['package'] = '4' * 64
            package_doc['ordinary_vk_file_sha256'] = 'f' * 64
            package.write_text(json.dumps(package_doc), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'ordinary_vk_file_sha256'):
                tool.export_summary(witness, setup, package,
                                    root / 'vk-mismatch.json')

            package_doc['ordinary_vk_file_sha256'] = 'd' * 64
            package_doc['public_schema_sha256'] = 'f' * 64
            package.write_text(json.dumps(package_doc), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'public_schema_sha256'):
                tool.export_summary(witness, setup, package,
                                    root / 'schema-mismatch.json')

            setup_doc = json.loads(setup.read_text())
            setup_doc['accepted_suite_sha256'] = 'f' * 64
            setup.write_text(json.dumps(setup_doc), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'accepted suite report'):
                tool.export_summary(witness, setup, package,
                                    root / 'suite-mismatch.json')

            setup_doc['accepted_suite_sha256'] = hashlib.sha256(
                witness.read_bytes()).hexdigest()
            setup_doc['wasm_sha256'] = 'f' * 64
            setup.write_text(json.dumps(setup_doc), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'R1CS/WASM'):
                tool.export_summary(witness, setup, package,
                                    root / 'wasm-mismatch.json')

    def test_rejects_nonconservative_admission_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness, setup, package, *_ = _fixture(root)
            package_doc = json.loads(package.read_text())
            package_doc['admitted'] = True
            package.write_text(json.dumps(package_doc), encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'admitted'):
                tool.export_summary(witness, setup, package, root / 'summary.json')

    def test_requires_fresh_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness, setup, package, *_ = _fixture(root)
            output = root / 'summary.json'
            output.write_text('existing', encoding='utf-8')

            with self.assertRaises(FileExistsError):
                tool.export_summary(witness, setup, package, output)

    def test_cli_exposes_the_four_required_inputs(self):
        import subprocess
        import sys

        script = Path(tool.__file__).resolve()
        result = subprocess.run([sys.executable, '-B', str(script), '--help'],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        for flag in ('--witness-report', '--setup-manifest',
                     '--package-check-report', '--output'):
            self.assertIn(flag, result.stdout)


if __name__ == '__main__':
    unittest.main()
