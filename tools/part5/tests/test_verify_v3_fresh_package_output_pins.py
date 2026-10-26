"""Synthetic package-pin verification only; never performs setup or proving."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from tools.part5 import verify_v3_fresh_package_input_pins as input_tool
from tools.part5 import verify_v3_fresh_package_output_pins as tool


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _write(path, raw, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return _sha(raw)


def _json(path, value, mode):
    return _write(path, json.dumps(value, sort_keys=True, separators=(',', ':')).encode(), mode)


def _input_pins():
    return dict(schema=input_tool.SCHEMA, source_commit='a' * 40,
                toolchain=dict(circom_version='2.2.3', node_version='v22.14.0',
                               rustc_version='1.90.0', cargo_version='1.90.0',
                               circom_binary_sha256='b' * 64),
                semantic_hashes=dict(input_tool.SEMANTIC_HASHES),
                census=dict(input_tool.CENSUS),
                ordered_public_inputs=list(input_tool.PUBLIC_INPUTS),
                reviewed_suite=dict(report_sha256='c' * 64, total_count=52,
                                    accepted_count=18, rejected_count=34),
                public_repo_files=[])


def _identity():
    return dict(matrix='1' * 64, circuit='2' * 64, pk='3' * 64,
                engine_extended_vk='4' * 64, package='5' * 64)


def _valid_fixture(root):
    setup_dir = root / 'artifacts/dynark/part5/v3-development-setup-002'
    check_dir = root / 'artifacts/dynark/part5/v3-package-check-002'
    setup_dir.mkdir(parents=True, mode=0o700)
    check_dir.mkdir(parents=True, mode=0o700)
    setup_dir.chmod(0o700)
    check_dir.chmod(0o700)

    input_path = root / tool.INPUT_PINS_PATH
    input_sha = _json(input_path, _input_pins(), 0o644)
    input_abs = str(input_path.resolve())

    source = root / tool.SETUP_SOURCE_PATH
    manifest_source = root / tool.SETUP_MANIFEST_SOURCE_PATH
    lock = root / tool.SETUP_LOCK_PATH
    binary = root / tool.SETUP_BINARY_PATH
    source_sha = _write(source, b'fn main() { /* synthetic source */ }\n', 0o644)
    manifest_source_sha = _write(manifest_source, b'[package]\nname = "synthetic"\n', 0o644)
    lock_sha = _write(lock, b'# synthetic lock\n', 0o644)
    binary_sha = _write(binary, b'synthetic executable bytes', 0o755)

    vk_path = setup_dir / 'ordinary.vk'
    pk_path = setup_dir / 'development.pk'
    vk_sha = _write(vk_path, b'synthetic ordinary vk', 0o600)
    pk_sha = _write(pk_path, b'synthetic proving key', 0o600)
    setup_path = setup_dir / 'setup-manifest.json'
    report_path = check_dir / 'package-check-report.json'
    package_identity = _identity()
    public_schema_sha = tool.PUBLIC_SCHEMA_SHA256
    semantic = dict(input_tool.SEMANTIC_HASHES)
    suite_sha = _input_pins()['reviewed_suite']['report_sha256']
    setup_manifest = {
        'schema': 'credential-v3-bounded-setup-v2',
        'development_only': True,
        'admitted': False,
        'curve': 'BN254',
        'reduction': 'Original',
        'circuit_source_identity': semantic['circuit_source_sha256'],
        'launcher_src_sha256': source_sha,
        'package_manifest_sha256': manifest_source_sha,
        'package_lock_sha256': lock_sha,
        'semantic_schema_sha256': semantic['semantic_schema_sha256'],
        'public_schema_sha256': public_schema_sha,
        'ordered_public_inputs': list(input_tool.PUBLIC_INPUTS),
        'r1cs_sha256': semantic['r1cs_sha256'],
        'wasm_sha256': semantic['wasm_sha256'],
        'profile_sha256': semantic['profile_sha256'],
        'input_pins_sha256': input_sha,
        'accepted_suite_sha256': suite_sha,
        'constraints': input_tool.CENSUS['constraints'],
        'matrix_entries': input_tool.CENSUS['matrix_entries'],
        'assignment_fields': input_tool.CENSUS['assignment_fields'],
        'instance_fields_including_one': 7,
        'ordinary_vk_ic_count': 7,
        'domain': input_tool.CENSUS['domain_size'],
        'ordinary_vk_tagged_digest': None,
        'six_field_adapter_qualified': False,
        'identity': package_identity,
        'pk_file_sha256': pk_sha,
        'ordinary_vk_file_sha256': vk_sha,
        'binary_sha256': binary_sha,
        'accepted_suite_path': '/private/suite/report.json',
        'input_pins_path': input_abs,
        'provenance': 'one-time OS-CSPRNG trusted development setup; no production ceremony or secure erasure claim',
        'secret_scalars_written': False,
        'elapsed_ms': 1.0,
    }
    setup_sha = _json(setup_path, setup_manifest, 0o600)
    report = {
        'schema': 'credential-v3-bounded-public-package-check-v2',
        'passed': True,
        'development_only': True,
        'identity': package_identity,
        'ordinary_vk_file_sha256': vk_sha,
        'input_pins_sha256': input_sha,
        'accepted_suite_sha256': suite_sha,
        'semantic_schema_sha256': semantic['semantic_schema_sha256'],
        'public_schema_sha256': public_schema_sha,
        'constraints': input_tool.CENSUS['constraints'],
        'matrix_entries': input_tool.CENSUS['matrix_entries'],
        'assignment_fields': input_tool.CENSUS['assignment_fields'],
        'accepted_complete_assignments': 18,
        'root_refresh_pairs': 9,
        'public_package_loads': 1,
        'ordinary_vk_ic_count': 7,
        'single_shared_package': True,
        'setup_or_proofs_executed': False,
        'six_field_adapter_qualified': False,
        'elapsed_ms': 1.0,
        'admitted': False,
    }
    report_sha = _json(report_path, report, 0o600)

    record = {
        'schema': tool.SCHEMA,
        'source_commit': 'a' * 40,
        'input_pins': {'path': tool.INPUT_PINS_PATH, 'sha256': input_sha},
        'setup_manifest': {'path': str(setup_path.relative_to(root)), 'sha256': setup_sha},
        'package_check_report': {'path': str(report_path.relative_to(root)), 'sha256': report_sha},
        'ordinary_vk': {'path': str(vk_path.relative_to(root)), 'sha256': vk_sha},
        'proving_key': {'path': str(pk_path.relative_to(root)), 'sha256': pk_sha},
        'package_identity': package_identity,
        'setup_launcher': {
            'binary': {'path': tool.SETUP_BINARY_PATH, 'sha256': binary_sha},
            'source': {'path': tool.SETUP_SOURCE_PATH, 'sha256': source_sha},
            'manifest': {'path': tool.SETUP_MANIFEST_SOURCE_PATH, 'sha256': manifest_source_sha},
            'lock': {'path': tool.SETUP_LOCK_PATH, 'sha256': lock_sha},
        },
        'semantic_hashes': semantic,
        'census': dict(input_tool.CENSUS),
        'ordered_public_inputs': list(input_tool.PUBLIC_INPUTS),
    }
    record_path = root / 'docs/dynark/part5/v3-fresh-package-v2-package-pins.json'
    record_sha = _json(record_path, record, 0o644)
    return record_path, record_sha, record, setup_path, report_path, vk_path, pk_path


class FreshPackageOutputPinsTests(unittest.TestCase):
    def test_valid_synthetic_package_output_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            record_path, digest, *_ = _valid_fixture(root)
            result = tool.verify_file(record_path, digest, repo_root=root)
            self.assertTrue(result['package_output_record_consistent'])
            self.assertFalse(result['clean_checkout_reproduction_established'])
            self.assertFalse(result['proof_runner_or_application_compatibility_established'])
            self.assertFalse(result['setup_or_proofs_executed_by_verifier'])
            self.assertNotIn(temporary, json.dumps(result))

    def test_external_digest_and_exact_schema_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            record_path, digest, record, *_ = _valid_fixture(root)
            with self.assertRaisesRegex(ValueError, 'byte digest'):
                tool.verify_file(record_path, '0' * 64, repo_root=root)
            bad = copy.deepcopy(record)
            bad['private_assignments_path'] = '/secret/assignments.json'
            bad_digest = _json(record_path, bad, 0o644)
            with self.assertRaisesRegex(ValueError, 'unknown or missing'):
                tool.verify_file(record_path, bad_digest, repo_root=root)

    def test_rehashes_output_artifacts_and_rejects_context_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            record_path, digest, record, _, report_path, vk_path, _ = _valid_fixture(root)
            vk_path.write_bytes(b'replaced ordinary vk')
            with self.assertRaisesRegex(ValueError, 'artifact digest'):
                tool.verify_file(record_path, digest, repo_root=root)
            vk_path.write_bytes(b'synthetic ordinary vk')
            vk_path.chmod(0o600)
            report = json.loads(report_path.read_text())
            report['accepted_complete_assignments'] = 17
            record['package_check_report']['sha256'] = _json(report_path, report, 0o600)
            digest = _json(record_path, record, 0o644)
            with self.assertRaisesRegex(ValueError, 'package-check v2 context'):
                tool.verify_file(record_path, digest, repo_root=root)

    def test_private_artifact_permissions_and_public_source_bytes_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            record_path, digest, _, _, _, _, pk_path = _valid_fixture(root)
            pk_path.chmod(0o640)
            with self.assertRaisesRegex(ValueError, 'private artifact permissions/owner'):
                tool.verify_file(record_path, digest, repo_root=root)
            pk_path.chmod(0o600)
            source = root / tool.SETUP_SOURCE_PATH
            source.write_bytes(b'changed setup source')
            source.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'artifact digest'):
                tool.verify_file(record_path, digest, repo_root=root)


if __name__ == '__main__':
    unittest.main()
