import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import freeze_v3_campaign_cohort as tool


class FreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.part5 = self.root / 'artifacts/dynark/part5'
        self.results = self.root / 'results/dynark/part5'
        self.part5.mkdir(parents=True)
        self.results.mkdir(parents=True, mode=0o700)
        for name, value in [('ROOT', self.root), ('PART5', self.part5),
                            ('RESULTS', self.results), ('SETUP', self.part5 / 'setup'),
                            ('COMPILE', self.part5 / 'compile'), ('PROOF', self.root / 'proof'),
                            ('REGISTRY_FILES', ['registry.rs']), ('CLIENT_FILES', ['client.py'])]:
            patch = mock.patch.object(tool, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        key = rsa.RSAPublicNumbers(65537, (1 << 2047) + 123).public_key()
        self.public = key.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
        self.key_path = self.part5 / 'earlier.pem'
        self.key_path.write_bytes(self.public)

    def write(self, path, raw=b'fixture'):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def fixture(self):
        paths = [tool.COMPILE / 'credential.r1cs', tool.COMPILE / 'credential_js/credential.wasm',
                 self.root / 'circuits/credential-v3-bounded/profile.json', tool.SETUP / 'ordinary.vk',
                 tool.PROOF / 'target/release/credential-v3-bounded-proof-qualification-v1',
                 self.root / 'tools/part5/prepare_v3_request_fixture.py',
                 self.part5 / 'application-v3-sbf-build-002/elf/zk_fresh_program.so',
                 self.root / 'adapter', self.root / 'registry.rs', self.root / 'client.py']
        for path in paths:
            self.write(path)
        file_hash = hashlib.sha256(b'fixture').hexdigest()
        setup = dict(schema='credential-v3-bounded-setup-v1', development_only=True,
                     identity={'circuit': 'a' * 64}, profile_sha256=file_hash,
                     r1cs_sha256=file_hash, wasm_sha256=file_hash,
                     ordinary_vk_file_sha256=file_hash, binary_sha256=file_hash)
        setup_path = self.write(tool.SETUP / 'setup-manifest.json', json.dumps(setup).encode())
        self.application_manifest = {'source_pins': {'example.rs': file_hash}}
        prepared = dict(schema=1, scope='part5-v3-local-prepare', status='failed',
                        application_effect=False, devnet=False, cleanup={'reaped': True, 'exit_code': -2},
                        ledger_reuse_requires_review=True,
                        prepared_application_accounts=False,
                        source_manifest_sha256=tool.digest(json.dumps(self.application_manifest, sort_keys=True).encode()),
                        loaded_program=dict(elf_match=True, elf_sha256=file_hash, genesis='genesis'),
                        v3_vk=dict(setup_manifest_sha256=tool.file_digest(setup_path), circuit_id='a' * 64))
        self.status = self.write(self.root / 'status.json', json.dumps(prepared).encode())
        return prepared

    def freeze(self):
        with mock.patch('harness.tests.queue_v3_build_prep.source_manifest', return_value=self.application_manifest):
            return tool.freeze(self.results / 'freeze.json', self.results / 'manifest.json',
                               self.status, self.root / 'adapter')

    def test_complete_freeze_is_consumable_and_records_provenance(self):
        self.fixture()
        result = self.freeze()
        _, boundary = tool.cohort._boundary(self.results / 'freeze.json',
                                            result['freeze_sha256'], time.time_ns())
        self.assertEqual(set(boundary['identities']), tool.cohort.keys.IDENTITY_ROLES)
        self.assertEqual(len(boundary['identities']), 13)
        report = json.loads((self.results / 'manifest.json').read_bytes())
        self.assertEqual(report['prepare_status_sha256'], tool.file_digest(self.status))
        self.assertEqual(report['prior_public_key_sources'][0]['sha256'], tool.digest(self.public))
        self.assertEqual(report['identity_inputs']['proof_runner']['path'],
                         str((tool.PROOF / 'target/release/credential-v3-bounded-proof-qualification-v1')
                             .relative_to(self.root)))
        self.assertNotIn('BEGIN', json.dumps(report))
        for path in self.results.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_explicit_proof_binary_is_hashed_and_recorded(self):
        self.fixture()
        proof_binary = self.write(self.part5 / 'v3-proof-runner-training-010',
                                  b'corrected isolated proof runner')
        freeze_path, manifest_path = self.results / 'freeze.json', self.results / 'manifest.json'
        with mock.patch('harness.tests.queue_v3_build_prep.source_manifest',
                        return_value=self.application_manifest):
            result = tool.freeze(freeze_path, manifest_path, self.status,
                                 self.root / 'adapter', proof_binary=proof_binary)
        report = json.loads(manifest_path.read_bytes())
        expected_hash = hashlib.sha256(b'corrected isolated proof runner').hexdigest()
        self.assertEqual(result['freeze_sha256'], report['freeze_sha256'])
        self.assertEqual(report['identities']['proof_runner'], expected_hash)
        self.assertEqual(report['identity_inputs']['proof_runner'],
                         {'path': str(proof_binary.relative_to(self.root)), 'sha256': expected_hash})

    def test_explicit_proof_binary_must_be_absolute_and_canonical(self):
        self.fixture()
        proof_binary = self.write(self.part5 / 'v3-proof-runner-training-010')
        with mock.patch('harness.tests.queue_v3_build_prep.source_manifest',
                        return_value=self.application_manifest), self.assertRaises(ValueError):
            tool.freeze(self.results / 'freeze.json', self.results / 'manifest.json',
                        self.status, self.root / 'adapter',
                        proof_binary=proof_binary.relative_to(self.root))
        self.assertEqual(list(self.results.iterdir()), [])

    def test_changed_or_malformed_identity_rejects_without_outputs(self):
        prepared = self.fixture()
        for change in [dict(application_effect=True), dict(source_manifest_sha256='b' * 64),
                       dict(v3_vk={}), dict(source_manifest_sha256='wrong')]:
            self.status.write_text(json.dumps(dict(prepared, **change)))
            with self.assertRaises(ValueError):
                self.freeze()
            self.assertEqual(list(self.results.iterdir()), [])

    def test_symlink_writable_and_nonregular_inputs_reject(self):
        alias = self.root / 'alias.pem'
        alias.symlink_to(self.key_path)
        with self.assertRaises(ValueError):
            tool.read_input(alias)
        self.key_path.chmod(0o666)
        with self.assertRaises(ValueError):
            tool.prior_keys()
        fifo = self.root / 'pipe'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            tool.read_input(fifo)

    def test_prior_der_public_key_and_malformed_inventory(self):
        key = serialization.load_pem_public_key(self.public)
        self.write(self.part5 / 'earlier.der', key.public_bytes(serialization.Encoding.DER,
                   serialization.PublicFormat.SubjectPublicKeyInfo))
        fingerprints, sources = tool.prior_keys()
        self.assertEqual((len(fingerprints), len(sources)), (1, 2))
        self.write(self.part5 / 'unparsed.der', b'malformed')
        with self.assertRaises(ValueError):
            tool.prior_keys()

    def test_multi_object_pem_inventory_rejects(self):
        self.key_path.write_bytes(self.public + self.public)
        with self.assertRaises(ValueError):
            tool.prior_keys()

    def test_second_publication_failure_rolls_back_manifest(self):
        output, report = self.results / 'freeze.json', self.results / 'manifest.json'
        original = os.link
        def link(source, target, **kwargs):
            if target == output:
                raise OSError('injected publication failure')
            return original(source, target, **kwargs)
        with mock.patch.object(tool.os, 'link', side_effect=link), self.assertRaises(OSError):
            tool.write_pair(output, {}, report, {})
        self.assertEqual(list(self.results.iterdir()), [])

    def test_changed_source_before_publication_rejects(self):
        self.fixture()
        hashes = tool.cohort.source_hashes()
        with mock.patch.object(tool.cohort, 'source_hashes', side_effect=[hashes, {}]):
            with self.assertRaises(ValueError):
                self.freeze()
        self.assertEqual(list(self.results.iterdir()), [])

    def test_private_child_directory_outputs_are_supported(self):
        private = self.results / 'freeze-001'
        private.mkdir(mode=0o700)
        self.assertEqual(tool.fresh(private / 'freeze.json'), private / 'freeze.json')
        private.chmod(0o755)
        with self.assertRaises(ValueError):
            tool.fresh(private / 'freeze.json')

    def test_duplicate_or_existing_outputs_reject_without_writes(self):
        self.fixture()
        target = self.results / 'same.json'
        with self.assertRaises(ValueError):
            tool.freeze(target, target, self.status, self.root / 'adapter')
        target.write_text('preserve')
        with self.assertRaises(ValueError):
            tool.fresh(target)
        self.assertEqual(target.read_text(), 'preserve')

    def test_cli_imports_from_another_working_directory(self):
        script = Path(tool.__file__).resolve()
        result = subprocess.run([sys.executable, str(script), '--help'], cwd=self.root,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn('--proof-binary', result.stdout.decode())


if __name__ == '__main__':
    unittest.main()
