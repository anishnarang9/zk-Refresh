import unittest
import hashlib
import json
from pathlib import Path
import tempfile
from unittest import mock

from tools.part5 import preflight_v3_heldout_freeze_v2 as tool


class HeldoutFreezeV2PreflightTests(unittest.TestCase):
    def setUp(self):
        self.setup_sha = 'a' * 64
        self.package_sha = 'b' * 64
        self.elf_sha = 'c' * 64
        self.source_sha = 'd' * 64
        self.identity = {
            'matrix': '1' * 64,
            'circuit': '2' * 64,
            'pk': '3' * 64,
            'engine_extended_vk': '4' * 64,
            'package': self.package_sha,
        }
        self.pin_record = {
            'schema': 'part5-v3-fresh-package-output-pins-v2',
            'setup_manifest': {
                'path': 'artifacts/dynark/part5/v3-development-setup-002/setup-manifest.json',
                'sha256': self.setup_sha,
            },
            'package_identity': dict(self.identity),
        }
        self.setup = {
            'schema': 'credential-v3-bounded-setup-v2',
            'development_only': True,
            'admitted': False,
            'identity': dict(self.identity),
        }
        self.prepare = {
            'schema': 1,
            'status': 'passed',
            'scope': 'part5-v3-local-prepare-v2',
            'application_effect': False,
            'devnet': False,
            'source_manifest_sha256': self.source_sha,
            'loaded_program': {'elf_match': True, 'elf_sha256': self.elf_sha},
            'v3_vk': {
                'setup_manifest_sha256': self.setup_sha,
                'package_digest': self.package_sha,
            },
        }

    def test_v2_setup_must_match_external_package_pin(self):
        tool.validate_setup_pin(self.setup, self.pin_record, self.setup_sha)

        mismatched = dict(self.setup, identity=dict(self.identity, package='e' * 64))
        with self.assertRaisesRegex(ValueError, 'setup/package identity'):
            tool.validate_setup_pin(mismatched, self.pin_record, self.setup_sha)

    def test_prepare_must_bind_fresh_package_source_and_loaded_elf(self):
        tool.validate_prepare_binding(
            self.prepare,
            setup_manifest_sha256=self.setup_sha,
            package_digest=self.package_sha,
            application_source_sha256=self.source_sha,
            application_elf_sha256=self.elf_sha,
        )

        historical = {
            'schema': 1,
            'status': 'passed',
            'scope': 'local Full application preparation only',
            'full_proof_created': False,
            'loaded_program': {'elf_match': True, 'elf_sha256': self.elf_sha},
        }
        with self.assertRaisesRegex(ValueError, 'fresh v2 prepare identity'):
            tool.validate_prepare_binding(
                historical,
                setup_manifest_sha256=self.setup_sha,
                package_digest=self.package_sha,
                application_source_sha256=self.source_sha,
                application_elf_sha256=self.elf_sha,
            )

        changed_elf = dict(self.prepare, loaded_program={'elf_match': True, 'elf_sha256': 'f' * 64})
        with self.assertRaisesRegex(ValueError, 'loaded ELF'):
            tool.validate_prepare_binding(
                changed_elf,
                setup_manifest_sha256=self.setup_sha,
                package_digest=self.package_sha,
                application_source_sha256=self.source_sha,
                application_elf_sha256=self.elf_sha,
            )

    def test_direct_identity_fields_are_copies_of_nested_roles(self):
        identities = {role: f'{index:064x}'
                      for index, role in enumerate(tool.IDENTITY_ROLES, 1)}
        document = tool.boundary_identity_fields(identities)

        self.assertEqual(document['identities'], identities)
        for field, role in tool.DIRECT_IDENTITY_ROLES.items():
            self.assertEqual(document[field], identities[role])

        identities['package'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'external pin mismatch'):
            tool.boundary_identity_fields(identities, external_pins={
                'setup_manifest_sha256': '1' * 64,
                'package_digest': '2' * 64,
                'package_pins_sha256': '3' * 64,
            })

    def test_preflight_accepts_matching_synthetic_inputs_without_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)

            def write(relative, raw, mode=0o600):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_bytes(raw)
                path.chmod(mode)
                return path

            setup_raw = json.dumps(self.setup, sort_keys=True).encode()
            setup_path = write(
                'artifacts/dynark/part5/v3-development-setup-002/setup-manifest.json',
                setup_raw)
            self.pin_record['setup_manifest']['sha256'] = hashlib.sha256(setup_raw).hexdigest()
            self.setup_sha = self.pin_record['setup_manifest']['sha256']
            self.prepare['v3_vk']['setup_manifest_sha256'] = self.setup_sha
            pins_path = write(
                'docs/dynark/part5/v3-fresh-package-v2-package-pins.json',
                json.dumps(self.pin_record, sort_keys=True).encode())
            self.prepare['source_manifest_sha256'] = None
            source = {'files': {'program/src/lib.rs': 'e' * 64}}
            source_path = write('application/source-manifest.json',
                                json.dumps(source, sort_keys=True).encode())
            source_sha = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
            self.prepare['source_manifest_sha256'] = source_sha
            elf_path = write('application/zk_fresh_program.so', b'new-elf')
            elf_sha = hashlib.sha256(b'new-elf').hexdigest()
            self.prepare['loaded_program']['elf_sha256'] = elf_sha
            prepare_path = write('application/prepare.json',
                                 json.dumps(self.prepare, sort_keys=True).encode())
            proof_path = write('proof/runner', b'proof-runner-v2', 0o700)
            preparer_path = write('tools/prepare-v2.py', b'input-preparer-v2')
            client_path = write('client/source.py', b'client-v2')
            adapter_path = write('adapter', b'adapter-v2', 0o700)
            proof_sha = hashlib.sha256(proof_path.read_bytes()).hexdigest()
            preparer_sha = hashlib.sha256(preparer_path.read_bytes()).hexdigest()
            with (mock.patch.object(tool, 'ROOT', root),
                  mock.patch.object(tool, 'PACKAGE_PINS_PATH', pins_path),
                  mock.patch.object(tool.package_pins_v2, 'verify_file'),
                  mock.patch.object(tool.packet_v2, 'proof_source_identity', return_value='f' * 64)):
                result = tool.preflight(
                    package_pins_path=pins_path,
                    package_pins_sha256=hashlib.sha256(pins_path.read_bytes()).hexdigest(),
                    prepare_status=prepare_path,
                    application_source_manifest=source_path,
                    application_elf=elf_path,
                    proof_binary=proof_path,
                    proof_binary_sha256=proof_sha,
                    input_preparer=preparer_path,
                    input_preparer_sha256=preparer_sha,
                    client_source=client_path,
                    adapter_binary=adapter_path,
                )
            self.assertTrue(result['preflight_passed'])
            self.assertFalse(result['freeze_published'])
            self.assertEqual(result['schema'], 'credential-v3-heldout-freeze-preflight-v2')
            self.assertNotEqual(result['schema'], tool.packet_v2.FREEZE_SCHEMA)
            self.assertEqual(result['identities']['application_elf'], elf_sha)
            self.assertEqual(result['application_elf_sha256'], elf_sha)
            self.assertFalse((root / 'freeze.json').exists())


if __name__ == '__main__':
    unittest.main()
