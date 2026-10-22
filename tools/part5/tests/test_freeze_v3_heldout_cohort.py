import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import generate_v3_heldout_keys as keygen
from tools.part5 import freeze_v3_heldout_cohort as tool
from tools.part5 import build_v3_heldout_cohort as builder
from tools.part5 import build_v3_heldout_run_manifest as manifest_builder
from tools.part5 import verify_v3_heldout_acceptance as verifier


class HeldoutFreezePinClosureTests(unittest.TestCase):
    def test_heldout_gates_pin_queue_runner_005_consistently(self):
        expected = 'artifacts/dynark/part5/v3-heldout-queue-runner-005'
        self.assertEqual(tool.RUNNER_BINARY, expected)
        self.assertEqual(manifest_builder.freeze_tool.RUNNER_BINARY, expected)
        self.assertEqual(verifier.QUEUE_RUNNER_REL, expected)

    def test_client_bundle_pins_current_r2_rejection_tools(self):
        required = {
            'tools/part5/check_v3_r2_counterfactual.py',
            'tools/part5/witness_check.py',
            'tools/part5/prepare_v3_heldout_proof.py',
            'tools/part5/model_v3_heldout_break_even.py',
            'tools/part5/observe_v3_heldout_cohort.py',
            'tools/part5/run_v3_heldout_complete_arm.py',
            'tools/part5/run_v3_heldout_direct_arm.py',
            'tools/part5/finalize_v3_expired_status_negative.py',
            'tools/part5/heldout_expired_status_evidence.py',
            'tools/part5/build_v3_expired_status_negative_inputs.py',
            'tools/part5/heldout_queue_capacity_evidence.py',
            'tools/part5/prepare_v3_queue_capacity_fixture.py',
            'tools/part5/finalize_v3_queue_capacity_negative.py',
            'tools/part5/run_v3_heldout_whole_session.py',
            'crates/dynark-native-client/tests/support/v3_relation_witness.cjs',
        }
        self.assertTrue(required.issubset(set(tool.CLIENT_FILES)))
        self.assertEqual(len(tool.CLIENT_FILES), len(set(tool.CLIENT_FILES)))

    def test_registry_bundle_pins_queue_runner_local_build_inputs(self):
        required = {
            'harness/src/solana/queue_v3.rs',
            'harness/src/solana/queue_v3/branch.rs',
            'harness/src/solana/queue_v3/campaign.rs',
            'harness/src/solana/queue_v3/disabled_config.rs',
            'harness/src/lib.rs',
            'harness/src/main.rs',
            'harness/src/solana.rs',
            'harness/src/benchmark.rs',
            'harness/src/fixtures.rs',
            'harness/src/policy.rs',
            'harness/src/prover.rs',
            'harness/src/registry.rs',
            'harness/src/setup.rs',
            'harness/tests/queue_v3.rs',
            'harness/tests/queue_v3_ambiguous_rpc_proxy.py',
            'harness/tests/queue_v3_local_ambiguous_restart.py',
            'harness/tests/queue_v3_clone_prepared.py',
            'harness/tests/queue_v3_local_expired_status_negative.py',
            'harness/tests/queue_v3_loaded_negative_checks.py',
            'harness/tests/queue_v3_blank_seed.py',
            'harness/tests/queue_v3_capacity_runtime.py',
            'harness/tests/queue_v3_local_queue_capacity_negative.py',
            'harness/Cargo.toml',
            'harness/Cargo.lock',
            'circuits/profile.json',
            'program/src/lib.rs',
            'program/Cargo.toml',
            'crates/credential-registry/src/lib.rs',
            'crates/credential-registry/src/protocol.rs',
            'crates/credential-registry/src/storage.rs',
            'crates/credential-registry/Cargo.toml',
            tool.RUNNER_BINARY,
        }
        self.assertTrue(required.issubset(set(tool.REGISTRY_FILES)))
        self.assertEqual(len(tool.REGISTRY_FILES), len(set(tool.REGISTRY_FILES)))

    def test_registry_bundle_digest_tracks_compile_time_profile_contents(self):
        profile_path = 'circuits/profile.json'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile = root / profile_path
            profile.parent.mkdir(parents=True)
            profile.write_bytes(b'{"profile":"initial"}')
            with mock.patch.object(tool.prior_freeze, 'ROOT', root):
                before, members = tool.prior_freeze.bundle([profile_path])
                self.assertEqual([member['path'] for member in members], [profile_path])
                profile.write_bytes(b'{"profile":"changed"}')
                after, _ = tool.prior_freeze.bundle([profile_path])
        self.assertNotEqual(before, after)

    def test_declared_source_bundles_cover_local_python_import_closure(self):
        import ast

        root = Path(__file__).resolve().parents[3]
        pinned = set(tool.CLIENT_FILES + tool.REGISTRY_FILES)

        def local_module_path(module):
            if module.startswith('tools.part5.'):
                base = root / 'tools/part5'
                relative = module.removeprefix('tools.part5.')
            elif module.startswith('harness.tests.'):
                base = root / 'harness/tests'
                relative = module.removeprefix('harness.tests.')
            else:
                return None
            candidate = base / (relative.replace('.', '/') + '.py')
            return candidate.relative_to(root).as_posix() if candidate.is_file() else None

        pending = list(pinned)
        visited = set()
        missing = set()
        while pending:
            relative = pending.pop()
            if relative in visited:
                continue
            visited.add(relative)
            source = root / relative
            if source.suffix != '.py' or not source.is_file():
                continue
            tree = ast.parse(source.read_text())
            dependencies = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    path = local_module_path(node.module)
                    if path:
                        dependencies.add(path)
                    if node.module in ('tools.part5', 'harness.tests'):
                        for alias in node.names:
                            path = local_module_path(node.module + '.' + alias.name)
                            if path:
                                dependencies.add(path)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        path = local_module_path(alias.name)
                        if path:
                            dependencies.add(path)
            for dependency in dependencies:
                if dependency not in pinned:
                    missing.add(dependency)
                pending.append(dependency)

        self.assertEqual(missing, set())


class HeldoutFreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.part5 = self.root / 'artifacts/dynark/part5'
        self.results = self.root / 'results/dynark/part5'
        self.part5.mkdir(parents=True)
        self.results.mkdir(parents=True, mode=0o700)
        self.compile = self.part5 / 'v3-compile-001'
        self.setup_dir = self.part5 / 'v3-development-setup-001'
        self.proof = self.root / 'proof-runner'
        for name, value in (
                ('ROOT', self.root), ('PART5', self.part5), ('RESULTS', self.results),
                ('COMPILE', self.compile), ('SETUP', self.setup_dir), ('PROOF', self.proof),
                ('LOADED_ELF', self.part5 / 'application-v3-sbf-build-002/elf/zk_fresh_program.so'),
                ('REGISTRY_FILES', ['registry/one.rs', 'registry/two.rs']),
                ('CLIENT_FILES', ['client/one.rs', 'client/two.py'])):
            for module in (tool, tool.prior_freeze):
                if hasattr(module, name):
                    patch = mock.patch.object(module, name, value)
                    patch.start()
                    self.addCleanup(patch.stop)
        self.output = self.results / 'v3-heldout-freeze-001'
        self.freeze_path = self.output / 'freeze.json'
        self.inventory_path = self.output / 'prior-key-inventory.json'
        self.prepare_path = self.root / 'prepare.json'
        self.adapter = self.root / 'ordinary-adapter'
        self._fixture()

    def _write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, bytes) else value.encode()
        path.write_bytes(raw)
        return raw

    def _fixture(self):
        self.inputs = {
            'profile': self.root / 'circuits/credential-v3-bounded/profile.json',
            'r1cs': self.compile / 'credential.r1cs',
            'witness_executable': self.compile / 'credential_js/credential.wasm',
            'setup_manifest': self.setup_dir / 'setup-manifest.json',
            'ordinary_vk': self.setup_dir / 'ordinary.vk',
            'proof_runner': self.proof / 'target/release/credential-v3-bounded-proof-qualification-v1',
            'signer_interface': self.root / 'tools/part5/prepare_v3_request_fixture.py',
            'ordinary_adapter': self.adapter,
            'loaded_elf': self.part5 / 'application-v3-sbf-build-002/elf/zk_fresh_program.so',
        }
        profile = {
            'profile': 'credential-v3-bounded-der-v1', 'certificate_length': 952,
            'tbs_length': 672, 'aki_bytes': 20, 'organization_bytes': 16,
            'group_bytes': 32, 'rsa': {'bits': 2048, 'digest': 'SHA256',
                'exponent': 65537, 'padding': 'PKCS1-v1_5'},
            'serial': 'canonical positive exactly 16 octets; first octet 1..127',
            'validity': 'canonical UTCTime 2000-2049, real calendar, inclusive endpoints',
            'layouts': [{'layout': i} for i in range(8)],
        }
        self._write(self.inputs['profile'], json.dumps(profile, sort_keys=True))
        for role, path in self.inputs.items():
            if role != 'profile':
                self._write(path, (role + '-bytes').encode())
        self._write(self.root / 'registry/one.rs', b'registry-one')
        self._write(self.root / 'registry/two.rs', b'registry-two')
        self._write(self.root / 'client/one.rs', b'client-one')
        self._write(self.root / 'client/two.py', b'client-two')
        circuit = 'a' * 64
        file_sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        setup = {
            'schema': 'credential-v3-bounded-setup-v1', 'development_only': True,
            'identity': {'circuit': circuit},
            'profile_sha256': file_sha(self.inputs['profile']),
            'r1cs_sha256': file_sha(self.inputs['r1cs']),
            'wasm_sha256': file_sha(self.inputs['witness_executable']),
            'ordinary_vk_file_sha256': file_sha(self.inputs['ordinary_vk']),
        }
        setup_raw = json.dumps(setup, sort_keys=True).encode()
        self._write(self.inputs['setup_manifest'], setup_raw)
        self.application_manifest = {'source_pins': {'program/src/lib.rs': 'b' * 64}}
        source_sha = hashlib.sha256(json.dumps(
            self.application_manifest, sort_keys=True).encode()).hexdigest()
        self.prepare = {
            'schema': 1, 'scope': 'part5-v3-local-prepare', 'status': 'passed',
            'application_effect': False, 'devnet': False,
            'cleanup': {'reaped': True, 'exit_code': 0},
            'prepared_application_accounts': False,
            'source_manifest_sha256': source_sha,
            'loaded_program': {'elf_match': True, 'elf_sha256': file_sha(self.inputs['loaded_elf']),
                               'genesis': 'local-genesis'},
            'v3_vk': {'setup_manifest_sha256': hashlib.sha256(setup_raw).hexdigest(),
                      'circuit_id': circuit},
        }
        self._write(self.prepare_path, json.dumps(self.prepare, sort_keys=True))
        prior_key = rsa.RSAPublicNumbers(65537, (1 << 2047) + 123).public_key()
        prior_der = prior_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self._write(self.part5 / 'earlier/public.pem', prior_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self._write(self.part5 / 'older/public.der', prior_der)

    def _freeze(self):
        with mock.patch('harness.tests.queue_v3_build_prep.source_manifest',
                        return_value=self.application_manifest):
            return tool.freeze(self.prepare_path, self.adapter, self.output)

    def test_freeze_pins_explicit_proof_binary_hash_and_keeps_boundary_schema(self):
        proof_binary = self.root / 'isolated-proof-runner'
        proof_binary.write_bytes(b'corrected proof runner')
        proof_binary.chmod(0o700)
        with mock.patch('harness.tests.queue_v3_build_prep.source_manifest',
                        return_value=self.application_manifest):
            receipt = tool.freeze(self.prepare_path, self.adapter, self.output,
                                  proof_binary=proof_binary)

        boundary = json.loads(self.freeze_path.read_text())
        self.assertEqual(boundary['identities']['proof_runner'], hashlib.sha256(
            proof_binary.read_bytes()).hexdigest())
        self.assertEqual(set(boundary), {
            'schema', 'frozen_at_unix_ns', 'issuance_tool_sha256',
            'key_generation_tool_sha256', 'identities', 'forbidden_public_key_sha256'})
        self.assertEqual(receipt['identities']['proof_runner'],
                         boundary['identities']['proof_runner'])

    def test_freeze_pins_all_product_inputs_and_publishes_prior_inventory_first(self):
        receipt = self._freeze()
        boundary = json.loads(self.freeze_path.read_text())
        inventory = json.loads(self.inventory_path.read_text())
        self.assertEqual(set(boundary), {
            'schema', 'frozen_at_unix_ns', 'issuance_tool_sha256',
            'key_generation_tool_sha256', 'identities', 'forbidden_public_key_sha256'})
        self.assertEqual(boundary['schema'], keygen.FREEZE_SCHEMA)
        self.assertEqual(set(boundary['identities']), keygen.IDENTITY_ROLES)
        self.assertEqual(boundary['identities']['circuit'], 'a' * 64)
        self.assertEqual(boundary['identities']['profile'], hashlib.sha256(
            self.inputs['profile'].read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['r1cs'], hashlib.sha256(
            self.inputs['r1cs'].read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['witness_executable'], hashlib.sha256(
            self.inputs['witness_executable'].read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['setup_manifest'], hashlib.sha256(
            self.inputs['setup_manifest'].read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['ordinary_vk'], hashlib.sha256(
            self.inputs['ordinary_vk'].read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['proof_runner'], hashlib.sha256(
            self.inputs['proof_runner'].read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['signer_interface'], hashlib.sha256(
            self.inputs['signer_interface'].read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['ordinary_adapter'], hashlib.sha256(
            self.adapter.read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['loaded_elf'], hashlib.sha256(
            self.inputs['loaded_elf'].read_bytes()).hexdigest())
        self.assertEqual(boundary['identities']['application_source'], self.prepare['source_manifest_sha256'])
        self.assertEqual(boundary['issuance_tool_sha256'], keygen.file_sha(keygen.ISSUANCE_TOOL))
        self.assertEqual(boundary['key_generation_tool_sha256'], keygen.file_sha(Path(keygen.__file__)))
        self.assertEqual(inventory['schema'], tool.INVENTORY_SCHEMA)
        self.assertEqual(inventory['freeze_sha256'], receipt['freeze_sha256'])
        self.assertEqual(inventory['public_key_sha256'], boundary['forbidden_public_key_sha256'])
        self.assertLess(inventory['observed_at_unix_ns'], boundary['frozen_at_unix_ns'])
        self.assertEqual(len(inventory['public_key_sha256']), 1)
        _, keygen_boundary = keygen._freeze(
            self.freeze_path, receipt['freeze_sha256'], tool.time.time_ns())
        raw_inventory, _ = builder._inventory(
            self.inventory_path, receipt['freeze_sha256'],
            keygen_boundary['forbidden_public_key_sha256'],
            keygen_boundary['frozen_at_unix_ns'])
        self.assertEqual(hashlib.sha256(raw_inventory).hexdigest(),
                         receipt['prior_key_inventory_sha256'])
        self.assertEqual(receipt['prior_public_key_count'], 1)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.freeze_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.inventory_path.stat().st_mode & 0o777, 0o600)
        encoded = self.freeze_path.read_bytes() + self.inventory_path.read_bytes()
        self.assertNotIn(b'BEGIN ', encoded)
        self.assertNotIn(str(self.root).encode(), encoded)

    def test_bad_prepare_or_profile_bounds_leave_no_published_directory(self):
        for bad in ('effect', 'elf', 'profile'):
            with self.subTest(bad=bad):
                self.output = self.results / f'bad-{bad}'
                self.freeze_path = self.output / 'freeze.json'
                self.inventory_path = self.output / 'prior-key-inventory.json'
                if bad == 'effect':
                    value = dict(self.prepare, application_effect=True)
                    self.prepare_path.write_text(json.dumps(value))
                elif bad == 'elf':
                    value = dict(self.prepare)
                    value['loaded_program'] = dict(value['loaded_program'], elf_sha256='0' * 64)
                    self.prepare_path.write_text(json.dumps(value))
                else:
                    profile = json.loads(self.inputs['profile'].read_text())
                    profile['rsa']['bits'] = 1024
                    self.inputs['profile'].write_text(json.dumps(profile, sort_keys=True))
                    setup = json.loads(self.inputs['setup_manifest'].read_text())
                    setup['profile_sha256'] = hashlib.sha256(
                        self.inputs['profile'].read_bytes()).hexdigest()
                    self.inputs['setup_manifest'].write_text(json.dumps(setup, sort_keys=True))
                    self.prepare['v3_vk']['setup_manifest_sha256'] = hashlib.sha256(
                        self.inputs['setup_manifest'].read_bytes()).hexdigest()
                    self.prepare_path.write_text(json.dumps(self.prepare))
                with mock.patch('harness.tests.queue_v3_build_prep.source_manifest',
                                return_value=self.application_manifest), self.assertRaises(ValueError):
                    tool.freeze(self.prepare_path, self.adapter, self.output)
                self.assertFalse(self.output.exists())
                self.prepare_path.write_text(json.dumps(self.prepare))
                self._fixture()

    def test_existing_or_noncanonical_output_is_never_replaced(self):
        self.output.mkdir(mode=0o700)
        sentinel = self.output / 'sentinel'
        sentinel.write_text('preserve')
        with self.assertRaises(ValueError):
            self._freeze()
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_pair_write_failure_removes_staging_directory(self):
        real_write = tool._write_file
        calls = 0

        def fail_second(directory, name, raw):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('injected write failure')
            real_write(directory, name, raw)

        with mock.patch.object(tool, '_write_file', side_effect=fail_second), \
                self.assertRaises(OSError):
            tool._publish_pair(self.output, b'freeze', b'inventory')
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.results.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
