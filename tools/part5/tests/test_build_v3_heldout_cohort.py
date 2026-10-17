import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import generate_v3_heldout_keys as keygen
from tools.part5 import build_v3_heldout_cohort as tool


class HeldoutCohortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.freeze = self.root / 'freeze.json'
        self.inventory = self.root / 'prior-keys.json'
        self.output = self.root / 'heldout'
        self.forbidden = ['f' * 64, 'e' * 64]
        self.boundary = dict(
            schema=keygen.FREEZE_SCHEMA,
            frozen_at_unix_ns=100,
            issuance_tool_sha256=keygen.file_sha(keygen.ISSUANCE_TOOL),
            key_generation_tool_sha256=keygen.file_sha(Path(keygen.__file__)),
            identities={name: 'a' * 64 for name in keygen.IDENTITY_ROLES},
            forbidden_public_key_sha256=self.forbidden,
        )
        self.save_inputs()

    def save_inputs(self):
        self.freeze.write_text(json.dumps(self.boundary))
        self.freeze.chmod(0o600)
        self.freeze_sha = hashlib.sha256(self.freeze.read_bytes()).hexdigest()
        self.inventory.write_text(json.dumps(dict(
            schema=tool.INVENTORY_SCHEMA,
            observed_at_unix_ns=50,
            freeze_sha256=self.freeze_sha,
            public_key_sha256=self.forbidden,
        )))
        self.inventory.chmod(0o600)

    def fake_key(self, index):
        key = mock.Mock(spec=rsa.RSAPrivateKey)
        key.key_size = 2048
        public = key.public_key.return_value
        public.key_size = 2048
        public.public_numbers.return_value.e = 65537
        public.public_numbers.return_value.n = (1 << 2047) + index + 1
        public.public_bytes.return_value = f'public-{index}'.encode()
        key.private_bytes.return_value = f'private-{index}'.encode()
        return key

    def run_cohort(self, *, inventory_digest=None):
        keys = [self.fake_key(i) for i in range(12)]
        pem_to_key = {f'private-{i}'.encode(): key for i, key in enumerate(keys)}
        inventory_digest = inventory_digest or hashlib.sha256(self.inventory.read_bytes()).hexdigest()
        with mock.patch.object(keygen, '_ignored', return_value=True), \
             mock.patch.object(keygen, '_new_key', side_effect=keys) as generate_key, \
             mock.patch.object(tool.serialization, 'load_pem_private_key',
                               side_effect=lambda pem, password=None: pem_to_key[pem]), \
             mock.patch.object(tool.issuance, 'issue_certificate', side_effect=self.fake_issue) as issue, \
             mock.patch.object(tool, 'admit_certificate', side_effect=self.fake_admit), \
             mock.patch.object(tool, 'public_bindings', side_effect=self.fake_bindings), \
             mock.patch.object(tool.subprocess, 'run', return_value=mock.Mock(stdout='OpenSSL test')):
            receipt = tool.build(
                self.freeze, self.freeze_sha, self.inventory,
                self.output, inventory_sha256=inventory_digest,
            )
        return receipt, generate_key, issue

    def fake_issue(self, issuer, holder, params, encoder):
        aki = hashlib.sha256(issuer.public_key().public_bytes.return_value).digest()[:20].hex()
        raw = f"DER-{params['variant']}-{encoder}-{holder.public_key().public_numbers().n}-{aki}".encode()
        return raw.ljust(952, b'\0')

    def fake_admit(self, der, modulus):
        _, variant, encoder, holder_modulus, aki = der.rstrip(b'\0').decode().split('-')
        variant = int(variant)
        params = tool._certificate_parameters(variant, '0' * 64)
        organization = bytes([1 if variant < 4 else 2]) * 16
        group = bytes([0x40 if variant < 4 else 0x41]) * 32
        return dict(variant=variant, organization=organization, group=group,
                    aki=bytes.fromhex(aki), tbs=b'tbs',
                    holder_modulus=int(holder_modulus),
                    serial=params['serial'].to_bytes(16, 'big'),
                    not_before=tool._epoch(params['not_before']),
                    not_after=tool._epoch(params['not_after']))

    def fake_bindings(self, parsed, modulus):
        return 1000 + parsed['variant'], 2000 + (parsed['organization'][0] - 1)

    def test_generates_full_fresh_cohort_after_freeze_and_scrubs_receipt(self):
        receipt, generate_key, issue = self.run_cohort()
        self.assertEqual(generate_key.call_count, 12)
        self.assertEqual(issue.call_count, 8)
        self.assertEqual(receipt['counts'], dict(issuers=4, holders=8, certificates=8,
                                                 openssl_issuances=4, policies=2))
        self.assertEqual([row['variant'] for row in receipt['certificates']], list(range(8)))
        self.assertEqual(sum(row['encoder'] == 'openssl' for row in receipt['certificates']), 4)
        self.assertEqual({row['issuer_index'] for row in receipt['certificates'][:4]}, {0, 1, 2, 3})
        self.assertEqual(len({row['policy_hash'] for row in receipt['certificates']}), 2)
        self.assertEqual(len({row['issuer_public_key_sha256'] for row in receipt['certificates']}), 4)
        self.assertEqual(len({row['holder_public_key_sha256'] for row in receipt['certificates']}), 8)
        self.assertTrue(all(row['issuance_started_unix_ns'] > self.boundary['frozen_at_unix_ns']
                            for row in receipt['certificates']))
        self.assertGreater(receipt['generation_started_unix_ns'], self.boundary['frozen_at_unix_ns'])
        self.assertEqual(receipt['freeze_sha256'], self.freeze_sha)
        self.assertEqual(receipt['prior_key_inventory_sha256'], hashlib.sha256(
            self.inventory.read_bytes()).hexdigest())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        for path in self.output.rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        self.assertEqual(len(list((self.output / 'keys').glob('issuer-*.pem'))), 4)
        self.assertEqual(len(list((self.output / 'keys').glob('holder-*.pem'))), 8)
        der_paths = sorted(self.output.glob('certificate-*/credential.der'))
        self.assertEqual(len(der_paths), 8)
        self.assertTrue(all(path.stat().st_size == 952 for path in der_paths))
        raw_receipt = json.dumps(receipt)
        for secret in (b'private-0', b'DER-0-openssl', str(self.root).encode()):
            self.assertNotIn(secret.decode(), raw_receipt)

    def test_bad_freeze_or_inventory_rejects_before_any_key_generation(self):
        cases = ('inventory_digest', 'inventory_mismatch', 'inventory_after_freeze',
                 'freeze_future', 'freeze_hash')
        for case in cases:
            with self.subTest(case=case):
                self.boundary = dict(
                    schema=keygen.FREEZE_SCHEMA,
                    frozen_at_unix_ns=100,
                    issuance_tool_sha256=keygen.file_sha(keygen.ISSUANCE_TOOL),
                    key_generation_tool_sha256=keygen.file_sha(Path(keygen.__file__)),
                    identities={name: 'a' * 64 for name in keygen.IDENTITY_ROLES},
                    forbidden_public_key_sha256=list(self.forbidden),
                )
                self.output = self.root / f'heldout-{case}'
                self.save_inputs()
                expected_freeze = self.freeze_sha
                expected_inventory = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
                if case == 'inventory_digest':
                    expected_inventory = '0' * 64
                elif case == 'inventory_mismatch':
                    self.boundary['forbidden_public_key_sha256'] = ['d' * 64]
                    self.save_inputs()
                    expected_freeze = self.freeze_sha
                    expected_inventory = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
                elif case == 'inventory_after_freeze':
                    value = json.loads(self.inventory.read_text())
                    value['observed_at_unix_ns'] = 101
                    self.inventory.write_text(json.dumps(value))
                    self.inventory.chmod(0o600)
                    expected_inventory = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
                elif case == 'freeze_future':
                    self.boundary['frozen_at_unix_ns'] = 10**30
                    self.save_inputs()
                    expected_freeze = self.freeze_sha
                    expected_inventory = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
                elif case == 'freeze_hash':
                    expected_freeze = '0' * 64
                with mock.patch.object(keygen, '_new_key') as generate_key, \
                     mock.patch.object(keygen, '_ignored', return_value=True), \
                     self.assertRaises(ValueError):
                    tool.build(self.freeze, expected_freeze, self.inventory, self.output,
                               inventory_sha256=expected_inventory)
                generate_key.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_duplicate_json_inventory_fields_are_rejected_before_generation(self):
        self.inventory.write_text('{"schema":"x","schema":"y"}')
        self.inventory.chmod(0o600)
        with mock.patch.object(keygen, '_new_key') as generate_key, self.assertRaises(ValueError):
            tool.build(self.freeze, self.freeze_sha, self.inventory, self.output)
        generate_key.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_nonignored_output_is_rejected_before_any_key_generation(self):
        inventory_digest = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
        with mock.patch.object(keygen, '_ignored', return_value=False), \
             mock.patch.object(keygen, '_new_key') as generate_key, \
             self.assertRaises(ValueError):
            tool.build(self.freeze, self.freeze_sha, self.inventory, self.output,
                       inventory_sha256=inventory_digest)
        generate_key.assert_not_called()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
