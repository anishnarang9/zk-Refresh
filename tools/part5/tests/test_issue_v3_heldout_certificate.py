import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from tools.part5.credential_profile import admit_certificate, public_bindings


TOOL = Path(__file__).resolve().parents[1] / 'issue_v3_heldout_certificate.py'


class IssuanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.holder = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def tool(self):
        self.assertTrue(TOOL.exists(), 'parameterized heldout issuer missing')
        spec = importlib.util.spec_from_file_location('heldout_issuer', TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def parameters(self, variant=0):
        return dict(variant=variant, serial=(1 << 120) + 1000 + variant,
                    not_before=f'2026-01-{variant + 1:02d}T00:00:00Z',
                    not_after=f'2028-02-{variant + 1:02d}T00:00:00Z',
                    organization=(bytes([variant + 11]) * 16).hex(),
                    group=(bytes([variant + 21]) * 32).hex(),
                    aki=(bytes([variant + 31]) * 20).hex())

    def test_both_encoders_admit_all_eight_layouts_and_requested_signed_fields(self):
        tool = self.tool()
        policies = set()
        for encoder in ('cryptography', 'openssl'):
            for variant in range(8):
                params = self.parameters(variant)
                with self.subTest(encoder=encoder, variant=variant):
                    der = tool.issue_certificate(self.issuer, self.holder, params, encoder)
                    parsed = admit_certificate(der, self.issuer.public_key().public_numbers().n)
                    self.assertEqual((len(der), len(parsed['tbs']), parsed['variant']),
                                     (952, 672, variant))
                    self.assertEqual(parsed['aki'], bytes.fromhex(params['aki']))
                    self.assertEqual(parsed['organization'], bytes.fromhex(params['organization']))
                    self.assertEqual(parsed['group'], bytes.fromhex(params['group']))
                    expected = datetime.datetime.fromisoformat(params['not_before'].replace('Z', '+00:00'))
                    self.assertEqual(parsed['not_before'], int(expected.timestamp()))
                    end = datetime.datetime.fromisoformat(params['not_after'].replace('Z', '+00:00'))
                    self.assertEqual(parsed['not_after'], int(end.timestamp()))
                    self.assertEqual(x509.load_der_x509_certificate(der).serial_number, params['serial'])
                    self.assertEqual(parsed['holder_modulus'], self.holder.public_key().public_numbers().n)
                    policies.add(public_bindings(parsed, self.issuer.public_key().public_numbers().n)[1])
        self.assertEqual(len(policies), 8)

    def test_invalid_profile_parameters_reject_before_issuance(self):
        tool = self.tool()
        changes = [('variant', 8), ('variant', True), ('serial', 1),
                   ('serial', 1 << 127), ('not_before', '1999-01-01T00:00:00Z'),
                   ('not_after', '2050-01-01T00:00:00Z'),
                   ('not_after', '2025-01-01T00:00:00Z'), ('aki', '00'),
                   ('organization', '00'), ('group', 'zz' * 32)]
        for key, value in changes:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                tool.issue_certificate(self.issuer, self.holder,
                                       {**self.parameters(), key: value}, 'cryptography')
        with self.assertRaises(ValueError):
            tool.issue_certificate(self.issuer, self.issuer, self.parameters(), 'cryptography')

    def test_openssl_private_key_temporary_directory_is_ignored(self):
        tool = self.tool()
        with mock.patch.object(tool.tempfile, 'TemporaryDirectory',
                               side_effect=RuntimeError('temp location probe')) as temporary:
            with self.assertRaisesRegex(RuntimeError, 'temp location probe'):
                tool._openssl(self.issuer, self.holder,
                              tool._parameters(self.parameters()), 'I' * 40, 'H' * 24)
        self.assertEqual(Path(temporary.call_args.kwargs['dir']), tool.ROOT / 'artifacts')

    def test_private_publication_links_exact_freeze_and_never_claims_key_freshness(self):
        tool = self.tool()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            os.chmod(root, 0o700)
            output = root / 'output'
            output.mkdir(mode=0o700)
            for name, key in [('issuer.pem', self.issuer), ('holder.pem', self.holder)]:
                path = root / name
                path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                path.chmod(0o600)
            params = root / 'parameters.json'
            params.write_text(json.dumps(self.parameters()))
            params.chmod(0o600)
            freeze = root / 'freeze.json'
            freeze.write_text(json.dumps(dict(schema='credential-v3-frozen-holdout-boundary-v1',
                frozen_at_unix_ns=time.time_ns() - 1_000_000,
                issuance_tool_sha256=hashlib.sha256(TOOL.read_bytes()).hexdigest())))
            freeze.chmod(0o600)
            receipt = tool.issue_to_directory(root / 'issuer.pem', root / 'holder.pem',
                                              params, freeze, output, 'cryptography')
            self.assertEqual(receipt['freeze_receipt_sha256'], hashlib.sha256(freeze.read_bytes()).hexdigest())
            self.assertGreater(receipt['issuance_started_unix_ns'], json.loads(freeze.read_text())['frozen_at_unix_ns'])
            self.assertFalse(receipt['fresh_key_generation_proven'])
            self.assertEqual(set(p.name for p in output.iterdir()), {'credential.der', 'issuance-receipt.json'})
            for path in output.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt['credential_sha256'], hashlib.sha256((output / 'credential.der').read_bytes()).hexdigest())
            with self.assertRaises(ValueError):
                tool.issue_to_directory(root / 'issuer.pem', root / 'holder.pem',
                                        params, freeze, output, 'cryptography')
            empty = root / 'empty'
            empty.mkdir(mode=0o700)
            freeze.write_text(json.dumps(dict(schema='credential-v3-frozen-holdout-boundary-v1',
                frozen_at_unix_ns=time.time_ns() + 10**12,
                issuance_tool_sha256=hashlib.sha256(TOOL.read_bytes()).hexdigest())))
            with self.assertRaises(ValueError):
                tool.issue_to_directory(root / 'issuer.pem', root / 'holder.pem',
                                        params, freeze, empty, 'cryptography')
            self.assertEqual(list(empty.iterdir()), [])

    def test_ambiguous_parameter_json_does_not_publish(self):
        tool = self.tool()
        self.assertTrue(hasattr(tool, 'decode_parameters'), 'strict issuance JSON decoder missing')
        with self.assertRaises(ValueError):
            tool.decode_parameters('{"variant":0,"variant":1}')


if __name__ == '__main__':
    unittest.main()
