from pathlib import Path
import stat
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from tools.part5.credential_profile import admit_certificate
from tools.part5.prepare_v3_request_fixture import prepare, sign_action


class PrepareFixtureTests(unittest.TestCase):
    def test_prepare(self):
        with tempfile.TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            directory.chmod(0o700)
            result = prepare(directory)
            self.assertIsInstance(result, dict)
            self.assertTrue({'credential_der', 'holder_key_pem', 'issuer_modulus'} <= result.keys())
            self.assertIsInstance(result['issuer_modulus'], int)
            for name in ('credential_der', 'holder_key_pem'):
                path = result[name]
                self.assertIsInstance(path, Path)
                self.assertEqual(path.parent.resolve(), directory.resolve())
                info = path.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(info.st_nlink, 1)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            der = result['credential_der'].read_bytes()
            self.assertEqual(len(der), 952)
            certificate = x509.load_der_x509_certificate(der)
            holder = serialization.load_pem_private_key(result['holder_key_pem'].read_bytes(), password=None)
            self.assertEqual(holder.public_key().public_numbers(), certificate.public_key().public_numbers())
            self.assertIsInstance(admit_certificate(der, result['issuer_modulus']), dict)

    def test_retained_holder_signs_exact_canonical_action(self):
        with tempfile.TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            directory.chmod(0o700)
            fixture = prepare(directory)
            action = (12345).to_bytes(32, 'big')
            signature = sign_action(fixture['holder_key_pem'], action)
            self.assertIsInstance(signature, bytes)
            self.assertEqual(len(signature), 256)
            certificate = x509.load_der_x509_certificate(fixture['credential_der'].read_bytes())
            certificate.public_key().verify(signature, action, padding.PKCS1v15(), hashes.SHA256())
            fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            for invalid in (action[:-1], fr.to_bytes(32, 'big')):
                with self.subTest(action_bytes=len(invalid)):
                    with self.assertRaises(ValueError):
                        sign_action(fixture['holder_key_pem'], invalid)
