from pathlib import Path
import stat
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tools.part5.credential_profile import admit_certificate
from tools.part5.prepare_v3_request_fixture import prepare


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
