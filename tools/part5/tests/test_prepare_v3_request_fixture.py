from pathlib import Path
import hashlib
import stat
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from tools.part5.credential_profile import admit_certificate, public_bindings
from tools.part5.poseidon import poseidon
from tools.part5.prepare_v3_request_fixture import prepare, sign_action, build_membership


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

    def test_synthetic_complete_tree_membership_and_revocation_roots(self):
        with tempfile.TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            directory.chmod(0o700)
            fixture = prepare(directory)
            der = fixture['credential_der'].read_bytes()
            parsed = admit_certificate(der, fixture['issuer_modulus'])
            result = build_membership(der, fixture['issuer_modulus'])
            self.assertIsInstance(result, dict)
            self.assertTrue({'slot', 'issuer_hash', 'policy_hash', 'active_root',
                             'active_siblings', 'unrelated_root', 'unrelated_siblings',
                             'own_revoked_root', 'own_revoked_siblings'} <= result.keys())
            self.assertIs(type(result['slot']), int)
            self.assertTrue(0 <= result['slot'] < 1024)
            self.assertEqual((result['issuer_hash'], result['policy_hash']),
                             public_bindings(parsed, fixture['issuer_modulus']))
            fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            constants = Path(__file__).resolve().parents[3] / 'node_modules/circomlib/circuits/poseidon_constants.circom'
            digest = hashlib.sha256(parsed['tbs']).digest()
            for root_name, path_name, active in [('active_root', 'active_siblings', 1),
                                                 ('unrelated_root', 'unrelated_siblings', 1),
                                                 ('own_revoked_root', 'own_revoked_siblings', 0)]:
                siblings = result[path_name]
                self.assertEqual(len(siblings), 10)
                node = poseidon([2026101504, int.from_bytes(digest[:16], 'big'),
                                 int.from_bytes(digest[16:], 'big'), result['slot'], active], constants)
                for level, sibling in enumerate(siblings):
                    self.assertIs(type(sibling), int)
                    self.assertTrue(0 <= sibling < fr)
                    pair = [sibling, node] if (result['slot'] >> level) & 1 else [node, sibling]
                    node = poseidon(pair, constants)
                self.assertEqual(node, result[root_name])
            for name in ('issuer_hash', 'policy_hash', 'active_root', 'unrelated_root', 'own_revoked_root'):
                self.assertIs(type(result[name]), int)
                self.assertTrue(0 <= result[name] < fr)
            self.assertNotEqual(result['active_root'], result['unrelated_root'])
            self.assertNotEqual(result['own_revoked_root'], result['active_root'])
            self.assertNotEqual(result['own_revoked_root'], result['unrelated_root'])
