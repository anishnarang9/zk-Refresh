"""Synthetic in-memory keys only; no retained PEM, real key or credential input."""
import hashlib
from pathlib import Path
import types
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

WORKER = Path(__file__).resolve().parents[1] / 'workers/v3_action_worker.py'
worker = types.ModuleType('v3_action_worker')
worker.__file__ = str(WORKER)
exec(compile(WORKER.read_bytes(), str(WORKER), 'exec'), worker.__dict__)


class ActionSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.holder = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.modulus = cls.holder.public_key().public_numbers().n.to_bytes(256, 'big')
        cls.other_modulus = cls.other.public_key().public_numbers().n.to_bytes(256, 'big')
        cls.action = bytes.fromhex('09b1b947699a3927e6654b5b37caf74211edde16b887afba5da2796b56411cc2')
        cls.signature = cls.holder.sign(cls.action, padding.PKCS1v15(), hashes.SHA256())

    def verify(self, modulus=None, signer=None, action=None, signature=None):
        return worker.verify_action_signature(
            self.modulus if modulus is None else modulus,
            self.modulus if signer is None else signer,
            self.action if action is None else action,
            self.signature if signature is None else signature)

    def test_matching_synthetic_holder_verifies_exact_canonical_action(self):
        self.assertIsNone(self.verify())

    def test_wrong_signer_and_spoofed_public_modulus_are_rejected(self):
        other_sig = self.other.sign(self.action, padding.PKCS1v15(), hashes.SHA256())
        with self.assertRaises(worker.ActionVerificationError):
            self.verify(signer=self.other_modulus, signature=other_sig)
        with self.assertRaises(worker.ActionVerificationError):
            self.verify(signature=other_sig)

    def test_changed_action_or_signature_is_rejected(self):
        changed = (int.from_bytes(self.action, 'big') + 1).to_bytes(32, 'big')
        bad_sig = bytearray(self.signature)
        bad_sig[0] ^= 1
        for args in [{'action': changed}, {'signature': bytes(bad_sig)},
                     {'signature': self.signature[:-1]}, {'action': self.action[:-1]}]:
            with self.subTest(kind=next(iter(args))):
                with self.assertRaises(worker.ActionVerificationError):
                    self.verify(**args)

    def test_double_hash_pss_and_noncanonical_field_or_signature_are_rejected(self):
        double_hash = self.holder.sign(hashlib.sha256(self.action).digest(),
                                     padding.PKCS1v15(), hashes.SHA256())
        pss = self.holder.sign(self.action, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                     salt_length=32), hashes.SHA256())
        modulus_alias = (21888242871839275222246405745257275088548364400416034343698204186575808495617).to_bytes(32, 'big')
        for args in [{'signature': double_hash}, {'signature': pss},
                     {'signature': self.modulus}, {'action': modulus_alias},
                     {'modulus': bytes(256)}, {'signer': bytes(255)}]:
            with self.subTest(kind=next(iter(args))):
                with self.assertRaises(worker.ActionVerificationError):
                    self.verify(**args)


if __name__ == '__main__':
    unittest.main()
