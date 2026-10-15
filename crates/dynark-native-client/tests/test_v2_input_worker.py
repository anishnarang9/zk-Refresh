import hashlib
import importlib.util
from pathlib import Path
import unittest
import tempfile
import subprocess
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('v2_input_worker', ROOT / 'crates/dynark-native-client/workers/v2_input_worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class InputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile, cls.witness = worker.sources()
        cls.issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.holder = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.modulus = cls.issuer.public_key().public_numbers().n
        cls.certificate = cls.profile.sign_certificate(cls.profile.build_tbs(cls.holder.public_key().public_numbers().n), cls.issuer)
        cls.action = (98765).to_bytes(32, 'big')
        cls.key = cls.holder.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cls.signature = worker.sign(cls.key, cls.action)
        cls.siblings = [17 + i for i in range(10)]
        cls.constants = ROOT / 'node_modules/circomlib/circuits/poseidon_constants.circom'
        parsed = cls.profile.admit_certificate(cls.certificate, cls.modulus)
        cls.root = cls.witness.registry_root({'tbs': list(parsed['tbs']), 'slot': 7, 'siblings': cls.siblings}, cls.constants)
        limbs = cls.profile.rsa_limbs(cls.modulus)
        cls.issuer_hash = cls.witness.poseidon([cls.witness.poseidon(limbs[:8], cls.constants), cls.witness.poseidon(limbs[8:], cls.constants)], cls.constants)

    def request(self):
        return (self.certificate + self.modulus.to_bytes(256, 'big') + self.action + self.signature
            + (7).to_bytes(2, 'big') + b''.join(v.to_bytes(32, 'little') for v in self.siblings)
            + self.root.to_bytes(32, 'little') + self.issuer_hash.to_bytes(32, 'little'))

    def test_exact_action_signature_and_five_public_order(self):
        self.profile.verify_action(self.holder.public_key().public_numbers().n, self.action, self.signature)
        with self.assertRaises(ValueError):
            self.profile.verify_action(self.holder.public_key().public_numbers().n, hashlib.sha256(self.action).digest(), self.signature)
        output = worker.build(self.request())
        self.assertEqual(output[0:4], b'V2I1')
        self.assertEqual(int.from_bytes(output[4:36], 'little'), self.root)
        self.assertEqual(int.from_bytes(output[36:68], 'little'), self.issuer_hash)
        self.assertEqual(int.from_bytes(output[132:164], 'little'), 98765)
        self.assertEqual(output[164:196], hashlib.sha256(self.profile.admit_certificate(self.certificate, self.modulus)['tbs']).digest())

    def test_private_file_protocol_returns_signature_without_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            directory.chmod(0o700)
            for name, value in [('key.pem', self.key), ('action.be', self.action)]:
                path = directory / name
                path.write_bytes(value)
                path.chmod(0o600)
            result = subprocess.run([sys.executable, str(ROOT / 'crates/dynark-native-client/workers/v2_input_worker.py'),
                'sign', str(directory)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'')
            output = directory / 'output.bin'
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.profile.verify_action(self.holder.public_key().public_numbers().n, self.action, output.read_bytes())

    def test_wrong_root_issuer_action_and_signature_reject(self):
        request = self.request()
        for position in [936 + 256, 936 + 256 + 32, len(request) - 64, len(request) - 32]:
            bad = bytearray(request)
            bad[position] ^= 1
            with self.assertRaises(ValueError):
                worker.build(bytes(bad))

    def test_noncanonical_action_and_path_encoding_reject(self):
        request = self.request()
        for offset, value in [(936 + 256, worker.FR.to_bytes(32, 'big')),
                (936 + 256 + 32 + 256, (1024).to_bytes(2, 'big')),
                (936 + 256 + 32 + 256 + 2, worker.FR.to_bytes(32, 'little'))]:
            bad = request[:offset] + value + request[offset+len(value):]
            with self.assertRaises(ValueError):
                worker.build(bad)
        with self.assertRaises(ValueError):
            worker.build(request[:-1])


if __name__ == '__main__':
    unittest.main()
