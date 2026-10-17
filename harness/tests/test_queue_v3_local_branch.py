import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from harness.tests.queue_v3_local_branch import signed_successor


class SignedSuccessorTests(unittest.TestCase):
    def test_exact_source_signature_and_change_are_required(self):
        key = Ed25519PrivateKey.generate()
        source = list(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        prior = bytes([3] * 32)
        own = bytes([5] * 32)
        observation = {'scope': {'id': 1}, 'issuer': {'source_key': source},
                       'sequence': 3, 'observed_at': 100, 'valid_until': 280,
                       'previous_digest': list(prior),
                       'changes': [{'Revoke': {'tbs_digest': list(own)}}]}
        signed = {'observation': observation, 'signature': []}
        message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
            observation, separators=(',', ':')).encode()
        signed['signature'] = list(key.sign(message))
        enrolled = {'scope': {'id': 1}, 'issuer': {'source_key': source}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def write(name, value):
                fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(json.dumps(value, separators=(',', ':')).encode())
            write('signed-source.json', signed)
            write('enrolled-source.json', enrolled)
            self.assertEqual(len(signed_successor(root, {'source': source},
                                                  'own-revocation', prior.hex(), own.hex())), 64)
            with self.assertRaises(ValueError):
                signed_successor(root, {'source': source}, 'anchor', prior.hex(), own.hex())
            with self.assertRaises(ValueError):
                signed_successor(root, {'source': source},
                                 'own-revocation', bytes(32).hex(), own.hex())
            signed['signature'][0] ^= 1
            write('signed-source.json', signed)
            with self.assertRaises(Exception):
                signed_successor(root, {'source': source},
                                 'own-revocation', prior.hex(), own.hex())


if __name__ == '__main__':
    unittest.main()
