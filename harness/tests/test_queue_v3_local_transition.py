import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


source = Path(__file__).with_name('queue_v3_local_transition.py')
spec = importlib.util.spec_from_file_location('v3_transition', source)
transition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transition)


class SignedRevocationCheck(unittest.TestCase):
    def test_source_signature_and_wire_digest_are_independently_checked(self):
        signer = Ed25519PrivateKey.generate()
        key = signer.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
        observation = {'scope': {}, 'issuer': {'source_key': list(key)},
                       'sequence': 2, 'previous_digest': [1] * 32,
                       'observed_at': 100, 'valid_until': 200,
                       'issuer_status_active': True,
                       'changes': [{'Revoke': {'tbs_digest': [9] * 32}}]}
        message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
            observation, separators=(',', ':')).encode()
        signed = {'observation': observation, 'signature': list(signer.sign(message))}
        enrolled = {'issuer': {'source_key': list(key)}}
        wire = b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
            signed, separators=(',', ':')).encode()
        report = {'unrelated_tbs_digest': bytes([9] * 32).hex(),
                  'source_head_digest': hashlib.sha256(wire).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for name, value in [('signed-source.json', signed),
                                ('enrolled-source.json', enrolled)]:
                file = path / name
                descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'w') as stream:
                    json.dump(value, stream)
            transition.check_signed_source(path, {'source': list(key)}, report)
            wrong = dict(report, source_head_digest='00' * 32)
            with self.assertRaises(ValueError):
                transition.check_signed_source(path, {'source': list(key)}, wrong)
            signed['signature'][0] ^= 1
            (path / 'signed-source.json').write_text(json.dumps(signed))
            with self.assertRaises(Exception):
                transition.check_signed_source(path, {'source': list(key)}, report)


if __name__ == '__main__':
    unittest.main()
