import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from harness.tests.queue_v3_local_branch import matched_proof_report, signed_successor


class MatchedProofReportTests(unittest.TestCase):
    def test_exact_mode_counts_action_and_roots(self):
        config = {'mode': 'anchor', 'stage_report_sha256': 'stage',
                  'transition_report_sha256': 'transition', 'expected_genesis': 'genesis'}
        context = {'base_root': '01', 'near_root': '02'}
        full = bytearray(448)
        near = bytearray(448)
        full[0:32] = (1).to_bytes(32, 'big')
        near[0:32] = (2).to_bytes(32, 'big')
        full[159] = near[159] = 3
        wires = {'full': bytes(full), 'anchor': bytes(near)}
        report = {'schema': 'credential-v3-matched-k1-proof-v1',
                  'mode': 'matched-anchor-k1', 'passed': True,
                  'application_verified': False, 'qualification_extras_executed': False,
                  'counts': {'proofs': 2, 'positive_checks': 2,
                             'altered_public_checks': 12, 'cross_root_checks': 2,
                             'ordinary_checks': 16},
                  'application_stage_pins': {
                      'base_root': '1', 'near_root': '2', 'action_hash': '3',
                      'base_stage_report_sha256': 'stage',
                      'near_state_report_sha256': 'transition',
                      'program_id': 'program', 'genesis_hash': 'genesis',
                      'request_address': 'request', 'loaded_elf_sha256': 'elf'}}
        staged = {'request': 'request'}
        original = {'program': 'program', 'elf_sha256': 'elf'}
        matched_proof_report(config, report, context, wires, staged, original)
        for altered in ({**report, 'mode': 'matched-full-k1'},
                        {**report, 'counts': {**report['counts'], 'proofs': 3}},
                        {**report, 'application_stage_pins': {
                            **report['application_stage_pins'], 'near_root': '4'}}):
            with self.assertRaises(ValueError):
                matched_proof_report(config, altered, context, wires, staged, original)


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
            observation['changes'] = []
            message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
                observation, separators=(',', ':')).encode()
            signed['signature'] = list(key.sign(message))
            write('signed-source.json', signed)
            self.assertEqual(len(signed_successor(root, {'source': source},
                                                  'full', prior.hex(), own.hex())), 64)
            self.assertEqual(len(signed_successor(root, {'source': source},
                                                  'anchor', prior.hex(), own.hex())), 64)
            with self.assertRaises(ValueError):
                signed_successor(root, {'source': source},
                                 'own-revocation', prior.hex(), own.hex())
            signed['signature'][0] ^= 1
            write('signed-source.json', signed)
            with self.assertRaises(Exception):
                signed_successor(root, {'source': source},
                                 'own-revocation', prior.hex(), own.hex())


if __name__ == '__main__':
    unittest.main()
