"""Tests-first private V3Q1 bridge contract; no proof or application authority.

The canonical action below represents request-derived input at this boundary.
These unit tests do not establish its origin from an application request, chain
freshness, issuer authorization, or complete circuit/proof validity.
"""
import contextlib
import copy
import hashlib
import io
from pathlib import Path
import tempfile
import types
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tools.part5 import prepare_v3_request_fixture as bridge
from tools.part5.credential_profile import admit_certificate


ROOT = Path(__file__).resolve().parents[3]
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# A canonical, full-width request-derived boundary input, never a claim of
# application authority. End-to-end request derivation is a separate gate.
ACTION_BE = bytes.fromhex('129eacbd5f0317a6c86d420b751fe99837a642c05db7e1938af46bc951d802e3')
WORKER_SHA = 'b1349652a0acc86b4d8a820020ea6c8cdbba1f021958c6a9770a200e3124762e'


class V3RequestBoundBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = None

    def setUp(self):
        self.builder = getattr(bridge, 'build_v3q1', None)
        self.assertTrue(callable(self.builder), 'missing build_v3q1 request-bound bridge')
        cls = type(self)
        if cls.fixture is None:
            temporary = tempfile.TemporaryDirectory()
            cls.addClassCleanup(temporary.cleanup)
            directory = Path(temporary.name)
            directory.chmod(0o700)
            cls.fixture = bridge.prepare(directory)
            cls.der = cls.fixture['credential_der'].read_bytes()
            cls.membership = bridge.build_membership(cls.der, cls.fixture['issuer_modulus'])
            worker_path = ROOT / 'crates/dynark-native-client/workers/v3_input_worker.py'
            source = worker_path.read_bytes()
            self.assertEqual(hashlib.sha256(source).hexdigest(), WORKER_SHA,
                             'reviewed worker source identity')
            cls.worker = types.ModuleType('pinned_bridge_input_worker')
            cls.worker.__file__ = str(worker_path)
            exec(compile(source, str(worker_path), 'exec'), cls.worker.__dict__)

    def request(self, **changes):
        arguments = dict(der=self.der, issuer_modulus=self.fixture['issuer_modulus'],
                         holder_key_pem=self.fixture['holder_key_pem'],
                         action_be=ACTION_BE, membership=copy.deepcopy(self.membership))
        arguments.update(changes)
        return self.builder(**arguments)

    def candidate_fields(self, request):
        response = self.worker.build(request)
        self.assertEqual(len(response), 24495)
        self.assertEqual(response[:4], b'V3I1')
        return [int.from_bytes(response[start:start + 32], 'little')
                for start in range(463, 24495, 32)]

    def test_exact_wire_binds_imported_holder_and_all_membership_fields(self):
        request = self.request()
        self.assertIs(type(request), bytes)
        self.assertEqual(len(request), 1918)
        self.assertEqual(request[:4], b'V3Q1')
        self.assertEqual(request[4:956], self.der)
        self.assertEqual(request[956:1212], self.fixture['issuer_modulus'].to_bytes(256, 'big'))
        self.assertEqual(request[1212:1244], ACTION_BE)
        certificate = x509.load_der_x509_certificate(self.der)
        parsed = admit_certificate(self.der, self.fixture['issuer_modulus'])
        self.assertEqual(certificate.public_key().public_numbers().n, parsed['holder_modulus'])
        certificate.public_key().verify(request[1244:1500], ACTION_BE,
                                        padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(int.from_bytes(request[1500:1502], 'big'), self.membership['slot'])
        expected_tail = (self.membership['active_siblings']
                         + [self.membership['active_root'], self.membership['issuer_hash'],
                            self.membership['policy_hash']])
        self.assertEqual(request[1502:], b''.join(value.to_bytes(32, 'little')
                                                 for value in expected_tail))
        fields = self.candidate_fields(request)
        self.assertEqual(fields[4], int.from_bytes(ACTION_BE, 'big'))
        self.assertEqual(fields[7], self.membership['slot'])
        self.assertEqual(fields[-20:-10], self.membership['active_siblings'])
        self.assertEqual(fields[-10:], [(self.membership['slot'] >> level) & 1
                                       for level in range(10)])

    def test_altered_action_rejects_the_retained_holder_signature(self):
        request = self.request()
        changed_action = (int.from_bytes(ACTION_BE, 'big') + 1).to_bytes(32, 'big')
        changed = request[:1212] + changed_action + request[1244:]
        with self.assertRaises(self.worker.InputFailure):
            self.worker.build(changed)

    def test_unrelated_root_refresh_keeps_exact_action_and_signature(self):
        active = self.request()
        unrelated = self.request(root_kind='unrelated')
        self.assertEqual(active[:1502], unrelated[:1502])
        self.assertNotEqual(active[1822:1854], unrelated[1822:1854])
        expected_tail = (self.membership['unrelated_siblings']
                         + [self.membership['unrelated_root'], self.membership['issuer_hash'],
                            self.membership['policy_hash']])
        self.assertEqual(unrelated[1502:], b''.join(value.to_bytes(32, 'little')
                                                   for value in expected_tail))
        self.assertEqual(self.candidate_fields(active)[4],
                         self.candidate_fields(unrelated)[4])

    def test_wrong_holder_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            wrong_key = directory / 'wrong.pem'
            wrong_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                    serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
            wrong_key.chmod(0o600)
            with self.assertRaises(ValueError):
                self.request(holder_key_pem=wrong_key)

    def test_mismatched_root_path_and_revoked_membership_are_rejected(self):
        mutations = []
        changed_root = copy.deepcopy(self.membership)
        changed_root['active_root'] = (changed_root['active_root'] + 1) % FR
        mutations.append(changed_root)
        changed_path = copy.deepcopy(self.membership)
        changed_path['active_siblings'][0] = (changed_path['active_siblings'][0] + 1) % FR
        mutations.append(changed_path)
        revoked = copy.deepcopy(self.membership)
        revoked['active_root'] = revoked['own_revoked_root']
        revoked['active_siblings'] = revoked['own_revoked_siblings']
        mutations.append(revoked)
        for index, membership in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                self.request(membership=membership)

    def test_action_selector_slot_and_field_bounds_are_fail_closed(self):
        for action in (b'', ACTION_BE[:-1], ACTION_BE + b'\x00', bytearray(ACTION_BE),
                       FR.to_bytes(32, 'big')):
            with self.subTest(case='action', width=len(action)), self.assertRaises(ValueError):
                self.request(action_be=action)
        for selector in ('', 'own_revoked', 'ACTIVE', None):
            with self.subTest(case='selector', selector=selector), self.assertRaises(ValueError):
                self.request(root_kind=selector)
        for slot in (-1, 1024, True, '1'):
            membership = copy.deepcopy(self.membership)
            membership['slot'] = slot
            with self.subTest(case='slot', slot=slot), self.assertRaises(ValueError):
                self.request(membership=membership)
        for name in ('active_root', 'issuer_hash', 'policy_hash'):
            membership = copy.deepcopy(self.membership)
            membership[name] = FR
            with self.subTest(case='field', name=name), self.assertRaises(ValueError):
                self.request(membership=membership)

    def test_bridge_emits_no_private_material_or_diagnostics(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            request = self.request()
            with self.assertRaises(ValueError):
                self.request(action_be=FR.to_bytes(32, 'big'))
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')
        pem = self.fixture['holder_key_pem'].read_bytes()
        self.assertNotIn(pem, request)
        self.assertNotIn(b'PRIVATE KEY', request)
        self.assertNotIn(str(self.fixture['holder_key_pem']).encode(), request)


if __name__ == '__main__':
    unittest.main()
