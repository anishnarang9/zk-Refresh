"""Local TRAINING fixture join. No live account or proof authority is established."""
import contextlib
import copy
import hashlib
import io
import re
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tools.part5 import prepare_v3_request_fixture as bridge
from tools.part5.credential_profile import admit_certificate, public_bindings

ROOT = Path(__file__).resolve().parents[3]
EXPORTER = ROOT / 'program/target/debug/examples/export_v3_request_fixture'


def development_config(root, policy):
    # Explicit synthetic Config, encoded in the application's documented format.
    # Rust Config::decode remains the pin/canonical-codec authority.
    source = (ROOT / 'program/src/generated_vk_v3.rs').read_text()
    pin = lambda name: bytes.fromhex(re.search(
        rf'pub const {name}: \[u8; 32\] =\s*hex\(b"([0-9a-f]+)"\)', source)[1])
    return (b'DYNCONF3' + bytes([11]) * 32 + bytes([12]) * 32
            + bytes([13]) * 32 + bytes([14]) * 32 + policy.to_bytes(32, 'big')
            + (1).to_bytes(4, 'big')
            + b''.join(pin(name) for name in ('CIRCUIT_ID', 'PACKAGE_ID',
                'SEMANTIC_SCHEMA_ID', 'PROFILE_ID', 'ORDINARY_VK_DIGEST'))
            + root.to_bytes(32, 'big') + (1).to_bytes(8, 'big')
            + (1).to_bytes(8, 'big') + b'\x01')


class RustRequestJoinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_plan = getattr(bridge, 'build_v3p1', None)
        if not callable(cls.build_plan):
            raise AssertionError('missing public V3P1 plan builder')
        private = ROOT / 'artifacts/private-v3-request-join-tests'
        private.mkdir(mode=0o700, parents=True, exist_ok=True)
        private.chmod(0o700)
        cls.temporary = tempfile.TemporaryDirectory(dir=private)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.directory.chmod(0o700)
        cls.fixture = bridge.prepare(cls.directory)
        cls.der = cls.fixture['credential_der'].read_bytes()
        cls.modulus = cls.fixture['issuer_modulus']
        cls.membership = bridge.build_membership(cls.der, cls.modulus)
        cls.parsed = admit_certificate(cls.der, cls.modulus)
        cls.config = development_config(cls.membership['active_root'], cls.membership['policy_hash'])
        cls.plan = cls.make_plan()
        cls.finalized = bridge.finalize_v3p1(cls.plan, EXPORTER)

    @classmethod
    def make_plan(cls, **changes):
        arguments = dict(config_bytes=cls.config, program_id=bytes([20]) * 32,
                         creator=bytes([21]) * 32, nonce=bytes([22]) * 32,
                         recipient=bytes([23]) * 32, request_type=1,
                         deadline=1792109040, now=1792108800,
                         payload=bytes(index % 251 for index in range(777)))
        arguments.update(changes)
        return bridge.build_v3p1(cls.der, cls.modulus, cls.membership, **arguments)

    def bound(self, **changes):
        arguments = dict(der=self.der, issuer_modulus=self.modulus,
                         holder_key_pem=self.fixture['holder_key_pem'],
                         membership=self.membership, plan_wire=self.plan,
                         finalized=self.finalized, exporter=EXPORTER)
        arguments.update(changes)
        return bridge.build_request_bound_v3q1(**arguments)

    def test_new_training_credential_joins_exact_rust_action_and_six_publics(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            q1 = self.bound()
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ('', ''))
        self.assertEqual(len(q1), 1918)
        self.assertEqual(q1[:4], b'V3Q1')
        f1, f2 = self.finalized['v3f1'], self.finalized['v3f2']
        self.assertEqual(len(f1), 2874)
        self.assertEqual(f2[164:196], f1[180:212])
        self.assertEqual(q1[1212:1244], f2[164:196])
        x509.load_der_x509_certificate(self.der).public_key().verify(
            q1[1244:1500], f2[164:196], padding.PKCS1v15(), hashes.SHA256())
        issuer, policy = public_bindings(self.parsed, self.modulus)
        expected = [self.membership['active_root'], issuer, self.parsed['not_before'],
                    self.parsed['not_after'], int.from_bytes(f2[164:196], 'big'), policy]
        self.assertEqual([int.from_bytes(f1[start:start + 32], 'big')
                          for start in range(52, 244, 32)], expected)
        self.assertEqual(self.finalized['exporter_sha256'], hashlib.sha256(EXPORTER.read_bytes()).hexdigest())
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        for key in ('credential_der', 'holder_key_pem'):
            self.assertEqual(stat.S_IMODE(self.fixture[key].stat().st_mode), 0o600)
        self.assertNotIn(b'PRIVATE KEY', q1)

    def test_changed_request_rejects_stale_finalized_action(self):
        for change in ({'nonce': bytes([42]) * 32}, {'payload': b'changed payload'}):
            with self.subTest(change=next(iter(change))), self.assertRaises(ValueError):
                self.bound(plan_wire=self.make_plan(**change))
        changed_config = bytearray(self.config)
        changed_config[167] ^= 1
        with self.assertRaises(ValueError):
            self.make_plan(config_bytes=bytes(changed_config))
        changed = dict(self.finalized)
        f2 = bytearray(changed['v3f2'])
        f2[164] ^= 1
        changed['v3f2'] = bytes(f2)
        with self.assertRaises(ValueError):
            self.bound(finalized=changed)

    def test_issuer_policy_root_public_and_signer_substitutions_rejected(self):
        for name in ('issuer_hash', 'policy_hash', 'active_root'):
            changed = copy.deepcopy(self.membership)
            changed[name] += 1
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.bound(membership=changed)
        for index in range(6):
            changed = dict(self.finalized)
            f1 = bytearray(changed['v3f1'])
            f1[52 + index * 32 + 31] ^= 1
            changed['v3f1'] = bytes(f1)
            with self.subTest(public=index), self.assertRaises(ValueError):
                self.bound(finalized=changed)
        wrong_key = self.directory / 'wrong.pem'
        wrong_key.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048)
                              .private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        wrong_key.chmod(0o600)
        with self.assertRaises(ValueError):
            self.bound(holder_key_pem=wrong_key)

    def test_bad_exporter_output_framing_fails_closed(self):
        f1, f2 = self.finalized['v3f1'], self.finalized['v3f2']
        for output in (b'', b'BAD!' + f1[4:], f1[:-1], f1 + b'\x00'):
            with self.subTest(frame='f1', length=len(output)), patch.object(
                    bridge, '_run_public_exporter', return_value=output), self.assertRaises(ValueError):
                bridge.finalize_v3p1(self.plan, EXPORTER)
        for output in (b'', b'BAD!' + f2[4:], f2[:-1], f2 + b'\x00'):
            with self.subTest(frame='f2', length=len(output)), patch.object(
                    bridge, '_run_public_exporter', side_effect=[f1, output]), self.assertRaises(ValueError):
                bridge.finalize_v3p1(self.plan, EXPORTER)

    def test_valid_but_different_request_output_is_rejected(self):
        for change in ({'nonce': bytes([52]) * 32}, {'payload': b'another payload'},
                       {'recipient': bytes([53]) * 32}, {'request_type': 2},
                       {'deadline': 1792109039}, {'creator': bytes([54]) * 32}):
            with self.subTest(change=next(iter(change))), patch.object(
                    bridge, '_run_public_exporter', side_effect=[self.finalized['v3f1'],
                                                                self.finalized['v3f2']]), self.assertRaises(ValueError):
                bridge.finalize_v3p1(self.make_plan(**change), EXPORTER)

    def test_mocked_account_order_flags_and_owners_are_rejected(self):
        f1, f2 = self.finalized['v3f1'], self.finalized['v3f2']
        request_start = 625
        mutations = []
        swapped = bytearray(f1)
        first, second = request_start + 185, request_start + 250
        swapped[first:first + 65], swapped[second:second + 65] = (
            swapped[second:second + 65], swapped[first:first + 65])
        mutations.append(('swapped request/queue metas', bytes(swapped)))
        for name, offset in [('request flags', 217), ('queue flags', 282),
                             ('request owner', 218), ('queue owner', 283)]:
            changed = bytearray(f1)
            changed[request_start + offset] ^= 1
            mutations.append((name, bytes(changed)))
        for name, changed in mutations:
            with self.subTest(mutation=name), patch.object(
                    bridge, '_run_public_exporter', side_effect=[changed, f2]) as exporter:
                with self.assertRaisesRegex(ValueError, '^invalid finalized local-development fixture$'):
                    bridge.finalize_v3p1(self.plan, EXPORTER)
                # Mock a successful F1->F2 exporter so the Python account checks
                # must reject these substitutions independently.
                self.assertEqual(exporter.call_count, 2)
                self.assertEqual(exporter.call_args.args[2], changed)


if __name__ == '__main__':
    unittest.main()
