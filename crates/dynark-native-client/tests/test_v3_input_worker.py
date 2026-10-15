"""Tests-first real synthetic signatures and independent DER; no files or proofs.

All keys, DER, signatures and candidate fields stay in process memory. Fixture
certificates use cryptography.x509, never the profile constructor or byte patches.
Reference repository modules are compiled from exact pinned bytes without pycache.
cryptography is a trusted test-fixture dependency, never a worker admission claim.
"""
import datetime
import hashlib
from pathlib import Path
import types
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier

ROOT = Path(__file__).resolve().parents[3]
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FIELDS = (
    ('root', 1), ('issuerHash', 1), ('notBefore', 1), ('notAfter', 1),
    ('actionHash', 1), ('policyHash', 1), ('layout', 1), ('slot', 1),
    ('tbs', 672), ('issuerModulus', 17), ('issuerSignature', 17),
    ('holderSignature', 17), ('siblings', 10), ('pathIndices', 10),
)
OFFSET_FIELDS = ('serial', 'not_before', 'not_after', 'issuer_cn', 'subject_cn',
                 'modulus', 'aki', 'organization', 'group')


def module(relative, expected=None):
    path = ROOT / relative
    source = path.read_bytes()
    if len(source) > 128 * 1024 or (
            expected is not None and hashlib.sha256(source).hexdigest() != expected):
        raise RuntimeError('test reference source identity')
    result = types.ModuleType(path.stem)
    result.__file__ = str(path)
    exec(compile(source, str(path), 'exec'), result.__dict__)
    return result


worker = module('crates/dynark-native-client/workers/v3_input_worker.py')
profile = module('tools/part5/credential_profile.py',
                 'c960f3d2bb8e72c28c0d6a9164b6eaa17ec2ff4ef36a7e0af23811737470f2e6')
poseidon = module('tools/part5/poseidon.py',
                  '82d6a93d2af03f17fe340eb7a2d0edbd47dd774ef205d7332b956c2e8c743d68')
CONSTANTS = ROOT / 'node_modules/circomlib/circuits/poseidon_constants.circom'
constants_bytes = CONSTANTS.read_bytes()
if len(constants_bytes) > 3 * 1024 * 1024 or hashlib.sha256(constants_bytes).hexdigest() != (
        '94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee'):
    raise RuntimeError('test reference Poseidon constants identity')
del constants_bytes


def certificate(issuer, holder, variant):
    issuer_length, subject_length = (24, 40) if variant & 4 else (40, 24)
    kind = _ASN1Type.PrintableString if variant & 1 else _ASN1Type.UTF8String
    def name(text):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text, _type=kind)])
    result = (x509.CertificateBuilder()
              .issuer_name(name(('Issuer %d' % variant).ljust(issuer_length, 'I')))
              .subject_name(name(('Holder %d' % variant).ljust(subject_length, 'H')))
              .public_key(holder.public_key()).serial_number((1 << 120) + 101 + variant)
              .not_valid_before(datetime.datetime(2026, 1, variant + 1,
                                                 tzinfo=datetime.timezone.utc))
              .not_valid_after(datetime.datetime(2028, 2, variant + 1,
                                                tzinfo=datetime.timezone.utc)))
    aki = hashlib.sha256(issuer.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()[:20]
    extensions = [
        (x509.AuthorityKeyIdentifier(aki, None, None), False),
        (x509.KeyUsage(True, False, False, False, False, False, False, None, None), True),
        (x509.BasicConstraints(False, None), True),
        (x509.ExtendedKeyUsage([ObjectIdentifier(profile.TEST_OIDS['purpose'])]), True),
        (x509.UnrecognizedExtension(ObjectIdentifier(profile.TEST_OIDS['organization']),
                                   b'\x04\x10' + bytes([variant + 31]) * 16), True),
        (x509.UnrecognizedExtension(ObjectIdentifier(profile.TEST_OIDS['group']),
                                   b'\x04\x20' + bytes([variant + 63]) * 32), True),
    ]
    for extension, critical in reversed(extensions) if variant & 2 else extensions:
        result = result.add_extension(extension, critical)
    return result.sign(issuer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def membership_root(parsed, slot, siblings, active=1):
    digest = hashlib.sha256(parsed['tbs']).digest()
    node = poseidon.poseidon([2026101504, int.from_bytes(digest[:16], 'big'),
                              int.from_bytes(digest[16:], 'big'), slot, active], CONSTANTS)
    for level, sibling in enumerate(siblings):
        pair = [sibling, node] if (slot >> level) & 1 else [node, sibling]
        node = poseidon.poseidon(pair, CONSTANTS)
    return node


def field(value):
    return value.to_bytes(32, 'little')


def patch(request, start, end, replacement):
    return request[:start] + replacement + request[end:]


class V3InputWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuers = [rsa.generate_private_key(public_exponent=65537, key_size=2048)
                       for _ in range(2)]
        cls.holders = [rsa.generate_private_key(public_exponent=65537, key_size=2048)
                       for _ in range(3)]

    def fixture(self, variant=0):
        issuer, holder = self.issuers[variant % 2], self.holders[variant % 3]
        der = certificate(issuer, holder, variant)
        self.assertEqual(len(der), 952, 'independent supported DER width')
        modulus = issuer.public_key().public_numbers().n
        parsed = profile.admit_certificate(der, modulus)
        self.assertTrue(parsed['tbs'] == x509.load_der_x509_certificate(der).tbs_certificate_bytes,
                        'independent TBS encoding agrees')
        action = (987654321 + variant).to_bytes(32, 'big')
        signature = holder.sign(action, padding.PKCS1v15(), hashes.SHA256())
        material = profile.credential_witness_material(parsed, modulus, action, signature)
        limbs = profile.rsa_limbs(modulus)
        key_hash = poseidon.poseidon([poseidon.poseidon(limbs[:8], CONSTANTS),
                                      poseidon.poseidon(limbs[8:], CONSTANTS)], CONSTANTS)
        issuer_hash = poseidon.poseidon([2026101505, key_hash,
                                         int.from_bytes(parsed['aki'], 'big')], CONSTANTS)
        policy_hash = poseidon.poseidon([2026101503, int.from_bytes(parsed['organization'], 'big'),
                                         int.from_bytes(parsed['group'][:16], 'big'),
                                         int.from_bytes(parsed['group'][16:], 'big')], CONSTANTS)
        slot = 513 + variant
        siblings = [1009 + level * 17 + variant for level in range(10)]
        root = membership_root(parsed, slot, siblings)
        material.update(root=root, issuerHash=issuer_hash, policyHash=policy_hash,
                        slot=slot, siblings=siblings,
                        pathIndices=[(slot >> level) & 1 for level in range(10)])
        request = (b'V3Q1' + der + modulus.to_bytes(256, 'big') + action + signature
                   + slot.to_bytes(2, 'big') + b''.join(field(value) for value in siblings)
                   + field(root) + field(issuer_hash) + field(policy_hash))
        summary = (b'V3A1' + bytes([variant]) + hashlib.sha256(parsed['tbs']).digest()
                   + parsed['holder_modulus'].to_bytes(256, 'big')
                   + field(issuer_hash) + field(policy_hash)
                   + parsed['not_before'].to_bytes(8, 'big')
                   + parsed['not_after'].to_bytes(8, 'big')
                   + parsed['aki'] + parsed['organization'] + parsed['group']
                   + b''.join(parsed['offsets'][name].to_bytes(2, 'big')
                              for name in OFFSET_FIELDS))
        flat = []
        for name, count in FIELDS:
            values = [material[name]] if count == 1 else material[name]
            self.assertEqual(len(values), count, 'reference array dimensions')
            flat.extend(values)
        self.assertEqual(len(request), 1918)
        self.assertEqual(len(summary), 459)
        self.assertEqual(len(flat), 751)
        expected = b'V3I1' + summary + b''.join(field(value) for value in flat)
        self.assertEqual(len(expected), 24495)
        return request, expected, parsed, material

    def test_independently_signed_credential_binds_all_751_candidate_fields(self):
        request, expected, _, _ = self.fixture()
        result = worker.build(request)
        self.assertTrue(type(result) is bytes and result == expected,
                        'exact independently derived V3I1 response required')

    def test_all_eight_layouts_varied_issuers_holders_and_paths_share_one_schema(self):
        for variant in range(8):
            with self.subTest(layout=variant):
                request, expected, _, _ = self.fixture(variant)
                self.assertTrue(worker.build(request) == expected,
                                'exact response for each admitted layout')

    def rejected(self, cases):
        for name, request in cases:
            with self.subTest(mutation=name):
                with self.assertRaises(worker.InputFailure):
                    worker.build(request)

    def test_exact_protocol_width_magic_and_canonical_fields_are_required(self):
        request, _, _, _ = self.fixture()
        self.rejected([
            ('short', request[:-1]), ('trailing', request + b'\x00'),
            ('magic', b'V2Q1' + request[4:]), ('mutable', bytearray(request)),
            ('action_alias', patch(request, 1212, 1244, FR.to_bytes(32, 'big'))),
            ('root_alias', patch(request, 1822, 1854, field(FR))),
            ('issuer_alias', patch(request, 1854, 1886, field(FR))),
            ('policy_alias', patch(request, 1886, 1918, field(FR))),
            ('sibling_alias', patch(request, 1502, 1534, field(FR))),
            ('slot_bound', patch(request, 1500, 1502, (1024).to_bytes(2, 'big'))),
        ])

    def test_der_issuer_and_signed_policy_cannot_be_substituted(self):
        request, _, _, material = self.fixture()
        changed_der = bytearray(request[4:956])
        changed_der[100] ^= 1
        other_modulus = self.issuers[1].public_key().public_numbers().n.to_bytes(256, 'big')
        substituted = certificate(self.issuers[0], self.holders[1], 0)
        self.rejected([
            ('changed_der', patch(request, 4, 956, bytes(changed_der))),
            ('other_eligible_der', patch(request, 4, 956, substituted)),
            ('other_issuer', patch(request, 956, 1212, other_modulus)),
            ('zero_issuer', patch(request, 956, 1212, bytes(256))),
            ('wrong_issuer_hash', patch(request, 1854, 1886, field((material['issuerHash'] + 1) % FR))),
            ('wrong_policy_hash', patch(request, 1886, 1918, field((material['policyHash'] + 1) % FR))),
        ])

    def test_holder_signature_requires_exact_action_and_imported_holder(self):
        request, _, _, _ = self.fixture()
        action = request[1212:1244]
        changed = bytearray(request[1244:1500])
        changed[0] ^= 1
        wrong_holder = self.holders[1].sign(action, padding.PKCS1v15(), hashes.SHA256())
        double_hash = self.holders[0].sign(hashlib.sha256(action).digest(),
                                            padding.PKCS1v15(), hashes.SHA256())
        pss = self.holders[0].sign(action, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=32), hashes.SHA256())
        holder_modulus = self.holders[0].public_key().public_numbers().n.to_bytes(256, 'big')
        self.rejected([
            ('changed_action', patch(request, 1212, 1244,
                                     (int.from_bytes(action, 'big') + 1).to_bytes(32, 'big'))),
            ('changed_signature', patch(request, 1244, 1500, bytes(changed))),
            ('other_holder', patch(request, 1244, 1500, wrong_holder)),
            ('double_hash', patch(request, 1244, 1500, double_hash)),
            ('pss', patch(request, 1244, 1500, pss)),
            ('signature_alias', patch(request, 1244, 1500, holder_modulus)),
        ])

    def test_active_leaf_root_slot_and_every_sibling_are_bound(self):
        request, _, parsed, material = self.fixture()
        revoked_root = membership_root(parsed, material['slot'], material['siblings'], active=0)
        cases = [
            ('wrong_root', patch(request, 1822, 1854, field((material['root'] + 1) % FR))),
            ('revoked_leaf', patch(request, 1822, 1854, field(revoked_root))),
            ('changed_slot', patch(request, 1500, 1502,
                                   (material['slot'] ^ 1).to_bytes(2, 'big'))),
        ]
        for level, sibling in enumerate(material['siblings']):
            start = 1502 + level * 32
            cases.append(('sibling_%d' % level,
                          patch(request, start, start + 32, field((sibling + 1) % FR))))
        self.rejected(cases)

    def test_coherent_unrelated_path_refresh_produces_new_exact_fields(self):
        request, expected, parsed, material = self.fixture()
        siblings = list(material['siblings'])
        siblings[0] += 1
        root = membership_root(parsed, material['slot'], siblings)
        refreshed = patch(request, 1502, 1534, field(siblings[0]))
        refreshed = patch(refreshed, 1822, 1854, field(root))
        # Scalar order is eight singletons, TBS672, three RSA17 arrays, then siblings.
        sibling_offset = 4 + 459 + 32 * (8 + 672 + 3 * 17)
        expected = patch(expected, 4 + 459, 4 + 459 + 32, field(root))
        expected = patch(expected, sibling_offset, sibling_offset + 32, field(siblings[0]))
        self.assertTrue(worker.build(refreshed) == expected,
                        'coherent unrelated refresh changes root and sibling only')


if __name__ == '__main__':
    unittest.main()
