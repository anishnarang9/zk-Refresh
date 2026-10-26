"""Previously unseen synthetic DER imports; no circuit/witness/proof execution."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import sys
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.name import _ASN1Type

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('v3_admission_worker', ROOT / 'crates/dynark-native-client/workers/v3_admission_worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def certificate(issuer, holder, variant, organization=None, group=None):
    p, _ = worker.sources()
    issuer_length, holder_length = (24, 40) if variant & 4 else (40, 24)
    kind = _ASN1Type.PrintableString if variant & 1 else _ASN1Type.UTF8String
    name = lambda text: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text, _type=kind)])
    builder = (x509.CertificateBuilder().issuer_name(name(('Issuer%d' % variant).ljust(issuer_length, 'I')))
        .subject_name(name(('Holder%d' % variant).ljust(holder_length, 'H'))).public_key(holder.public_key())
        .serial_number((1 << 120) + 17 + variant)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2028, 1, 1, tzinfo=datetime.timezone.utc)))
    aki = hashlib.sha256(issuer.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).digest()[:20]
    organization = bytes([variant + 1]) * 16 if organization is None else organization
    group = bytes([variant + 2]) * 32 if group is None else group
    extensions = [(x509.AuthorityKeyIdentifier(aki, None, None), False),
        (x509.KeyUsage(True, False, False, False, False, False, False, None, None), True),
        (x509.BasicConstraints(False, None), True),
        (x509.ExtendedKeyUsage([x509.ObjectIdentifier(p.TEST_OIDS['purpose'])]), True),
        (x509.UnrecognizedExtension(x509.ObjectIdentifier(p.TEST_OIDS['organization']), b'\x04\x10' + organization), True),
        (x509.UnrecognizedExtension(x509.ObjectIdentifier(p.TEST_OIDS['group']), b'\x04\x20' + group), True)]
    for value, critical in reversed(extensions) if variant & 2 else extensions:
        builder = builder.add_extension(value, critical)
    return builder.sign(issuer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def openssl_certificate(issuer, holder):
    openssl = shutil.which('openssl')
    if not openssl:
        raise RuntimeError('independent OpenSSL encoder required')
    p, _ = worker.sources()
    with tempfile.TemporaryDirectory(prefix='native-v3-openssl-') as temporary:
        directory = Path(temporary).resolve()
        directory.chmod(0o700)
        for name, key in [('issuer', issuer), ('holder', holder)]:
            path = directory / (name + '.pem')
            path.touch(mode=0o600)
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        config = ('[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=' + 'O' * 24
            + '\n[ext]\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=keyid\n'
            + 'keyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n'
            + 'extendedKeyUsage=critical,' + p.TEST_OIDS['purpose'] + '\n'
            + p.TEST_OIDS['organization'] + '=critical,DER:04:10:' + (b'X' * 16).hex(':') + '\n'
            + p.TEST_OIDS['group'] + '=critical,DER:04:20:' + (b'Y' * 32).hex(':') + '\n')
        (directory / 'openssl.cnf').write_text(config)
        def run(*args):
            subprocess.run([openssl, *args], cwd=directory, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        run('req', '-new', '-x509', '-key', 'issuer.pem', '-subj', '/CN=' + 'C' * 40,
            '-days', '365', '-out', 'issuer.crt', '-sha256', '-addext', 'subjectKeyIdentifier=hash')
        run('req', '-new', '-key', 'holder.pem', '-config', 'openssl.cnf', '-out', 'holder.csr')
        run('x509', '-req', '-in', 'holder.csr', '-CA', 'issuer.crt', '-CAkey', 'issuer.pem',
            '-set_serial', '0x11223344556677889900112233445566', '-days', '365', '-sha256',
            '-extfile', 'openssl.cnf', '-extensions', 'ext', '-outform', 'DER', '-out', 'holder.der')
        return (directory / 'holder.der').read_bytes()


class V3AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuers = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]
        cls.holders = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]

    def fixture(self, variant=0, independent=False):
        issuer, holder = self.issuers[variant % 2], self.holders[variant % 3]
        der = openssl_certificate(issuer, holder) if independent else certificate(issuer, holder, variant)
        modulus = issuer.public_key().public_numbers().n.to_bytes(256, 'big')
        return der, modulus, worker.admit(der, modulus)

    def test_all_eight_layouts_two_issuers_varied_holders_share_one_profile(self):
        for variant in range(8):
            der, _, admitted = self.fixture(variant)
            parsed = admitted['parsed']
            self.assertEqual(len(der), 952)
            self.assertEqual(parsed['variant'], variant)
            self.assertEqual(parsed['tbs'], x509.load_der_x509_certificate(der).tbs_certificate_bytes)
            encoded = worker.admission_bytes(admitted)
            self.assertEqual(len(encoded), 459)
            self.assertEqual(encoded[:5], b'V3A1' + bytes([variant]))
            self.assertEqual(encoded[5:37], hashlib.sha256(parsed['tbs']).digest())
            for field, length in [('serial', 16), ('not_before', 13), ('not_after', 13),
                    ('aki', 20), ('organization', 16), ('group', 32), ('modulus', 256),
                    ('issuer_cn', 24 if variant & 4 else 40), ('subject_cn', 40 if variant & 4 else 24)]:
                extracted = parsed['tbs'][parsed['offsets'][field]:parsed['offsets'][field]+length]
                expected = parsed[field] if field in ('serial', 'aki', 'organization', 'group', 'issuer_cn', 'subject_cn') else None
                if expected is not None:
                    self.assertEqual(extracted, expected)
                if field == 'modulus':
                    self.assertEqual(int.from_bytes(extracted, 'big'), parsed['holder_modulus'])
                if field in ('not_before', 'not_after'):
                    p, _ = worker.sources()
                    self.assertEqual(p.utc_epoch(extracted), parsed[field])

    def test_private_admission_protocol_has_no_logs_or_secret_retention(self):
        der, modulus, _ = self.fixture()
        with tempfile.TemporaryDirectory(prefix='native-v3-admission-') as temporary:
            directory = Path(temporary).resolve()
            directory.chmod(0o700)
            request = directory / 'request.bin'
            request.touch(mode=0o600)
            request.write_bytes(der + modulus)
            command = [sys.executable, str(ROOT / 'crates/dynark-native-client/workers/v3_admission_worker.py'), 'admit', str(directory)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))
            output = directory / 'output.bin'
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(output.read_bytes()), 459)
            output.unlink()
            request.write_bytes(b'not a certificate')
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (10, b'', b''))
            self.assertFalse(output.exists())

    def test_independent_openssl_import_has_no_certificate_specific_offsets(self):
        der, _, admitted = self.fixture(independent=True)
        self.assertEqual(len(der), 952)
        self.assertIn(admitted['parsed']['variant'], range(8))
        self.assertEqual(admitted['parsed']['tbs'], x509.load_der_x509_certificate(der).tbs_certificate_bytes)
        self.assertEqual(len(worker.admission_bytes(admitted)), 459)

    def test_signed_malformed_calendar_name_unknown_and_duplicate_extension_fail(self):
        _, modulus, admitted = self.fixture()
        profile, _ = worker.sources()
        original = admitted['parsed']
        def replaced(tbs):
            signature = self.issuers[0].sign(bytes(tbs), padding.PKCS1v15(), hashes.SHA256())
            return profile.tlv(0x30, bytes(tbs) + profile.SHA256_RSA_ALGORITHM + profile.tlv(3, b'\x00' + signature))
        changes = [('not_before', b'260230000000Z'), ('issuer_cn', b'@')]
        for field, replacement in changes:
            tbs = bytearray(original['tbs']);position = original['offsets'][field]
            tbs[position:position+len(replacement)] = replacement
            with self.assertRaises(worker.AdmissionFailure) as failure:
                worker.admit(replaced(tbs), modulus)
            self.assertEqual(failure.exception.code, 10)
        org_oid = profile.oid_der(profile.TEST_OIDS['organization'])
        group_oid = profile.oid_der(profile.TEST_OIDS['group'])
        tbs = bytearray(original['tbs']);position = tbs.index(group_oid)
        self.assertEqual(len(group_oid), len(org_oid))
        tbs[position:position+len(group_oid)] = org_oid
        with self.assertRaises(worker.AdmissionFailure) as failure:
            worker.admit(replaced(tbs), modulus)
        self.assertEqual(failure.exception.code, 10)
        tbs = bytearray(original['tbs']);position = tbs.index(org_oid);tbs[position+len(org_oid)-1] ^= 1
        with self.assertRaises(worker.AdmissionFailure) as failure:
            worker.admit(replaced(tbs), modulus)
        self.assertEqual(failure.exception.code, 10)

    def test_signed_policy_and_aki_variations_are_imported_but_never_enrolled(self):
        _, modulus, admitted = self.fixture()
        profile, _ = worker.sources()
        for field in ['organization', 'group', 'aki']:
            tbs = bytearray(admitted['parsed']['tbs']);tbs[admitted['parsed']['offsets'][field]] ^= 1
            signature = self.issuers[0].sign(bytes(tbs), padding.PKCS1v15(), hashes.SHA256())
            der = profile.tlv(0x30, bytes(tbs) + profile.SHA256_RSA_ALGORITHM + profile.tlv(3, b'\x00' + signature))
            changed = worker.admit(der, modulus)
            if field == 'aki':
                self.assertNotEqual(changed['issuer_hash'], admitted['issuer_hash'])
            else:
                self.assertNotEqual(changed['policy_hash'], admitted['policy_hash'])
            self.assertNotIn('enrolled', changed)

    def test_changed_or_symlinked_poseidon_constants_fail_explicit_closure_pin(self):
        der, modulus, _ = self.fixture()
        with tempfile.TemporaryDirectory(prefix='native-v3-constants-') as temporary:
            directory = Path(temporary).resolve()
            constants = directory / 'constants.circom'
            constants.write_bytes(b'changed constants')
            with mock.patch.object(worker, 'POSEIDON_CONSTANTS_PATH', constants):
                with self.assertRaises(worker.AdmissionFailure) as failure:
                    worker.admit(der, modulus)
                self.assertEqual(failure.exception.code, 20)
            constants.unlink()
            constants.symlink_to(ROOT / 'node_modules/circomlib/circuits/poseidon_constants.circom')
            with mock.patch.object(worker, 'POSEIDON_CONSTANTS_PATH', constants):
                with self.assertRaises(worker.AdmissionFailure) as failure:
                    worker.admit(der, modulus)
                self.assertEqual(failure.exception.code, 20)

    def test_clear_truncated_noncanonical_and_issuer_signature_failures(self):
        der, modulus, _ = self.fixture()
        for bad in [der[:-1], der + b'\x00', bytes([0x31]) + der[1:], der[:1] + b'\x80' + der[2:]]:
            with self.assertRaises(worker.AdmissionFailure) as failure:
                worker.admit(bad, modulus)
            self.assertEqual(failure.exception.code, 10)
        wrong = self.issuers[1].public_key().public_numbers().n.to_bytes(256, 'big')
        with self.assertRaises(worker.AdmissionFailure) as failure:
            worker.admit(der, wrong)
        self.assertEqual(failure.exception.code, 11)


if __name__ == '__main__':
    unittest.main()
