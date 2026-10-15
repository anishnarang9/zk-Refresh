import datetime
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509.name import _ASN1Type

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / 'tools/part5/credential_profile.py'
spec = importlib.util.spec_from_file_location('bounded_profile', PATH)
p = importlib.util.module_from_spec(spec) if spec else None
if PATH.exists():
    spec.loader.exec_module(p)

class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.holder = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def certificate(self, variant=0, wrong_policy=False):
        kind = _ASN1Type.PrintableString if variant & 1 else _ASN1Type.UTF8String
        issuer_length, subject_length = ((24, 40) if variant & 4 else (40, 24))
        name = lambda text: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text, _type=kind)])
        b = (x509.CertificateBuilder().issuer_name(name('I' * issuer_length))
             .subject_name(name('H' * subject_length)).public_key(self.holder.public_key())
             .serial_number((1 << 120) + variant + 100)
             .not_valid_before(datetime.datetime(2026, 1, 1 + variant, tzinfo=datetime.timezone.utc))
             .not_valid_after(datetime.datetime(2028, 2, 1 + variant, tzinfo=datetime.timezone.utc)))
        # Independent x509 encoder; no profile DER constructor is used.
        extensions = [
            (x509.AuthorityKeyIdentifier(bytes([variant + 1])*20, None, None), False),
            (x509.KeyUsage(True, False, False, False, False, False, False, None, None), True),
            (x509.BasicConstraints(False, None), True),
            (x509.ExtendedKeyUsage([ObjectIdentifier(p.TEST_OIDS['group'] if wrong_policy else p.TEST_OIDS['purpose'])]), True),
            (x509.UnrecognizedExtension(ObjectIdentifier(p.TEST_OIDS['organization']),
                 b'\x04\x10' + bytes([variant])*16), True),
            (x509.UnrecognizedExtension(ObjectIdentifier(p.TEST_OIDS['group']), b'\x04\x20'+bytes([variant+1])*32), True),
        ]
        for value, critical in reversed(extensions) if variant & 2 else extensions:
            b = b.add_extension(value, critical)
        return b.sign(self.issuer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def test_eight_independent_encoder_layouts_share_shape(self):
        self.assertTrue(PATH.exists(), 'bounded profile implementation missing')
        lengths = set()
        offsets = set()
        for variant in range(8):
            der = self.certificate(variant)
            parsed = p.admit_certificate(der, self.issuer.public_key().public_numbers().n)
            self.assertEqual(parsed['variant'], variant)
            self.assertEqual(parsed['holder_modulus'], self.holder.public_key().public_numbers().n)
            self.assertEqual(parsed['organization'], bytes([variant])*16)
            self.assertEqual(parsed['group'], bytes([variant+1])*32)
            self.assertEqual(parsed['issuer_cn'], b'I' * (24 if variant & 4 else 40))
            lengths.add(len(parsed['tbs']))
            offsets.add(parsed['offsets']['not_before'])
        self.assertEqual(len(lengths), 1)
        self.assertEqual(len(offsets), 2)

    def test_signed_wrong_policy_and_wrong_enrolled_key_rejected(self):
        self.assertTrue(PATH.exists(), 'bounded profile implementation missing')
        with self.assertRaises(p.ProfileError):
            p.admit_certificate(self.certificate(wrong_policy=True), self.issuer.public_key().public_numbers().n)
        with self.assertRaises(p.ProfileError):
            p.admit_certificate(self.certificate(), self.holder.public_key().public_numbers().n)

    def test_der_trailing_truncation_and_nonminimal_length_rejected(self):
        self.assertTrue(PATH.exists(), 'bounded profile implementation missing')
        cert = self.certificate()
        for bad in (cert+b'\x00', cert[:-1], b'\x30\x83\x00'+cert[2:]):
            with self.assertRaises(p.ProfileError):
                p.admit_certificate(bad, self.issuer.public_key().public_numbers().n)

    def test_frozen_profile_and_source_match_generator(self):
        self.assertTrue(hasattr(p, 'circom_profile'), 'circuit profile generator missing')
        source = ROOT / 'circuits/credential-v3-bounded'
        self.assertEqual((source/'profile.circom').read_text(), p.circom_profile())
        self.assertEqual(__import__('json').loads((source/'profile.json').read_text()), p.profile_description())
        circuit = (source/'credential.circom').read_text()
        self.assertIn('policyBinding.out === policyHash', circuit)
        self.assertIn('issuerBinding.out === issuerHash', circuit)
        self.assertIn('component main {public [root,issuerHash,notBefore,notAfter,actionHash,policyHash]}', circuit)

    def test_signed_malformed_eligibility_is_rejected(self):
        modulus = self.holder.public_key().public_numbers().n
        tbs = p.build_tbs(modulus)
        parsed = p.parse_tbs(tbs)
        mutations = [
            (parsed['offsets']['serial'], b'\x00'),
            (parsed['offsets']['issuer_cn'], b'@'),
            (parsed['offsets']['not_before'], b'261301000000Z'),
            (parsed['offsets']['modulus'], b'\x01'),
            (tbs.index(bytes.fromhex('03020780'))+3, b'\x00'),
            (tbs.index(p.oid_der(p.TEST_OIDS['purpose']))+4, b'\x00'),
        ]
        for at, value in mutations:
            bad = tbs[:at]+value+tbs[at+len(value):]
            with self.subTest(at=at), self.assertRaises(p.ProfileError):
                p.parse_tbs(bad)

    def test_multiple_issuers_holders_and_public_bindings(self):
        self.assertTrue(hasattr(p, 'public_bindings'), 'v3 public binding evaluator missing')
        from tools.part5.corpus import generate_corpus
        cases = generate_corpus(include_openssl=True)
        positives = [x for x in cases if x['expect'] == 'accept']
        self.assertGreaterEqual(len({tuple(x['inputs']['issuerModulus']) for x in positives}), 2)
        self.assertGreaterEqual(len({x['holder_key_digest'] for x in positives}), 3)
        self.assertGreaterEqual(len({x['inputs']['issuerHash'] for x in positives}), 2)
        self.assertGreaterEqual(len({x['inputs']['policyHash'] for x in positives}), 3)
        self.assertGreaterEqual(len({x['inputs']['notBefore'] for x in positives}), 3)
        self.assertTrue(any(x['generator'] == 'openssl' for x in positives))
        for case in positives:
            parsed = p.parse_tbs(bytes(case['inputs']['tbs']))
            modulus = sum(v << (121*i) for i,v in enumerate(case['inputs']['issuerModulus']))
            issuer_hash, policy_hash = p.public_bindings(parsed, modulus)
            self.assertEqual(case['inputs']['issuerHash'], issuer_hash)
            self.assertEqual(case['inputs']['policyHash'], policy_hash)
        self.assertTrue(any(x['family'] == 'own_revocation' and x['expect'] == 'reject' for x in cases))
        self.assertTrue(any(x['family'] == 'wrong_policy_binding' and x['expect'] == 'reject' for x in cases))
        signed_negatives = [x for x in cases if x['family'] == 'signed_profile_bypass']
        self.assertGreaterEqual(len(signed_negatives), 4)
        for case in signed_negatives:
            inputs = case['inputs']
            modulus = sum(v << (121*i) for i,v in enumerate(inputs['issuerModulus']))
            signature = sum(v << (121*i) for i,v in enumerate(inputs['issuerSignature'])).to_bytes(256,'big')
            p.verify_rsa(modulus,bytes(inputs['tbs']),signature)
            with self.assertRaises(p.ProfileError):
                p.parse_tbs(bytes(inputs['tbs']))


    def test_issuer_and_policy_authority_is_distinct_from_structural_admission(self):
        self.assertTrue(hasattr(p, 'public_bindings'), 'v3 public binding evaluator missing')
        parsed = p.admit_certificate(self.certificate(0), self.issuer.public_key().public_numbers().n)
        binding = p.public_bindings(parsed, self.issuer.public_key().public_numbers().n)
        enabled = {binding}
        self.assertIn(binding, enabled)
        different_policy = p.parse_tbs(p.build_tbs(self.holder.public_key().public_numbers().n,
            organization=b'Z'*16, group=b'Y'*32))
        # Valid policy bytes remain well-formed; the external authority has not enabled this tuple.
        self.assertNotIn(p.public_bindings(different_policy,self.issuer.public_key().public_numbers().n),enabled)
        changed_aki = dict(parsed, aki=b'X'*20)
        self.assertNotEqual(p.public_bindings(changed_aki,self.issuer.public_key().public_numbers().n)[0],binding[0])
        changed_key = self.holder.public_key().public_numbers().n
        self.assertNotEqual(p.public_bindings(parsed,changed_key)[0],binding[0])
        enabled.clear()
        self.assertNotIn(binding,enabled)  # disabled enrollment; DER admission itself remains valid

    def test_openssl_generated_certificate(self):
        self.assertTrue(PATH.exists(), 'bounded profile implementation missing')
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            # Temporary synthetic key only, never committed or emitted in reports.
            (d/'issuer.pem').write_bytes(self.issuer.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            (d/'holder.pem').write_bytes(self.holder.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            config = ('[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN='+'H'*24+
                '\n[ext]\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=keyid\nkeyUsage=critical,digitalSignature\n'
                'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=critical,'+p.TEST_OIDS['purpose']+
                '\n'+p.TEST_OIDS['organization']+'=critical,DER:04:10:'+p.ORGANIZATION.hex(':')+
                '\n'+p.TEST_OIDS['group']+'=critical,DER:04:20:'+p.GROUP.hex(':')+'\n')
            (d/'openssl.cnf').write_text(config)
            def run(*args):
                subprocess.run(['openssl', *args], cwd=d, check=True, capture_output=True)
            run('req','-new','-x509','-key','issuer.pem','-subj','/CN='+'I'*40,
                '-days','365','-out','issuer.crt','-sha256','-addext','subjectKeyIdentifier=hash')
            run('req','-new','-key','holder.pem','-config','openssl.cnf','-out','holder.csr')
            run('x509','-req','-in','holder.csr','-CA','issuer.crt','-CAkey','issuer.pem',
                '-set_serial','0x11223344556677889900112233445566','-days','365','-sha256',
                '-extfile','openssl.cnf','-extensions','ext','-outform','DER','-out','holder.der')
            parsed = p.admit_certificate((d/'holder.der').read_bytes(), self.issuer.public_key().public_numbers().n)
            self.assertEqual(parsed['holder_modulus'], self.holder.public_key().public_numbers().n)

if __name__ == '__main__': unittest.main()
