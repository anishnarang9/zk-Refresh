import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from tools.part5 import build_v3_heldout_cohort as cohort_builder
from tools.part5 import prepare_v3_heldout_context as tool


class HeldoutContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.cohort = self.root / 'cohort'
        self.cohort.mkdir(mode=0o700)
        (self.cohort / 'keys').mkdir(mode=0o700)
        self.rows = []
        self.keys = {}
        for issuer_index in range(4):
            self.write_key(f'issuer-{issuer_index}.pem', f'issuer-{issuer_index}'.encode())
            self.keys[f'issuer-{issuer_index}'.encode()] = self.fake_key(
                issuer_index + 100, issuer_index)
        for holder_index in range(8):
            self.write_key(f'holder-{holder_index}.pem', f'holder-{holder_index}'.encode())
            self.keys[f'holder-{holder_index}'.encode()] = self.fake_key(
                holder_index + 210, holder_index + 100)
        for variant in range(8):
            issuer_index = variant % 4
            holder_index = variant
            cert_dir = self.cohort / f'certificate-{variant:02d}'
            cert_dir.mkdir(mode=0o700)
            der = f'der-{variant}'.encode().ljust(952, b'!')
            self.write_file(cert_dir / 'credential.der', der)
            row = {
                'variant': variant,
                'issuer_index': issuer_index,
                'holder_index': holder_index,
                'credential_sha256': hashlib.sha256(der).hexdigest(),
                'tbs_sha256': hashlib.sha256(f'tbs-{variant}'.encode()).hexdigest(),
                'issuer_public_key_sha256': f'{issuer_index + 1:064x}',
                'holder_public_key_sha256': f'{holder_index + 101:064x}',
                'issuer_hash': str(1000 + issuer_index),
                'policy_hash': str(2000 + variant // 4),
                'aki_sha256': hashlib.sha256(f'aki-{issuer_index}'.encode()).hexdigest(),
                'not_before_unix': 1_800_000_000 + variant,
                'not_after_unix': 1_900_000_000 + variant,
            }
            self.rows.append(row)
        receipt = {
            'schema': tool.COHORT_SCHEMA,
            'status': 'cohort_issued_pending_application_gate',
            'keys_generated_after_freeze': True,
            'freeze_sha256': 'a' * 64,
            'counts': {'issuers': 4, 'holders': 8, 'certificates': 8,
                       'openssl_issuances': 4, 'policies': 2},
            'policy_hashes': ['2000', '2001'],
            'issuer_aki_sha256': sorted({row['aki_sha256'] for row in self.rows}),
            'certificates': self.rows,
        }
        self.receipt_raw = tool.encoded(receipt)
        self.write_file(self.cohort / 'cohort-receipt.json', self.receipt_raw)
        self.cohort_sha = hashlib.sha256(self.receipt_raw).hexdigest()
        self.output = self.root / 'case'
        self.output.mkdir(mode=0o700)

    def write_file(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def write_key(self, name, raw):
        self.write_file(self.cohort / 'keys' / name, raw)

    @staticmethod
    def fake_key(n, fingerprint_index):
        pub = SimpleNamespace(public_numbers=lambda: SimpleNamespace(n=n, e=65537))
        return SimpleNamespace(public_key=lambda: pub, key_size=2048,
                               fingerprint=f'{fingerprint_index + 1:064x}')

    def mock_crypto(self):
        def admit(der, modulus):
            try:
                variant = int(der.rstrip(b'!').decode().split('-')[1])
            except (UnicodeDecodeError, IndexError, ValueError):
                raise ValueError('invalid synthetic certificate') from None
            row = self.rows[variant]
            return {
                'variant': variant, 'tbs': f'tbs-{variant}'.encode(),
                'aki': f'aki-{row["issuer_index"]}'.encode(),
                'holder_modulus': 200 + variant + 10,
                'not_before': row['not_before_unix'], 'not_after': row['not_after_unix'],
            }

        def bindings(parsed, modulus):
            row = self.rows[parsed['variant']]
            return 1000 + row['issuer_index'], 2000 + row['variant'] // 4

        def load(raw, password=None):
            return self.keys[raw]

        return (mock.patch.object(tool.rsa, 'RSAPrivateKey', SimpleNamespace),
                mock.patch.object(tool.serialization, 'load_pem_private_key', side_effect=load),
                mock.patch.object(tool, 'admit_certificate', side_effect=admit),
                mock.patch.object(tool, 'public_bindings', side_effect=bindings),
                mock.patch.object(cohort_builder, '_public_key_digest',
                                  side_effect=lambda key: key.fingerprint))

    def prepare_case(self, variant=0):
        patches = self.mock_crypto()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), patches[0], patches[1], patches[2], patches[3], patches[4]:
            return tool.prepare(self.cohort, self.cohort_sha, variant, self.output)

    def test_case_pair_is_issuer_matched_and_carries_independent_roots(self):
        self.prepare_case(variant=0)
        case = json.loads((self.output / 'case-context.json').read_text())
        pair = json.loads((self.output / 'cohort-receipt.json').read_text())
        stage = json.loads((self.output / 'stage-context.json').read_text())
        membership = json.loads((self.output / 'membership.json').read_text())

        self.assertEqual(case['schema'], 'credential-v3-heldout-case-context-v1')
        self.assertFalse(case['heldout_acceptance'])
        self.assertEqual(case['frozen_cohort']['cohort_receipt_sha256'], self.cohort_sha)
        self.assertEqual(case['target']['variant'], 0)
        self.assertEqual(case['unrelated']['variant'], 4)
        self.assertEqual(case['target']['issuer_index'], case['unrelated']['issuer_index'])
        self.assertNotEqual(case['target']['policy_hash'], case['unrelated']['policy_hash'])
        self.assertEqual(case['membership']['R0'], f"{membership['active_root']:064x}")
        self.assertEqual(case['membership']['R1'], f"{membership['unrelated_root']:064x}")
        self.assertEqual(case['membership']['R2'], f"{membership['own_revoked_root']:064x}")
        self.assertEqual(stage['schema'], 'part5-v3-local-training-context-v1')
        self.assertEqual(stage['initial_allocations']['cohort_receipt_sha256'],
                         hashlib.sha256(tool.encoded(pair)).hexdigest())
        self.assertEqual(pair['schema'], 'v3-two-signed-training-credentials-v1')
        self.assertFalse(pair['live_state_authenticated'])
        self.assertEqual((self.output / 'holder.pem').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('holder.pem', json.dumps(case))
        self.assertEqual((self.output / 'credential.der').read_bytes(),
                         (self.cohort / 'certificate-00' / 'credential.der').read_bytes())

    def test_pair_selection_uses_receipt_identity_not_variant_offset(self):
        # Reordering rows must not change which same-issuer certificate is selected.
        receipt = json.loads(self.receipt_raw)
        receipt['certificates'].reverse()
        self.write_file(self.cohort / 'cohort-receipt.json', tool.encoded(receipt))
        self.cohort_sha = hashlib.sha256((self.cohort / 'cohort-receipt.json').read_bytes()).hexdigest()
        self.prepare_case(variant=5)
        case = json.loads((self.output / 'case-context.json').read_text())
        self.assertEqual(case['target']['variant'], 5)
        self.assertEqual(case['unrelated']['variant'], 1)

    def test_prepares_all_eight_issuer_policy_cases(self):
        for variant in range(8):
            self.output = self.root / f'case-{variant:02d}'
            self.output.mkdir(mode=0o700)
            with self.subTest(variant=variant):
                self.prepare_case(variant=variant)
                case = json.loads((self.output / 'case-context.json').read_text())
                self.assertEqual(case['target']['variant'], variant)
                self.assertEqual(case['target']['issuer_index'], case['unrelated']['issuer_index'])
                self.assertNotEqual(case['target']['variant'], case['unrelated']['variant'])
                self.assertEqual(case['membership']['unrelated_slot'],
                                 case['membership']['slot'] ^ 1)

    def test_rejects_duplicate_or_unmatched_receipt_identity_before_writing(self):
        receipt = json.loads(self.receipt_raw)
        receipt['certificates'][1]['variant'] = 0
        raw = tool.encoded(receipt)
        self.write_file(self.cohort / 'cohort-receipt.json', raw)
        self.cohort_sha = hashlib.sha256(raw).hexdigest()
        patches = self.mock_crypto()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
            tool.prepare(self.cohort, self.cohort_sha, 0, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_target_der_that_does_not_match_frozen_cohort_row(self):
        cert = self.cohort / 'certificate-00' / 'credential.der'
        self.write_file(cert, b'tampered'.ljust(952, b'!'))
        patches = self.mock_crypto()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(ValueError):
            tool.prepare(self.cohort, self.cohort_sha, 0, self.output)
        self.assertEqual(list(self.output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
