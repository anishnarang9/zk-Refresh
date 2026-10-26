import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from tools.part5 import build_v3_heldout_cohort as cohort_builder
from tools.part5 import build_v3_campaign_packet as campaign_packet
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
                'aki_sha256': hashlib.sha256(bytes([issuer_index + 1]) * 20).hexdigest(),
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
                'aki': bytes([row['issuer_index'] + 1]) * 20,
                'holder_modulus': 200 + variant + 10,
                'not_before': row['not_before_unix'], 'not_after': row['not_after_unix'],
            }

        def bindings(parsed, modulus):
            row = self.rows[parsed['variant']]
            return 1000 + row['issuer_index'], 2000 + row['variant'] // 4

        def load(raw, password=None):
            return self.keys[raw]

        public_digests = {}
        for row in self.rows:
            public_digests[100 + row['issuer_index']] = row['issuer_public_key_sha256']
            public_digests[210 + row['holder_index']] = row['holder_public_key_sha256']

        return (mock.patch.object(tool.rsa, 'RSAPrivateKey', SimpleNamespace),
                mock.patch.object(tool.serialization, 'load_pem_private_key', side_effect=load),
                mock.patch.object(tool, 'admit_certificate', side_effect=admit),
                mock.patch.object(tool, 'public_bindings', side_effect=bindings),
                mock.patch.object(cohort_builder, '_public_key_digest',
                                  side_effect=lambda key: key.fingerprint),
                mock.patch.object(tool, '_public_key_digest_from_modulus',
                                  side_effect=lambda n: public_digests[n]))

    def prepare_case(self, variant=0):
        patches = self.mock_crypto()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            return tool.prepare(self.cohort, self.cohort_sha, variant, self.output)

    def make_stage(self, case_root, name='stage'):
        stage = self.root / name
        stage.mkdir(mode=0o700)
        case = json.loads((case_root / 'case-context.json').read_text())
        target = case['target']
        issuer = int(target['issuer_hash']).to_bytes(32, 'big')
        policy = int(target['policy_hash']).to_bytes(32, 'big')
        root = bytes.fromhex(case['membership']['R0'])
        aki = bytes([target['issuer_index'] + 1]) * 20 + bytes(12)
        program, genesis = bytes([3]) * 32, bytes([4]) * 32
        creator, nonce, recipient = bytes([5]) * 32, bytes([6]) * 32, bytes([7]) * 32
        payload, deadline = b'heldout-payload', 1_900_000_100
        plan = {
            'program': list(program), 'genesis': list(genesis),
            'creator': list(creator), 'seed': [8] * 32, 'nonce': list(nonce),
            'recipient': list(recipient), 'issuer_hash': list(issuer),
            'aki': list(aki), 'root': list(root), 'policy_id': list(policy),
            'deadline': deadline, 'payload': list(payload),
        }
        plan_raw = tool.encoded(plan)
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[104:136] = genesis
        config[136:168] = policy
        config[168:172] = (1).to_bytes(4, 'big')
        config[172:204] = bytes([9]) * 32
        config[332:364] = root
        config[364:372] = (0).to_bytes(8, 'big')
        config[380] = 1

        request = bytearray(2249)
        request[:8] = b'DYNREQ03'
        request[8:40] = bytes([10]) * 32
        request[40:72] = creator
        request[72:104] = nonce
        request[104:136] = issuer
        request[136:168] = recipient
        request[168:170] = (1).to_bytes(2, 'big')
        request[170:178] = deadline.to_bytes(8, 'big', signed=True)
        request[178:180] = len(payload).to_bytes(2, 'big')
        request[180:182] = len(payload).to_bytes(2, 'big')
        request[182] = 2
        request[183] = 1
        request[184] = 2
        for index, key in enumerate((bytes([11]) * 32, bytes([12]) * 32)):
            start = 185 + index * 65
            request[start:start + 32] = key
            request[start + 32] = 2
            request[start + 33:start + 65] = bytes([13 + index]) * 32
        request[1225:1225 + len(payload)] = payload
        issuer_account = bytearray(374)
        issuer_account[:8] = b'DYNISS03'
        issuer_account[40:72] = issuer
        issuer_account[108:140] = aki
        issuer_account[172] = 1
        issuer_account[173:181] = (1).to_bytes(8, 'big')
        issuer_account[181:213] = bytes([17]) * 32
        issuer_account[229:261] = root
        issuer_account[357] = 1
        head = bytearray(280)
        head[:8] = b'DYNHEAD3'
        head[104:112] = (1).to_bytes(8, 'big')
        head[112:144] = bytes([18]) * 32
        head[176:208] = root
        head[216:224] = (1).to_bytes(8, 'big')
        head[224:256] = bytes([17]) * 32
        queue = bytearray(2090)
        queue[:8] = b'DYNQUE03'
        accounts = [bytes(config), bytes(issuer_account), bytes(head),
                    bytes(request), bytes(queue)]
        names = ('config.bin', 'issuer.bin', 'head.bin', 'request.bin', 'queue.bin')
        for filename, raw in zip(names, accounts):
            self.write_file(stage / filename, raw)
        self.write_file(stage / 'plan.json', plan_raw)
        report = {
            'schema': 'part5-v3-local-stage-v1', 'passed': True,
            'training_only': True, 'proof_created': False, 'application_effect': False,
            'devnet': False, 'upstream_source_authentication': True,
            'upstream_publisher_authentication': True,
            'registry_history_authenticated': True,
            'allocation_history_authenticated': True,
            'plan_sha256': hashlib.sha256(plan_raw).hexdigest(),
            'source_head_digest': (bytes([17]) * 32).hex(),
            'publisher_envelope_digest': (bytes([18]) * 32).hex(),
            'signed_history_sha256': hashlib.sha256(b'signed-history').hexdigest(),
            'initial_allocations_sha256': hashlib.sha256(
                tool.encoded(json.loads((case_root / 'stage-context.json').read_text())['initial_allocations'])
            ).hexdigest(),
            'program': tool._base58(program),
            'genesis': tool._base58(genesis),
            'config': tool._base58(bytes([10]) * 32),
            'issuer': tool._base58(bytes([19]) * 32),
            'head': tool._base58(bytes([20]) * 32),
            'request': tool._base58(bytes([21]) * 32),
            'queue': tool._base58(bytes([22]) * 32),
            'finalized_slot': 10,
            'account_sha256': [hashlib.sha256(raw).hexdigest() for raw in accounts],
        }
        report_raw = tool.encoded(report)
        self.write_file(stage / 'stage-report.json', report_raw)
        self.write_file(stage / 'signed-history.json', b'signed-history')
        self.write_file(stage / 'initial-allocations.json',
                        tool.encoded(json.loads((case_root / 'stage-context.json').read_text())['initial_allocations']))
        return stage, case, plan, report

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
        self.assertEqual((self.output / 'heldout-cohort-receipt.json').read_bytes(), self.receipt_raw)

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
        with mock.patch.object(tool.keys, '_ignored', return_value=True), patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], self.assertRaises(ValueError):
            tool.prepare(self.cohort, self.cohort_sha, 0, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_target_der_that_does_not_match_frozen_cohort_row(self):
        cert = self.cohort / 'certificate-00' / 'credential.der'
        self.write_file(cert, b'tampered'.ljust(952, b'!'))
        patches = self.mock_crypto()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], self.assertRaises(ValueError):
            tool.prepare(self.cohort, self.cohort_sha, 0, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_prepares_exact_transition_context_from_pinned_stage_and_case(self):
        self.prepare_case(variant=0)
        stage, case, _, report = self.make_stage(self.output)
        output = self.root / 'transition-context.json'
        patches = self.mock_crypto()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            result = tool.prepare_transition(self.output, stage, output)
        transition = json.loads(output.read_text())
        self.assertEqual(transition, {
            'schema': 'part5-v3-unrelated-training-transition-v1',
            'training_only': True,
            'stage_report_sha256': hashlib.sha256((stage / 'stage-report.json').read_bytes()).hexdigest(),
            'cohort_receipt_sha256': case['pair_view']['cohort_receipt_sha256'],
            'membership_sha256': case['pair_view']['membership_sha256'],
            'own_tbs_digest': case['target']['tbs_sha256'],
            'unrelated_tbs_digest': case['unrelated']['tbs_sha256'],
            'slot': case['membership']['slot'],
            'unrelated_slot': case['membership']['unrelated_slot'],
            'base_root': case['membership']['R0'],
            'near_root': case['membership']['R1'],
        })
        self.assertEqual(result['stage_report_sha256'], transition['stage_report_sha256'])
        self.assertEqual(len(result['action_hash']), 64)
        self.assertLess(int(result['action_hash'], 16), tool.FR)
        self.assertEqual(
            int(result['action_hash'], 16),
            int(campaign_packet.action(
                (stage / 'config.bin').read_bytes(), (stage / 'request.bin').read_bytes(),
                json.loads((stage / 'plan.json').read_text())),
        ))
        self.assertEqual(report['schema'], 'part5-v3-local-stage-v1')

    def test_transition_rejects_stage_plan_with_a_different_root_or_request(self):
        self.prepare_case(variant=0)
        stage, case, plan, _ = self.make_stage(self.output, 'stage-root-mismatch')
        plan['root'] = [17] * 32
        plan_raw = tool.encoded(plan)
        self.write_file(stage / 'plan.json', plan_raw)
        report = json.loads((stage / 'stage-report.json').read_text())
        report['plan_sha256'] = hashlib.sha256(plan_raw).hexdigest()
        self.write_file(stage / 'stage-report.json', tool.encoded(report))
        out = self.root / 'bad-transition.json'
        patches = self.mock_crypto()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], self.assertRaises(ValueError):
            tool.prepare_transition(self.output, stage, out)
        self.assertFalse(out.exists())

    def test_transition_rejects_changed_frozen_cohort_receipt(self):
        self.prepare_case(variant=0)
        stage, _, _, _ = self.make_stage(self.output, 'stage-receipt-mismatch')
        receipt_path = self.output / 'heldout-cohort-receipt.json'
        self.write_file(receipt_path, receipt_path.read_bytes() + b' ')
        out = self.root / 'bad-receipt-transition.json'
        with self.assertRaises(ValueError):
            tool.prepare_transition(self.output, stage, out)
        self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
