import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from tools.part5 import prepare_v3_heldout_source as tool
from tools.part5.prepare_v3_revocation_cohort import membership_for_pair


class HeldoutSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.cohort = self.root / 'cohort'
        self.case = self.root / 'case'
        self.stage = self.root / 'stage'
        self.transition = self.root / 'transition'
        self.transition_context = self.root / 'transition-context.json'
        self.output0 = self.root / 'out-r0'
        self.output1 = self.root / 'out-r1'
        for directory in (self.cohort, self.case, self.stage, self.transition,
                          self.output0, self.output1):
            directory.mkdir(mode=0o700)
        (self.cohort / 'keys').mkdir(mode=0o700)
        for variant in (0, 4):
            (self.cohort / f'certificate-{variant:02d}').mkdir(mode=0o700)
        self.freeze = self.root / 'freeze.json'
        self.freeze_raw = self.write(self.freeze, b'freeze')
        self.freeze_sha = tool.digest(self.freeze_raw)
        self.now = 1_800_000_000
        self.request = b'DYNREQ03' + b'R' * (2249 - 8)
        self.action = bytes.fromhex('01' * 32)
        self.f2 = bytearray(561)
        self.f2[:4] = b'V3F2'
        self.f2[164:196] = self.action
        self.f2 = bytes(self.f2)
        self.der = {}
        self.parsed = {}
        self.rows = []
        self.keys = {}
        for variant in range(8):
            issuer_index, holder_index = variant % 4, variant
            der = (f'certificate-{variant}'.encode()).ljust(952, b'!')
            if variant in (0, 4):
                self.der[variant] = der
                self.write(self.cohort / f'certificate-{variant:02d}' / 'credential.der', der)
            self.rows.append({
                'variant': variant, 'issuer_index': issuer_index, 'holder_index': holder_index,
                'credential_sha256': tool.digest(der), 'tbs_sha256': tool.digest(f'tbs-{variant}'.encode()),
                'issuer_public_key_sha256': f'{issuer_index + 1:064x}',
                'holder_public_key_sha256': f'{holder_index + 101:064x}',
                'issuer_hash': str(1000 + issuer_index), 'policy_hash': str(2000 + variant // 4),
                'aki_sha256': tool.digest(f'aki-{issuer_index}'.encode().ljust(20, b'x')),
                'not_before_unix': 1_700_000_000, 'not_after_unix': 1_900_000_000,
                'encoder': 'openssl' if variant < 4 else 'cryptography',
            })
        self.issuer_key = self.fake_key(1 << 2047 | 17, f'{1:064x}')
        self.holder0 = self.fake_key(1 << 2047 | 29, f'{101:064x}')
        self.holder4 = self.fake_key(1 << 2047 | 33, f'{105:064x}')
        self.keys.update({b'issuer0': self.issuer_key, b'holder0': self.holder0,
                          b'holder4': self.holder4})
        for name, raw in (('issuer-0.pem', b'issuer0'), ('holder-0.pem', b'holder0'),
                          ('holder-4.pem', b'holder4')):
            self.write(self.cohort / 'keys' / name, raw)
        self.modulus = self.issuer_key.public_key().public_numbers().n.to_bytes(256, 'big')
        self.write(self.case / 'credential.der', self.der[0])
        self.write(self.case / 'unrelated.der', self.der[4])
        self.write(self.case / 'holder.pem', b'holder0')
        self.write(self.case / 'issuer-modulus.bin', self.modulus)

        # Rebuild the pair from the selected TBS and deterministic target slot.
        slot = int.from_bytes(hashlib.sha256(b'tbs-0').digest()[:2], 'big') & 1023
        self.membership = membership_for_pair(hashlib.sha256(b'tbs-0').digest(),
                                              hashlib.sha256(b'tbs-4').digest(), slot)
        self.membership.update(issuer_hash=1000, policy_hash=2000)
        self.member_raw = tool.encoded(self.membership)
        self.pair_receipt = {
            'schema': 'v3-two-signed-training-credentials-v1', 'training_only': True,
            'heldout_acceptance': False, 'allocation_authorized': False,
            'registry_history_authenticated': False, 'live_state_authenticated': False,
            'credential_sha256': tool.digest(self.der[0]),
            'unrelated_credential_sha256': tool.digest(self.der[4]),
            'membership_sha256': tool.digest(self.member_raw),
            'issuer_hash': '1000', 'policy_hash': '2000',
        }
        self.pair_raw = tool.encoded(self.pair_receipt)
        self.write(self.case / 'membership.json', self.member_raw)
        self.write(self.case / 'cohort-receipt.json', self.pair_raw)
        self.full_receipt = {
            'schema': 'credential-v3-heldout-issuance-cohort-v1',
            'status': 'cohort_issued_pending_application_gate',
            'keys_generated_after_freeze': True, 'freeze_sha256': self.freeze_sha,
            'frozen_at_unix_ns': 100, 'generation_started_unix_ns': 110,
            'generation_completed_unix_ns': 120,
            'counts': {'issuers': 4, 'holders': 8, 'certificates': 8,
                       'openssl_issuances': 4, 'policies': 2},
            'certificates': self.rows,
        }
        self.full_raw = tool.encoded(self.full_receipt)
        self.full_sha = tool.digest(self.write(self.cohort / 'cohort-receipt.json', self.full_raw))
        self.write(self.case / 'heldout-cohort-receipt.json', self.full_raw)
        for index in range(4):
            if index == 0:
                key_raw = b'issuer0'
            else:
                key_raw = f'issuer{index}'.encode()
                self.keys[key_raw] = self.fake_key(1 << 2047 | 40 + index, f'{index + 1:064x}')
                self.write(self.cohort / 'keys' / f'issuer-{index}.pem', key_raw)
        for index in range(8):
            if index == 0:
                continue
            if index == 4:
                continue
            key_raw = f'holder{index}'.encode()
            self.keys[key_raw] = self.fake_key(1 << 2047 | 50 + index, f'{index + 101:064x}')
            self.write(self.cohort / 'keys' / f'holder-{index}.pem', key_raw)

        self.stage_context = {
            'schema': 'part5-v3-local-training-context-v1', 'training_only': True,
            'root': f"{self.membership['active_root']:064x}", 'issuer_hash': f'{1000:064x}',
            'policy_id': f'{2000:064x}', 'aki': (b'aki-0'.ljust(20, b'x') + bytes(12)).hex(),
            'evidence_digest': hashlib.sha256(
                b'credential-v3-heldout-case-evidence/v1\0' + bytes.fromhex(self.full_sha)
                + bytes.fromhex(self.rows[0]['credential_sha256'])
                + bytes.fromhex(self.rows[4]['credential_sha256'])).hexdigest(),
            'not_before': 1_700_000_000,
            'not_after': 1_900_000_000,
        }
        self.stage_context['initial_allocations'] = {
            'own_tbs_digest': hashlib.sha256(b'tbs-0').hexdigest(),
            'unrelated_tbs_digest': hashlib.sha256(b'tbs-4').hexdigest(),
            'slot': self.membership['slot'], 'allocation_epoch': 1,
            'cohort_receipt_sha256': tool.digest(self.pair_raw),
            'membership_sha256': tool.digest(self.member_raw),
        }
        self.case_context = {
            'schema': 'credential-v3-heldout-case-context-v1', 'heldout_acceptance': False,
            'authenticated': {'registry_history': False, 'live_state': False,
                              'current_head': False, 'finalized_account_batch': False},
            'frozen_cohort': {'schema': 'credential-v3-heldout-issuance-cohort-v1',
                              'freeze_sha256': self.freeze_sha,
                              'cohort_receipt_sha256': self.full_sha},
            'target': {key: self.rows[0][key] for key in (
                'variant', 'issuer_index', 'holder_index', 'credential_sha256', 'tbs_sha256',
                'issuer_public_key_sha256', 'holder_public_key_sha256', 'issuer_hash', 'policy_hash',
                'aki_sha256', 'not_before_unix', 'not_after_unix')},
            'unrelated': {key: self.rows[4][key] for key in (
                'variant', 'issuer_index', 'holder_index', 'credential_sha256', 'tbs_sha256',
                'issuer_public_key_sha256', 'holder_public_key_sha256', 'issuer_hash', 'policy_hash',
                'aki_sha256', 'not_before_unix', 'not_after_unix')},
            'pair_view': {'cohort_receipt_sha256': tool.digest(self.pair_raw),
                          'membership_sha256': tool.digest(self.member_raw),
                          'stage_context_sha256': tool.digest(tool.encoded(self.stage_context))},
            'membership': {
                'slot': self.membership['slot'], 'unrelated_slot': self.membership['unrelated_slot'],
                'R0': f"{self.membership['active_root']:064x}",
                'R1': f"{self.membership['unrelated_root']:064x}",
                'R2': f"{self.membership['own_revoked_root']:064x}",
                'active_siblings': self.membership['active_siblings'],
                'unrelated_siblings': self.membership['unrelated_siblings'],
                'own_revoked_siblings': self.membership['own_revoked_siblings'],
            },
        }
        self.case_context_raw = tool.encoded(self.case_context)
        self.stage_context_raw = tool.encoded(self.stage_context)
        self.write(self.case / 'case-context.json', self.case_context_raw)
        self.write(self.case / 'stage-context.json', self.stage_context_raw)
        self.plan = {
            key: [i for i in range(32)] for key in
            ('program', 'genesis', 'creator', 'nonce', 'recipient')
        }
        self.plan.update(root=list(self.membership['active_root'].to_bytes(32, 'big')),
                         issuer_hash=list((1000).to_bytes(32, 'big')),
                         policy_id=list((2000).to_bytes(32, 'big')),
                         deadline=1_800_000_100, payload=[1, 2, 3])
        self.config0 = bytearray(381)
        self.config0[:8] = b'DYNCONF3'
        self.config0[332:364] = bytes.fromhex(f"{self.membership['active_root']:064x}")
        self.config1 = bytearray(self.config0)
        self.write_stage()
        self.write_transition()
        self.exporter = self.root / 'exporter'
        self.write(self.exporter, b'fake executable')
        self.exporter.chmod(0o700)

    @staticmethod
    def fake_key(n, fingerprint):
        public = SimpleNamespace(public_numbers=lambda: SimpleNamespace(n=n, e=65537))
        return SimpleNamespace(key_size=2048, public_key=lambda: public, fingerprint=fingerprint)

    @staticmethod
    def write(path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)
        return raw

    def write_stage(self):
        self.write(self.stage / 'plan.json', tool.encoded(self.plan))
        self.write(self.stage / 'config.bin', bytes(self.config0))
        for name, raw in zip(('issuer.bin', 'head.bin', 'request.bin', 'queue.bin'),
                             (b'I' * 40, b'H' * 40, self.request, b'Q' * 40)):
            self.write(self.stage / name, raw)
        allocations = tool.encoded(self.stage_context['initial_allocations'])
        self.write(self.stage / 'initial-allocations.json', allocations)
        self.write(self.stage / 'signed-history.json', b'{}')
        accounts = [bytes(self.config0), b'I' * 40, b'H' * 40, self.request, b'Q' * 40]
        self.stage_report = {
            'schema': 'part5-v3-local-stage-v1', 'passed': True, 'training_only': True,
            'registry_history_authenticated': True, 'allocation_history_authenticated': True,
            'proof_created': False, 'application_effect': False,
            'plan_sha256': tool.digest(tool.encoded(self.plan)),
            'signed_history_sha256': tool.digest(b'{}'),
            'initial_allocations_sha256': tool.digest(allocations),
            'account_sha256': [tool.digest(value) for value in accounts],
            'transactions': [{'scenario': 'v3-bind-head', 'blockTime': self.now}],
        }
        self.write(self.stage / 'stage-report.json', tool.encoded(self.stage_report))

    def write_transition(self):
        self.config1[332:364] = bytes.fromhex(self.case_context['membership']['R1'])
        self.config1[364:372] = (1).to_bytes(8, 'little')
        self.write(self.transition / 'plan.json', tool.encoded(self.plan))
        self.write(self.transition / 'config.bin', bytes(self.config1))
        for name, raw in zip(('issuer.bin', 'head.bin', 'request.bin', 'queue.bin'),
                             (b'I' * 40, b'H' * 40, self.request, b'Q' * 40)):
            self.write(self.transition / name, raw)
        self.write(self.transition / 'signed-history.json', b'{}')
        accounts = [bytes(self.config1), b'I' * 40, b'H' * 40, self.request, b'Q' * 40]
        transition_context = {
            'schema': 'part5-v3-unrelated-training-transition-v1',
            'training_only': True,
            'stage_report_sha256': tool.digest(tool.encoded(self.stage_report)),
            'stage_plan_sha256': tool.digest(tool.encoded(self.plan)),
            'cohort_receipt_sha256': tool.digest(self.pair_raw),
            'membership_sha256': tool.digest(self.member_raw),
            'own_tbs_digest': self.rows[0]['tbs_sha256'],
            'unrelated_tbs_digest': self.rows[4]['tbs_sha256'],
            'slot': self.membership['slot'],
            'unrelated_slot': self.membership['unrelated_slot'],
            'base_root': self.case_context['membership']['R0'],
            'near_root': self.case_context['membership']['R1'],
        }
        transition_context_raw = tool.encoded(transition_context)
        self.write(self.transition_context, transition_context_raw)
        self.transition_report = {
            'schema': 'part5-v3-unrelated-local-transition-v1', 'passed': True,
            'training_only': True, 'devnet': False,
            'request_unconsumed': True, 'upstream_source_authentication': True,
            'application_effect': False,
            'stage_report_sha256': tool.digest(tool.encoded(self.stage_report)),
            'stage_plan_sha256': tool.digest(tool.encoded(self.plan)),
            'cohort_receipt_sha256': tool.digest(self.pair_raw),
            'membership_sha256': tool.digest(self.member_raw),
            'transition_context_sha256': tool.digest(transition_context_raw),
            'base_root': self.case_context['membership']['R0'],
            'near_root': self.case_context['membership']['R1'],
            'unrelated_tbs_digest': self.case_context['unrelated']['tbs_sha256'],
            'signed_history_sha256': tool.digest(b'{}'),
            'account_sha256': [tool.digest(value) for value in accounts],
        }
        self.write(self.transition / 'transition-report.json', tool.encoded(self.transition_report))

    def patches(self, action_r1=None):
        def parsed(raw, modulus):
            variant = int(raw.rstrip(b'!').decode().split('-')[1])
            row = self.rows[variant]
            return {'variant': variant, 'tbs': f'tbs-{variant}'.encode(),
                    'aki': f'aki-{row["issuer_index"]}'.encode().ljust(20, b'x'),
                    'holder_modulus': 1 << 2047 | 29 + variant,
                    'not_before': row['not_before_unix'], 'not_after': row['not_after_unix']}

        def load_key(raw, password=None):
            return self.keys[raw]

        def build(der, modulus, membership, **kwargs):
            root = membership['active_root']
            return b'plan-r0' if root == self.membership['active_root'] else b'plan-r1'

        def finalize(plan_wire, exporter):
            root = self.membership['active_root'] if plan_wire == b'plan-r0' else self.membership['unrelated_root']
            action = action_r1 if plan_wire == b'plan-r1' and action_r1 is not None else self.action
            f1 = b'V3F1' + root.to_bytes(32, 'big') + bytes(589) + self.request
            f1 = f1[:625] + self.request
            f2 = bytearray(self.f2)
            f2[164:196] = action
            return {'v3f1': f1, 'v3f2': bytes(f2), 'exporter_sha256': tool.digest(exporter.read_bytes())}

        class FakePreparer:
            BRIDGE_SHA = 'b' * 64
            WORKER_SHA = 'c' * 64
            RELATION_HELPER_SHA = 'd' * 64

            @staticmethod
            def prepare(source, output, exporter):
                values = {
                    'request.bin': b'V3Q1' + b'q' * 1914, 'summary.bin': b's' * 459,
                    'input.json': b'{}', 'public.json': b'[]',
                    'input-coordinates.bin': b'coor', 'internal-coordinate.bin': b'ints',
                }
                for name, data in values.items():
                    HeldoutSourceTests.write(output / name, data)
                config = (source / 'config.bin').read_bytes()
                membership = json.loads((source / 'membership.json').read_bytes())
                params = json.loads((source / 'parameters.json').read_bytes())
                finalized = finalize(build((source / 'credential.der').read_bytes(), 0, membership), exporter)
                receipt = {
                    'schema': 'v3-request-bound-training-input-v1', 'training_only': True,
                    'live_state_authenticated': False, 'proof_created': False,
                    'complete_relation_checked': False, 'bridge_sha256': FakePreparer.BRIDGE_SHA,
                    'worker_sha256': FakePreparer.WORKER_SHA,
                    'exporter_sha256': params['exporter_sha256'],
                    'config_sha256': tool.digest(config),
                    'membership_sha256': tool.digest((source / 'membership.json').read_bytes()),
                    'parameters_sha256': tool.digest((source / 'parameters.json').read_bytes()),
                    'finalized_fixture_sha256': tool.digest(finalized['v3f1']),
                    'finalized_action_transport_sha256': tool.digest(finalized['v3f2']),
                    'artifact_sha256': {key: tool.digest(data) for key, data in values.items()
                                        if key in ('request.bin', 'input.json', 'public.json')},
                }
                HeldoutSourceTests.write(output / 'training-receipt.json', tool.encoded(receipt))

        return (
            mock.patch.object(tool.keygen, '_freeze', return_value=(self.freeze_raw, {
                'schema': 'credential-v3-frozen-holdout-boundary-v1',
                'frozen_at_unix_ns': 100, 'identities': {},
            })),
            mock.patch.object(tool.rsa, 'RSAPrivateKey', SimpleNamespace),
            mock.patch.object(tool.serialization, 'load_pem_private_key', side_effect=load_key),
            mock.patch.object(tool, 'spki_fingerprint', side_effect=lambda key: key.fingerprint),
            mock.patch.object(tool, 'admit_certificate', side_effect=parsed),
            mock.patch.object(tool, 'public_bindings', side_effect=lambda cert, modulus:
                              (1000, 2000 + cert['variant'] // 4)),
            mock.patch.object(tool.bridge, 'build_v3p1', side_effect=build),
            mock.patch.object(tool.bridge, 'finalize_v3p1', side_effect=finalize),
            mock.patch.object(tool, 'load_preparer', return_value=FakePreparer),
        )

    def run_prepare(self, variant, output, action_r1=None, **kwargs):
        patches = self.patches(action_r1=action_r1)
        with (patches[0], patches[1], patches[2], patches[3], patches[4],
              patches[5], patches[6], patches[7], patches[8]):
            return tool.prepare(
                self.case, self.cohort, self.freeze, self.freeze_sha,
                self.stage, self.exporter, variant, output,
                transition_root=self.transition if variant == 'R1' else None,
                transition_context=self.transition_context if variant == 'R1' else None,
                transition_context_sha256=(tool.digest(self.transition_context.read_bytes())
                                           if variant == 'R1' else None),
                **kwargs,
            )

    def test_r0_and_r1_keep_exact_staged_request_and_action(self):
        r0 = self.run_prepare('R0', self.output0)
        r0_path = self.output0 / 'source-receipt.json'
        r0_sha = tool.digest(r0_path.read_bytes())
        r1 = self.run_prepare('R1', self.output1,
                              r0_source_receipt=r0_path,
                              r0_source_receipt_sha256=r0_sha)
        self.assertEqual(r0['schema'], 'credential-v3-heldout-request-source-v1')
        self.assertIsNone(r0['transition_report_sha256'])
        self.assertEqual(r0['staged_request_sha256'], r1['staged_request_sha256'])
        self.assertEqual(r0['action_hash'], r1['action_hash'])
        self.assertEqual(r0['finalized_action_transport_sha256'],
                         r1['finalized_action_transport_sha256'])
        self.assertNotEqual(r0['selected_root'], r1['selected_root'])
        self.assertTrue(r1['transition_report_sha256'])
        self.assertFalse(r1['proof_created'])
        self.assertFalse(r1['application_effect'])
        self.assertFalse(r1['live_state_authenticated'])
        self.assertFalse((self.output0 / 'source-input').exists())
        self.assertFalse(any(path.name == 'holder.pem' for path in self.output0.rglob('*')))

    def test_r1_rejects_action_drift_without_publishing(self):
        r0 = self.run_prepare('R0', self.output0)
        r0_path = self.output0 / 'source-receipt.json'
        with self.assertRaisesRegex(ValueError, 'action'):
            self.run_prepare('R1', self.output1, action_r1=bytes.fromhex('02' * 32),
                             r0_source_receipt=r0_path,
                             r0_source_receipt_sha256=tool.digest(r0_path.read_bytes()))
        self.assertEqual(list(self.output1.iterdir()), [])

    def test_r1_requires_report_to_pin_transition_context(self):
        r0 = self.run_prepare('R0', self.output0)
        r0_path = self.output0 / 'source-receipt.json'
        report = json.loads((self.transition / 'transition-report.json').read_bytes())
        report['transition_context_sha256'] = '0' * 64
        self.write(self.transition / 'transition-report.json', tool.encoded(report))
        with self.assertRaisesRegex(ValueError, 'does not pin heldout transition context'):
            self.run_prepare('R1', self.output1,
                             r0_source_receipt=r0_path,
                             r0_source_receipt_sha256=tool.digest(r0_path.read_bytes()))
        self.assertEqual(list(self.output1.iterdir()), [])

    def test_pair_der_mismatch_is_rejected_before_output(self):
        self.write(self.case / 'credential.der', b'changed'.ljust(952, b'!'))
        with self.assertRaisesRegex(ValueError, 'heldout pair'):
            self.run_prepare('R0', self.output0)
        self.assertEqual(list(self.output0.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
