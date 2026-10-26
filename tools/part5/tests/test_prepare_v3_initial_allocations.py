import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import prepare_v3_initial_allocations as tool


class InitialAllocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.cohort = self.root / 'cohort'
        self.cohort.mkdir(mode=0o700)
        self.output = self.root / 'context-new.json'
        self.context_path = self.root / 'context.json'
        self.own, self.other = b'own-signed-tbs', b'other-signed-tbs'
        self.member = dict(slot=0, unrelated_slot=1,
            own_tbs_digest=hashlib.sha256(self.own).hexdigest(),
            unrelated_tbs_digest=hashlib.sha256(self.other).hexdigest(),
            active_root=1, active_siblings=[0] * 10,
            unrelated_root=2, unrelated_siblings=[1] + [0] * 9,
            own_revoked_root=3, own_revoked_siblings=[2] + [0] * 9)
        self.context = dict(schema='part5-v3-local-training-context-v1', training_only=True,
            root=f'{1:064x}', issuer_hash=f'{111:064x}', policy_id=f'{222:064x}',
            aki=(b'a' * 20 + bytes(12)).hex(), evidence_digest='e' * 64,
            not_before=100, not_after=200)
        self.write(self.cohort / 'credential.der', b'own-der')
        self.write(self.cohort / 'unrelated.der', b'other-der')
        self.write(self.cohort / 'issuer-modulus.bin', (1 << 2047).to_bytes(256, 'big'))

    def write(self, path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    def sha(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def run_producer(self):
        member = {**self.member, 'issuer_hash': 111, 'policy_hash': 222}
        self.write(self.cohort / 'membership.json', json.dumps(member).encode())
        receipt = dict(schema='v3-two-signed-training-credentials-v1', training_only=True,
            registry_history_authenticated=False, live_state_authenticated=False,
            issuer_hash='111', policy_hash='222',
            credential_sha256=self.sha(self.cohort / 'credential.der'),
            unrelated_credential_sha256=self.sha(self.cohort / 'unrelated.der'),
            membership_sha256=self.sha(self.cohort / 'membership.json'))
        self.write(self.cohort / 'cohort-receipt.json', json.dumps(receipt).encode())
        self.write(self.context_path, json.dumps(self.context).encode())
        def admitted(raw, modulus):
            return dict(tbs=self.own if raw == b'own-der' else self.other,
                        aki=b'a' * 20, not_before=100, not_after=200)
        with mock.patch.object(tool, 'admit_certificate', side_effect=admitted), \
             mock.patch.object(tool, 'public_bindings', return_value=(111, 222)), \
             mock.patch.object(tool.schedule, 'membership_for_pair', return_value={**self.member}), \
             mock.patch.object(tool.keys, '_ignored', return_value=True):
            return tool.prepare(self.cohort, self.sha(self.cohort / 'cohort-receipt.json'),
                self.sha(self.cohort / 'membership.json'), self.context_path,
                self.sha(self.context_path), f'{1:064x}', self.output)

    def test_produces_exact_context_addition_from_admitted_two_leaf_cohort(self):
        receipt = self.run_producer()
        context = json.loads(self.output.read_text())
        self.assertEqual({k: v for k, v in context.items() if k != 'initial_allocations'}, self.context)
        initial = context['initial_allocations']
        self.assertEqual(set(initial), {'own_tbs_digest', 'unrelated_tbs_digest', 'slot',
                         'allocation_epoch', 'cohort_receipt_sha256', 'membership_sha256'})
        self.assertEqual(initial['allocation_epoch'], 1)
        self.assertEqual(initial['own_tbs_digest'], self.member['own_tbs_digest'])
        self.assertEqual(initial['membership_sha256'], self.sha(self.cohort / 'membership.json'))
        self.assertEqual(receipt['context_sha256'], self.sha(self.output))
        self.assertFalse(receipt['allocation_authorized'])
        self.assertNotIn(str(self.root), json.dumps(receipt))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_context_root_issuer_policy_aki_validity_and_extra_field_mismatch_reject(self):
        for field, value in [('root', f'{2:064x}'), ('issuer_hash', 'f' * 64),
                             ('policy_id', 'f' * 64), ('aki', 'f' * 64),
                             ('not_after', 201), ('training_only', False), ('extra', 1)]:
            original = dict(self.context)
            self.context[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_producer()
            self.assertFalse(self.output.exists())
            self.context = original

    def test_membership_digest_context_link_and_slots_are_checked(self):
        for field, value in [('own_tbs_digest', 'f' * 64), ('slot', True), ('unrelated_slot', 5)]:
            original = dict(self.member)
            self.member[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_producer()
            self.assertFalse(self.output.exists())
            self.member = original


if __name__ == '__main__':
    unittest.main()
