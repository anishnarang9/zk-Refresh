import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import prepare_v3_campaign_cohort as tool


class CampaignCohortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.freeze = self.root / 'freeze.json'
        self.output = self.root / 'campaign'
        self.boundary = dict(schema=tool.FREEZE_SCHEMA, frozen_at_unix_ns=100,
            identities={name: 'a' * 64 for name in tool.keys.IDENTITY_ROLES},
            source_sha256=tool.source_hashes(), forbidden_public_key_sha256=['f' * 64])

    def save(self):
        self.freeze.write_text(json.dumps(self.boundary))
        self.freeze.chmod(0o600)
        return tool.keys.file_sha(self.freeze)

    def key(self, index):
        key = mock.Mock(spec=rsa.RSAPrivateKey)
        key.key_size = 2048
        key.public_key.return_value.public_numbers.return_value.e = 65537
        key.public_key.return_value.public_numbers.return_value.n = (1 << 2047) + index
        key.public_key.return_value.public_bytes.return_value = f'public-{index}'.encode()
        key.private_bytes.return_value = f'PRIVATE-MOCK-{index}'.encode()
        return key

    def parsed(self, der, modulus):
        index = der[0]
        return dict(tbs=bytes([index]) * 672, variant=index % 8,
            holder_modulus=(1 << 2047) + index + 1,
            serial=((1 << 120) + index + 1).to_bytes(16, 'big'),
            aki=hashlib.sha256(b'public-0').digest()[:20],
            organization=tool.ORGANIZATION, group=tool.GROUP,
            not_before=1767225600, not_after=1830297600)

    def sequence(self, own, others):
        return dict(holder_slot=0, unrelated_slots=list(range(16, 26)),
            tbs_digests=[d.hex() for d in [own, *others]], roots=list(range(1, 12)),
            holder_siblings=[[0] * 4 + [i] + [0] * 5 for i in range(11)])

    def prepare(self, key_list=None, admitted=None, **kwargs):
        digest = self.save()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), \
             mock.patch.object(tool.keys, '_new_key', side_effect=key_list or [self.key(i) for i in range(12)]) as gen, \
             mock.patch.object(tool.time, 'time_ns', side_effect=range(200, 900)), \
             mock.patch.object(tool.issuance, 'issue_certificate', side_effect=lambda issuer, holder, p, encoder:
                               bytes([p['serial'] - (1 << 120) - 1]) * 952) as issue, \
             mock.patch.object(tool, 'admit_certificate', side_effect=admitted or self.parsed), \
             mock.patch.object(tool, 'public_bindings', return_value=(111, 222)), \
             mock.patch.object(tool.schedule, 'membership_for_sequence', side_effect=self.sequence) as tree:
            receipt = tool.prepare(self.freeze, digest, self.output, **kwargs)
        return receipt, gen, issue, tree

    def test_prepares_eleven_signed_leaves_and_the_exact_committed_schedule(self):
        receipt, gen, issue, tree = self.prepare()
        self.assertEqual((gen.call_count, issue.call_count, tree.call_count), (12, 11, 1))
        self.assertEqual(receipt['counts'], {'issuers': 1, 'holders': 11, 'certificates': 11, 'roots': 11})
        self.assertEqual([c['slot'] for c in receipt['certificates']], [0, *range(16, 26)])
        self.assertTrue(receipt['training_only'])
        for name in ('registry_history_authenticated', 'live_state_authenticated', 'allocation_authorized'):
            self.assertFalse(receipt[name])
        self.assertEqual(len(set(c['tbs_sha256'] for c in receipt['certificates'])), 11)
        self.assertEqual(len(list(self.output.glob('credential-*.der'))), 11)
        self.assertEqual(len(list(self.output.glob('holder-*.pem'))), 11)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for word in (str(self.root), 'PRIVATE-MOCK', '.pem', 'BEGIN'):
            self.assertNotIn(word, json.dumps(receipt))
        membership = json.loads((self.output / 'membership.json').read_text())
        self.assertEqual(membership['issuer_hash'], '111')
        self.assertEqual(membership['holder_policy_hash'], '222')
        self.assertEqual(receipt['membership_sha256'], tool.keys.file_sha(self.output / 'membership.json'))
        self.assertEqual(json.loads((self.output / 'cohort-receipt.json').read_text()), receipt)

    def test_malformed_future_mismatched_freeze_rejects_before_keys(self):
        for field, value in [('schema', 'wrong'), ('frozen_at_unix_ns', 5000),
                             ('identities', {}), ('source_sha256', {}),
                             ('forbidden_public_key_sha256', []), ('extra', True)]:
            original = dict(self.boundary)
            self.boundary[field] = value
            with self.subTest(field=field), mock.patch.object(tool.keys, '_new_key') as gen, self.assertRaises(ValueError):
                self.prepare()
            gen.assert_not_called()
            self.assertFalse(self.output.exists())
            self.boundary = original

    def test_duplicate_and_previously_recorded_keys_reject_without_publication(self):
        key_list = [self.key(i) for i in range(12)]
        key_list[-1] = key_list[1]
        with self.assertRaises(ValueError):
            self.prepare(key_list)
        self.boundary['forbidden_public_key_sha256'] = [hashlib.sha256(b'public-0').hexdigest()]
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_wrong_holder_or_aki_and_repeated_signed_tbs_are_not_admitted(self):
        for field, value in [('holder_modulus', 3), ('aki', b'wrong'), ('tbs', b'same' * 168)]:
            def bad(der, modulus):
                return {**self.parsed(der, modulus), field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.prepare(admitted=bad)
            self.assertFalse(self.output.exists())

    def test_profile_and_encoder_are_bounded(self):
        with self.assertRaises(ValueError):
            self.prepare(encoder='unknown')
        with self.assertRaises(ValueError):
            self.prepare(max_seconds=301)
        self.assertFalse(self.output.exists())

    def test_deadline_and_unsafe_output_reject_before_generation(self):
        with mock.patch.object(tool.time, 'monotonic', side_effect=[0, 181]), self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.output.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_freeze_digest_and_permissions_are_checked(self):
        digest = self.save()
        with mock.patch.object(tool.keys, '_ignored', return_value=True), \
             mock.patch.object(tool.keys, '_new_key') as gen:
            with self.assertRaises(ValueError):
                tool.prepare(self.freeze, '0' * 64, self.output)
            self.freeze.chmod(0o644)
            with self.assertRaises(ValueError):
                tool.prepare(self.freeze, digest, self.output)
            gen.assert_not_called()

    def test_mid_publication_failure_cleans_fresh_outputs(self):
        real_write = tool.issuance._write
        count = 0
        def fail(*args):
            nonlocal count
            count += 1
            if count == 3:
                raise OSError('mock write failure')
            return real_write(*args)
        with mock.patch.object(tool.issuance, '_write', side_effect=fail), self.assertRaises(OSError):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertTrue(self.freeze.exists())


if __name__ == '__main__':
    unittest.main()
