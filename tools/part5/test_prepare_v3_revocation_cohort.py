import hashlib
import unittest

from tools.part5.prepare_v3_revocation_cohort import membership_for_pair, membership_for_sequence
from tools.part5.registry_v3_vectors import h, leaf


class RevocationCohortTest(unittest.TestCase):
    def test_unrelated_revocation_preserves_own_active_leaf(self):
        own = hashlib.sha256(b'signed own TBS').digest()
        other = hashlib.sha256(b'signed unrelated TBS').digest()
        membership = membership_for_pair(own, other, 44)
        self.assertEqual(membership['unrelated_slot'], 45)
        self.assertEqual(membership['own_tbs_digest'], own.hex())
        self.assertEqual(membership['unrelated_tbs_digest'], other.hex())
        self.assertEqual(sum(a != b for a, b in zip(
            membership['active_siblings'], membership['unrelated_siblings'])), 1)
        for state in ('active', 'unrelated'):
            node = leaf(own, 44, True)
            for level, sibling in enumerate(membership[state + '_siblings']):
                node = h((node, sibling) if not (44 >> level) & 1 else (sibling, node))
            self.assertEqual(node, membership[state + '_root'])
        self.assertNotEqual(membership['active_root'], membership['unrelated_root'])
        self.assertNotEqual(membership['unrelated_root'], membership['own_revoked_root'])

    def test_invalid_pair_cannot_be_allocated(self):
        own = hashlib.sha256(b'one').digest()
        for other, slot in ((own, 1), (bytes(32), 1), (hashlib.sha256(b'two').digest(), 1024)):
            with self.assertRaises(ValueError):
                membership_for_pair(own, other, slot)

    def test_frozen_ten_update_schedule_has_distinct_roots_and_one_changed_holder_sibling(self):
        digests = [hashlib.sha256(('signed TBS %d' % index).encode()).digest()
                   for index in range(11)]
        sequence = membership_for_sequence(digests[0], digests[1:])
        self.assertEqual(sequence['holder_slot'], 0)
        self.assertEqual(sequence['unrelated_slots'], list(range(16, 26)))
        self.assertEqual(len(sequence['roots']), 11)
        self.assertEqual(len(set(sequence['roots'])), 11)
        self.assertEqual(sequence['tbs_digests'], [value.hex() for value in digests])
        for index, (root, path) in enumerate(zip(sequence['roots'], sequence['holder_siblings'])):
            node = leaf(digests[0], 0, True)
            for sibling in path:
                node = h((node, sibling))
            self.assertEqual(node, root)
            if index:
                self.assertEqual([level for level, (a, b) in enumerate(zip(
                    sequence['holder_siblings'][0], path)) if a != b], [4])

    def test_frozen_schedule_rejects_duplicate_or_missing_signed_leaf_digest(self):
        digests = [hashlib.sha256(('signed TBS %d' % index).encode()).digest()
                   for index in range(11)]
        for bad in (digests[:10], digests[:10] + [digests[0]],
                    digests[:10] + [bytes(32)], digests[:10] + [b'short']):
            with self.assertRaises(ValueError):
                membership_for_sequence(bad[0], bad[1:])


if __name__ == '__main__':
    unittest.main()
