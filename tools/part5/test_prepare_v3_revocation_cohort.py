import hashlib
import unittest

from tools.part5.prepare_v3_revocation_cohort import membership_for_pair
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


if __name__ == '__main__':
    unittest.main()
