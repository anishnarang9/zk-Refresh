import unittest
from tools.part5 import prepare_v3_queue_capacity_fixture as fixture


class CapacityFixtureTests(unittest.TestCase):
    def test_zero_update_packet_uses_exact_single_full_mode_and_action(self):
        packet = fixture.single_full_packet(
            {name: name for name in fixture.PACKAGE_FIELDS},
            {'root_version': 0, 'wtns_path': '/private/output.wtns'},
            {'near_root': '1', 'base_root': '1', 'action_hash': '2'},
            'a'*64, 'b'*64, 'c'*64)
        self.assertEqual(packet['schema'], 'credential-v3-cumulative-coalesced-request-v1')
        self.assertEqual(packet['update_count'], 0)
        self.assertEqual(packet['final']['root_version'], 0)
        self.assertNotIn('pairs', packet)
        self.assertEqual(packet['application_stage']['action_hash'], '2')

    def test_single_full_packet_rejects_changed_root_and_nonzero_version(self):
        for spec, app in [({'root_version': 1}, {'base_root': '1', 'near_root': '1'}),
                          ({'root_version': 0}, {'base_root': '1', 'near_root': '2'})]:
            with self.assertRaises(ValueError):
                fixture.single_full_packet({}, spec, app, 'a'*64, 'b'*64, 'c'*64)

    def test_proof_receipt_cannot_claim_validity_with_unbound_action(self):
        with self.assertRaises(ValueError):
            fixture.check_proof_receipt({'schema': fixture.PROOF_SCHEMA},
                                       {'action_sha256':'a'*64}, b'\0'*448)


if __name__ == '__main__':
    unittest.main()
