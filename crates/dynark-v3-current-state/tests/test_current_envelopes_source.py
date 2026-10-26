"""Source-only authority-shape checks; Rust signature/behavior tests are separate."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CurrentEnvelopeSourceTests(unittest.TestCase):
    def test_join_accepts_only_opaque_current_batch_and_signed_envelopes(self):
        path = ROOT / 'src/current_envelopes.rs'
        self.assertTrue(path.is_file(), 'same-batch join missing')
        source = path.read_text()
        self.assertTrue('impl AuthenticatedV3Current' in source)
        self.assertTrue('pub fn authenticate_detached_envelopes(' in source)
        self.assertTrue('publisher.check_current_envelopes(' in source)
        self.assertTrue('registry: self.queue_account().to_bytes()' in source)
        self.assertTrue('source_key: issuer.source.to_bytes()' in source)
        self.assertTrue('clock_unix: self.clock().unix_timestamp' in source)
        self.assertTrue('self.validated_at()' in source)

    def test_join_result_keeps_current_batch_private_and_grants_no_proof_authority(self):
        path = ROOT / 'src/current_envelopes.rs'
        self.assertTrue(path.is_file(), 'opaque envelope result missing')
        source = path.read_text()
        self.assertTrue("current: &'a AuthenticatedV3Current" in source)
        self.assertNotIn('pub current:', source)
        self.assertNotIn('ValidatedAssignment', source)
        self.assertNotIn('dynark_bn254::prove', source)
        self.assertNotIn('impl AuthenticatedV3State', source)


if __name__ == '__main__':
    unittest.main()
