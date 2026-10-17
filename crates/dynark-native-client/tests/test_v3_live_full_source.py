"""Source-only gate-order checks; these do not qualify a Full proof or live RPC."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LiveFullSourceTests(unittest.TestCase):
    def test_bound_entry_requires_concrete_state_and_all_math_gates(self):
        source = (ROOT / 'src/v3_binding.rs').read_text()
        for required in ['V3RequestStateSource', 'input.state.authenticate(', 'input.worker.build(',
                         'V3CheckedRelation::check(', 'checked.into_assignment()',
                         'dynark_bn254::prove(', 'rand::rngs::OsRng', 'verify_bound_statement(']:
            self.assertTrue(required in source, required)
        self.assertNotIn("state: &'a dyn AuthenticatedV3State", source)
        self.assertGreaterEqual(source.count('input.state.authenticate('), 3)

    def test_history_is_replayed_against_chain_derived_enrollment_and_heads(self):
        path = ROOT / 'src/v3_live_state.rs'
        self.assertTrue(path.is_file(), 'concrete state source missing')
        source = path.read_text()
        for required in ['verify_current(', 'authenticate_detached_envelopes(',
                         'HistoricalReplay::new(', 'replay.apply(', 'replay.source_head()',
                         'replay.publication_digest()', 'replay.active_holder(',
                         'source_key: issuer.source.to_bytes()', 'SystemTime::now()',
                         'request.metas.len() != 2']:
            self.assertTrue(required in source, required)
        self.assertNotIn('membership: &HistoricalMembership', source)


if __name__ == '__main__':
    unittest.main()
