import json
from pathlib import Path
import tempfile
import unittest

from tools.part5 import assemble_v3_heldout_acceptance as assembler


class HeldoutAcceptanceAssemblerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.artifact = self.root / 'pin.bin'
        self.artifact.write_bytes(b'pinned reference')
        self.artifact.chmod(0o600)
        self.ref = {'path': str(self.artifact),
                    'sha256': assembler._sha(self.artifact.read_bytes())}
        self.globals = {
            'freeze_receipt': self.ref,
            'cohort_receipt': self.ref,
            'cohort_observation': self.ref,
            'frozen_files': {role: self.ref for role in assembler.FROZEN_ROLES},
            'frozen_bundles': {
                name: [{'path': f'{name}/file', 'artifact': self.ref}]
                for name in ('registry', 'client')},
            'application_source_manifest': self.ref,
            'application_source_files': {'src/file.rs': self.ref},
            'source_files': {role: self.ref for role in assembler.SOURCE_ROLES},
            'proof_inputs': {role: self.ref for role in assembler.PROOF_ROLES},
        }
        self.fragments = []
        for variant in range(8):
            branch_costs = {
                name: {'proof_seconds': 1.0, 'clone_seconds': 2.0,
                       'effect_seconds': 3.0, 'total_seconds': 6.0}
                for name in ('full', 'unrelated_full', 'anchor')}
            branch_costs['own_revocation'] = {
                'proof_seconds': 1.0, 'clone_seconds': 2.0,
                'effect_seconds': 3.0, 'r2_active_witness_seconds': 4.0,
                'total_seconds': 10.0}
            payload = {
                'variant': variant,
                'case_context': self.ref,
                'stage_context': self.ref,
                'pair_receipt': self.ref,
                'membership': self.ref,
                'stage': {slot: {'report': self.ref} for slot in 'ABC'},
                'transition': {slot: {'report': self.ref} for slot in 'ABC'},
                'sources': {slot: {'R0': {'receipt': self.ref, 'artifacts': {}},
                                   'R1': {'receipt': self.ref, 'artifacts': {}}}
                            for slot in 'ABC'},
                'branches': {
                    name: ({'result': {'report': self.ref},
                            'current_r2_witness_rejection': self.ref}
                           if name == 'own_revocation'
                           else {'result': {'report': self.ref}})
                    for name in ('full', 'unrelated_full', 'anchor',
                                 'own_revocation')},
                'run_manifest': self.ref,
                'run_journal': self.ref,
                'all_step_wall_seconds': {'step': 1.0},
                'shared_costs': {'shared_stage_seconds': 2.0,
                                 'shared_transition_seconds': 3.0},
                'branch_wall_components': branch_costs,
                'branch_wall_seconds': {name: 6.0 for name in branch_costs},
                'shared_stage_transition_wall_seconds': {
                    'stage': {slot: 1.0 for slot in 'ABC'},
                    'transition': {slot: 1.0 for slot in 'ABC'}},
                'branch_order': (['unrelated_full', 'anchor'] if variant % 2 == 0
                                 else ['anchor', 'unrelated_full']),
                'proof_order': {'unrelated_compare': (
                    ['full', 'anchor'] if variant % 2 == 0 else ['anchor', 'full'])},
            }
            case_dir = self.root / f'case-{variant}'
            case_dir.mkdir(mode=0o700)
            path = case_dir / 'acceptance-case-fragment.json'
            path.write_text(json.dumps({
                'schema': assembler.FRAGMENT_SCHEMA, 'variant': variant,
                **self.globals, **payload,
            }))
            path.chmod(0o600)
            self.fragments.append(path)

    def assemble(self, paths=None):
        paths = self.fragments if paths is None else paths
        refs = [(path, assembler._sha(path.read_bytes())) for path in paths]
        return assembler.assemble(refs)

    def test_assembles_exactly_eight_cases_in_variant_order(self):
        manifest = self.assemble()
        self.assertEqual(manifest['schema'], assembler.MANIFEST_SCHEMA)
        self.assertEqual([case['variant'] for case in manifest['cases']], list(range(8)))
        self.assertEqual(manifest['proof_inputs'], self.globals['proof_inputs'])
        self.assertEqual(manifest['cases'][0]['run_journal'], self.ref)
        self.assertEqual(manifest['cases'][0]['branch_order'],
                         ['unrelated_full', 'anchor'])
        self.assertEqual(manifest['cases'][1]['proof_order'],
                         {'unrelated_compare': ['anchor', 'full']})
        self.assertIn('all_step_wall_seconds', manifest['cases'][0])
        self.assertEqual(manifest['cases'][0]['run_manifest'], self.ref)

    def test_own_revocation_requires_pinned_current_r2_witness_rejection(self):
        changed = json.loads(self.fragments[0].read_text())
        changed['branches']['own_revocation']['current_r2_witness_rejection'] = self.ref
        self.fragments[0].write_text(json.dumps(changed))
        manifest = self.assemble()
        self.assertEqual(
            manifest['cases'][0]['branches']['own_revocation'][
                'current_r2_witness_rejection'], self.ref)

        changed = json.loads(self.fragments[0].read_text())
        del changed['branches']['own_revocation']['current_r2_witness_rejection']
        self.fragments[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'current-R2 witness rejection'):
            self.assemble()

    def test_own_revocation_rejection_receipt_must_have_exact_ref_shape(self):
        changed = json.loads(self.fragments[0].read_text())
        changed['branches']['own_revocation']['current_r2_witness_rejection'] = {
            **self.ref, 'unexpected': True}
        self.fragments[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'absolute pinned artifact reference'):
            self.assemble()

    def test_own_revocation_rejection_receipt_must_be_a_valid_pin(self):
        changed = json.loads(self.fragments[0].read_text())
        changed['branches']['own_revocation']['current_r2_witness_rejection'] = {
            'path': str(self.artifact), 'sha256': '0' * 64}
        self.fragments[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'artifact reference pin mismatch'):
            self.assemble()

    def test_rejects_missing_pinned_run_manifest(self):
        changed = json.loads(self.fragments[0].read_text())
        del changed['run_manifest']
        self.fragments[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'complete normalized heldout case'):
            self.assemble()

    def test_rejects_missing_cost_evidence(self):
        changed = json.loads(self.fragments[0].read_text())
        del changed['branch_order']
        self.fragments[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'complete normalized heldout case'):
            self.assemble()

    def test_own_revocation_cost_requires_r2_active_witness_component(self):
        changed = json.loads(self.fragments[0].read_text())
        del changed['branch_wall_components']['own_revocation'][
            'r2_active_witness_seconds']
        self.fragments[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError,
                                    'complete finite own_revocation wall-time components'):
            self.assemble()

    def test_rejects_incorrect_order_parity(self):
        changed = json.loads(self.fragments[0].read_text())
        changed['branch_order'] = ['anchor', 'unrelated_full']
        self.fragments[0].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'registered branch/proof order'):
            self.assemble()

    def test_rejects_duplicate_variant(self):
        duplicate = json.loads(self.fragments[7].read_text())
        duplicate['variant'] = 6
        self.fragments[7].write_text(json.dumps(duplicate))
        with self.assertRaisesRegex(ValueError, 'duplicate heldout variant'):
            self.assemble()

    def test_rejects_common_identity_mismatch(self):
        changed = json.loads(self.fragments[7].read_text())
        changed['cohort_receipt'] = {'path': str(self.artifact), 'sha256': '0' * 64}
        self.fragments[7].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'common identities'):
            self.assemble()

    def test_requires_same_pinned_cohort_observation_for_all_cases(self):
        for path in self.fragments:
            changed = json.loads(path.read_text())
            changed['cohort_observation'] = self.ref
            path.write_text(json.dumps(changed))
        manifest = self.assemble()
        self.assertEqual(manifest['cohort_observation'], self.ref)

        changed = json.loads(self.fragments[7].read_text())
        changed['cohort_observation'] = {'path': str(self.artifact),
                                         'sha256': '0' * 64}
        self.fragments[7].write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'common identities'):
            self.assemble()

    def test_rejects_missing_slot_or_variant(self):
        missing_slot = json.loads(self.fragments[0].read_text())
        del missing_slot['sources']['A']['R1']
        self.fragments[0].write_text(json.dumps(missing_slot))
        with self.assertRaisesRegex(ValueError, 'A/B/C slot evidence'):
            self.assemble()
        with self.assertRaisesRegex(ValueError, 'exactly eight'):
            self.assemble(self.fragments[:7])

    def test_rejects_wrong_artifact_hash(self):
        bad = json.loads(self.fragments[0].read_text())
        bad['freeze_receipt'] = {'path': str(self.artifact), 'sha256': '0' * 64}
        self.fragments[0].write_text(json.dumps(bad))
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            self.assemble()

    def test_rejects_fragment_hash_pin_mismatch(self):
        refs = [(path, assembler._sha(path.read_bytes())) for path in self.fragments]
        refs[0] = (refs[0][0], '0' * 64)
        with self.assertRaisesRegex(ValueError, 'fragment SHA-256 pin mismatch'):
            assembler.assemble(refs)


if __name__ == '__main__':
    unittest.main()
