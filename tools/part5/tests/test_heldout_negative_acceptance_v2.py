import unittest
import json
from tools.part5.tests import test_assemble_v3_heldout_acceptance as fixtures
from tools.part5 import assemble_v3_heldout_acceptance as assembler
from tools.part5 import verify_v3_heldout_acceptance as verifier
from tools.part5 import analyze_v3_heldout_costs as costs

class NegativeAcceptanceV2(unittest.TestCase):
    def test_final_boundary_requires_new_schema(self):
        self.assertTrue(assembler.FRAGMENT_SCHEMA.endswith('-v2'))
        self.assertTrue(assembler.MANIFEST_SCHEMA.endswith('-v2'))
        self.assertEqual(verifier.MANIFEST_SCHEMA, assembler.MANIFEST_SCHEMA)
        self.assertIn('expired_status_negative', assembler.CASE_FIELDS)
        self.assertIn('expired_status_negative_wall_seconds', assembler.CASE_FIELDS)

    def test_v2_assembly_requires_capacity_and_all_eight_expiry_refs(self):
        fixture = fixtures.HeldoutAcceptanceAssemblerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for path in fixture.fragments:
            doc = json.loads(path.read_bytes())
            doc['schema'] = assembler.FRAGMENT_SCHEMA
            doc['expired_status_negative'] = fixture.ref
            doc['expired_status_negative_wall_seconds'] = 6
            path.write_text(json.dumps(doc))
        refs = lambda: [(p, assembler._sha(p.read_bytes())) for p in fixture.fragments]
        with self.assertRaisesRegex(ValueError, 'capacity'):
            assembler.assemble(refs())
        result = assembler.assemble(refs(), fixture.ref, 12)
        self.assertEqual(result['schema'], assembler.MANIFEST_SCHEMA)
        self.assertEqual(len(result['cases']), 8)
        doc = json.loads(fixture.fragments[-1].read_bytes())
        del doc['expired_status_negative']
        fixture.fragments[-1].write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError, 'complete normalized'):
            assembler.assemble(refs(), fixture.ref, 12)

    def test_capacity_stub_cannot_issue_final_acceptance(self):
        fixture = fixtures.HeldoutAcceptanceAssemblerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        # A well-formed reference alone is never runtime capacity evidence.
        with self.assertRaises(ValueError):
            verifier._verify_queue_capacity_negative({'queue_capacity_negative': fixture.ref,
                                                       'queue_capacity_negative_wall_seconds': 1})

    def test_actual_v1_fragments_are_explicitly_core_only(self):
        fixture = fixtures.HeldoutAcceptanceAssemblerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for path in fixture.fragments:
            doc = json.loads(path.read_bytes())
            doc['schema'] = 'credential-v3-heldout-acceptance-case-fragment-v1'
            path.write_text(json.dumps(doc))
        result = fixture.assemble()
        self.assertEqual(result['schema'], 'credential-v3-heldout-acceptance-manifest-v1')
        self.assertEqual(result['evidence_scope'], 'legacy-core-path-only')

    def test_expiry_replay_reopens_finalization_and_snapshot_bytes(self):
        from tools.part5.tests import test_finalize_v3_expired_status_negative as retained
        fixture = retained.FinalizerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        manifest = fixture.with_positive()
        finalized = retained.finalizer.finalize(manifest)
        config = fixture.config
        sidecar = {'schema': 'credential-v3-heldout-expired-status-negative-v1',
            'variant': config['variant'], 'stage_report_sha256': config['stage_report_sha256'],
            'stage_plan_sha256': config['stage_plan_sha256'],
            'r0_source_receipt_sha256': config['source_receipt_sha256'],
            'full_proof_receipt_sha256': config['full_proof_receipt_sha256'],
            'clone_receipt': retained.finalizer.config_ref(config, 'clone_receipt', 'clone_receipt_sha256'),
            'full_wire': retained.finalizer.config_ref(config, 'full_wire', 'full_wire_sha256'),
            'config': manifest['refs']['config'], 'status': manifest['refs']['supervisor_status'],
            'outer': manifest['refs']['monitor'], 'monitor_invocation': manifest['refs']['monitor_invocation'],
            'candidate': manifest['refs']['candidate'],
            'finalizer_manifest': retained.save(fixture.root / 'finalizer-input.json', manifest),
            'finalization': retained.save(fixture.root / 'finalization.json', finalized),
            'report': retained.save(fixture.root / 'final-report.json', finalized['evidence'])}
        ref = retained.save(fixture.root / 'sidecar.json', sidecar)
        _, _, _, replayed = verifier._replay_expired_status_sidecar(ref)
        self.assertEqual(replayed['facts']['custom_error'], 705)
        self.assertEqual(replayed['facts']['instruction_index'], 1)
        self.assertEqual(replayed['facts']['application_account_count'], 5)
        from pathlib import Path
        snapshot = Path(finalized['evidence']['snapshots'][0]['before']['path'])
        snapshot.write_bytes(snapshot.read_bytes() + b'tamper')
        with self.assertRaises(ValueError):
            verifier._replay_expired_status_sidecar(ref)

    def test_expiry_journal_requires_all_steps_and_exact_cost(self):
        names = ('positive_full:expired-status-clone', 'positive_full:expired-status-negative',
                 'positive_full:expired-status-finalize')
        journal = {'steps': {name: {'status': 'passed', 'wall_seconds': i+1}
                             for i, name in enumerate(names)}}
        case = {'expired_status_negative_wall_seconds': 6}
        self.assertEqual(costs._expired_status_cost(case, journal), 6)
        case['expired_status_negative_wall_seconds'] = 5
        with self.assertRaises(ValueError):
            costs._expired_status_cost(case, journal)
        case['expired_status_negative_wall_seconds'] = 6
        del journal['steps'][names[-1]]
        with self.assertRaises(ValueError):
            costs._expired_status_cost(case, journal)

if __name__ == '__main__': unittest.main()
