import unittest
from pathlib import Path
import subprocess
import sys
import hashlib
import json
import tempfile
from unittest import mock

from tools.part5 import reconcile_v3_campaign_costs as tool


class CampaignCostReconciliationTests(unittest.TestCase):
    def _matrix_fixture(self, root):
        validated = {'output_root': root, 'campaign_id': 'training-007',
                     'manifest_sha256': 'a' * 64}
        planned = []
        sequence = []
        paths_by_sequence = {}
        previous = None
        for index in range(1, 61):
            path = root / f'slot-{index}.json'
            receipt = {'sequence': index, 'clone_preparation_wall_seconds': 1.0}
            path.write_text(json.dumps(receipt), encoding='utf-8')
            outer_path = root / f'outer-{index}.json'
            outer_path.write_text(json.dumps({
                'started_at_utc': f'start-{index}',
                'ended_at_utc': f'end-{index}'}), encoding='utf-8')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            slot = {'sequence': index, 'identity_sha256': f'{index:064x}'}
            planned.append(slot)
            paths_by_sequence[index] = {'slot_receipt': path,
                                        'outer_report': outer_path}
            sequence.append({'sequence': index, 'slot_identity_sha256': slot['identity_sha256'],
                             'slot_receipt_sha256': digest,
                             'previous_slot_receipt_sha256': previous,
                             'clone_preparation_wall_seconds': 1.0,
                             'outer_started_at_utc': f'start-{index}',
                             'outer_ended_at_utc': f'end-{index}'})
            previous = digest
        sequence_path = root / 'sequence-receipt.json'
        sequence_receipt = {'schema': 'part5-v3-campaign-matrix-sequence-v1',
                            'passed': True, 'cross_session_order_verified': True,
                            'campaign_id': validated['campaign_id'],
                            'manifest_sha256': validated['manifest_sha256'],
                            'sequence_count': 60, 'sequence': sequence,
                            'final_slot_receipt_sha256': previous}
        sequence_path.write_text(json.dumps(sequence_receipt), encoding='utf-8')
        return validated, planned, paths_by_sequence, sequence_path

    def _matrix_patches(self, planned, paths_by_sequence):
        def verify_slot(slot, _validated, paths, _previous, _previous_end):
            digest = hashlib.sha256(paths['slot_receipt'].read_bytes()).hexdigest()
            receipt = json.loads(paths['slot_receipt'].read_text(encoding='utf-8'))
            return digest, receipt
        return {'plan_slots': mock.Mock(return_value=planned),
            'output_paths': mock.Mock(side_effect=lambda _v, slot:
                                      paths_by_sequence[slot['sequence']]),
            'verify_actual_sequence': mock.Mock(return_value=True),
            'verify_existing_slot': mock.Mock(side_effect=verify_slot)}

    def test_reconcile_rejects_missing_current_receipt_before_slot_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            validated, planned, paths, _ = self._matrix_fixture(root)
            paths[20]['slot_receipt'].unlink()
            values = self._matrix_patches(planned, paths)
            with mock.patch.multiple(tool.matrix, **values) as mocks:
                with self.assertRaisesRegex(ValueError, 'all 60 current matrix slot receipts'):
                    tool.verify_completed_matrix(validated)
                self.assertEqual(values['verify_existing_slot'].call_count, 19)

    def test_reconcile_binds_verified_sequence_receipt_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            validated, planned, paths, sequence_path = self._matrix_fixture(root)
            values = self._matrix_patches(planned, paths)
            with mock.patch.multiple(tool.matrix, **values) as mocks:
                expected_sha = hashlib.sha256(sequence_path.read_bytes()).hexdigest()
                with mock.patch.object(tool, 'shared_steps', return_value={'by_count_seconds': {}}), \
                     mock.patch.object(tool, 'clone_costs', return_value={}), \
                     mock.patch.object(tool, 'one_time_costs', return_value={}), \
                     mock.patch.object(tool, 'derive', return_value=[]):
                    report = tool.reconcile(validated, {
                        'schema': 'part5-v3-campaign-economics-report-v1',
                        'pairs': []})
                self.assertEqual(report['sequence_receipt_sha256'], expected_sha)
                values['verify_actual_sequence'].assert_called_once()

    def test_reconcile_rejects_sequence_timestamp_not_in_current_outer_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            validated, planned, paths, _ = self._matrix_fixture(root)
            paths[20]['outer_report'].write_text(json.dumps({
                'started_at_utc': 'different-start',
                'ended_at_utc': 'end-20'}), encoding='utf-8')
            values = self._matrix_patches(planned, paths)
            with mock.patch.multiple(tool.matrix, **values):
                with self.assertRaisesRegex(ValueError, 'sequence entry differs'):
                    tool.verify_completed_matrix(validated)

    def test_common_cost_uses_only_exact_r0_to_rk_transition(self):
        transitions = {1: 11.0, 2: 22.0, 5: 55.0, 10: 110.0}
        self.assertEqual(tool.by_count_seconds(3.0, 7.0, transitions),
                         {0: 10.0, 1: 21.0, 2: 32.0,
                          5: 65.0, 10: 120.0})

    def test_direct_script_help_from_repository_root(self):
        script = Path(tool.__file__).resolve()
        completed = subprocess.run(
            [sys.executable, '-B', str(script), '--help'],
            cwd=script.parents[2], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('--matrix-manifest', completed.stdout)

    def test_common_signed_history_changes_total_fraction_but_not_comparison(self):
        rows = [
            {'target_count': 1, 'repetition': 1, 'status': 'matched',
             'full_session_wall_seconds': 100.0, 'anchor_session_wall_seconds': 150.0,
             'session_wall_savings_fraction': -0.5},
            {'target_count': 1, 'repetition': 2, 'status': 'incomplete'},
        ]
        clones = {(1, 1, 'full'): 0.2, (1, 1, 'anchor'): 0.4}
        report = tool.derive(rows, {1: 80.0}, clones)
        self.assertEqual(report[0]['full_component_sum_seconds'], 180.2)
        self.assertEqual(report[0]['anchor_component_sum_seconds'], 230.4)
        self.assertAlmostEqual(report[0]['full_minus_anchor_component_sum_seconds'], -50.2)
        self.assertLess(report[0]['component_sum_savings_fraction'], 0)
        self.assertGreater(report[0]['component_sum_savings_fraction'], -0.5)
        self.assertEqual(report[1]['status'], 'incomplete')
        self.assertIsNone(report[1]['component_sum_savings_fraction'])

    def test_missing_clone_cost_never_becomes_a_zero_cost_trial(self):
        rows = [{'target_count': 0, 'repetition': 1, 'status': 'matched',
                 'full_session_wall_seconds': 50.0, 'anchor_session_wall_seconds': 45.0}]
        report = tool.derive(rows, {0: 30.0}, {(0, 1, 'full'): 0.2})
        self.assertEqual(report[0]['status'], 'incomplete')
        self.assertIsNone(report[0]['component_sum_savings_fraction'])


if __name__ == '__main__':
    unittest.main()
