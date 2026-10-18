import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.part5 import model_v3_heldout_break_even as model


class HeldoutConditionalBreakEvenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.heldout = {
            'schema': model.HELDOUT_SCHEMA,
            'assembled_manifest_sha256': 'c' * 64,
            'acceptance_report_sha256': 'd' * 64,
            'pairs': [{'variant': v, 'full_B_seconds': 100.0,
                       'anchor_B_seconds': 105.0,
                       'pair_view_one_time_seconds': 2.0}
                      for v in range(8)],
        }
        self.training = {
            'schema': model.TRAINING_SCHEMA,
            'training_only': True,
            'matrix_grid_complete': True,
            'source_hashes': {
                'matrix_manifest_sha256': 'e' * 64,
                'sequence_receipt_sha256': 'c' * 64,
                'economics_report_sha256': 'f' * 64,
            },
            'matched_pairs': 20,
            'expected_pairs': 20,
            'pairs': [],
        }
        for repetition in range(1, 5):
            for count in model.COUNTS:
                self.training['pairs'].append({
                    'repetition': repetition,
                    'target_count': count,
                    'status': 'matched',
                    'full_total_wall_seconds': 100.0,
                    'anchor_total_wall_seconds': 110.0,
                })

    def _pinned(self, name, value):
        path = self.root / name
        raw = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()
        path.write_bytes(raw)
        return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

    def test_reports_no_crossing_and_keeps_transferred_values_model_labeled(self):
        result = model.build(self.heldout, self.training,
                             'a' * 64, 'b' * 64)

        self.assertEqual(result['schema'], model.OUTPUT_SCHEMA)
        self.assertEqual(result['source_hashes'], {
            'matrix_manifest_sha256': 'e' * 64,
            'sequence_receipt_sha256': 'c' * 64,
            'economics_report_sha256': 'f' * 64,
        })
        self.assertEqual(len(result['variants']), 8)
        self.assertEqual(result['pooled_first_crossing_counts'], {
            '0': 0, '1': 0, '2': 0, '5': 0, '10': 0,
            'not_crossed_through_k10': 32,
            'expected_variant_repetition_pairs': 32,
        })
        first = result['variants'][0]
        self.assertEqual(first['direct_heldout_k1'], {
            'full_B_seconds': 100.0,
            'anchor_B_seconds': 105.0,
            'pair_view_one_time_seconds': 2.0,
            'observed_anchor_minus_full_seconds': 5.0,
        })
        self.assertEqual(first['per_repetition'][0]['first_crossing'],
                         'not_crossed_through_k10')
        self.assertEqual(first['per_repetition'][0]['deltas'][0], {
            'target_count': 0, 'anchor_minus_full_seconds': 5.0,
            'basis': 'model/inference',
        })
        self.assertFalse(result['claims']['cpu_savings'])
        self.assertFalse(result['claims']['winner'])
        self.assertFalse(result['interpolation_or_extrapolation_used'])

    def test_reports_first_sampled_crossing_and_k1_calibrates_to_direct(self):
        for pair in self.training['pairs']:
            if pair['target_count'] == 2:
                pair['anchor_total_wall_seconds'] = 90.0
        result = model.build(self.heldout, self.training,
                             'a' * 64, 'b' * 64)

        self.assertEqual(result['pooled_first_crossing_counts']['2'], 32)
        first = result['variants'][0]
        self.assertEqual(first['per_repetition'][0]['first_crossing'], 2)
        deltas = {row['target_count']: row
                  for row in first['per_repetition'][0]['deltas']}
        self.assertEqual(deltas[1]['anchor_minus_full_seconds'], 5.0)
        self.assertEqual(deltas[1]['basis'], 'direct heldout k1 calibration')
        self.assertEqual(deltas[2]['basis'], 'model/inference')

    def test_equal_conditional_cost_is_not_a_crossing(self):
        for pair in self.training['pairs']:
            if pair['target_count'] == 2:
                pair['anchor_total_wall_seconds'] = 105.0
            elif pair['target_count'] == 5:
                pair['anchor_total_wall_seconds'] = 104.0
        result = model.build(self.heldout, self.training,
                             'a' * 64, 'b' * 64)
        first = result['variants'][0]['per_repetition'][0]
        self.assertEqual(first['deltas'][2]['anchor_minus_full_seconds'], 0.0)
        self.assertEqual(first['first_crossing'], 5)
        self.assertEqual(result['method']['first_crossing'],
                         'first sampled k with D_vrk < 0')

    def test_rejects_complete_matched_pairs_when_matrix_grid_is_incomplete(self):
        self.training['matrix_grid_complete'] = False
        self.assertEqual(len(self.training['pairs']), 20)
        with self.assertRaisesRegex(ValueError, 'matrix grid complete'):
            model.build(self.heldout, self.training, 'a' * 64, 'b' * 64)

    def test_rejects_incomplete_training_pair_grid(self):
        self.training['pairs'].pop()
        with self.assertRaisesRegex(ValueError, 'complete 4x5'):
            model.build(self.heldout, self.training, 'a' * 64, 'b' * 64)

    def test_rejects_tampered_input_pin(self):
        heldout_pin = self._pinned('heldout.json', self.heldout)
        training_pin = self._pinned('training.json', self.training)
        with (Path(heldout_pin['path'])).open('ab') as stream:
            stream.write(b' ')
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            model.load_and_build(heldout_pin, training_pin)

    def test_rejects_nonpositive_or_nonfinite_heldout_totals(self):
        self.heldout['pairs'][0]['full_B_seconds'] = 0
        with self.assertRaisesRegex(ValueError, 'finite positive'):
            model.build(self.heldout, self.training, 'a' * 64, 'b' * 64)

        self.heldout['pairs'][0]['full_B_seconds'] = 10 ** 1000
        with self.assertRaisesRegex(ValueError, 'finite positive'):
            model.build(self.heldout, self.training, 'a' * 64, 'b' * 64)

    def test_rejects_missing_or_malformed_evidence_hashes(self):
        for field in ('assembled_manifest_sha256', 'acceptance_report_sha256'):
            heldout = dict(self.heldout)
            heldout[field] = 'not-a-sha'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'SHA-256'):
                model.build(heldout, self.training, 'a' * 64, 'b' * 64)

        training = dict(self.training)
        training['source_hashes'] = dict(self.training['source_hashes'])
        training['source_hashes']['matrix_manifest_sha256'] = None
        with self.assertRaisesRegex(ValueError, 'source hash'):
            model.build(self.heldout, training, 'a' * 64, 'b' * 64)

    def test_rejects_missing_or_malformed_training_sequence_receipt_hash(self):
        for pin in (None, 'z' * 64, 'c' * 63):
            training = dict(self.training)
            training['source_hashes'] = dict(self.training['source_hashes'])
            if pin is None:
                training['source_hashes'].pop('sequence_receipt_sha256')
            else:
                training['source_hashes']['sequence_receipt_sha256'] = pin
            with self.subTest(pin=pin), self.assertRaisesRegex(
                    ValueError, 'sequence-receipt'):
                model.build(self.heldout, training, 'a' * 64, 'b' * 64)

    def test_rejects_training_summary_with_wrong_pair_accounting(self):
        for field, value in (('matched_pairs', 19), ('expected_pairs', 20.0)):
            training = dict(self.training)
            training[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, '20 matched'):
                model.build(self.heldout, training, 'a' * 64, 'b' * 64)

    def test_rejects_arithmetic_overflow(self):
        for pair in self.training['pairs']:
            if pair['target_count'] == 0:
                pair['anchor_total_wall_seconds'] = 1e308
                pair['full_total_wall_seconds'] = 1.0
            elif pair['target_count'] == 1:
                pair['anchor_total_wall_seconds'] = 1.0
                pair['full_total_wall_seconds'] = 1e308
        with self.assertRaisesRegex(ValueError, 'conditional derived delta must be finite'):
            model.build(self.heldout, self.training, 'a' * 64, 'b' * 64)


if __name__ == '__main__':
    unittest.main()
