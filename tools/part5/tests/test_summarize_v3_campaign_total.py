import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.part5 import summarize_v3_campaign_total as tool


class CampaignTotalSummaryTests(unittest.TestCase):
    def pair(self, count, repetition, full, anchor, common, full_clone, anchor_clone):
        full_total = full + common + full_clone
        anchor_total = anchor + common + anchor_clone
        return (
            {'target_count': count, 'repetition': repetition, 'status': 'matched',
             'full_session_wall_seconds': full, 'anchor_session_wall_seconds': anchor,
             'full_sampled_peak_owned_tree_rss_bytes': 1000 + repetition,
             'anchor_sampled_peak_owned_tree_rss_bytes': 2000 + repetition,
             'full_sampled_peak_storage_growth_bytes': 3000 + repetition,
             'anchor_sampled_peak_storage_growth_bytes': 4000 + repetition},
            {'target_count': count, 'repetition': repetition, 'status': 'derived',
             'shared_signed_state_seconds': common,
             'full_clone_seconds': full_clone, 'anchor_clone_seconds': anchor_clone,
             'full_component_sum_seconds': full_total,
             'anchor_component_sum_seconds': anchor_total},
        )

    def fixtures(self):
        economics_pairs, total_pairs = [], []
        for rep in range(1, 5):
            for count in (0, 1):
                if count == 0:
                    full, anchor = 100.0 + rep, 120.0 + rep
                    common, full_clone, anchor_clone = 10.0, 1.0, 2.0
                else:
                    full, anchor = 200.0 + rep, 140.0 + rep
                    common, full_clone, anchor_clone = 20.0, 1.0, 2.0
                econ, total = self.pair(count, rep, full, anchor, common,
                                        full_clone, anchor_clone)
                economics_pairs.append(econ)
                total_pairs.append(total)
        economics = {'schema': 'part5-v3-campaign-economics-report-v1',
                     'training_only': True, 'grid_complete': False,
                     'pairs': economics_pairs}
        reconciler = {
            'schema': 'part5-v3-campaign-observed-component-costs-v1',
            'training_only': True,
            'directly_timed_whole_application_session': False,
            'matrix_manifest_sha256': 'a' * 64,
            'economics_report_sha256': 'b' * 64,
            'pairs': total_pairs,
            'one_time': {'development_setup_seconds': 500.0,
                         'cohort_preparation_seconds': 700.0,
                         'charged_per_request': False},
        }
        return economics, reconciler

    def complete_fixtures(self):
        economics_pairs, total_pairs = [], []
        crossing = {1: 0, 2: 2, 3: 5, 4: None}
        for rep in range(1, 5):
            for count in tool.COUNTS:
                full, common, full_clone, anchor_clone = 100.0, 10.0, 1.0, 2.0
                anchor = 90.0 if crossing[rep] is not None and count >= crossing[rep] else 110.0
                if rep == 1 and count == 0:
                    anchor = full + full_clone - anchor_clone
                econ, total = self.pair(count, rep, full, anchor, common,
                                        full_clone, anchor_clone)
                economics_pairs.append(econ)
                total_pairs.append(total)
        economics = {'schema': 'part5-v3-campaign-economics-report-v1',
                     'training_only': True, 'grid_complete': True,
                     'pairs': economics_pairs}
        reconciler = {
            'schema': 'part5-v3-campaign-observed-component-costs-v1',
            'training_only': True,
            'directly_timed_whole_application_session': False,
            'matrix_manifest_sha256': 'a' * 64,
            'economics_report_sha256': 'b' * 64,
            'pairs': total_pairs,
            'one_time': {'development_setup_seconds': 500.0,
                         'cohort_preparation_seconds': 700.0,
                         'charged_per_request': False},
        }
        return economics, reconciler

    def test_reports_paired_signs_and_first_crossing_distribution(self):
        economics, reconciler = self.complete_fixtures()
        report = tool.summarize(reconciler, economics)

        self.assertEqual(report['matched_pairs'], 20)
        self.assertEqual(report['by_update_count']['0']['paired_sign_counts'],
                         {'full_minus_anchor_positive': 0,
                          'full_minus_anchor_zero': 1,
                          'full_minus_anchor_negative': 3,
                          'matched_pairs': 4, 'expected_pairs': 4})
        self.assertEqual(report['by_update_count']['2']['paired_sign_counts'],
                         {'full_minus_anchor_positive': 2,
                          'full_minus_anchor_zero': 0,
                          'full_minus_anchor_negative': 2,
                          'matched_pairs': 4, 'expected_pairs': 4})
        self.assertEqual(report['break_even']['first_crossing_distribution'], {
            'by_sampled_k': {'0': 0, '1': 1, '2': 1, '5': 1, '10': 0},
            'not_crossed_through_k10': 1,
            'incomplete': 0,
            'expected_repetitions': 4,
        })
        self.assertEqual(report['break_even']['measured_median'], {
            'status': 'crossed', 'first_sampled_k': 5,
            'previous_sampled_k': 2,
            'basis': 'first sampled k with positive median of four paired Full-minus-Anchor totals',
        })

    def test_summarizes_total_pair_costs_spread_break_even_and_target(self):
        economics, reconciler = self.fixtures()
        report = tool.summarize(reconciler, economics)

        self.assertEqual(report['matched_pairs'], 8)
        k1 = report['by_update_count']['1']
        self.assertEqual(k1['matched_pairs'], 4)
        self.assertGreater(k1['median_total_wall_savings_fraction'], 0.20)
        self.assertEqual(k1['registered_20_percent_total_wall_target'], 'met_by_median')
        self.assertLessEqual(k1['fraction_min'], k1['median_total_wall_savings_fraction'])
        self.assertGreaterEqual(k1['fraction_max'], k1['median_total_wall_savings_fraction'])
        self.assertEqual(report['pairs'][1]['anchor_sampled_peak_owned_tree_rss_bytes'], 2001)

        rep1 = report['break_even']['per_repetition']['1']
        self.assertEqual(rep1['first_positive_pair_k'], 1)
        self.assertEqual(rep1['status'], 'crossed')
        self.assertEqual(report['break_even']['measured_median']['status'], 'incomplete')
        self.assertEqual(report['one_time_costs']['charged_per_request'], False)
        self.assertFalse(report['cpu']['complete_tree_cpu_qualified'])
        self.assertFalse(report['extrapolation_used'])

    def test_reports_available_effect_transaction_metrics_from_economics(self):
        economics, reconciler = self.fixtures()
        economics['application_effect_costs'] = {
            'transaction_bytes_available': True,
            'compute_units_available': True,
            'fee_lamports_available': True,
            'confirmed_rpc_metrics': {'by_mode': {
                'full': {'available_samples': 1, 'sampled_values': [
                    {'target_count': 1, 'repetition': 1,
                     'transaction_bytes': 825, 'compute_units': 185532,
                     'fee_lamports': 5000}]},
                'anchor': {'available_samples': 1, 'sampled_values': [
                    {'target_count': 1, 'repetition': 1,
                     'transaction_bytes': 903, 'compute_units': 190000,
                     'fee_lamports': 5000}]},
                'coalesced-full': {'available_samples': 0, 'sampled_values': []},
            }},
        }
        report = tool.summarize(reconciler, economics)
        resources = report['resource_limits']
        self.assertTrue(resources['transaction_bytes_available'])
        self.assertTrue(resources['compute_units_available'])
        self.assertTrue(resources['fee_lamports_available'])
        self.assertEqual(resources['confirmed_application_effect_metric_sessions'], 2)
        self.assertEqual(resources['confirmed_rpc_metrics_by_mode']['anchor']['sampled_values'],
                         [{'target_count': 1, 'repetition': 1,
                           'transaction_bytes': 903, 'compute_units': 190000,
                           'fee_lamports': 5000}])

    def test_rejects_effect_metric_count_without_matching_samples(self):
        economics, reconciler = self.fixtures()
        economics['application_effect_costs'] = {
            'transaction_bytes_available': True,
            'compute_units_available': True,
            'fee_lamports_available': True,
            'confirmed_rpc_metrics': {'by_mode': {
                'full': {'available_samples': 1, 'sampled_values': []},
                'anchor': {'available_samples': 0, 'sampled_values': []},
                'coalesced-full': {'available_samples': 0, 'sampled_values': []},
            }},
        }
        with self.assertRaisesRegex(ValueError, 'sample count'):
            tool.summarize(reconciler, economics)

    def test_carries_training_matrix_grid_completeness(self):
        economics, reconciler = self.complete_fixtures()
        economics['grid_complete'] = False
        self.assertFalse(tool.summarize(reconciler, economics)['matrix_grid_complete'])
        economics['grid_complete'] = True
        self.assertTrue(tool.summarize(reconciler, economics)['matrix_grid_complete'])

    def test_break_even_is_incomplete_when_an_earlier_sample_is_missing(self):
        economics, reconciler = self.fixtures()
        economics['pairs'] = [row for row in economics['pairs']
                              if not (row['target_count'] == 0 and row['repetition'] == 2)]
        reconciler['pairs'] = [row for row in reconciler['pairs']
                               if not (row['target_count'] == 0 and row['repetition'] == 2)]
        report = tool.summarize(reconciler, economics)
        self.assertEqual(report['break_even']['per_repetition']['2']['status'], 'incomplete')
        self.assertIsNone(report['break_even']['per_repetition']['2']['first_positive_pair_k'])
        self.assertEqual(report['break_even']['first_crossing_distribution']['incomplete'], 1)

    def test_rejects_pair_rows_that_do_not_match_or_reconcile(self):
        economics, reconciler = self.fixtures()
        reconciler['pairs'][0]['anchor_component_sum_seconds'] += 1
        with self.assertRaisesRegex(ValueError, 'component total mismatch'):
            tool.summarize(reconciler, economics)

    def test_pinned_input_loader_checks_matrix_and_economics_hashes(self):
        economics, reconciler = self.fixtures()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            matrix_path = root / 'matrix.json'
            econ_path = root / 'economics.json'
            rec_path = root / 'reconciled.json'
            matrix = {'schema': 'fixture-matrix'}
            matrix_path.write_text(json.dumps(matrix))
            econ_raw = json.dumps(economics).encode()
            econ_path.write_bytes(econ_raw)
            reconciler['matrix_manifest_sha256'] = hashlib.sha256(
                (json.dumps(matrix, sort_keys=True, separators=(',', ':')) + '\n').encode()
            ).hexdigest()
            reconciler['economics_report_sha256'] = hashlib.sha256(econ_raw).hexdigest()
            rec_path.write_text(json.dumps(reconciler))

            report = tool.load_and_summarize(rec_path, matrix_path, econ_path)
            self.assertEqual(report['matched_pairs'], 8)

            econ_path.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'economics report pin mismatch'):
                tool.load_and_summarize(rec_path, matrix_path, econ_path)


if __name__ == '__main__':
    unittest.main()
