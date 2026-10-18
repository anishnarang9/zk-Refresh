import unittest
from pathlib import Path
import subprocess
import sys

from tools.part5 import reconcile_v3_campaign_costs as tool


class CampaignCostReconciliationTests(unittest.TestCase):
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
