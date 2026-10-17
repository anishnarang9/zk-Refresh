import json
import tempfile
import unittest
from pathlib import Path

from tools.part5.analyze_v3_campaign_economics import aggregate, make_manifest


class CampaignEconomicsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return str(path)

    def session(self, mode, count, repetition, wall):
        order = [
            ('full', 'anchor', 'coalesced-full'),
            ('anchor', 'coalesced-full', 'full'),
            ('full', 'coalesced-full', 'anchor'),
            ('coalesced-full', 'anchor', 'full'),
        ][repetition - 1]
        return {
            'schema': 'part5-v3-campaign-session-v1',
            'mode': mode,
            'target_count': count,
            'repetition': repetition,
            'registered_order': list(order),
            'registered_order_position': order.index(mode) + 1,
            'passed': True,
            'effect_verified': True,
            'effect_supervisor_status': 'passed',
            'ledger_reuse_requires_review': False,
            'validator_cleanup': {'exit_code': 0, 'reaped': True,
                                  'graceful': True},
            'freeze_sha256': 'a' * 64,
            'cohort_receipt_sha256': 'b' * 64,
            'current_root': f'root-{count}',
            'current_report_sha256': f'{count:064x}',
            'source_identities': {'proof_runner': 'c' * 64},
            'exact_request_sha256': f'{count + 100:064x}',
            'effect_report_sha256': 'f' * 64,
            'total_command_wall_seconds': wall - 0.1,
            'waited_child_cpu_seconds_sum': 2.0,
            'stage_wall_seconds_sum': 3.0,
            'preexisting_signed_history_preparation_charged': False,
            'preexisting_ledger_clone_charged': False,
            'preexisting_state_wait_charged': False,
            'coalesced_state_wait_seconds_observed': None,
            'complete_tree_cpu_qualified': False,
            'stages': [{'stage': 'application', 'exit_code': 0,
                        'wall_seconds': 3.0, 'waited_child_cpu_seconds': 2.0}],
        }

    def outer(self, mode, count, wall):
        return {
            'schema': 1,
            'measurement': 'bounded_complete_session',
            'owner': f'v3-campaign-{mode}-k{count}',
            'duration_seconds': wall,
            'passed': True,
            'censored': False,
            'stop_reason': None,
            'runner_error_type': None,
            'cleanup_remaining_owned_processes': 0,
            'cleanup_status_unknown': False,
            'limits': {'runtime_seconds': 2400,
                       'owned_tree_rss_bytes': 4 * 1024**3,
                       'storage_growth_bytes': 1024**3,
                       'poll_seconds': 0.25},
            'environment': {'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': None,
                            'TZ': 'UTC'},
            'sampled_peak_owned_tree_rss_bytes': 1000,
            'sampled_peak_storage_growth_bytes': 2000,
            'cpu': {'complete_tree_cpu_qualified': False},
        }

    def full_manifest(self, failed_anchor=None, missing_full=None, mismatch=None):
        sessions = []
        for repetition in range(1, 5):
            for count in (0, 1, 2, 5, 10):
                for mode in ('full', 'anchor', 'coalesced-full'):
                    key = (mode, count, repetition)
                    if key == missing_full:
                        continue
                    # Direct measured crossing is first at k=5 in every repetition.
                    full_wall = 10.0 + 2.0 * count
                    anchor_wall = 14.0 + 0.5 * count
                    wall = (full_wall if mode == 'full' else anchor_wall
                            if mode == 'anchor' else 8.0 + count)
                    report = self.session(mode, count, repetition, wall)
                    if key == failed_anchor:
                        report['passed'] = False
                        report['effect_verified'] = False
                        report['error_type'] = 'ValueError'
                    if key == mismatch:
                        report['freeze_sha256'] = 'd' * 64
                    entry = {'mode': mode, 'target_count': count,
                             'repetition': repetition,
                             'session_report': self.write(
                                 f'{mode}-{count}-{repetition}.json', report)}
                    if key != failed_anchor:
                        entry['outer_report'] = self.write(
                            f'{mode}-{count}-{repetition}-outer.json',
                            self.outer(mode, count, wall))
                    sessions.append(entry)
        return {'schema': 'part5-v3-campaign-economics-input-v1',
                'sessions': sessions}

    def test_aggregates_complete_matched_grid_and_direct_break_even(self):
        report = aggregate(self.full_manifest(), self.root)

        self.assertTrue(report['grid_complete'])
        self.assertEqual(report['complete_pairs'], 20)
        self.assertEqual(report['matched_three_mode_groups'], 20)
        self.assertEqual(report['by_update_count']['5']['matched_pairs'], 4)
        self.assertEqual(report['by_update_count']['5']['median_session_wall_savings_fraction'],
                         0.175)
        self.assertEqual(report['break_even']['per_repetition'], [5, 5, 5, 5])
        self.assertEqual(report['break_even']['basis'],
                         'session-only first sampled k where Anchor outer wall <= Full outer wall')
        self.assertFalse(report['cpu']['complete_tree_savings_claimed'])
        self.assertFalse(report['whole_application_benefit_established'])
        self.assertEqual(report['whole_application_savings_fraction'], None)
        self.assertFalse(report['application_effect_costs']['transaction_bytes_available'])
        self.assertEqual(
            report['common_cost_accounting']['session_report_values'][
                'preexisting_ledger_clone_charged'], [False])

    def test_mode_specific_uncensored_runner_caps_do_not_break_pairing(self):
        manifest = self.full_manifest()
        for mode, runtime, storage in (
                ('full', 2400, 256 * 1024 * 1024),
                ('anchor', 3600, 192 * 1024 * 1024),
                ('coalesced-full', 4800, 128 * 1024 * 1024)):
            entry = next(row for row in manifest['sessions']
                         if row['mode'] == mode and row['target_count'] == 1
                         and row['repetition'] == 1)
            outer = json.loads(Path(entry['outer_report']).read_text())
            outer['limits']['runtime_seconds'] = runtime
            outer['limits']['storage_growth_bytes'] = storage
            Path(entry['outer_report']).write_text(json.dumps(outer))

        report = aggregate(manifest, self.root)
        pair = next(row for row in report['pairs']
                    if row['target_count'] == 1 and row['repetition'] == 1)

        self.assertEqual(pair['status'], 'matched')
        self.assertEqual(pair['full_outer_limits']['runtime_seconds'], 2400)
        self.assertEqual(pair['anchor_outer_limits']['runtime_seconds'], 3600)
        self.assertEqual(pair['coalesced_outer_limits']['runtime_seconds'], 4800)
        self.assertEqual(report['three_mode_groups'][1]['status'], 'matched')

    def test_manifest_generator_lists_all_absolute_report_slots(self):
        session_root = self.root / 'sessions'
        outer_root = self.root / 'outer'
        manifest = make_manifest(session_root, outer_root)

        self.assertEqual(len(manifest['sessions']), 60)
        self.assertEqual(len({row['session_report'] for row in manifest['sessions']}), 60)
        self.assertEqual(len({row['outer_report'] for row in manifest['sessions']}), 60)
        self.assertTrue(all(Path(row['session_report']).is_absolute()
                            and Path(row['outer_report']).is_absolute()
                            for row in manifest['sessions']))
        self.assertFalse(session_root.exists())
        self.assertFalse(outer_root.exists())

    def test_manifest_with_absent_files_reports_all_slots_missing(self):
        manifest = make_manifest(self.root / 'sessions', self.root / 'outer')
        report = aggregate(manifest, self.root)

        self.assertFalse(report['grid_complete'])
        self.assertEqual(report['complete_pairs'], 0)
        self.assertEqual(len(report['sessions']), 60)
        self.assertTrue(all(row['status'] == 'missing' for row in report['sessions']))
        self.assertTrue(all(value['median_session_wall_savings_fraction'] is None
                            for value in report['by_update_count'].values()))
        self.assertEqual(report['break_even']['per_repetition_status'],
                         ['incomplete'] * 4)

    def test_reviewed_validator_shutdown_can_still_be_a_verified_session(self):
        session = self.session('anchor', 1, 1, 14.5)
        session.update({
            'effect_supervisor_status': 'failed',
            'ledger_reuse_requires_review': True,
            'validator_cleanup': {'exit_code': -2, 'reaped': True,
                                  'graceful': False},
        })
        session['stages'][0]['exit_code'] = 1
        manifest = {'schema': 'part5-v3-campaign-economics-input-v1',
                    'sessions': [{
                        'mode': 'anchor', 'target_count': 1, 'repetition': 1,
                        'session_report': self.write('reviewed-session.json', session),
                        'outer_report': self.write('reviewed-outer.json',
                                                   self.outer('anchor', 1, 14.5)),
                    }]}

        report = aggregate(manifest, self.root)
        row = next(row for row in report['sessions']
                   if row['mode'] == 'anchor' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'valid')
        self.assertTrue(row['ledger_reuse_requires_review'])

    def test_missing_and_failed_sessions_are_reported_and_excluded(self):
        manifest = self.full_manifest(
            failed_anchor=('anchor', 5, 2), missing_full=('full', 2, 3))
        report = aggregate(manifest, self.root)

        self.assertFalse(report['grid_complete'])
        self.assertEqual(report['complete_pairs'], 18)
        self.assertEqual(report['session_status_counts']['missing'], 1)
        self.assertEqual(report['session_status_counts']['failed'], 1)
        self.assertEqual(report['by_update_count']['2']['matched_pairs'], 3)
        self.assertEqual(report['by_update_count']['5']['matched_pairs'], 3)
        self.assertEqual(report['break_even']['per_repetition_status'][1], 'incomplete')
        slots = {(row['mode'], row['target_count'], row['repetition']): row
                 for row in report['sessions']}
        self.assertEqual(slots[('full', 2, 3)]['status'], 'missing')
        self.assertEqual(slots[('anchor', 5, 2)]['status'], 'failed')

    def test_mismatched_frozen_cohort_is_not_counted_as_a_pair(self):
        manifest = self.full_manifest(mismatch=('anchor', 1, 1))
        report = aggregate(manifest, self.root)

        self.assertEqual(report['complete_pairs'], 19)
        pair = next(row for row in report['pairs']
                    if row['target_count'] == 1 and row['repetition'] == 1)
        self.assertEqual(pair['status'], 'unmatched')
        self.assertIn('freeze_sha256', pair['mismatch_fields'])

    def test_mismatched_current_root_is_not_counted_as_a_pair(self):
        manifest = self.full_manifest()
        anchor = next(row for row in manifest['sessions']
                      if row['mode'] == 'anchor' and row['target_count'] == 2
                      and row['repetition'] == 4)
        report = json.loads(Path(anchor['session_report']).read_text())
        report['current_root'] = 'a different root'
        Path(anchor['session_report']).write_text(json.dumps(report))

        result = aggregate(manifest, self.root)
        pair = next(row for row in result['pairs']
                    if row['target_count'] == 2 and row['repetition'] == 4)
        self.assertEqual(pair['status'], 'unmatched')
        self.assertIn('current_root', pair['mismatch_fields'])

    def test_coalesced_control_must_share_the_exact_request_identity(self):
        manifest = self.full_manifest()
        control = next(row for row in manifest['sessions']
                       if row['mode'] == 'coalesced-full'
                       and row['target_count'] == 1 and row['repetition'] == 1)
        report = json.loads(Path(control['session_report']).read_text())
        report['exact_request_sha256'] = 'e' * 64
        Path(control['session_report']).write_text(json.dumps(report))

        result = aggregate(manifest, self.root)
        pair = next(row for row in result['pairs']
                    if row['target_count'] == 1 and row['repetition'] == 1)
        group = next(row for row in result['three_mode_groups']
                     if row['target_count'] == 1 and row['repetition'] == 1)
        self.assertEqual(pair['status'], 'unmatched')
        self.assertIn('coalesced.exact_request_sha256', pair['mismatch_fields'])
        self.assertEqual(group['status'], 'full_anchor_incomplete_or_unmatched')

    def test_exact_request_identity_is_required(self):
        manifest = self.full_manifest()
        full = next(row for row in manifest['sessions']
                    if row['mode'] == 'full' and row['target_count'] == 0
                    and row['repetition'] == 1)
        report = json.loads(Path(full['session_report']).read_text())
        del report['exact_request_sha256']
        Path(full['session_report']).write_text(json.dumps(report))

        result = aggregate(manifest, self.root)
        slot = next(row for row in result['sessions']
                    if row['mode'] == 'full' and row['target_count'] == 0
                    and row['repetition'] == 1)
        self.assertEqual(slot['status'], 'invalid')
        self.assertEqual(slot['reason'], 'matched_identity_missing')


if __name__ == '__main__':
    unittest.main()
