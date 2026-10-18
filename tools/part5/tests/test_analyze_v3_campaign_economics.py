import json
import hashlib
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

    def effect_monitor(self, mode, count, exit_code):
        return {
            'schema': 1,
            'measurement': 'bounded_complete_session',
            'owner': f'v3-campaign-{mode}-k{count}',
            'passed': exit_code == 0,
            'censored': False,
            'stop_reason': None,
            'exit_code': exit_code,
            'runner_error_type': None,
            'cleanup_remaining_owned_processes': 0,
            'cleanup_status_unknown': False,
        }

    def write_session(self, mode, count, repetition, report):
        directory = f'{mode}-{count}-{repetition}'
        monitor_path = self.root / directory / 'effect-monitor.json'
        monitor_path.parent.mkdir(parents=True, exist_ok=True)
        monitor_exit = 1 if report['effect_supervisor_status'] == 'failed' else 0
        monitor_path.write_text(json.dumps(self.effect_monitor(mode, count, monitor_exit)))
        report['effect_monitor_sha256'] = hashlib.sha256(monitor_path.read_bytes()).hexdigest()
        return self.write(f'{directory}/session-report.json', report)

    def write_pinned_effect_session(self, mode='full', count=1, repetition=1,
                                    report_mutator=None):
        report = self.session(mode, count, repetition, 10.0)
        artifact_root = self.root / 'artifacts' / 'dynark' / 'part5'
        campaign_root = artifact_root / 'v3-matrix-training-006'
        slot_root = campaign_root / f'slot-r{repetition}-k{count}-{mode}'
        work_root = slot_root / 'work'
        work_root.mkdir(parents=True)

        monitor_path = work_root / 'effect-monitor.json'
        monitor_path.write_text(json.dumps(self.effect_monitor(mode, count, 0)))
        report['effect_monitor_sha256'] = hashlib.sha256(
            monitor_path.read_bytes()).hexdigest()

        effect_output = artifact_root / (
            f'application-v3-matrix-training-006-r{repetition}-k{count}-{mode}-effect')
        effect_output.mkdir(mode=0o700)
        effect = {
            'schema': 'part5-v3-campaign-effect-v1',
            'mode': mode,
            'target_count': count,
            'passed': True,
            'training_only': True,
            'application_effect': True,
            'request_consumed': True,
            'effect_count': 1,
            'finalized_slot': 187,
            'bound_finalized_slot': 119,
            'transactions': [
                {'scenario': 'v3-campaign-bind-current-head', 'err': None,
                 'transactionBytes': 618, 'computeUnits': 22376,
                 'feeLamports': 10000, 'slot': 119, 'signature': 'setup'},
                {'scenario': f'v3-campaign-valid-{mode}', 'err': None,
                 'transactionBytes': 825, 'computeUnits': 185532,
                 'feeLamports': 5000, 'slot': 186, 'signature': 'application'},
                {'scenario': f'v3-campaign-replay-{mode}',
                 'err': {'InstructionError': [1, {'Custom': 707}]},
                 'transactionBytes': 825, 'computeUnits': 46910,
                 'feeLamports': 5000, 'slot': 187, 'signature': 'replay'},
            ],
        }
        effect_path = effect_output / 'effect-report.json'
        effect_path.write_text(json.dumps(effect))
        config = {
            'schema': 1,
            'scope': 'part5-v3-campaign-effect',
            'mode': mode,
            'proof_mode': mode,
            'target_count': count,
            'effect_output': str(effect_output),
        }
        config_path = work_root / 'effect-config.json'
        config_path.write_text(json.dumps(config))
        report['effect_config_sha256'] = hashlib.sha256(
            config_path.read_bytes()).hexdigest()
        report['effect_report_sha256'] = hashlib.sha256(
            effect_path.read_bytes()).hexdigest()
        if report_mutator is not None:
            report_mutator(report, config_path, effect_path)

        session_path = work_root / 'session-report.json'
        session_path.write_text(json.dumps(report))
        outer_path = self.root / f'{mode}-{count}-{repetition}-outer.json'
        outer_path.write_text(json.dumps(self.outer(mode, count, 10.0)))
        manifest = {
            'schema': 'part5-v3-campaign-economics-input-v1',
            'sessions': [{
                'mode': mode, 'target_count': count, 'repetition': repetition,
                'session_report': str(session_path),
                'outer_report': str(outer_path),
            }],
        }
        return manifest, session_path, effect_path

    def test_reads_only_pinned_successful_mode_specific_transaction_metrics(self):
        manifest, _, _ = self.write_pinned_effect_session()

        report = aggregate(manifest, self.root)

        row = next(row for row in report['sessions']
                   if row['mode'] == 'full' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'valid')
        self.assertEqual(row['application_effect_cost_metrics_status'], 'available')
        self.assertEqual(row['confirmed_rpc_metrics'], {
            'transaction_bytes': 825,
            'compute_units': 185532,
            'fee_lamports': 5000,
            'slot': 186,
        })
        self.assertEqual(row['finalized_effect_scope'], {
            'finalized_slot': 187,
            'bound_finalized_slot': 119,
            'effect_count': 1,
        })
        self.assertEqual(
            report['application_effect_costs']['confirmed_rpc_metrics']['by_mode']
            ['full']['sampled_values'],
            [{'target_count': 1, 'repetition': 1,
              'transaction_bytes': 825, 'compute_units': 185532,
              'fee_lamports': 5000}])

    def test_effect_report_pin_mismatch_invalidates_pinned_session(self):
        def mutate(_session, _config_path, effect_path):
            effect = json.loads(effect_path.read_text())
            effect['transactions'][1]['computeUnits'] = 1
            effect_path.write_text(json.dumps(effect))

        manifest, _, _ = self.write_pinned_effect_session(report_mutator=mutate)
        report = aggregate(manifest, self.root)

        row = next(row for row in report['sessions']
                   if row['mode'] == 'full' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'invalid')
        self.assertEqual(row['reason'], 'application_effect_metrics_invalid')
        self.assertEqual(row['application_effect_cost_metrics_status'],
                         'effect_report_identity_mismatch')
        self.assertIsNone(row['confirmed_rpc_metrics'])
        self.assertIsNone(row['finalized_effect_scope'])

    def test_other_mode_success_scenario_does_not_supply_transaction_metrics(self):
        def mutate(session, _config_path, effect_path):
            effect = json.loads(effect_path.read_text())
            effect['transactions'][1]['scenario'] = 'v3-campaign-valid-anchor'
            effect_path.write_text(json.dumps(effect))
            session['effect_report_sha256'] = hashlib.sha256(
                effect_path.read_bytes()).hexdigest()

        pinned_manifest, _, _ = self.write_pinned_effect_session(report_mutator=mutate)
        manifest = self.full_manifest()
        pinned_row = pinned_manifest['sessions'][0]
        manifest['sessions'] = [
            pinned_row if (row['mode'], row['target_count'], row['repetition'])
            == ('full', 1, 1) else row
            for row in manifest['sessions']]
        report = aggregate(manifest, self.root)

        row = next(row for row in report['sessions']
                   if row['mode'] == 'full' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'invalid')
        self.assertEqual(row['reason'], 'application_effect_metrics_invalid')
        self.assertEqual(row['application_effect_cost_metrics_status'],
                         'successful_application_transaction_missing_or_ambiguous')
        self.assertIsNone(row['confirmed_rpc_metrics'])

    def test_multiple_effects_cannot_enter_matched_economics(self):
        def mutate(session, _config_path, effect_path):
            effect = json.loads(effect_path.read_text())
            effect['effect_count'] = 2
            effect_path.write_text(json.dumps(effect))
            session['effect_report_sha256'] = hashlib.sha256(
                effect_path.read_bytes()).hexdigest()

        manifest, _, _ = self.write_pinned_effect_session(report_mutator=mutate)
        report = aggregate(manifest, self.root)
        row = next(row for row in report['sessions']
                   if row['mode'] == 'full' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'invalid')
        self.assertEqual(row['application_effect_cost_metrics_status'],
                         'finalized_effect_scope_invalid')
        self.assertEqual(report['complete_pairs'], 0)

    def test_missing_optional_rpc_field_keeps_verified_session_valid(self):
        def mutate(session, _config_path, effect_path):
            effect = json.loads(effect_path.read_text())
            del effect['transactions'][1]['transactionBytes']
            effect_path.write_text(json.dumps(effect))
            session['effect_report_sha256'] = hashlib.sha256(
                effect_path.read_bytes()).hexdigest()

        pinned_manifest, _, _ = self.write_pinned_effect_session(report_mutator=mutate)
        manifest = self.full_manifest()
        pinned_row = pinned_manifest['sessions'][0]
        manifest['sessions'] = [
            pinned_row if (row['mode'], row['target_count'], row['repetition'])
            == ('full', 1, 1) else row
            for row in manifest['sessions']]
        report = aggregate(manifest, self.root)

        row = next(row for row in report['sessions']
                   if row['mode'] == 'full' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'valid')
        self.assertEqual(row['application_effect_cost_metrics_status'],
                         'successful_application_transaction_metrics_unavailable')
        self.assertIsNone(row['confirmed_rpc_metrics'])
        self.assertEqual(row['finalized_effect_scope'], {
            'finalized_slot': 187,
            'bound_finalized_slot': 119,
            'effect_count': 1,
        })
        pair = next(row for row in report['pairs']
                    if row['target_count'] == 1 and row['repetition'] == 1)
        self.assertEqual(pair['status'], 'matched')
        self.assertEqual(
            report['application_effect_costs']['finalized_effect_scope']['by_mode']
            ['full']['available_samples'], 1)

    def test_pinned_config_cannot_redirect_effect_output_outside_slot_root(self):
        def mutate(session, config_path, _effect_path):
            config = json.loads(config_path.read_text())
            redirected = self.root / 'redirected-effect'
            redirected.mkdir(mode=0o700)
            config['effect_output'] = str(redirected)
            config_path.write_text(json.dumps(config))
            session['effect_config_sha256'] = hashlib.sha256(
                config_path.read_bytes()).hexdigest()

        manifest, _, _ = self.write_pinned_effect_session(report_mutator=mutate)
        report = aggregate(manifest, self.root)

        row = next(row for row in report['sessions']
                   if row['mode'] == 'full' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'invalid')
        self.assertEqual(row['reason'], 'application_effect_metrics_invalid')
        self.assertEqual(row['application_effect_cost_metrics_status'],
                         'effect_output_path_invalid')
        self.assertIsNone(row['confirmed_rpc_metrics'])

    def test_older_valid_receipts_without_effect_config_remain_accepted(self):
        manifest = self.full_manifest()

        report = aggregate(manifest, self.root)

        row = next(row for row in report['sessions']
                   if row['mode'] == 'full' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'valid')
        self.assertEqual(row['application_effect_cost_metrics_status'],
                         'effect_config_missing')
        self.assertIsNone(row['confirmed_rpc_metrics'])
        self.assertIsNone(row['finalized_effect_scope'])

    def test_matrix_slot_requires_effect_pin_even_when_pin_field_is_removed(self):
        def mutate(session, _config_path, effect_path):
            session.pop('effect_config_sha256')
            effect = json.loads(effect_path.read_text())
            effect['transactions'][1]['computeUnits'] = 1
            effect_path.write_text(json.dumps(effect))

        pinned_manifest, _, _ = self.write_pinned_effect_session(report_mutator=mutate)
        manifest = self.full_manifest()
        pinned_row = pinned_manifest['sessions'][0]
        manifest['sessions'] = [
            pinned_row if (row['mode'], row['target_count'], row['repetition'])
            == ('full', 1, 1) else row
            for row in manifest['sessions']]

        report = aggregate(manifest, self.root)

        row = next(row for row in report['sessions']
                   if row['mode'] == 'full' and row['target_count'] == 1
                   and row['repetition'] == 1)
        pair = next(row for row in report['pairs']
                    if row['target_count'] == 1 and row['repetition'] == 1)
        self.assertEqual(row['status'], 'invalid')
        self.assertEqual(row['reason'], 'application_effect_metrics_invalid')
        self.assertEqual(row['application_effect_cost_metrics_status'],
                         'effect_config_missing')
        self.assertEqual(pair['status'], 'incomplete')

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
                    session_path = self.write_session(mode, count, repetition, report)
                    entry = {'mode': mode, 'target_count': count,
                             'repetition': repetition,
                             'session_report': session_path}
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
                         'session-only first sampled k with positive Full-minus-Anchor outer wall')
        self.assertFalse(report['cpu']['complete_tree_savings_claimed'])
        self.assertFalse(report['whole_application_benefit_established'])
        self.assertEqual(report['whole_application_savings_fraction'], None)
        self.assertFalse(report['application_effect_costs']['transaction_bytes_available'])
        self.assertEqual(
            report['common_cost_accounting']['session_report_values'][
                'preexisting_ledger_clone_charged'], [False])

    def test_exact_wall_tie_is_not_a_break_even_win(self):
        for all_tied in (False, True):
            with self.subTest(all_tied=all_tied):
                manifest = self.full_manifest()
                for entry in manifest['sessions']:
                    count = entry['target_count']
                    if entry['mode'] not in ('full', 'anchor') or (count != 0 and not all_tied):
                        continue
                    path = Path(entry['outer_report'])
                    outer = json.loads(path.read_text())
                    outer['duration_seconds'] = max(10.0 + 2.0 * count, 14.0 + 0.5 * count)
                    path.write_text(json.dumps(outer))
                report = aggregate(manifest, self.root)
                self.assertTrue(report['grid_complete'])
                self.assertEqual(report['break_even']['per_repetition'],
                                 [None] * 4 if all_tied else [5] * 4)
                self.assertEqual(report['break_even']['per_repetition_status'],
                                 ['not_crossed_through_k10'] * 4 if all_tied else ['crossed'] * 4)

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
                        'session_report': self.write_session('anchor', 1, 1, session),
                        'outer_report': self.write('reviewed-outer.json',
                                                   self.outer('anchor', 1, 14.5)),
                    }]}

        report = aggregate(manifest, self.root)
        row = next(row for row in report['sessions']
                   if row['mode'] == 'anchor' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'valid')
        self.assertTrue(row['ledger_reuse_requires_review'])

    def test_reviewed_shutdown_requires_nested_monitor_exit_to_match_status(self):
        session = self.session('anchor', 1, 1, 14.5)
        session.update({
            'effect_supervisor_status': 'failed',
            'ledger_reuse_requires_review': True,
            'validator_cleanup': {'exit_code': -2, 'reaped': True,
                                  'graceful': False},
        })
        session['stages'][0]['exit_code'] = 1
        session_path = Path(self.write_session('anchor', 1, 1, session))
        monitor_path = session_path.parent / 'effect-monitor.json'
        monitor = self.effect_monitor('anchor', 1, 0)
        monitor_path.write_text(json.dumps(monitor))
        session['effect_monitor_sha256'] = hashlib.sha256(
            monitor_path.read_bytes()).hexdigest()
        session_path.write_text(json.dumps(session))
        manifest = {'schema': 'part5-v3-campaign-economics-input-v1',
                    'sessions': [{
                        'mode': 'anchor', 'target_count': 1, 'repetition': 1,
                        'session_report': str(session_path),
                        'outer_report': self.write('reviewed-mismatch-outer.json',
                                                   self.outer('anchor', 1, 14.5)),
                    }]}

        report = aggregate(manifest, self.root)
        row = next(row for row in report['sessions']
                   if row['mode'] == 'anchor' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['status'], 'invalid')
        self.assertEqual(row['reason'], 'effect_monitor_status_exit_mismatch')

    def test_nested_monitor_must_match_session_hash_and_cleanup(self):
        session = self.session('anchor', 1, 1, 14.5)
        session.update({
            'effect_supervisor_status': 'failed',
            'ledger_reuse_requires_review': True,
            'validator_cleanup': {'exit_code': -2, 'reaped': True,
                                  'graceful': False},
        })
        session['stages'][0]['exit_code'] = 1
        session_path = Path(self.write_session('anchor', 1, 1, session))
        monitor_path = session_path.parent / 'effect-monitor.json'
        manifest = {'schema': 'part5-v3-campaign-economics-input-v1',
                    'sessions': [{
                        'mode': 'anchor', 'target_count': 1, 'repetition': 1,
                        'session_report': str(session_path),
                        'outer_report': self.write('reviewed-hash-outer.json',
                                                   self.outer('anchor', 1, 14.5)),
                    }]}

        monitor = self.effect_monitor('anchor', 1, 1)
        monitor['sample_count'] = 1
        monitor_path.write_text(json.dumps(monitor))
        report = aggregate(manifest, self.root)
        row = next(row for row in report['sessions']
                   if row['mode'] == 'anchor' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['reason'], 'effect_monitor_identity_mismatch')

        monitor = self.effect_monitor('anchor', 1, 1)
        monitor['cleanup_status_unknown'] = True
        monitor_path.write_text(json.dumps(monitor))
        session['effect_monitor_sha256'] = hashlib.sha256(
            monitor_path.read_bytes()).hexdigest()
        session_path.write_text(json.dumps(session))
        report = aggregate(manifest, self.root)
        row = next(row for row in report['sessions']
                   if row['mode'] == 'anchor' and row['target_count'] == 1
                   and row['repetition'] == 1)
        self.assertEqual(row['reason'], 'effect_monitor_cleanup_evidence_invalid')

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
