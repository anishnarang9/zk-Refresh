import unittest

from tools.part5 import run_v3_campaign_matrix as matrix


class CampaignMatrixTests(unittest.TestCase):
    def test_explicit_caps_cover_full_matrix_and_anchor_k1_floor(self):
        limits = {
            str(count): {
                mode: {'runtime_seconds': 2400,
                       'rss_bytes': 4294967296,
                       'storage_bytes': 268435456}
                for mode in matrix.session.MODES
            }
            for count in matrix.session.COUNTS
        }

        normalized = matrix.validate_caps(limits, matrix.CAMPAIGN_SECONDS)
        self.assertEqual(normalized['1']['anchor']['runtime_seconds'], 2400)

        limits['1']['anchor']['runtime_seconds'] = 2399
        with self.assertRaisesRegex(ValueError, 'Anchor k=1'):
            matrix.validate_caps(limits, matrix.CAMPAIGN_SECONDS)

    def test_schedule_uses_registered_order_for_each_count_and_repetition(self):
        slots = matrix.slot_specs()

        self.assertEqual(len(slots), 60)
        for repetition in range(1, 5):
            for count in matrix.session.COUNTS:
                group = [slot for slot in slots
                         if slot['repetition'] == repetition
                         and slot['target_count'] == count]
                self.assertEqual(
                    [slot['mode'] for slot in group],
                    list(matrix.session.ORDERS[repetition - 1]))
                self.assertEqual(
                    [slot['registered_order_position'] for slot in group],
                    [1, 2, 3])

    def test_outer_owner_matches_economics_analyzer_prefix(self):
        owner = matrix.slot_owner(2, 1, 'anchor')

        self.assertEqual(owner, 'v3-campaign-anchor-k1-r2-matrix')
        self.assertTrue(owner.startswith('v3-campaign-anchor-k1'))

    def test_effect_outputs_satisfy_loaded_application_supervisor(self):
        from harness.tests.queue_v3_local_stage import validate_stage_paths

        plan = {'output_root': matrix.ARTIFACTS / 'v3-matrix-training-003',
                'campaign_id': 'training-003'}
        slot = {'repetition': 1, 'target_count': 0, 'mode': 'full'}
        paths = matrix.output_paths(plan, slot)
        validate_stage_paths(paths['effect_output'], paths['control_output'],
                             matrix.ARTIFACTS)

    def test_economics_input_manifest_has_all_60_exact_report_paths(self):
        planned = []
        for slot in matrix.slot_specs():
            stem = (f"r{slot['repetition']}-k{slot['target_count']}-"
                    f"{slot['mode']}")
            planned.append({**slot, 'paths': {
                'session_report': f'/campaign/slot-{stem}/work/session-report.json',
                'outer_report': f'/campaign/slot-{stem}/outer-report.json',
            }})

        manifest = matrix.economics_input_manifest(planned)
        self.assertEqual(manifest['schema'], matrix.ECONOMICS_INPUT_SCHEMA)
        self.assertEqual(len(manifest['sessions']), 60)
        self.assertEqual(
            [(row['repetition'], row['target_count'], row['mode'])
             for row in manifest['sessions']],
            [(slot['repetition'], slot['target_count'], slot['mode'])
             for slot in matrix.slot_specs()])
        self.assertEqual(
            manifest['sessions'][0]['session_report'],
            '/campaign/slot-r1-k0-full/work/session-report.json')
        self.assertEqual(
            manifest['sessions'][-1]['outer_report'],
            '/campaign/slot-r4-k10-full/outer-report.json')

    def test_actual_sequence_receipt_checks_order_chain_and_timestamps(self):
        slots = [dict(slot, identity_sha256=f'{index:064x}')
                 for index, slot in enumerate(matrix.slot_specs(), 1)]
        sequence = []
        previous_receipt = None
        for index, slot in enumerate(slots, 1):
            receipt_sha = f'{index:064x}'
            sequence.append({
                'sequence': index,
                'slot_identity_sha256': f'{index:064x}',
                'slot_receipt_sha256': receipt_sha,
                'previous_slot_receipt_sha256': previous_receipt,
                'mode': slot['mode'],
                'target_count': slot['target_count'],
                'repetition': slot['repetition'],
                'registered_order': slot['registered_order'],
                'registered_order_position': slot['registered_order_position'],
                'outer_started_at_utc': f'2026-10-17T00:{(index - 1) // 60:02d}:{(index - 1) % 60:02d}+00:00',
                'outer_ended_at_utc': f'2026-10-17T00:{(index - 1) // 60:02d}:{(index - 1) % 60:02d}+00:00',
            })
            previous_receipt = receipt_sha

        self.assertTrue(matrix.verify_actual_sequence(sequence, slots))
        sequence[1]['mode'] = 'full'
        with self.assertRaises(ValueError):
            matrix.verify_actual_sequence(sequence, slots)

    def test_resume_accepts_only_passed_reports_with_matching_slot_identity(self):
        slot = {
            'identity_sha256': 'a' * 64,
            'sequence': 1,
            'repetition': 1,
            'target_count': 0,
            'mode': 'full',
            'registered_order': ['full', 'anchor', 'coalesced-full'],
            'registered_order_position': 1,
            'owner': matrix.slot_owner(1, 0, 'full'),
            'limits': {'runtime_seconds': 2400,
                       'rss_bytes': 4294967296,
                       'storage_bytes': 268435456},
            'session_source_sha256': 'b' * 64,
        }
        receipt = {
            'schema': matrix.SLOT_RECEIPT_SCHEMA,
            'slot_identity_sha256': slot['identity_sha256'],
            'sequence': slot['sequence'],
            'repetition': slot['repetition'],
            'target_count': slot['target_count'],
            'mode': slot['mode'],
            'registered_order': slot['registered_order'],
            'registered_order_position': slot['registered_order_position'],
            'clone_report_sha256': 'e' * 64,
            'outer_report_sha256': 'c' * 64,
            'session_report_sha256': 'd' * 64,
        }
        outer = {
            'schema': 1,
            'measurement': 'bounded_complete_session',
            'passed': True,
            'censored': False,
            'owner': slot['owner'],
            'stop_reason': None,
            'exit_code': 0,
            'runner_error_type': None,
            'cleanup_remaining_owned_processes': 0,
            'cleanup_status_unknown': False,
            'started_at_utc': '2026-10-17T00:00:00+00:00',
            'ended_at_utc': '2026-10-17T00:00:01+00:00',
            'duration_seconds': 1.0,
            'limits': {
                'runtime_seconds': 2400,
                'owned_tree_rss_bytes': 4294967296,
                'storage_growth_bytes': 268435456,
            },
        }
        session_report = {
            'schema': 'part5-v3-campaign-session-v1',
            'mode': slot['mode'],
            'target_count': slot['target_count'],
            'repetition': slot['repetition'],
            'registered_order': slot['registered_order'],
            'registered_order_position': slot['registered_order_position'],
            'session_source_sha256': slot['session_source_sha256'],
            'clone_report_sha256': 'e' * 64,
            'passed': True,
            'effect_verified': True,
        }

        matrix.validate_slot_documents(
            slot, receipt, outer, session_report,
            outer_sha256='c' * 64, session_sha256='d' * 64,
            expected_previous_receipt_sha256=None)

        outer['passed'] = False
        with self.assertRaises(ValueError):
            matrix.validate_slot_documents(
                slot, receipt, outer, session_report,
                outer_sha256='c' * 64, session_sha256='d' * 64,
                expected_previous_receipt_sha256=None)

    def test_resume_rejects_a_report_from_another_slot(self):
        slot = {
            'identity_sha256': 'a' * 64, 'sequence': 1,
            'repetition': 1, 'target_count': 0, 'mode': 'full',
            'registered_order': ['full', 'anchor', 'coalesced-full'],
            'registered_order_position': 1, 'owner': 'owner',
            'limits': {'runtime_seconds': 2400,
                       'rss_bytes': 4294967296,
                       'storage_bytes': 268435456},
            'session_source_sha256': 'b' * 64,
        }
        receipt = {
            'schema': matrix.SLOT_RECEIPT_SCHEMA,
            'slot_identity_sha256': slot['identity_sha256'],
            'sequence': 1, 'repetition': 1, 'target_count': 0,
            'mode': 'anchor',
            'registered_order': slot['registered_order'],
            'registered_order_position': 1,
            'clone_report_sha256': 'e' * 64,
            'outer_report_sha256': 'c' * 64,
            'session_report_sha256': 'd' * 64,
        }
        with self.assertRaises(ValueError):
            matrix.validate_slot_documents(
                slot, receipt, {}, {}, outer_sha256='c' * 64,
                session_sha256='d' * 64,
                expected_previous_receipt_sha256=None)


if __name__ == '__main__':
    unittest.main()
