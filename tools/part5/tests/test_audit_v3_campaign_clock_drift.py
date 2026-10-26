import json
from pathlib import Path
import tempfile
import stat
import unittest
from unittest import mock

from tools.part5 import audit_v3_campaign_clock_drift as tool


class CampaignClockDriftTests(unittest.TestCase):
    def fixture(self, root, gap=0):
        validated = {'output_root': root, 'manifest_sha256': 'a' * 64}
        planned, paths = [], {}
        for index in range(1, 61):
            slot = {'sequence': index, 'repetition': (index - 1) // 15 + 1,
                    'target_count': 0, 'mode': 'full'}
            planned.append(slot)
            outer = root / f'outer-{index}.json'
            outer.write_text(json.dumps({
                'started_at_utc': '2026-10-18T00:00:00+00:00',
                'ended_at_utc': f'2026-10-18T00:{1 + (gap if index == 2 else 0):02}:00+00:00',
                'duration_seconds': 60.0,
                'argv': ['/private/key'], 'owner': 'private-owner'}))
            receipt = root / f'receipt-{index}.json'
            receipt.write_text(json.dumps({'outer_report_sha256': tool.matrix.sha256(outer)}))
            paths[index] = {'outer_report': outer, 'slot_receipt': receipt}
        (root / 'sequence-receipt.json').write_text(json.dumps({'sequence': [
            {'slot_receipt_sha256': tool.matrix.sha256(paths[i]['slot_receipt'])}
            for i in range(1, 61)]}))
        return validated, planned, paths

    def audit_fixture(self, root, gap=0, mutate=None):
        validated, planned, paths = self.fixture(root, gap)
        if mutate:
            mutate(planned, paths)
        with mock.patch.object(tool.matrix, 'validate_manifest', return_value=validated), \
                mock.patch.object(tool.costs, 'verify_completed_matrix', return_value=tool.matrix.sha256(root / 'sequence-receipt.json')) as gate, \
                mock.patch.object(tool.matrix, 'plan_slots', return_value=planned), \
                mock.patch.object(tool.matrix, 'output_paths', side_effect=lambda _, slot: paths[slot['sequence']]):
            result = tool.audit(root / 'manifest.json')
            gate.assert_called_once_with(validated)
            return result

    def test_complete_grid_passes_and_output_is_scrubbed(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.audit_fixture(Path(directory).resolve())
        self.assertTrue(report['passed'])
        self.assertEqual(report['slot_count'], 60)
        self.assertEqual(report['tolerance_seconds'], 5.0)
        self.assertTrue(all(row['within_tolerance'] for row in report['slots']))
        self.assertNotIn('/private', json.dumps(report))
        self.assertNotIn('argv', json.dumps(report))
        self.assertNotIn('owner', json.dumps(report))

    def test_synthetic_host_sleep_gap_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.audit_fixture(Path(directory).resolve(), gap=20)
        self.assertFalse(report['passed'])
        self.assertFalse(report['slots'][1]['within_tolerance'])
        self.assertEqual(report['slots'][1]['utc_minus_monotonic_seconds'], 1200)

    def test_backward_clock_jump_also_fails(self):
        self.assertFalse(tool.compare_timing({
            'started_at_utc': '2026-10-18T00:00:00Z',
            'ended_at_utc': '2026-10-18T00:00:50Z',
            'duration_seconds': 60}, 5)['within_tolerance'])

    def test_tolerance_boundary(self):
        value = {'started_at_utc': '2026-10-18T00:00:00Z',
                 'ended_at_utc': '2026-10-18T00:01:05Z', 'duration_seconds': 60}
        self.assertTrue(tool.compare_timing(value, 5)['within_tolerance'])
        value['duration_seconds'] = 59.999
        self.assertFalse(tool.compare_timing(value, 5)['within_tolerance'])

    def test_invalid_timings_fail_closed(self):
        baseline = {'started_at_utc': '2026-10-18T00:00:00Z',
                    'ended_at_utc': '2026-10-18T00:01:00Z', 'duration_seconds': 60}
        for key, value in [('duration_seconds', True), ('duration_seconds', float('nan')),
                           ('duration_seconds', -1), ('duration_seconds', 0),
                           ('started_at_utc', '2026-10-18T00:00:00'),
                           ('started_at_utc', 'bad'),
                           ('ended_at_utc', '2026-10-17T00:00:00Z')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                tool.compare_timing({**baseline, key: value}, 5)
        for tolerance in (-1, True, float('inf'), 6):
            with self.assertRaises(ValueError):
                tool.compare_timing(baseline, tolerance)

    def test_outer_hash_must_match_verified_receipt(self):
        def mutate(_, paths):
            paths[2]['outer_report'].write_text('{}')
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'outer report pin'):
            self.audit_fixture(Path(directory).resolve(), mutate=mutate)

    def test_exactly_sixty_slots_required(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, '60'):
            self.audit_fixture(Path(directory).resolve(), mutate=lambda slots, _: slots.pop())

    def test_real_complete_sequence_gate_rejects_missing_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            validated = {'output_root': Path(directory).resolve()}
            with mock.patch.object(tool.matrix, 'validate_manifest', return_value=validated), \
                    mock.patch.object(tool.matrix, 'plan_slots', return_value=[]), \
                    self.assertRaisesRegex(ValueError, 'completed matrix sequence receipt required'):
                tool.audit(Path(directory).resolve() / 'manifest.json')

    def test_cli_writes_owner_only_failed_report_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / 'audit.json'
            report = {'passed': False, 'slots': [{'within_tolerance': False}]}
            argv = ['audit', '--matrix-manifest', '/private/manifest.json',
                    '--output', str(output)]
            with mock.patch.object(tool.sys, 'argv', argv), \
                    mock.patch.object(tool, 'audit', return_value=report), \
                    self.assertRaisesRegex(SystemExit, 'discrepancy'):
                tool.main()
            self.assertEqual(json.loads(output.read_text()), report)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with mock.patch.object(tool.sys, 'argv', argv), \
                    mock.patch.object(tool, 'audit', return_value=report), \
                    self.assertRaisesRegex(SystemExit, 'rejected'):
                tool.main()
            self.assertEqual(json.loads(output.read_text()), report)

    def test_cli_scrubs_private_evidence_error(self):
        with mock.patch.object(tool.sys, 'argv', [
                'audit', '--matrix-manifest', '/private/manifest.json',
                '--output', '/private/output.json']), \
                mock.patch.object(tool, 'audit', side_effect=ValueError('/private/key')), \
                self.assertRaises(SystemExit) as result:
            tool.main()
        self.assertNotIn('/private', str(result.exception))
