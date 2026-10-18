import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.part5 import verify_v3_campaign_public_clock_audit as tool


COUNTS = (0, 1, 2, 5, 10)
ORDERS = (
    ('full', 'anchor', 'coalesced-full'),
    ('anchor', 'coalesced-full', 'full'),
    ('full', 'coalesced-full', 'anchor'),
    ('coalesced-full', 'anchor', 'full'),
)


def _report(*, campaign_id=None):
    rows = []
    for repetition, order in enumerate(ORDERS, 1):
        for target_count in COUNTS:
            for mode in order:
                sequence = len(rows) + 1
                rows.append({
                    'sequence': sequence,
                    'repetition': repetition,
                    'target_count': target_count,
                    'mode': mode,
                    'slot_receipt_sha256': f'{sequence:064x}',
                    'outer_report_sha256': f'{sequence + 100:064x}',
                    'utc_elapsed_seconds': 60.0,
                    'monotonic_duration_seconds': 60.0,
                    'utc_minus_monotonic_seconds': 0.0,
                    'within_tolerance': True,
                })
    report = {
        'schema': tool.AUDIT_SCHEMA,
        'passed': True,
        'slot_count': 60,
        'tolerance_seconds': 5.0,
        'matrix_manifest_sha256': 'a' * 64,
        'sequence_receipt_sha256': 'b' * 64,
        'slots': rows,
    }
    if campaign_id is not None:
        report['campaign_id'] = campaign_id
    return report


class PublicCampaignClockAuditVerificationTests(unittest.TestCase):
    def test_accepts_producer_schema_without_optional_campaign_id(self):
        result = tool.verify_report(_report())

        self.assertEqual(result['slot_count'], 60)
        self.assertTrue(result['report_passed'])
        self.assertEqual(result['campaign_id'], None)
        self.assertEqual(result['scope'], tool.SCOPE)
        self.assertIn('underlying private receipts are not verified', result['scope'])

    def test_accepts_canonical_training_campaign_id_when_present(self):
        result = tool.verify_report(_report(campaign_id='training-010'))

        self.assertEqual(result['campaign_id'], 'training-010')

    def test_rejects_noncanonical_or_early_campaign_ids(self):
        for campaign_id in ('training-009', 'training-10', 'training-0010',
                            'training-010/private', '/private/training-010'):
            with self.subTest(campaign_id=campaign_id), self.assertRaises(ValueError):
                tool.verify_report(_report(campaign_id=campaign_id))

    def test_rejects_unknown_or_missing_schema_fields(self):
        report = _report()
        report['private_path'] = '/private/receipt.json'
        with self.assertRaisesRegex(ValueError, 'unknown audit report fields'):
            tool.verify_report(report)

        report = _report()
        del report['sequence_receipt_sha256']
        with self.assertRaisesRegex(ValueError, 'missing audit report fields'):
            tool.verify_report(report)

    def test_rejects_incorrect_registered_grid_or_slot_count(self):
        report = _report()
        report['slots'][0]['target_count'] = 1
        with self.assertRaisesRegex(ValueError, 'registered matrix'):
            tool.verify_report(report)

        report = _report()
        report['slots'].pop()
        with self.assertRaisesRegex(ValueError, 'exactly 60'):
            tool.verify_report(report)

    def test_rejects_bad_hashes_and_nonfinite_or_nonpositive_durations(self):
        report = _report()
        report['slots'][0]['outer_report_sha256'] = 'g' * 64
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tool.verify_report(report)

        for duration in (0, -1, float('nan'), float('inf'), True):
            report = _report()
            report['slots'][0]['monotonic_duration_seconds'] = duration
            with self.subTest(duration=duration), self.assertRaisesRegex(
                    ValueError, 'finite positive'):
                tool.verify_report(report)

    def test_recomputes_timing_and_checks_declared_tolerance(self):
        report = _report()
        report['slots'][0]['utc_elapsed_seconds'] = 62.0
        with self.assertRaisesRegex(ValueError, 'discrepancy'):
            tool.verify_report(report)

        report = _report()
        report['slots'][0]['utc_minus_monotonic_seconds'] = 1.0
        with self.assertRaisesRegex(ValueError, 'discrepancy'):
            tool.verify_report(report)

        report = _report()
        report['tolerance_seconds'] = 5.01
        with self.assertRaisesRegex(ValueError, 'five seconds'):
            tool.verify_report(report)

    def test_rejects_private_values_and_timestamp_values_outside_public_schema(self):
        report = _report()
        report['slots'][0]['started_at_utc'] = '/private/session.json'
        with self.assertRaisesRegex(ValueError, 'unknown slot 1 fields'):
            tool.verify_report(report)

        report = _report()
        report['slots'][0]['outer_report_sha256'] = '/private/receipt'
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tool.verify_report(report)

    def test_allows_a_consistent_failed_public_clock_audit(self):
        report = _report()
        row = report['slots'][0]
        row['utc_elapsed_seconds'] = 70.0
        row['utc_minus_monotonic_seconds'] = 10.0
        row['within_tolerance'] = False
        report['passed'] = False

        result = tool.verify_report(report)

        self.assertFalse(result['report_passed'])

    def test_reads_a_scrubbed_report_file(self):
        report = _report()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'clock-audit.json'
            path.write_text(json.dumps(report), encoding='utf-8')

            result = tool.verify_file(path)

        self.assertEqual(result['slot_count'], 60)

    def test_standalone_cli_emits_public_only_verification_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'clock-audit.json'
            path.write_text(json.dumps(_report()), encoding='utf-8')

            completed = subprocess.run(
                [sys.executable, str(Path(tool.__file__)), str(path)],
                check=True, capture_output=True, text=True)

        result = json.loads(completed.stdout)
        self.assertTrue(result['report_verified'])
        self.assertEqual(result['scope'], tool.SCOPE)


if __name__ == '__main__':
    unittest.main()
