import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.part5 import verify_v3_campaign_public_receipts as tool


ORDERS = (
    ('full', 'anchor', 'coalesced-full'),
    ('anchor', 'coalesced-full', 'full'),
    ('full', 'coalesced-full', 'anchor'),
    ('coalesced-full', 'anchor', 'full'),
)
COUNTS = (0, 1, 2, 5, 10)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(document):
    return (json.dumps(document, sort_keys=True, indent=2) + '\n').encode()


def _rewrite_sequence(root, update):
    sequence_path = root / 'sequence-receipt.json'
    sequence = json.loads(sequence_path.read_bytes())
    update(sequence)
    sequence_raw = _json_bytes(sequence)
    sequence_path.write_bytes(sequence_raw)

    index_path = root / 'index.json'
    index = json.loads(index_path.read_bytes())
    index['sequence_receipt']['sha256'] = _sha(sequence_raw)
    index_path.write_bytes(_json_bytes(index))


def _bundle(root):
    root.mkdir()
    slot_dir = root / 'slot-receipts'
    slot_dir.mkdir()
    previous = None
    slot_index = []
    sequence_rows = []
    sequence = 0
    campaign_start = datetime(2026, 10, 18, tzinfo=timezone.utc)
    for repetition, order in enumerate(ORDERS, 1):
        for target_count in COUNTS:
            for position, mode in enumerate(order, 1):
                sequence += 1
                identity = f'{sequence:064x}'
                slot = {
                    'schema': tool.SLOT_SCHEMA,
                    'slot_identity_sha256': identity,
                    'sequence': sequence,
                    'repetition': repetition,
                    'target_count': target_count,
                    'mode': mode,
                    'registered_order': list(order),
                    'registered_order_position': position,
                    'previous_slot_receipt_sha256': previous,
                    'clone_report_sha256': 'a' * 64,
                    'clone_preparation_wall_seconds': 1.25,
                    'outer_report_sha256': 'b' * 64,
                    'session_report_sha256': 'c' * 64,
                }
                raw = _json_bytes(slot)
                digest = _sha(raw)
                filename = f'slot-{sequence:04d}.json'
                (slot_dir / filename).write_bytes(raw)
                outer_start = campaign_start + timedelta(seconds=2 * (sequence - 1))
                slot_index.append({
                    'sequence': sequence,
                    'repetition': repetition,
                    'target_count': target_count,
                    'mode': mode,
                    'path': f'slot-receipts/{filename}',
                    'sha256': digest,
                })
                sequence_rows.append({
                    'sequence': sequence,
                    'slot_identity_sha256': identity,
                    'slot_receipt_sha256': digest,
                    'previous_slot_receipt_sha256': previous,
                    'mode': mode,
                    'target_count': target_count,
                    'repetition': repetition,
                    'registered_order': list(order),
                    'registered_order_position': position,
                    'clone_preparation_wall_seconds': 1.25,
                    'outer_started_at_utc': outer_start.isoformat(),
                    'outer_ended_at_utc': (outer_start + timedelta(seconds=1)).isoformat(),
                })
                previous = digest

    manifest_sha = 'd' * 64
    sequence_doc = {
        'schema': tool.SEQUENCE_SCHEMA,
        'campaign_id': 'training-010',
        'manifest_sha256': manifest_sha,
        'campaign_runtime_seconds': 129600,
        'sequence_count': 60,
        'passed': True,
        'campaign_started_at_utc': '2026-10-18T00:00:00+00:00',
        'campaign_completed_at_utc': '2026-10-18T00:02:00+00:00',
        'cross_session_order_verified': True,
        'sequence': sequence_rows,
        'final_slot_receipt_sha256': previous,
        'registered_orders': [list(order) for order in ORDERS],
    }
    sequence_raw = _json_bytes(sequence_doc)
    (root / 'sequence-receipt.json').write_bytes(sequence_raw)
    index = {
        'schema': tool.INDEX_SCHEMA,
        'campaign_id': 'training-010',
        'matrix_manifest_canonical_sha256': manifest_sha,
        'sequence_receipt': {
            'path': 'sequence-receipt.json',
            'sha256': _sha(sequence_raw),
        },
        'slot_receipts': slot_index,
    }
    (root / 'index.json').write_bytes(_json_bytes(index))
    return root


class PublicCampaignReceiptVerificationTests(unittest.TestCase):
    def test_verifies_complete_registered_receipt_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            result = tool.verify_bundle(root)

            self.assertEqual(result['campaign_id'], 'training-010')
            self.assertEqual(result['slot_count'], 60)
            self.assertTrue(result['canonical_manifest_digest_consistent'])
            self.assertEqual(
                result['canonical_manifest_digest_scope'],
                'index and sequence agree; source manifest is not included')
            self.assertEqual(result['matrix_manifest_canonical_sha256'], 'd' * 64)
            self.assertEqual(result['scope'], tool.SCOPE)
            self.assertIn(
                'receipt chain only; underlying session/effect reports not independently verified',
                result['scope'])

    def test_rejects_tampered_receipt_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            path = root / 'slot-receipts/slot-0001.json'
            path.write_bytes(path.read_bytes() + b' ')

            with self.assertRaisesRegex(ValueError, 'byte hash mismatch'):
                tool.verify_bundle(root)

    def test_rejects_extra_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            (root / 'unindexed.txt').write_text('extra', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'unexpected bundle entries'):
                tool.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            (root / 'slot-receipts/extra-link.json').symlink_to(
                root / 'slot-receipts/slot-0001.json')
            with self.assertRaisesRegex(ValueError, 'unexpected slot receipt entries'):
                tool.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            first = root / 'slot-receipts/slot-0001.json'
            first.unlink()
            first.symlink_to(root / 'slot-receipts/slot-0002.json')
            with self.assertRaisesRegex(ValueError, 'regular non-symlink'):
                tool.verify_bundle(root)

    def test_rejects_unknown_fields_and_manifest_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            index_path = root / 'index.json'
            index = json.loads(index_path.read_bytes())
            index['local_path'] = '/Users/private'
            index_path.write_bytes(_json_bytes(index))
            with self.assertRaisesRegex(ValueError, 'unknown index fields'):
                tool.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            sequence_path = root / 'sequence-receipt.json'
            sequence = json.loads(sequence_path.read_bytes())
            sequence['manifest_sha256'] = 'e' * 64
            sequence_raw = _json_bytes(sequence)
            sequence_path.write_bytes(sequence_raw)
            index_path = root / 'index.json'
            index = json.loads(index_path.read_bytes())
            index['sequence_receipt']['sha256'] = _sha(sequence_raw)
            index_path.write_bytes(_json_bytes(index))
            with self.assertRaisesRegex(ValueError, 'canonical manifest digest'):
                tool.verify_bundle(root)

    def test_rejects_mismatched_sequence_and_slot_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            slot_path = root / 'slot-receipts/slot-0001.json'
            slot = json.loads(slot_path.read_bytes())
            slot['slot_identity_sha256'] = 'f' * 64
            slot_raw = _json_bytes(slot)
            slot_path.write_bytes(slot_raw)
            sequence_path = root / 'sequence-receipt.json'
            sequence = json.loads(sequence_path.read_bytes())
            sequence['sequence'][0]['slot_receipt_sha256'] = _sha(slot_raw)
            sequence_raw = _json_bytes(sequence)
            sequence_path.write_bytes(sequence_raw)
            index_path = root / 'index.json'
            index = json.loads(index_path.read_bytes())
            index['sequence_receipt']['sha256'] = _sha(sequence_raw)
            index['slot_receipts'][0]['sha256'] = _sha(slot_raw)
            index_path.write_bytes(_json_bytes(index))
            with self.assertRaisesRegex(ValueError, 'sequence row differs'):
                tool.verify_bundle(root)

    def test_rejects_boolean_sequence_number(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            index_path = root / 'index.json'
            index = json.loads(index_path.read_bytes())
            index['slot_receipts'][0]['sequence'] = True
            index_path.write_bytes(_json_bytes(index))

            with self.assertRaisesRegex(ValueError, 'registered grid'):
                tool.verify_bundle(root)

    def test_rejects_slot_ending_before_it_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            def invert_first_slot(sequence):
                sequence['sequence'][0]['outer_started_at_utc'] = '2026-10-18T00:00:02+00:00'
                sequence['sequence'][0]['outer_ended_at_utc'] = '2026-10-18T00:00:01+00:00'

            _rewrite_sequence(root, invert_first_slot)

            with self.assertRaisesRegex(ValueError, 'ends before it starts'):
                tool.verify_bundle(root)

    def test_rejects_overlapping_or_backward_slot_timeline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            def overlap_second_slot(sequence):
                sequence['sequence'][1]['outer_started_at_utc'] = '2026-10-18T00:00:00+00:00'

            _rewrite_sequence(root, overlap_second_slot)

            with self.assertRaisesRegex(ValueError, 'overlaps or precedes previous slot'):
                tool.verify_bundle(root)

    def test_accepts_adjacent_slots_with_equal_boundary_timestamp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            def make_slots_adjacent(sequence):
                sequence['sequence'][1]['outer_started_at_utc'] = (
                    sequence['sequence'][0]['outer_ended_at_utc'])

            _rewrite_sequence(root, make_slots_adjacent)

            self.assertEqual(tool.verify_bundle(root)['slot_count'], 60)

    def test_rejects_timestamp_without_explicit_timezone(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            def remove_timezone(sequence):
                sequence['sequence'][0]['outer_started_at_utc'] = '2026-10-18T00:00:00'

            _rewrite_sequence(root, remove_timezone)

            with self.assertRaisesRegex(ValueError, 'explicit UTC timestamp'):
                tool.verify_bundle(root)

    def test_rejects_timestamp_with_non_utc_offset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            def add_non_utc_offset(sequence):
                sequence['sequence'][0]['outer_started_at_utc'] = '2026-10-18T01:00:00+01:00'

            _rewrite_sequence(root, add_non_utc_offset)

            with self.assertRaisesRegex(ValueError, 'explicit UTC timestamp'):
                tool.verify_bundle(root)

    def test_rejects_slot_outside_campaign_interval(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            def finish_before_last_slot(sequence):
                sequence['campaign_completed_at_utc'] = '2026-10-18T00:01:00+00:00'

            _rewrite_sequence(root, finish_before_last_slot)

            with self.assertRaisesRegex(ValueError, 'outside campaign interval'):
                tool.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            def start_after_first_slot(sequence):
                sequence['campaign_started_at_utc'] = '2026-10-18T00:00:01+00:00'

            _rewrite_sequence(root, start_after_first_slot)

            with self.assertRaisesRegex(ValueError, 'outside campaign interval'):
                tool.verify_bundle(root)

    def test_rejects_malformed_timestamp_without_exposing_bundle_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')

            def corrupt_timestamp(sequence):
                sequence['sequence'][0]['outer_started_at_utc'] = '2026-99-18T00:00:00Z'

            _rewrite_sequence(root, corrupt_timestamp)

            with self.assertRaises(ValueError) as raised:
                tool.verify_bundle(root)
            self.assertIn('explicit UTC timestamp', str(raised.exception))
            self.assertNotIn(str(root), str(raised.exception))

    def test_cli_prints_receipt_chain_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _bundle(Path(temporary) / 'bundle')
            script = Path(tool.__file__).resolve()
            result = subprocess.run([sys.executable, '-B', str(script), str(root)],
                                    capture_output=True, text=True, check=False)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(tool.SCOPE, result.stdout)


if __name__ == '__main__':
    unittest.main()
