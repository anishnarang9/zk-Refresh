import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import export_v3_campaign_public_receipts as tool


def slot_receipt(sequence=1):
    return {
        'schema': 'part5-v3-campaign-matrix-slot-v1',
        'slot_identity_sha256': '1' * 64,
        'sequence': sequence,
        'repetition': 1,
        'target_count': 0,
        'mode': 'full',
        'registered_order': ['full', 'anchor', 'coalesced-full'],
        'registered_order_position': 1,
        'previous_slot_receipt_sha256': None,
        'clone_report_sha256': '2' * 64,
        'clone_preparation_wall_seconds': 1.25,
        'outer_report_sha256': '3' * 64,
        'session_report_sha256': '4' * 64,
    }


def sequence_row(sequence=1):
    return {
        'sequence': sequence,
        'slot_identity_sha256': '1' * 64,
        'slot_receipt_sha256': '2' * 64,
        'previous_slot_receipt_sha256': None,
        'mode': 'full',
        'target_count': 0,
        'repetition': 1,
        'registered_order': ['full', 'anchor', 'coalesced-full'],
        'registered_order_position': 1,
        'clone_preparation_wall_seconds': 1.25,
        'outer_started_at_utc': '2026-10-18T00:00:00+00:00',
        'outer_ended_at_utc': '2026-10-18T00:00:01+00:00',
    }


def sequence_receipt():
    return {
        'schema': 'part5-v3-campaign-matrix-sequence-v1',
        'campaign_id': 'training-010',
        'manifest_sha256': 'a' * 64,
        'campaign_runtime_seconds': 129600,
        'sequence_count': 60,
        'passed': True,
        'campaign_started_at_utc': '2026-10-18T00:00:00+00:00',
        'campaign_completed_at_utc': '2026-10-18T00:01:00+00:00',
        'cross_session_order_verified': True,
        'sequence': [sequence_row()],
        'final_slot_receipt_sha256': '2' * 64,
        'registered_orders': [['full', 'anchor', 'coalesced-full']],
    }


class PublicCampaignReceiptExportTests(unittest.TestCase):
    def test_slot_receipt_validation_rejects_unknown_fields(self):
        receipt = slot_receipt()
        receipt['private_ledger_path'] = '/private/ledger'

        with self.assertRaisesRegex(ValueError, 'unknown slot receipt fields'):
            tool.validate_slot_receipt(receipt)

    def test_index_projection_uses_only_relative_paths_and_exact_byte_hashes(self):
        sequence_bytes = b'{"sequence_count":60}\n'
        entries = []
        for sequence in range(1, 61):
            entries.append({
                'sequence': sequence,
                'repetition': (sequence - 1) // 15 + 1,
                'target_count': 0,
                'mode': 'full',
                'receipt_bytes': f'{{"sequence":{sequence}}}\n'.encode(),
            })

        index = tool.build_index('training-010', 'a' * 64, sequence_bytes, entries)

        self.assertEqual(index['sequence_receipt'], {
            'path': 'sequence-receipt.json',
            'sha256': hashlib.sha256(sequence_bytes).hexdigest(),
        })
        self.assertEqual(len(index['slot_receipts']), 60)
        self.assertEqual(index['slot_receipts'][0]['path'],
                         'slot-receipts/slot-0001.json')
        self.assertEqual(index['slot_receipts'][0]['sha256'],
                         hashlib.sha256(entries[0]['receipt_bytes']).hexdigest())
        self.assertEqual(index['slot_receipts'][-1]['sequence'], 60)
        self.assertNotIn('/Users/', json.dumps(index))
        self.assertEqual(index['matrix_manifest_canonical_sha256'], 'a' * 64)

    def test_sequence_receipt_validation_rejects_unknown_top_level_field(self):
        receipt = sequence_receipt()
        receipt['private_cohort_root'] = '/private/cohort'

        with self.assertRaisesRegex(ValueError, 'unknown sequence receipt fields'):
            tool.validate_sequence_receipt(receipt)

    def test_sequence_receipt_validation_rejects_unknown_row_field(self):
        receipt = sequence_receipt()
        receipt['sequence'][0]['ledger_path'] = '/private/ledger'

        with self.assertRaisesRegex(ValueError, 'unknown sequence row fields'):
            tool.validate_sequence_receipt(receipt)

    def test_export_refuses_incomplete_matrix_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / 'matrix.json'
            manifest.write_text('{}', encoding='utf-8')
            output = root / 'public-receipts'
            validated = {'campaign_id': 'training-010',
                         'manifest_sha256': 'a' * 64,
                         'output_root': root / 'matrix-output'}

            with mock.patch.object(tool.matrix, 'validate_manifest',
                                   return_value=validated), \
                    mock.patch.object(tool.costs, 'verify_completed_matrix',
                                      side_effect=ValueError('completed matrix required')) as gate:
                with self.assertRaisesRegex(ValueError, 'completed matrix required'):
                    tool.export_public_receipts(manifest, output)

            gate.assert_called_once_with(validated)
            self.assertFalse(output.exists())

    def test_export_copies_only_verified_public_receipt_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            matrix_root = root / 'matrix-output'
            matrix_root.mkdir()
            source_dir = matrix_root / 'slots'
            source_dir.mkdir()
            validated = {'campaign_id': 'training-010',
                         'manifest_sha256': 'a' * 64,
                         'output_root': matrix_root}
            planned = []
            sequence = []
            receipt_paths = {}
            previous = None
            for number in range(1, 61):
                row = {'sequence': number,
                       'repetition': (number - 1) // 15 + 1,
                       'target_count': 0,
                       'mode': 'full'}
                planned.append(row)
                receipt = slot_receipt(number)
                receipt['repetition'] = row['repetition']
                raw = (json.dumps(receipt, sort_keys=True) + '\n').encode()
                receipt_path = source_dir / f'slot-{number:04d}.json'
                receipt_path.write_bytes(raw)
                receipt_paths[number] = receipt_path
                receipt_sha = hashlib.sha256(raw).hexdigest()
                sequence.append({**sequence_row(number), **row,
                                 'slot_receipt_sha256': receipt_sha,
                                 'previous_slot_receipt_sha256': previous})
                previous = receipt_sha
            sequence_doc = {
                'schema': 'part5-v3-campaign-matrix-sequence-v1',
                'campaign_id': 'training-010',
                'manifest_sha256': 'a' * 64,
                'campaign_runtime_seconds': 129600,
                'sequence_count': 60,
                'passed': True,
                'campaign_started_at_utc': '2026-10-18T00:00:00+00:00',
                'campaign_completed_at_utc': '2026-10-18T00:01:00+00:00',
                'cross_session_order_verified': True,
                'sequence': sequence,
                'final_slot_receipt_sha256': previous,
                'registered_orders': [['full', 'anchor', 'coalesced-full']],
            }
            sequence_path = matrix_root / 'sequence-receipt.json'
            sequence_raw = (json.dumps(sequence_doc, sort_keys=True) + '\n').encode()
            sequence_path.write_bytes(sequence_raw)
            output = root / 'public-receipts'
            with mock.patch.object(tool.matrix, 'validate_manifest',
                                   return_value=validated), \
                    mock.patch.object(tool.costs, 'verify_completed_matrix',
                                      return_value=hashlib.sha256(sequence_raw).hexdigest()), \
                    mock.patch.object(tool.matrix, 'plan_slots', return_value=planned), \
                    mock.patch.object(tool.matrix, 'output_paths',
                                      side_effect=lambda _v, slot: {
                                          'slot_receipt': receipt_paths[slot['sequence']]}):
                tool.export_public_receipts(root / 'matrix-manifest.json', output)

            self.assertEqual((output / 'sequence-receipt.json').read_bytes(), sequence_raw)
            self.assertEqual(
                (output / 'slot-receipts/slot-0001.json').read_bytes(),
                receipt_paths[1].read_bytes())
            for number, source in receipt_paths.items():
                self.assertEqual(
                    (output / f'slot-receipts/slot-{number:04d}.json').read_bytes(),
                    source.read_bytes())
            self.assertEqual(len([path for path in output.rglob('*') if path.is_file()]), 62)
            self.assertEqual(json.loads((output / 'index.json').read_bytes())[
                'matrix_manifest_canonical_sha256'], 'a' * 64)


if __name__ == '__main__':
    unittest.main()
