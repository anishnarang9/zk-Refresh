#!/usr/bin/env python3
"""Export only a completed campaign's slot and sequence receipts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import reconcile_v3_campaign_costs as costs
from tools.part5 import run_v3_campaign_matrix as matrix

INDEX_SCHEMA = 'part5-v3-campaign-public-receipt-index-v1'
SLOT_RECEIPT_FIELDS = frozenset({
    'schema', 'slot_identity_sha256', 'sequence', 'repetition', 'target_count',
    'mode', 'registered_order', 'registered_order_position',
    'previous_slot_receipt_sha256', 'clone_report_sha256',
    'clone_preparation_wall_seconds', 'outer_report_sha256',
    'session_report_sha256',
})
SEQUENCE_RECEIPT_FIELDS = frozenset({
    'schema', 'campaign_id', 'manifest_sha256', 'campaign_runtime_seconds',
    'sequence_count', 'passed', 'campaign_started_at_utc',
    'campaign_completed_at_utc', 'cross_session_order_verified', 'sequence',
    'final_slot_receipt_sha256', 'registered_orders',
})
SEQUENCE_ROW_FIELDS = frozenset({
    'sequence', 'slot_identity_sha256', 'slot_receipt_sha256',
    'previous_slot_receipt_sha256', 'mode', 'target_count', 'repetition',
    'registered_order', 'registered_order_position',
    'clone_preparation_wall_seconds', 'outer_started_at_utc',
    'outer_ended_at_utc',
})
MODES = ('full', 'anchor', 'coalesced-full')
COUNTS = (0, 1, 2, 5, 10)
MAX_SEQUENCE_BYTES = 1024 * 1024
MAX_SLOT_RECEIPT_BYTES = 64 * 1024


def validate_slot_receipt(receipt):
    if type(receipt) is not dict:
        raise ValueError('slot receipt must be an object')
    fields = set(receipt)
    unknown = fields - SLOT_RECEIPT_FIELDS
    if unknown:
        names = ', '.join(sorted(map(str, unknown)))
        raise ValueError(f'unknown slot receipt fields: {names}')
    missing = SLOT_RECEIPT_FIELDS - fields
    if missing:
        names = ', '.join(sorted(missing))
        raise ValueError(f'missing slot receipt fields: {names}')
    if receipt.get('schema') != matrix.SLOT_RECEIPT_SCHEMA:
        raise ValueError('unsupported slot receipt schema')


def _validate_fields(value, allowed, description):
    if type(value) is not dict:
        raise ValueError(f'{description} must be an object')
    fields = set(value)
    unknown = fields - allowed
    if unknown:
        names = ', '.join(sorted(map(str, unknown)))
        raise ValueError(f'unknown {description} fields: {names}')
    missing = allowed - fields
    if missing:
        names = ', '.join(sorted(missing))
        raise ValueError(f'missing {description} fields: {names}')


def validate_sequence_receipt(receipt):
    _validate_fields(receipt, SEQUENCE_RECEIPT_FIELDS, 'sequence receipt')
    if receipt.get('schema') != matrix.SEQUENCE_SCHEMA:
        raise ValueError('unsupported sequence receipt schema')
    if type(receipt.get('sequence')) is not list:
        raise ValueError('sequence receipt rows must be a list')
    for row in receipt['sequence']:
        _validate_fields(row, SEQUENCE_ROW_FIELDS, 'sequence row')


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def build_index(campaign_id, manifest_canonical_sha256, sequence_bytes, slot_entries):
    if not isinstance(campaign_id, str) or not campaign_id:
        raise ValueError('campaign id required')
    if not isinstance(manifest_canonical_sha256, str) or not re.fullmatch(
            r'[0-9a-f]{64}', manifest_canonical_sha256):
        raise ValueError('canonical matrix manifest SHA-256 required')
    if type(sequence_bytes) is not bytes:
        raise ValueError('sequence receipt bytes required')
    if not isinstance(slot_entries, list) or len(slot_entries) != 60:
        raise ValueError('exactly 60 slot receipts required')

    slots = []
    for expected_sequence, entry in enumerate(slot_entries, 1):
        if type(entry) is not dict or set(entry) != {
                'sequence', 'repetition', 'target_count', 'mode', 'receipt_bytes'}:
            raise ValueError('invalid slot receipt projection entry')
        sequence = entry['sequence']
        repetition = entry['repetition']
        target_count = entry['target_count']
        mode = entry['mode']
        receipt_bytes = entry['receipt_bytes']
        if (type(sequence) is not int or sequence != expected_sequence
                or type(repetition) is not int or repetition not in (1, 2, 3, 4)
                or type(target_count) is not int or target_count not in COUNTS
                or mode not in MODES or type(receipt_bytes) is not bytes):
            raise ValueError('invalid slot receipt projection values')
        slots.append({
            'sequence': sequence,
            'repetition': repetition,
            'target_count': target_count,
            'mode': mode,
            'path': f'slot-receipts/slot-{sequence:04d}.json',
            'sha256': _sha256(receipt_bytes),
        })

    return {
        'schema': INDEX_SCHEMA,
        'campaign_id': campaign_id,
        'matrix_manifest_canonical_sha256': manifest_canonical_sha256,
        'sequence_receipt': {
            'path': 'sequence-receipt.json',
            'sha256': _sha256(sequence_bytes),
        },
        'slot_receipts': slots,
    }


def _read_pinned_file(path, cap):
    path = Path(path)
    expected_sha256 = matrix.sha256(path, cap=cap)
    raw = path.read_bytes()
    if len(raw) > cap or _sha256(raw) != expected_sha256:
        raise ValueError('receipt changed while being exported')
    return raw


def _write_new(path, raw):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _fresh_output_directory(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError('fresh public receipt output directory required')
    parent = path.parent.resolve(strict=True)
    output = parent / path.name
    if output.exists() or output.is_symlink():
        raise FileExistsError('fresh public receipt output directory required')
    if not parent.is_dir():
        raise ValueError('public receipt output parent must be a directory')
    return output


def export_public_receipts(matrix_manifest, output_dir):
    output = _fresh_output_directory(output_dir)
    validated = matrix.validate_manifest(Path(matrix_manifest))
    sequence_sha256 = costs.verify_completed_matrix(validated)
    planned = matrix.plan_slots(validated)
    if len(planned) != 60:
        raise ValueError('complete 60-slot matrix plan required')

    output_root = Path(validated['output_root'])
    sequence_path = output_root / 'sequence-receipt.json'
    sequence_bytes = _read_pinned_file(sequence_path, MAX_SEQUENCE_BYTES)
    if _sha256(sequence_bytes) != sequence_sha256:
        raise ValueError('sequence receipt changed after matrix verification')
    sequence_receipt = json.loads(sequence_bytes)
    validate_sequence_receipt(sequence_receipt)
    sequence = sequence_receipt.get('sequence')
    if not isinstance(sequence, list) or len(sequence) != 60:
        raise ValueError('complete sequence receipt required')

    entries = []
    for slot, sequence_row in zip(planned, sequence):
        path = matrix.output_paths(validated, slot)['slot_receipt']
        raw = _read_pinned_file(path, MAX_SLOT_RECEIPT_BYTES)
        if _sha256(raw) != sequence_row.get('slot_receipt_sha256'):
            raise ValueError('slot receipt changed after matrix verification')
        receipt = json.loads(raw)
        validate_slot_receipt(receipt)
        entries.append({
            'sequence': slot['sequence'],
            'repetition': slot['repetition'],
            'target_count': slot['target_count'],
            'mode': slot['mode'],
            'receipt_bytes': raw,
        })

    index = build_index(validated['campaign_id'], validated['manifest_sha256'],
                        sequence_bytes, entries)
    output.mkdir(mode=0o755)
    slot_directory = output / 'slot-receipts'
    slot_directory.mkdir(mode=0o755)
    _write_new(output / 'sequence-receipt.json', sequence_bytes)
    for entry, row in zip(entries, index['slot_receipts']):
        _write_new(output / row['path'], entry['receipt_bytes'])
    index_bytes = (json.dumps(index, sort_keys=True, indent=2) + '\n').encode()
    _write_new(output / 'index.json', index_bytes)
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix-manifest', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    index = export_public_receipts(args.matrix_manifest, args.output_dir)
    print(json.dumps({'campaign_id': index['campaign_id'],
                      'slot_receipt_count': len(index['slot_receipts']),
                      'output_dir': str(args.output_dir)}))


if __name__ == '__main__':
    main()
