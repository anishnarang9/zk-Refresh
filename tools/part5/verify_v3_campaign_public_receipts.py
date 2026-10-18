#!/usr/bin/env python3
"""Independently verify a public 60-slot campaign receipt chain."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat


INDEX_SCHEMA = 'part5-v3-campaign-public-receipt-index-v1'
SEQUENCE_SCHEMA = 'part5-v3-campaign-matrix-sequence-v1'
SLOT_SCHEMA = 'part5-v3-campaign-matrix-slot-v1'
SCOPE = ('receipt chain only; underlying session/effect reports not independently verified')
COUNTS = (0, 1, 2, 5, 10)
ORDERS = (
    ('full', 'anchor', 'coalesced-full'),
    ('anchor', 'coalesced-full', 'full'),
    ('full', 'coalesced-full', 'anchor'),
    ('coalesced-full', 'anchor', 'full'),
)
HEX_SHA256 = re.compile(r'[0-9a-f]{64}')
CAMPAIGN_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
MAX_INDEX_BYTES = 128 * 1024
MAX_SEQUENCE_BYTES = 1024 * 1024
MAX_SLOT_BYTES = 64 * 1024

INDEX_FIELDS = {
    'schema', 'campaign_id', 'matrix_manifest_canonical_sha256',
    'sequence_receipt', 'slot_receipts',
}
SEQUENCE_FIELDS = {
    'schema', 'campaign_id', 'manifest_sha256', 'campaign_runtime_seconds',
    'sequence_count', 'passed', 'campaign_started_at_utc',
    'campaign_completed_at_utc', 'cross_session_order_verified', 'sequence',
    'final_slot_receipt_sha256', 'registered_orders',
}
SEQUENCE_ROW_FIELDS = {
    'sequence', 'slot_identity_sha256', 'slot_receipt_sha256',
    'previous_slot_receipt_sha256', 'mode', 'target_count', 'repetition',
    'registered_order', 'registered_order_position',
    'clone_preparation_wall_seconds', 'outer_started_at_utc',
    'outer_ended_at_utc',
}
SLOT_FIELDS = {
    'schema', 'slot_identity_sha256', 'sequence', 'repetition',
    'target_count', 'mode', 'registered_order', 'registered_order_position',
    'previous_slot_receipt_sha256', 'clone_report_sha256',
    'clone_preparation_wall_seconds', 'outer_report_sha256',
    'session_report_sha256',
}
INDEX_SLOT_FIELDS = {
    'sequence', 'repetition', 'target_count', 'mode', 'path', 'sha256',
}
SEQUENCE_REF_FIELDS = {'path', 'sha256'}


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _require_fields(value, expected, description):
    if type(value) is not dict:
        raise ValueError(f'{description} must be an object')
    unknown = set(value) - expected
    if unknown:
        raise ValueError(f'unknown {description} fields')
    missing = expected - set(value)
    if missing:
        raise ValueError(f'missing {description} fields')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON object key')
        result[key] = value
    return result


def _json_object(raw, description):
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f'{description} must be valid UTF-8 JSON') from error
    except ValueError as error:
        if str(error) == 'duplicate JSON object key':
            raise
        raise ValueError(f'{description} must be valid JSON') from error
    if type(value) is not dict:
        raise ValueError(f'{description} must be an object')
    return value


def _read_regular(path, cap, description):
    flags = os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ValueError(f'{description} must be a regular non-symlink file') from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > cap:
            raise ValueError(f'{description} is not a bounded regular file')
        chunks = []
        remaining = cap + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        after = os.fstat(fd)
        if (len(raw) > cap or len(raw) != before.st_size
                or before.st_dev != after.st_dev or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns):
            raise ValueError(f'{description} changed or exceeded its size cap')
        return raw
    finally:
        os.close(fd)


def _require_hash(value, description):
    if type(value) is not str or HEX_SHA256.fullmatch(value) is None:
        raise ValueError(f'{description} must be a lowercase SHA-256')
    return value


def _require_int(value, expected, description):
    if type(value) is not int or value != expected:
        raise ValueError(f'{description} does not match registered matrix order')


def _check_grid_fields(document, expected, description, *, include_order):
    for field in ('sequence', 'repetition', 'target_count'):
        value = document.get(field)
        if type(value) is not int or value != expected[field]:
            raise ValueError(f'{description} differs from registered grid')
    if type(document.get('mode')) is not str or document['mode'] != expected['mode']:
        raise ValueError(f'{description} differs from registered grid')
    if include_order:
        order = document.get('registered_order')
        position = document.get('registered_order_position')
        if type(order) is not list or order != expected['registered_order']:
            raise ValueError(f'{description} differs from registered grid')
        if type(position) is not int or position != expected['registered_order_position']:
            raise ValueError(f'{description} differs from registered grid')


def _require_seconds(value, description):
    if (type(value) not in (int, float) or not math.isfinite(value)
            or value < 0):
        raise ValueError(f'{description} must be finite and nonnegative')


def _require_timestamp(value, description):
    if type(value) is not str or not value or len(value) > 128:
        raise ValueError(f'{description} must be a nonempty timestamp string')


def _registered_slots():
    slots = []
    sequence = 0
    for repetition, order in enumerate(ORDERS, 1):
        for target_count in COUNTS:
            for position, mode in enumerate(order, 1):
                sequence += 1
                slots.append({
                    'sequence': sequence,
                    'repetition': repetition,
                    'target_count': target_count,
                    'mode': mode,
                    'registered_order': list(order),
                    'registered_order_position': position,
                    'path': f'slot-receipts/slot-{sequence:04d}.json',
                })
    return slots


def _check_bundle_shape(root):
    try:
        root_info = root.lstat()
    except OSError as error:
        raise ValueError('bundle directory is unavailable') from error
    if not stat.S_ISDIR(root_info.st_mode):
        raise ValueError('bundle root must be a real directory, not a symlink')
    expected_top = {'index.json', 'sequence-receipt.json', 'slot-receipts'}
    if {entry.name for entry in root.iterdir()} != expected_top:
        raise ValueError('unexpected bundle entries')
    slots_dir = root / 'slot-receipts'
    slots_info = slots_dir.lstat()
    if not stat.S_ISDIR(slots_info.st_mode):
        raise ValueError('slot-receipts must be a real directory')
    expected_files = {f'slot-{sequence:04d}.json' for sequence in range(1, 61)}
    entries = list(slots_dir.iterdir())
    if {entry.name for entry in entries} != expected_files:
        raise ValueError('unexpected slot receipt entries')
    for entry in entries:
        if not stat.S_ISREG(entry.lstat().st_mode):
            raise ValueError('slot receipts must be regular non-symlink files')
    for name in ('index.json', 'sequence-receipt.json'):
        if not stat.S_ISREG((root / name).lstat().st_mode):
            raise ValueError(f'{name} must be a regular non-symlink file')


def verify_bundle(bundle_dir):
    """Verify public receipt bytes and their internal registered 60-slot chain."""
    root = Path(bundle_dir).absolute()
    _check_bundle_shape(root)

    index_raw = _read_regular(root / 'index.json', MAX_INDEX_BYTES, 'index')
    sequence_raw = _read_regular(
        root / 'sequence-receipt.json', MAX_SEQUENCE_BYTES, 'sequence receipt')
    index = _json_object(index_raw, 'index')
    sequence = _json_object(sequence_raw, 'sequence receipt')
    _require_fields(index, INDEX_FIELDS, 'index')
    _require_fields(sequence, SEQUENCE_FIELDS, 'sequence receipt')
    if index.get('schema') != INDEX_SCHEMA:
        raise ValueError('unsupported public receipt index schema')
    if sequence.get('schema') != SEQUENCE_SCHEMA:
        raise ValueError('unsupported campaign sequence schema')

    campaign_id = index.get('campaign_id')
    if type(campaign_id) is not str or CAMPAIGN_ID.fullmatch(campaign_id) is None:
        raise ValueError('invalid campaign id')
    if sequence.get('campaign_id') != campaign_id:
        raise ValueError('index and sequence campaign ids differ')
    manifest_sha = _require_hash(
        index.get('matrix_manifest_canonical_sha256'),
        'canonical matrix manifest digest')
    sequence_manifest_sha = _require_hash(
        sequence.get('manifest_sha256'), 'sequence manifest digest')
    if manifest_sha != sequence_manifest_sha:
        raise ValueError('canonical manifest digest differs between index and sequence')

    _require_int(sequence.get('campaign_runtime_seconds'), 129600,
                 'campaign runtime')
    _require_int(sequence.get('sequence_count'), 60, 'sequence count')
    if sequence.get('passed') is not True:
        raise ValueError('sequence receipt is not marked passed')
    if sequence.get('cross_session_order_verified') is not True:
        raise ValueError('sequence receipt does not attest registered cross-session order')
    for field in ('campaign_started_at_utc', 'campaign_completed_at_utc'):
        _require_timestamp(sequence.get(field), field)
    expected_orders = [list(order) for order in ORDERS]
    if sequence.get('registered_orders') != expected_orders:
        raise ValueError('sequence registered orders differ from matrix order')

    sequence_reference = index.get('sequence_receipt')
    if type(sequence_reference) is not dict:
        raise ValueError('sequence receipt reference must be an object')
    _require_fields(sequence_reference, SEQUENCE_REF_FIELDS,
                    'sequence receipt reference')
    if sequence_reference.get('path') != 'sequence-receipt.json':
        raise ValueError('sequence receipt path is not the registered relative path')
    if _require_hash(sequence_reference.get('sha256'), 'sequence receipt hash') \
            != _sha256(sequence_raw):
        raise ValueError('sequence receipt byte hash mismatch')

    rows = sequence.get('sequence')
    index_slots = index.get('slot_receipts')
    registered = _registered_slots()
    if type(rows) is not list or len(rows) != 60:
        raise ValueError('exactly 60 sequence rows are required')
    if type(index_slots) is not list or len(index_slots) != 60:
        raise ValueError('exactly 60 indexed slot receipts are required')

    previous_sha = None
    for expected, row, reference in zip(registered, rows, index_slots):
        _require_fields(row, SEQUENCE_ROW_FIELDS, 'sequence row')
        _require_fields(reference, INDEX_SLOT_FIELDS, 'slot index entry')
        _check_grid_fields(row, expected, 'sequence row', include_order=True)
        _check_grid_fields(reference, expected, 'slot index entry', include_order=False)
        if reference.get('path') != expected['path']:
            raise ValueError('slot receipt path is not the registered relative path')
        slot_path = root / expected['path']
        slot_raw = _read_regular(slot_path, MAX_SLOT_BYTES,
                                 f'slot {expected["sequence"]} receipt')
        receipt_sha = _sha256(slot_raw)
        indexed_sha = _require_hash(reference.get('sha256'), 'indexed slot receipt hash')
        sequence_sha = _require_hash(
            row.get('slot_receipt_sha256'), 'sequence slot receipt hash')
        if receipt_sha != indexed_sha or receipt_sha != sequence_sha:
            raise ValueError('slot receipt byte hash mismatch')
        receipt = _json_object(slot_raw, 'slot receipt')
        _require_fields(receipt, SLOT_FIELDS, 'slot receipt')
        if receipt.get('schema') != SLOT_SCHEMA:
            raise ValueError('unsupported slot receipt schema')

        _check_grid_fields(receipt, expected, 'slot receipt', include_order=True)
        identity_sha = _require_hash(
            receipt.get('slot_identity_sha256'), 'slot identity hash')
        if _require_hash(row.get('slot_identity_sha256'),
                         'sequence slot identity hash') != identity_sha:
            raise ValueError('sequence row differs from registered slot receipt identity')

        expected_previous = previous_sha
        for document, description in ((receipt, 'slot receipt'), (row, 'sequence row')):
            pointer = document.get('previous_slot_receipt_sha256')
            if pointer is not None:
                _require_hash(pointer, f'{description} previous receipt hash')
            if pointer != expected_previous:
                raise ValueError('previous slot receipt link is not contiguous')

        clone_seconds = receipt.get('clone_preparation_wall_seconds')
        _require_seconds(clone_seconds, 'slot clone preparation time')
        _require_seconds(row.get('clone_preparation_wall_seconds'),
                         'sequence clone preparation time')
        if row['clone_preparation_wall_seconds'] != clone_seconds:
            raise ValueError('sequence clone preparation time differs from slot receipt')
        for field in ('clone_report_sha256', 'outer_report_sha256',
                      'session_report_sha256'):
            _require_hash(receipt.get(field), field)
        for field in ('outer_started_at_utc', 'outer_ended_at_utc'):
            _require_timestamp(row.get(field), field)

        previous_sha = receipt_sha

    final_sha = _require_hash(
        sequence.get('final_slot_receipt_sha256'), 'final slot receipt hash')
    if final_sha != previous_sha:
        raise ValueError('final slot receipt hash differs from verified chain')

    # Recheck the inventory so additions/removals during verification are rejected.
    _check_bundle_shape(root)
    return {
        'status': 'verified',
        'scope': SCOPE,
        'campaign_id': campaign_id,
        'slot_count': 60,
        'canonical_manifest_digest_consistent': True,
        'canonical_manifest_digest_scope': (
            'index and sequence agree; source manifest is not included'),
        'matrix_manifest_canonical_sha256': manifest_sha,
        'index_sha256': _sha256(index_raw),
        'sequence_receipt_sha256': _sha256(sequence_raw),
        'final_slot_receipt_sha256': final_sha,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path,
                        help='public receipt bundle directory')
    args = parser.parse_args()
    try:
        result = verify_bundle(args.bundle)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
