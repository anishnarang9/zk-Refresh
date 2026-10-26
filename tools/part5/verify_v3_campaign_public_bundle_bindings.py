#!/usr/bin/env python3
"""Cross-bind an independently verified public campaign projection and receipt bundle."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import verify_v3_campaign_public_projection as projection
from tools.part5 import verify_v3_campaign_public_receipts as receipts

SCOPE = ('cross-binding only; private manifest and underlying session/effect reports '
         'not independently verified')
SLOT_BINDING_FIELDS = (
    'sequence', 'repetition', 'target_count', 'mode', 'registered_order',
    'registered_order_position', 'slot_identity_sha256',
)


def _real_root(directory):
    root = Path(directory).absolute()
    try:
        if root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError('public bundle root must be a real directory without symlink parents')
    except OSError as error:
        raise ValueError('public bundle directory is unavailable') from error
    return root


def _verified_document(root, filename, cap, digest):
    raw = projection._read_regular(root / filename, cap, filename)
    if projection._sha256(raw) != digest:
        raise ValueError(f'{filename} changed after independent verification')
    return projection._json_object(raw, filename)


def verify_bundles(projection_dir, receipt_dir):
    """Verify both public bundles first, then compare their registered identities."""
    plan_root = _real_root(projection_dir)
    receipt_root = _real_root(receipt_dir)
    public = projection.verify_bundle(plan_root)
    chain = receipts.verify_bundle(receipt_root)
    for field in ('campaign_id', 'matrix_manifest_canonical_sha256'):
        if public[field] != chain[field]:
            raise ValueError(f'public projection and receipt bundle differ in {field}')

    # Read only exact public filenames, and pin the bytes to the independent checks.
    plan = _verified_document(plan_root, 'matrix-plan.json', projection.MAX_PLAN_BYTES,
                              public['public_plan_sha256'])
    sequence = _verified_document(receipt_root, 'sequence-receipt.json',
                                  receipts.MAX_SEQUENCE_BYTES,
                                  chain['sequence_receipt_sha256'])
    projection._require_fields(plan, projection.PLAN_FIELDS, 'public plan')
    receipts._require_fields(sequence, receipts.SEQUENCE_FIELDS, 'sequence receipt')
    for document, manifest_field in ((plan, 'matrix_manifest_canonical_sha256'),
                                     (sequence, 'manifest_sha256')):
        if document['campaign_id'] != public['campaign_id']:
            raise ValueError('public documents differ in campaign_id')
        if document[manifest_field] != public['matrix_manifest_canonical_sha256']:
            raise ValueError('public documents differ in matrix_manifest_canonical_sha256')
    slots, rows = plan['slots'], sequence['sequence']
    if type(slots) is not list or type(rows) is not list or len(slots) != 60 or len(rows) != 60:
        raise ValueError('exactly 60 public plan slots and receipt rows are required')
    for position, (slot, row, expected) in enumerate(
            zip(slots, rows, projection._registered_slots()), 1):
        projection._require_fields(slot, projection.PLAN_SLOT_FIELDS, 'plan slot')
        receipts._require_fields(row, receipts.SEQUENCE_ROW_FIELDS, 'sequence row')
        for field in SLOT_BINDING_FIELDS:
            if type(slot[field]) is not type(row[field]) or slot[field] != row[field]:
                raise ValueError(f'slot {position} differs in {field}')
            if field in expected and (type(slot[field]) is not type(expected[field])
                                      or slot[field] != expected[field]):
                raise ValueError(f'slot {position} differs from registered {field}')
        projection._require_sha(slot['slot_identity_sha256'], 'slot identity digest')

    projection._check_inventory(plan_root)
    receipts._check_bundle_shape(receipt_root)
    return {
        'status': 'verified',
        'scope': SCOPE,
        'campaign_id': public['campaign_id'],
        'matrix_manifest_canonical_sha256': public['matrix_manifest_canonical_sha256'],
        'slot_count': 60,
        'public_plan_sha256': public['public_plan_sha256'],
        'sequence_receipt_sha256': chain['sequence_receipt_sha256'],
        'projection_index_sha256': public['index_sha256'],
        'receipt_index_sha256': chain['index_sha256'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('projection', type=Path, help='public projection directory')
    parser.add_argument('receipts', type=Path, help='public receipt bundle directory')
    args = parser.parse_args()
    try:
        result = verify_bundles(args.projection, args.receipts)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
