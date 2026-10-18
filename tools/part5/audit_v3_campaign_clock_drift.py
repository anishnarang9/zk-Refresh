#!/usr/bin/env python3
"""Audit completed matrix UTC elapsed time against bounded monotonic duration.

Run with the matrix-pinned Python interpreter. A discrepancy can detect host
sleep or a wall-clock adjustment; it cannot identify which caused the gap.
Matching clocks do not establish CPU accounting or the absence of suspension.
"""
import argparse
from datetime import datetime, timedelta
import json
import math
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import reconcile_v3_campaign_costs as costs
from tools.part5 import run_v3_campaign_matrix as matrix

SCHEMA = 'part5-v3-campaign-clock-drift-v1'
MAX_TOLERANCE_SECONDS = 5.0


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _tolerance(value):
    if not _number(value) or not 0 <= value <= MAX_TOLERANCE_SECONDS:
        raise ValueError('tolerance must be finite and between zero and five seconds')


def _utc(value):
    if not isinstance(value, str):
        raise ValueError('UTC timestamp required')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() != timedelta(0):
        raise ValueError('explicit UTC timestamp required')
    return parsed


def compare_timing(outer, tolerance):
    _tolerance(tolerance)
    duration = outer.get('duration_seconds')
    if not _number(duration) or duration <= 0:
        raise ValueError('finite positive monotonic duration required')
    elapsed = (_utc(outer.get('ended_at_utc')) -
               _utc(outer.get('started_at_utc'))).total_seconds()
    if not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError('nonnegative UTC elapsed time required')
    difference = elapsed - duration
    return {'utc_elapsed_seconds': elapsed, 'monotonic_duration_seconds': duration,
            'utc_minus_monotonic_seconds': difference,
            'within_tolerance': abs(difference) <= tolerance}


def audit(manifest_path, tolerance=MAX_TOLERANCE_SECONDS):
    _tolerance(tolerance)
    validated = matrix.validate_manifest(manifest_path)
    sequence_sha = costs.verify_completed_matrix(validated)
    planned = matrix.plan_slots(validated)
    if len(planned) != 60:
        raise ValueError('exactly 60 completed slots required')
    sequence_path = validated['output_root'] / 'sequence-receipt.json'
    if matrix.sha256(sequence_path) != sequence_sha:
        raise ValueError('sequence changed during clock audit')
    sequence = matrix.read_json(sequence_path)['sequence']
    if len(sequence) != 60:
        raise ValueError('exactly 60 verified sequence entries required')
    rows = []
    pins = [(sequence_path, sequence_sha)]
    for slot, entry in zip(planned, sequence):
        paths = matrix.output_paths(validated, slot)
        receipt_path, outer_path = paths['slot_receipt'], paths['outer_report']
        receipt_sha = matrix.sha256(receipt_path)
        if receipt_sha != entry['slot_receipt_sha256']:
            raise ValueError('slot receipt pin changed during clock audit')
        receipt = matrix.read_json(receipt_path)
        outer_sha = matrix.sha256(outer_path)
        if receipt.get('outer_report_sha256') != outer_sha:
            raise ValueError('outer report pin changed during clock audit')
        outer = matrix.read_json(outer_path)
        rows.append({'sequence': slot['sequence'],
                     'repetition': slot['repetition'],
                     'target_count': slot['target_count'], 'mode': slot['mode'],
                     'slot_receipt_sha256': receipt_sha,
                     'outer_report_sha256': outer_sha,
                     **compare_timing(outer, tolerance)})
        pins.extend(((receipt_path, receipt_sha), (outer_path, outer_sha)))
    if any(matrix.sha256(path) != digest for path, digest in pins):
        raise ValueError('evidence changed during clock audit')
    return {'schema': SCHEMA, 'passed': all(row['within_tolerance'] for row in rows),
            'slot_count': len(rows), 'tolerance_seconds': tolerance,
            'matrix_manifest_sha256': validated['manifest_sha256'],
            'sequence_receipt_sha256': sequence_sha, 'slots': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tolerance-seconds', type=float, default=MAX_TOLERANCE_SECONDS)
    args = parser.parse_args()
    try:
        report = audit(args.matrix_manifest, args.tolerance_seconds)
        output = args.output
        if (not output.is_absolute() or output.exists() or output.is_symlink()
                or output.parent.resolve(strict=True) != output.parent):
            raise ValueError('fresh absolute report output required')
        raw = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception as error:
        # Existing evidence validators may include private paths in exceptions.
        raise SystemExit(f'campaign clock audit rejected ({type(error).__name__}); no result established') from None
    if not report['passed']:
        raise SystemExit('campaign clock audit failed: UTC/monotonic discrepancy exceeds tolerance')
    print('Campaign clock audit passed for all 60 slots.')


if __name__ == '__main__':
    main()
