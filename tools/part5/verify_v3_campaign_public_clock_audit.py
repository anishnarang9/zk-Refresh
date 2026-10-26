#!/usr/bin/env python3
"""Independently verify the public 60-slot campaign clock-audit report.

This validates report shape and self-consistency only. It does not read or
verify the underlying private campaign receipts or timing source reports.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import stat


AUDIT_SCHEMA = 'part5-v3-campaign-clock-drift-v1'
VERIFIER_SCHEMA = 'part5-v3-campaign-public-clock-audit-verification-v1'
SCOPE = ('public clock audit report only; underlying private receipts are not verified')
COUNTS = (0, 1, 2, 5, 10)
ORDERS = (
    ('full', 'anchor', 'coalesced-full'),
    ('anchor', 'coalesced-full', 'full'),
    ('full', 'coalesced-full', 'anchor'),
    ('coalesced-full', 'anchor', 'full'),
)
MAX_TOLERANCE_SECONDS = 5.0
MAX_REPORT_BYTES = 256 * 1024
HEX_SHA256 = re.compile(r'[0-9a-f]{64}')
CAMPAIGN_ID = re.compile(r'training-(\d{3,})')

REPORT_FIELDS = {
    'schema', 'passed', 'slot_count', 'tolerance_seconds',
    'matrix_manifest_sha256', 'sequence_receipt_sha256', 'slots',
}
OPTIONAL_REPORT_FIELDS = {'campaign_id'}
SLOT_FIELDS = {
    'sequence', 'repetition', 'target_count', 'mode',
    'slot_receipt_sha256', 'outer_report_sha256',
    'utc_elapsed_seconds', 'monotonic_duration_seconds',
    'utc_minus_monotonic_seconds', 'within_tolerance',
}


def _require_fields(value, required, optional, description):
    if type(value) is not dict:
        raise ValueError(f'{description} must be an object')
    keys = set(value)
    unknown = keys - required - optional
    missing = required - keys
    if unknown:
        raise ValueError(f'unknown {description} fields')
    if missing:
        raise ValueError(f'missing {description} fields')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON object key')
        result[key] = value
    return result


def _number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _require_hash(value, description):
    if type(value) is not str or HEX_SHA256.fullmatch(value) is None:
        raise ValueError(f'{description} must be a lowercase SHA-256')


def _campaign_id(value):
    if type(value) is not str:
        raise ValueError('campaign id must be canonical training-NNN')
    match = CAMPAIGN_ID.fullmatch(value)
    if match is None:
        raise ValueError('campaign id must be canonical training-NNN')
    digits = match.group(1)
    number = int(digits)
    if number < 10 or str(number).zfill(3) != digits:
        raise ValueError('campaign id must be canonical training-NNN at or above training-010')
    return value


def _registered_slots():
    slots = []
    sequence = 0
    for repetition, order in enumerate(ORDERS, 1):
        for target_count in COUNTS:
            for mode in order:
                sequence += 1
                slots.append({
                    'sequence': sequence,
                    'repetition': repetition,
                    'target_count': target_count,
                    'mode': mode,
                })
    return slots


def _check_registered_slot(row, expected):
    for field in ('sequence', 'repetition', 'target_count'):
        if type(row.get(field)) is not int or row[field] != expected[field]:
            raise ValueError('slot row differs from registered matrix sequence/count/order')
    if type(row.get('mode')) is not str or row['mode'] != expected['mode']:
        raise ValueError('slot row differs from registered matrix sequence/count/order')


def verify_report(report):
    """Validate an already decoded public clock-audit report object."""
    _require_fields(report, REPORT_FIELDS, OPTIONAL_REPORT_FIELDS, 'audit report')
    if report.get('schema') != AUDIT_SCHEMA:
        raise ValueError('unsupported campaign clock-audit schema')
    campaign_id = (_campaign_id(report['campaign_id'])
                   if 'campaign_id' in report else None)
    if type(report.get('passed')) is not bool:
        raise ValueError('audit passed field must be boolean')
    if type(report.get('slot_count')) is not int or report['slot_count'] != 60:
        raise ValueError('audit must declare exactly 60 slots')
    tolerance = report.get('tolerance_seconds')
    if (not _number(tolerance) or tolerance < 0
            or tolerance > MAX_TOLERANCE_SECONDS):
        raise ValueError('tolerance must be finite and between zero and five seconds')
    _require_hash(report.get('matrix_manifest_sha256'), 'matrix manifest digest')
    _require_hash(report.get('sequence_receipt_sha256'), 'sequence receipt digest')
    rows = report.get('slots')
    if type(rows) is not list or len(rows) != 60:
        raise ValueError('audit must contain exactly 60 slots')

    registered = _registered_slots()
    all_within_tolerance = True
    for index, (row, expected) in enumerate(zip(rows, registered), 1):
        _require_fields(row, SLOT_FIELDS, set(), f'slot {index}')
        _check_registered_slot(row, expected)
        _require_hash(row.get('slot_receipt_sha256'), 'slot receipt digest')
        _require_hash(row.get('outer_report_sha256'), 'outer report digest')

        elapsed = row.get('utc_elapsed_seconds')
        duration = row.get('monotonic_duration_seconds')
        discrepancy = row.get('utc_minus_monotonic_seconds')
        if not _number(elapsed) or elapsed < 0:
            raise ValueError('UTC elapsed time must be finite and nonnegative')
        if not _number(duration) or duration <= 0:
            raise ValueError('monotonic duration must be finite positive seconds')
        if not _number(discrepancy):
            raise ValueError('UTC/monotonic discrepancy must be finite seconds')
        recomputed = elapsed - duration
        if not math.isclose(discrepancy, recomputed, rel_tol=0.0, abs_tol=1e-9):
            raise ValueError('reported UTC/monotonic discrepancy does not recompute')
        within = abs(recomputed) <= tolerance
        if type(row.get('within_tolerance')) is not bool or row['within_tolerance'] != within:
            raise ValueError('within-tolerance result does not match declared tolerance')
        all_within_tolerance = all_within_tolerance and within

    if report['passed'] != all_within_tolerance:
        raise ValueError('audit passed result does not match its 60 slot results')
    return {
        'schema': VERIFIER_SCHEMA,
        'report_verified': True,
        'report_passed': report['passed'],
        'campaign_id': campaign_id,
        'slot_count': 60,
        'tolerance_seconds': tolerance,
        'scope': SCOPE,
    }


def _read_report(path):
    flags = os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ValueError('report must be a regular non-symlink file') from error
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0
                or before.st_size > MAX_REPORT_BYTES):
            raise ValueError('report must be a bounded regular file')
        chunks = []
        remaining = MAX_REPORT_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        after = os.fstat(fd)
        if (len(raw) > MAX_REPORT_BYTES or len(raw) != before.st_size
                or before.st_dev != after.st_dev or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns):
            raise ValueError('report changed or exceeded its size cap')
    finally:
        os.close(fd)
    try:
        report = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('report must be valid UTF-8 JSON') from error
    if type(report) is not dict:
        raise ValueError('audit report must be an object')
    return report


def verify_file(path):
    """Read and verify one bounded public report, without opening receipts."""
    return verify_report(_read_report(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path, help='scrubbed public clock-audit JSON report')
    args = parser.parse_args()
    try:
        result = verify_file(args.report)
    except Exception as error:
        # The report may contain private values; never echo values or path details.
        raise SystemExit(f'public campaign clock-audit report rejected ({type(error).__name__})') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
