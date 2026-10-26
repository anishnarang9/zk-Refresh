#!/usr/bin/env python3
"""Join heldout k=1 request-B costs to sampled training deltas conditionally.

Only k=1 is a directly measured heldout comparison. Counts other than one use
the training campaign's delta change relative to its own k=1 calibration and
are explicitly reported as model/inference.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat


HELDOUT_SCHEMA = 'credential-v3-heldout-cost-analysis-v1'
TRAINING_SCHEMA = 'part5-v3-campaign-total-cost-summary-v1'
OUTPUT_SCHEMA = 'credential-v3-heldout-conditional-break-even-v1'
COUNTS = (0, 1, 2, 5, 10)
REPETITIONS = (1, 2, 3, 4)
VARIANTS = tuple(range(8))
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAX_INPUT_BYTES = 16 * 1024 * 1024


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _decode(raw):
    return json.loads(raw, object_pairs_hook=_unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError('non-finite JSON number')))


def _is_sha(value):
    return type(value) is str and HEX64.fullmatch(value) is not None


def _positive_finite(value):
    if type(value) not in (int, float) or value <= 0:
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _nonnegative_finite(value):
    if type(value) not in (int, float) or value < 0:
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _require_finite(value, label):
    if not math.isfinite(value):
        raise ValueError(f'{label} must be finite')
    return value


def _index_rows(rows, key_fn, label):
    if type(rows) is not list:
        raise ValueError(f'{label} pair array required')
    indexed = {}
    for row in rows:
        if type(row) is not dict:
            raise ValueError(f'{label} pair objects required')
        key = key_fn(row)
        if key in indexed:
            raise ValueError(f'duplicate {label} pair')
        indexed[key] = row
    return indexed


def _heldout_index(report):
    if type(report) is not dict or report.get('schema') != HELDOUT_SCHEMA:
        raise ValueError('heldout cost-analysis schema required')
    if any(not _is_sha(report.get(field)) for field in (
            'assembled_manifest_sha256', 'acceptance_report_sha256')):
        raise ValueError('heldout assembled-manifest and acceptance-report SHA-256 values required')

    def key(row):
        variant = row.get('variant')
        if type(variant) is not int or variant not in VARIANTS:
            raise ValueError('heldout variants 0 through 7 required')
        return variant

    indexed = _index_rows(report.get('pairs'), key, 'heldout')
    if set(indexed) != set(VARIANTS):
        raise ValueError('exactly eight heldout variants 0 through 7 required')
    for row in indexed.values():
        if any(not _positive_finite(row.get(field)) for field in (
                'full_B_seconds', 'anchor_B_seconds')):
            raise ValueError('heldout full_B and anchor_B totals must be finite positive')
        if not _nonnegative_finite(row.get('pair_view_one_time_seconds')):
            raise ValueError('heldout pair-view one-time cost must be finite nonnegative')
    return indexed


def _training_index(report):
    if (type(report) is not dict or report.get('schema') != TRAINING_SCHEMA
            or report.get('training_only') is not True):
        raise ValueError('training total-cost summary schema required')
    if report.get('matrix_grid_complete') is not True:
        raise ValueError('training summary matrix grid complete flag required')
    if (type(report.get('matched_pairs')) is not int
            or report['matched_pairs'] != 20
            or type(report.get('expected_pairs')) is not int
            or report['expected_pairs'] != 20):
        raise ValueError('training summary must report 20 matched pairs out of 20 expected')
    source_hashes = report.get('source_hashes')
    if (type(source_hashes) is not dict
            or not _is_sha(source_hashes.get('matrix_manifest_sha256'))
            or not _is_sha(source_hashes.get('sequence_receipt_sha256'))
            or not _is_sha(source_hashes.get('economics_report_sha256'))):
        raise ValueError('training summary matrix-manifest, sequence-receipt, and economics-report source hashes required')

    def key(row):
        count, repetition = row.get('target_count'), row.get('repetition')
        if type(count) is not int or count not in COUNTS:
            raise ValueError('registered training target_count required')
        if type(repetition) is not int or repetition not in REPETITIONS:
            raise ValueError('registered training repetition required')
        return repetition, count

    indexed = _index_rows(report.get('pairs'), key, 'training')
    expected = {(repetition, count) for repetition in REPETITIONS
                for count in COUNTS}
    if set(indexed) != expected:
        raise ValueError('complete 4x5 training matched-pair grid required')
    for row in indexed.values():
        if (row.get('status') != 'matched'
                or not _positive_finite(row.get('full_total_wall_seconds'))
                or not _positive_finite(row.get('anchor_total_wall_seconds'))):
            raise ValueError('complete 4x5 training matched-pair grid required')
    return indexed


def build(heldout_report, training_report, heldout_sha256, training_sha256,
          heldout_path=None, training_path=None):
    """Build the conditional join from already loaded, SHA-pinned reports."""
    if not _is_sha(heldout_sha256) or not _is_sha(training_sha256):
        raise ValueError('source report SHA-256 values required')
    heldout = _heldout_index(heldout_report)
    training = _training_index(training_report)

    variants = []
    pooled = {str(count): 0 for count in COUNTS}
    pooled['not_crossed_through_k10'] = 0
    pooled_per_variant_repetitions = 0
    for variant in VARIANTS:
        heldout_row = heldout[variant]
        direct_delta = _require_finite(
            float(heldout_row['anchor_B_seconds'])
            - float(heldout_row['full_B_seconds']),
            'heldout derived delta')
        repetitions = []
        first_distribution = {str(count): 0 for count in COUNTS}
        first_distribution['not_crossed_through_k10'] = 0
        for repetition in REPETITIONS:
            training_deltas = {
                count: _require_finite(
                    float(training[(repetition, count)]['anchor_total_wall_seconds'])
                    - float(training[(repetition, count)]['full_total_wall_seconds']),
                    'training derived delta')
                for count in COUNTS
            }
            baseline = training_deltas[1]
            deltas = []
            first_crossing = 'not_crossed_through_k10'
            crossed = False
            for count in COUNTS:
                value = (direct_delta if count == 1 else
                         direct_delta + (training_deltas[count] - baseline))
                _require_finite(value, 'conditional derived delta')
                if count == 1 and not math.isclose(
                        value, direct_delta, rel_tol=0.0, abs_tol=0.0):
                    raise ValueError('k=1 conditional calibration mismatch')
                deltas.append({
                    'target_count': count,
                    'anchor_minus_full_seconds': value,
                    'basis': ('direct heldout k1 calibration' if count == 1
                              else 'model/inference'),
                })
                if not crossed and count > 0 and value < 0:
                    first_crossing = count
                    crossed = True
            first_distribution[str(first_crossing)] += 1
            pooled[str(first_crossing)] += 1
            repetitions.append({
                'repetition': repetition,
                'training_k1_anchor_minus_full_seconds': baseline,
                'first_crossing': first_crossing,
                'deltas': deltas,
            })
        pooled_per_variant_repetitions += len(repetitions)
        variants.append({
            'variant': variant,
            'direct_heldout_k1': {
                'full_B_seconds': float(heldout_row['full_B_seconds']),
                'anchor_B_seconds': float(heldout_row['anchor_B_seconds']),
                'pair_view_one_time_seconds': float(
                    heldout_row['pair_view_one_time_seconds']),
                'observed_anchor_minus_full_seconds': direct_delta,
            },
            'first_crossing_distribution': {
                **first_distribution,
                'expected_repetitions': len(REPETITIONS),
            },
            'per_repetition': repetitions,
        })

    return {
        'schema': OUTPUT_SCHEMA,
        'source_reports': {
            'heldout_cost_analysis': {
                'path': heldout_path, 'sha256': heldout_sha256,
                'schema': HELDOUT_SCHEMA,
            },
            'training_total_summary': {
                'path': training_path, 'sha256': training_sha256,
                'schema': TRAINING_SCHEMA,
            },
        },
        'source_hashes': {
            'matrix_manifest_sha256': training_report['source_hashes'][
                'matrix_manifest_sha256'],
            'sequence_receipt_sha256': training_report['source_hashes'][
                'sequence_receipt_sha256'],
            'economics_report_sha256': training_report['source_hashes'][
                'economics_report_sha256'],
        },
        'method': {
            'heldout_observed_delta': 'D_v1 = anchor_B_seconds - full_B_seconds',
            'training_delta': ('D_rk = anchor_total_wall_seconds - '
                               'full_total_wall_seconds'),
            'conditional_transfer': 'D_vrk = D_v1 + (D_rk - D_r1)',
            'first_crossing': 'first sampled positive k with D_vrk < 0',
            'sampled_counts': list(COUNTS),
            'interpolation_or_extrapolation_used': False,
            'non_k1_basis': 'model/inference from training delta changes',
            'pair_view_one_time_cost': 'reported separately; excluded from deltas',
        },
        'variants': variants,
        'interpolation_or_extrapolation_used': False,
        'pooled_first_crossing_counts': {
            **pooled,
            'expected_variant_repetition_pairs': pooled_per_variant_repetitions,
        },
        'claims': {
            'cpu_savings': False,
            'winner': False,
            'operator_churn_weights_used': False,
        },
    }


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_pinned(ref, label):
    if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
            or type(ref['path']) is not str or not Path(ref['path']).is_absolute()
            or not _is_sha(ref['sha256'])):
        raise ValueError(f'{label} absolute PATH:SHA256 pin required')
    path = Path(ref['path'])
    try:
        before = path.lstat()
        if (path.resolve(strict=True) != path or not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid() or before.st_nlink != 1
                or before.st_mode & 0o022 or before.st_size <= 0
                or before.st_size > MAX_INPUT_BYTES):
            raise ValueError('canonical bounded owner-controlled file required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if _identity(opened) != _identity(before):
                raise ValueError('input changed at open')
            raw = stream.read(MAX_INPUT_BYTES + 1)
            if _identity(os.fstat(stream.fileno())) != _identity(before):
                raise ValueError('input changed during read')
        if (len(raw) != before.st_size or _identity(path.lstat()) != _identity(before)):
            raise ValueError('input changed while reading')
    except (OSError, ValueError) as error:
        raise ValueError(f'{label} pin invalid: {error}') from None
    actual = hashlib.sha256(raw).hexdigest()
    if actual != ref['sha256']:
        raise ValueError(f'{label} pin mismatch')
    try:
        value = _decode(raw)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f'{label} JSON invalid: {error}') from None
    if type(value) is not dict:
        raise ValueError(f'{label} JSON object required')
    return value, actual


def load_and_build(heldout_ref, training_ref):
    heldout, heldout_sha = _read_pinned(heldout_ref, 'heldout cost report')
    training, training_sha = _read_pinned(training_ref, 'training total report')
    return build(heldout, training, heldout_sha, training_sha,
                 heldout_ref['path'], training_ref['path'])


def _parse_ref(value):
    path, separator, sha256 = value.rpartition(':')
    if not separator or not path or not _is_sha(sha256):
        raise argparse.ArgumentTypeError('expected PATH:SHA256')
    return {'path': path, 'sha256': sha256}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--heldout-cost-report', required=True, type=_parse_ref,
                        metavar='PATH:SHA256')
    parser.add_argument('--training-total-summary', required=True, type=_parse_ref,
                        metavar='PATH:SHA256')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = load_and_build(args.heldout_cost_report,
                                args.training_total_summary)
        raw = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False)
               + '\n').encode()
        output = args.output
        if (not output.is_absolute() or output.exists() or output.is_symlink()
                or output.parent.resolve(strict=True) != output.parent):
            raise ValueError('fresh absolute output path required')
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception as error:
        raise SystemExit(f'heldout conditional break-even rejected: {error}') from None
    print(json.dumps({'path': str(output),
                      'sha256': hashlib.sha256(raw).hexdigest(),
                      'variants': len(report['variants']),
                      'variant_repetition_pairs': report[
                          'pooled_first_crossing_counts'][
                              'expected_variant_repetition_pairs']}, sort_keys=True))


if __name__ == '__main__':
    main()
