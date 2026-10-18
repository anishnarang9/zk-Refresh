#!/usr/bin/env python3
"""Create a narrowly allowlisted public projection of heldout evidence."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from statistics import median

from tools.part5 import model_v3_heldout_break_even as break_even


SUMMARY_SCHEMA = 'part5-v3-heldout-public-summary-v1'
INDEX_SCHEMA = 'part5-v3-heldout-public-index-v1'
REPORT_SCHEMA = 'part5-v3-heldout-public-report-v1'
SOURCE_KEYS = {
    'acceptance_report_sha256', 'cost_report_sha256',
    'conditional_model_report_sha256', 'training_total_summary_sha256',
    'freeze_sha256', 'cohort_receipt_sha256', 'assembled_manifest_sha256',
}
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAX_INPUT_BYTES = 64 * 1024 * 1024
OUTPUT_FILES = {'index.json', 'summary.json', 'report.md', 'SHA256SUMS'}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


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


def _finite(value, *, positive=False):
    return (type(value) in (int, float) and math.isfinite(value)
            and (value > 0 if positive else value >= 0))


def _read_regular(path, cap=MAX_INPUT_BYTES):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or before.st_mode & 0o022
            or before.st_size <= 0 or before.st_size > cap):
        raise ValueError('canonical owner-controlled regular input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode,
                                 info.st_uid, info.st_nlink, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        if identity(opened) != identity(before):
            raise ValueError('input changed at open')
        raw = stream.read(cap + 1)
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise ValueError('input changed while reading')
    if len(raw) != before.st_size or identity(path.lstat()) != identity(before):
        raise ValueError('input changed after read')
    return raw


def _parse_pin(value):
    path, separator, digest = value.rpartition(':')
    if not separator or not path or HEX64.fullmatch(digest) is None:
        raise ValueError('private input must be pinned as PATH:SHA256')
    return Path(path), digest


def read_pinned_json(value):
    path, expected = _parse_pin(value)
    if not path.is_absolute():
        raise ValueError('private input path must be absolute')
    raw = _read_regular(path)
    actual = _sha(raw)
    if actual != expected:
        raise ValueError('private input SHA-256 pin mismatch')
    document = _decode(raw)
    if type(document) is not dict:
        raise ValueError('private report object required')
    return document, actual, str(path)


def _check_model(cost, model, training, hashes, cost_path=None, training_path=None):
    if (model.get('schema') != break_even.OUTPUT_SCHEMA
            or model.get('claims') != {
                'cpu_savings': False, 'winner': False,
                'operator_churn_weights_used': False}):
        raise ValueError('conditional model schema and no-winner claims required')
    expected = break_even.build(
        cost, training, hashes['cost_report_sha256'],
        hashes['training_total_summary_sha256'], cost_path, training_path)
    if model != expected:
        raise ValueError('conditional model does not match recomputed pinned inputs')
    return expected


def _case_costs(acceptance, cost):
    if (acceptance.get('schema') != 'credential-v3-heldout-application-report-v1'
            or acceptance.get('verified') is not True
            or acceptance.get('heldout_acceptance') is not True
            or acceptance.get('source_drift_detected') is not False):
        raise ValueError('independently verified heldout acceptance required')
    counts = acceptance.get('counts')
    required_counts = {
        'variants': 8,
        'loaded_disabled_config_negatives': 8,
        'loaded_disabled_issuer_negatives': 8,
        'loaded_ambiguous_restarts': 8,
    }
    if type(counts) is not dict or any(counts.get(k) != v for k, v in required_counts.items()):
        raise ValueError('eight verified cases and eight disabled-config/issuer/restart negatives required')
    if (cost.get('schema') != 'credential-v3-heldout-cost-analysis-v1'
            or cost.get('claims') != {
                'cpu_savings': False, 'whole_application_benefit': False,
                'independent_production_freshness': False}):
        raise ValueError('heldout component-sum cost analysis required')
    if (cost.get('assembled_manifest_sha256') != acceptance.get('manifest_sha256')
            or cost.get('acceptance_report_sha256') is None):
        raise ValueError('acceptance and cost analysis identities differ')
    cases = acceptance.get('cases')
    if (type(cases) is not list or len(cases) != 8
            or {row.get('variant') for row in cases if type(row) is dict} != set(range(8))):
        raise ValueError('eight unique verified acceptance variants required')
    pair_rows = cost.get('pairs')
    if (type(pair_rows) is not list or len(pair_rows) != 8
            or {row.get('variant') for row in pair_rows if type(row) is dict} != set(range(8))):
        raise ValueError('eight unique heldout cost variants required')
    if cost.get('basis') != ('request-B preparation, stage, transition, source, proof, '
                              'clone, and effect wall time'):
        raise ValueError('matched request-B wall-time basis required')
    by_case = {row['variant']: row for row in cases}
    public_rows = []
    for source in sorted(pair_rows, key=lambda row: row['variant']):
        variant = source['variant']
        case = by_case[variant]
        full, anchor = source.get('full_B_seconds'), source.get('anchor_B_seconds')
        shared = source.get('shared_B_seconds')
        full_branch = source.get('full_B_branch_only_seconds')
        anchor_branch = source.get('anchor_B_branch_only_seconds')
        delta = source.get('anchor_minus_full_B_seconds')
        savings = source.get('B_total_wall_savings_fraction')
        if any(not _finite(v, positive=True) for v in (full, anchor)):
            raise ValueError('positive finite matched costs required')
        if (any(not _finite(v) for v in (shared, full_branch, anchor_branch))
                or type(delta) not in (int, float) or not math.isfinite(delta)
                or type(savings) not in (int, float) or not math.isfinite(savings)):
            raise ValueError('finite component summaries required')
        if (not math.isclose(full, shared + full_branch, rel_tol=1e-9, abs_tol=1e-6)
                or not math.isclose(anchor, shared + anchor_branch,
                                    rel_tol=1e-9, abs_tol=1e-6)
                or not math.isclose(delta, anchor - full, rel_tol=1e-9, abs_tol=1e-6)
                or not math.isclose(savings, (full - anchor) / full,
                                    rel_tol=1e-9, abs_tol=1e-9)):
            raise ValueError('heldout pair cost arithmetic mismatch')
        if (case.get('disabled_config_negative') is None
                or case.get('ambiguous_restart') is None):
            raise ValueError('verified disabled-config and ambiguous-restart evidence required')
        public_rows.append({
            'variant': variant,
            'full_B_seconds': float(full),
            'anchor_B_seconds': float(anchor),
            'anchor_minus_full_B_seconds': float(delta),
            'wall_savings_fraction': float(savings),
        })
    medians = {
        field: float(median(row[field] for row in public_rows))
        for field in ('full_B_seconds', 'anchor_B_seconds',
                      'anchor_minus_full_B_seconds', 'wall_savings_fraction')
    }
    return counts, public_rows, medians


def project_reports(acceptance, cost, model, training, source_hashes,
                    cost_path=None, training_path=None):
    if type(source_hashes) is not dict or set(source_hashes) != {
            'acceptance_report_sha256', 'cost_report_sha256',
            'conditional_model_report_sha256', 'training_total_summary_sha256'}:
        raise ValueError('exact private report source pins required')
    if any(type(v) is not str or HEX64.fullmatch(v) is None
           for v in source_hashes.values()):
        raise ValueError('lowercase SHA-256 source pins required')
    if cost.get('acceptance_report_sha256') != source_hashes['acceptance_report_sha256']:
        raise ValueError('cost report does not pin acceptance report bytes')
    if (cost.get('assembled_manifest_sha256') != acceptance.get('manifest_sha256')
            or model.get('source_reports', {}).get('heldout_cost_analysis', {}).get('sha256')
            != source_hashes['cost_report_sha256']
            or model.get('source_reports', {}).get('training_total_summary', {}).get('sha256')
            != source_hashes['training_total_summary_sha256']):
        raise ValueError('private report source identities differ')
    _check_model(cost, model, training, source_hashes, cost_path, training_path)
    counts, variants, medians = _case_costs(acceptance, cost)
    source_hashes = {
        **source_hashes,
        'freeze_sha256': acceptance['freeze_sha256'],
        'cohort_receipt_sha256': acceptance['cohort_receipt_sha256'],
        'assembled_manifest_sha256': acceptance['manifest_sha256'],
    }
    if any(type(v) is not str or HEX64.fullmatch(v) is None
           for v in source_hashes.values()):
        raise ValueError('acceptance provenance SHA-256 pins required')
    pooled = model['pooled_first_crossing_counts']
    conditional_counts = {key: pooled[key] for key in (
        '0', '1', '2', '5', '10', 'not_crossed_through_k10',
        'expected_variant_repetition_pairs')}
    if (conditional_counts['expected_variant_repetition_pairs'] != 32
            or sum(conditional_counts[k] for k in (
                '0', '1', '2', '5', '10', 'not_crossed_through_k10')) != 32):
        raise ValueError('conditional model must cover 32 variant/repetition pairs')
    summary = {
        'schema': SUMMARY_SCHEMA,
        'scope': 'core-path-only',
        'source_hashes': source_hashes,
        'acceptance': {
            'verified_variants': 8,
            'loaded_disabled_config_negatives': counts['loaded_disabled_config_negatives'],
            'loaded_disabled_issuer_negatives': counts['loaded_disabled_issuer_negatives'],
            'loaded_ambiguous_restart_negatives': counts['loaded_ambiguous_restarts'],
            'missing_loaded_expired_status_negatives': 8,
            'missing_loaded_queue_capacity_negatives': 1,
        },
        'timing': {
            'basis': 'matched request-B component-sum wall time',
            'measured_target_count': 1,
            'variant_count': 8,
            'median_component_direction': (
                'full_lower_cost' if medians['anchor_minus_full_B_seconds'] > 0
                else 'anchor_lower_cost' if medians['anchor_minus_full_B_seconds'] < 0
                else 'equal'),
            'variants': variants,
            'eight_case_medians': medians,
        },
        'conditional_model': {
            'basis': 'Training-012 sampled count-delta changes applied to heldout k=1 deltas',
            'non_k1_values_are_conditional': True,
            'measured_heldout_target_count': 1,
            'pooled_first_crossing_counts': conditional_counts,
        },
        'claims': {
            'component_sum_wall_timing': True,
            'non_k1_conditional_estimate': True,
            'cpu_savings': False,
            'economic_winner': False,
            'whole_application_benefit': False,
            'full_binding_plan_acceptance': False,
        },
    }
    report = render_report(summary)
    return summary, report


def render_report(summary):
    med = summary['timing']['eight_case_medians']
    counts = summary['acceptance']
    model_counts = summary['conditional_model']['pooled_first_crossing_counts']
    lines = [
        '# Heldout public application summary', '',
        'Scope: **core-path only**. The full binding acceptance plan is not established.', '',
        'Eight heldout variants passed the implemented application verifier, including '
        f"{counts['loaded_disabled_config_negatives']} disabled-config negatives, "
        f"{counts['loaded_disabled_issuer_negatives']} disabled-issuer negatives, and "
        f"{counts['loaded_ambiguous_restart_negatives']} ambiguous-restart cases.", '',
        f"Missing loaded negatives: {counts['missing_loaded_expired_status_negatives']} "
        'expired-status cases and '
        f"{counts['missing_loaded_queue_capacity_negatives']} queue-capacity case.", '',
        'Matched request-B timings are component-sum wall times for the eight variants. '
        'They do not establish CPU savings or a whole-application winner.', '',
        '| Metric | Eight-case median |', '|---|---:|',
        f"| Full B wall seconds | {med['full_B_seconds']:.9g} |",
        f"| Anchor B wall seconds | {med['anchor_B_seconds']:.9g} |",
        f"| Anchor minus Full B seconds | {med['anchor_minus_full_B_seconds']:.9g} |",
        f"| Wall savings fraction | {med['wall_savings_fraction']:.9g} |", '',
        (f"Median Anchor B cost was higher than Full B ({med['wall_savings_fraction']:.3%} "
         "wall savings is negative); no request-B component-sum benefit was measured."
         if med['anchor_minus_full_B_seconds'] > 0 else
         f"Median Anchor B cost was lower than Full B ({med['wall_savings_fraction']:.3%} "
         "wall savings); this request-B component result does not establish a whole-application benefit."
         if med['anchor_minus_full_B_seconds'] < 0 else
         'Median Anchor B and Full B costs were equal; no request-B component-sum benefit was measured.'), '',
        'Only heldout target count k=1 is measured. Other counts are conditional estimates '
        'using Training-012 sampled count-delta changes; they are not heldout runs or '
        'measured break-even results.', '',
        'Conditional first-crossing counts over 32 variant/repetition pairs: '
        + ', '.join(f"k={key}: {model_counts[key]}" for key in
                    ('0', '1', '2', '5', '10', 'not_crossed_through_k10')) + '.', '',
    ]
    return '\n'.join(lines)


def _json_bytes(document):
    return (json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def write_bundle(output_dir, summary, report):
    from tools.part5.verify_v3_heldout_public import validate_summary

    output_dir = Path(output_dir)
    if (not output_dir.is_absolute() or output_dir.exists() or output_dir.is_symlink()
            or output_dir.parent.resolve(strict=True) != output_dir.parent):
        raise ValueError('fresh absolute public output directory required')
    validate_summary(summary)
    if report != render_report(summary):
        raise ValueError('public report must be rendered from the allowlisted summary')
    summary_raw = _json_bytes(summary)
    report_raw = report.encode()
    index = {
        'schema': INDEX_SCHEMA,
        'files': {'summary.json': _sha(summary_raw), 'report.md': _sha(report_raw)},
        'source_hashes': summary['source_hashes'],
    }
    index_raw = _json_bytes(index)
    sums_raw = (f"{_sha(index_raw)}  index.json\n"
                f"{_sha(summary_raw)}  summary.json\n"
                f"{_sha(report_raw)}  report.md\n").encode()
    output_dir.mkdir(mode=0o700, parents=False)
    for name, raw in (('index.json', index_raw), ('summary.json', summary_raw),
                      ('report.md', report_raw), ('SHA256SUMS', sums_raw)):
        fd = os.open(output_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return _sha(sums_raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('acceptance-report', 'cost-report', 'conditional-model-report',
                 'training-total-summary'):
        parser.add_argument('--' + name, required=True, metavar='PATH:SHA256')
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    acceptance, ah, ap = read_pinned_json(args.acceptance_report)
    cost, ch, cp = read_pinned_json(args.cost_report)
    model, mh, _ = read_pinned_json(args.conditional_model_report)
    training, th, tp = read_pinned_json(args.training_total_summary)
    hashes = {'acceptance_report_sha256': ah, 'cost_report_sha256': ch,
              'conditional_model_report_sha256': mh,
              'training_total_summary_sha256': th}
    summary, report = project_reports(acceptance, cost, model, training, hashes,
                                      cp, tp)
    digest = write_bundle(args.output_dir, summary, report)
    print(json.dumps({'public_files': sorted(OUTPUT_FILES),
                      'sha256sums_sha256': digest}, sort_keys=True))


if __name__ == '__main__':
    main()
