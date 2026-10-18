#!/usr/bin/env python3
"""Offline verifier for the four-file heldout public projection."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from statistics import median

from tools.part5.publish_v3_heldout_public import (
    INDEX_SCHEMA, OUTPUT_FILES, SUMMARY_SCHEMA, _decode, _sha, render_report,
)


HEX64 = re.compile(r'[0-9a-f]{64}\Z')
SOURCE_KEYS = {
    'acceptance_report_sha256', 'cost_report_sha256',
    'conditional_model_report_sha256', 'training_total_summary_sha256',
    'freeze_sha256', 'cohort_receipt_sha256', 'assembled_manifest_sha256',
}
SUMMARY_KEYS = {'schema', 'scope', 'source_hashes', 'acceptance', 'timing',
                'conditional_model', 'claims'}


def _finite(value, *, positive=False):
    return (type(value) in (int, float) and math.isfinite(value)
            and (value > 0 if positive else value >= 0))


def _read_file(path, cap):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size <= 0 or before.st_size > cap):
        raise ValueError('canonical bounded public file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        ident = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_uid,
                             row.st_nlink, row.st_size, row.st_mtime_ns,
                             row.st_ctime_ns)
        if ident(opened) != ident(before):
            raise ValueError('public file changed at open')
        raw = stream.read(cap + 1)
        if ident(os.fstat(stream.fileno())) != ident(before):
            raise ValueError('public file changed while reading')
    if len(raw) != before.st_size or ident(path.lstat()) != ident(before):
        raise ValueError('public file changed after read')
    return raw


def _exact_object(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(f'{label} has missing or unknown fields')


def validate_summary(summary):
    _exact_object(summary, SUMMARY_KEYS, 'summary')
    if summary.get('schema') != SUMMARY_SCHEMA or summary.get('scope') != 'core-path-only':
        raise ValueError('core-path public summary schema required')
    hashes = summary['source_hashes']
    _exact_object(hashes, SOURCE_KEYS, 'source hashes')
    if any(type(value) is not str or HEX64.fullmatch(value) is None
           for value in hashes.values()):
        raise ValueError('public source hash required')
    acceptance = summary['acceptance']
    acceptance_keys = {'verified_variants', 'loaded_disabled_config_negatives',
                        'loaded_disabled_issuer_negatives',
                        'loaded_ambiguous_restart_negatives',
                        'missing_loaded_expired_status_negatives',
                        'missing_loaded_queue_capacity_negatives'}
    _exact_object(acceptance, acceptance_keys, 'acceptance')
    if acceptance != {
        'verified_variants': 8,
        'loaded_disabled_config_negatives': 8,
        'loaded_disabled_issuer_negatives': 8,
        'loaded_ambiguous_restart_negatives': 8,
        'missing_loaded_expired_status_negatives': 8,
        'missing_loaded_queue_capacity_negatives': 1,
    }:
        raise ValueError('core-path acceptance and missing-negative counts required')
    timing = summary['timing']
    _exact_object(timing, {'basis', 'measured_target_count', 'variant_count',
                           'median_component_direction',
                           'variants', 'eight_case_medians'}, 'timing')
    if (timing['basis'] != 'matched request-B component-sum wall time'
            or timing['measured_target_count'] != 1 or timing['variant_count'] != 8):
        raise ValueError('measured k=1 component-sum timing declaration required')
    variants = timing['variants']
    if type(variants) is not list or len(variants) != 8:
        raise ValueError('eight public variant rows required')
    row_keys = {'variant', 'full_B_seconds', 'anchor_B_seconds',
                'anchor_minus_full_B_seconds', 'wall_savings_fraction'}
    for index, row in enumerate(variants):
        _exact_object(row, row_keys, 'variant row')
        if row['variant'] != index:
            raise ValueError('public variant order must be 0 through 7')
        full, anchor = row['full_B_seconds'], row['anchor_B_seconds']
        delta, savings = (row['anchor_minus_full_B_seconds'],
                           row['wall_savings_fraction'])
        if (not _finite(full, positive=True) or not _finite(anchor, positive=True)
                or type(delta) not in (int, float) or not math.isfinite(delta)
                or type(savings) not in (int, float) or not math.isfinite(savings)
                or not math.isclose(delta, anchor - full, rel_tol=1e-9, abs_tol=1e-6)
                or not math.isclose(savings, (full - anchor) / full,
                                    rel_tol=1e-9, abs_tol=1e-9)):
            raise ValueError('public per-pair arithmetic mismatch')
    medians = timing['eight_case_medians']
    median_keys = {'full_B_seconds', 'anchor_B_seconds',
                   'anchor_minus_full_B_seconds', 'wall_savings_fraction'}
    _exact_object(medians, median_keys, 'eight-case medians')
    for field in median_keys:
        if (type(medians[field]) not in (int, float) or not math.isfinite(medians[field])
                or not math.isclose(medians[field], median(row[field] for row in variants),
                                    rel_tol=1e-9, abs_tol=1e-9)):
            raise ValueError('eight-case median does not match variant rows')
    expected_direction = (
        'full_lower_cost' if medians['anchor_minus_full_B_seconds'] > 0
        else 'anchor_lower_cost' if medians['anchor_minus_full_B_seconds'] < 0
        else 'equal')
    if timing['median_component_direction'] != expected_direction:
        raise ValueError('median component direction does not match paired totals')
    conditional = summary['conditional_model']
    _exact_object(conditional, {'basis', 'non_k1_values_are_conditional',
                                'measured_heldout_target_count',
                                'pooled_first_crossing_counts'}, 'conditional model')
    if (conditional['basis'] != 'Training-012 sampled count-delta changes applied to heldout k=1 deltas'
            or conditional['non_k1_values_are_conditional'] is not True
            or conditional['measured_heldout_target_count'] != 1):
        raise ValueError('conditional non-k1 model disclosure required')
    crossing = conditional['pooled_first_crossing_counts']
    crossing_keys = {'0', '1', '2', '5', '10', 'not_crossed_through_k10',
                     'expected_variant_repetition_pairs'}
    _exact_object(crossing, crossing_keys, 'conditional crossing counts')
    if (any(type(crossing[key]) is not int or crossing[key] < 0
            for key in crossing_keys)
            or crossing['expected_variant_repetition_pairs'] != 32
            or sum(crossing[k] for k in ('0', '1', '2', '5', '10',
                                         'not_crossed_through_k10')) != 32):
        raise ValueError('conditional model must cover 32 variant/repetition pairs')
    claims = summary['claims']
    _exact_object(claims, {'component_sum_wall_timing', 'non_k1_conditional_estimate',
                           'cpu_savings', 'economic_winner',
                           'whole_application_benefit',
                           'full_binding_plan_acceptance'}, 'claims')
    if claims != {
        'component_sum_wall_timing': True,
        'non_k1_conditional_estimate': True,
        'cpu_savings': False,
        'economic_winner': False,
        'whole_application_benefit': False,
        'full_binding_plan_acceptance': False,
    }:
        raise ValueError('required bounded claim labels missing')
    return summary


def verify_bundle(directory, expected_sums_sha256):
    directory = Path(directory)
    if (not directory.is_absolute() or directory.is_symlink()
            or not directory.is_dir() or directory.resolve(strict=True) != directory
            or type(expected_sums_sha256) is not str
            or HEX64.fullmatch(expected_sums_sha256) is None):
        raise ValueError('absolute public directory and trusted SHA256SUMS digest required')
    if {path.name for path in directory.iterdir()} != OUTPUT_FILES:
        raise ValueError('public bundle must contain exactly the four allowed files')
    raw = {name: _read_file(directory / name, 8 * 1024 * 1024)
           for name in OUTPUT_FILES}
    if _sha(raw['SHA256SUMS']) != expected_sums_sha256:
        raise ValueError('trusted SHA256SUMS digest mismatch')
    expected_lines = ''.join(f'{_sha(raw[name])}  {name}\n'
                             for name in ('index.json', 'summary.json', 'report.md'))
    if raw['SHA256SUMS'].decode('ascii') != expected_lines:
        raise ValueError('SHA256SUMS content mismatch')
    index = _decode(raw['index.json'])
    _exact_object(index, {'schema', 'files', 'source_hashes'}, 'index')
    if index['schema'] != INDEX_SCHEMA:
        raise ValueError('public index schema required')
    _exact_object(index['files'], {'summary.json', 'report.md'}, 'public file hashes')
    if index['files'] != {'summary.json': _sha(raw['summary.json']),
                          'report.md': _sha(raw['report.md'])}:
        raise ValueError('index file digest mismatch')
    summary = validate_summary(_decode(raw['summary.json']))
    if index['source_hashes'] != summary['source_hashes']:
        raise ValueError('index and summary provenance hashes differ')
    report = raw['report.md'].decode('utf-8')
    if report != render_report(summary):
        raise ValueError('public report does not match the allowlisted summary')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--expected-sha256sums', required=True)
    args = parser.parse_args()
    summary = verify_bundle(args.directory, args.expected_sha256sums)
    print(json.dumps({'verified': True, 'scope': summary['scope'],
                      'variants': summary['acceptance']['verified_variants']},
                     sort_keys=True))


if __name__ == '__main__':
    main()
