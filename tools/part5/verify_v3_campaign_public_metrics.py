#!/usr/bin/env python3
"""Offline receipt linkage and arithmetic verification for the public metrics capsule."""
import argparse
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import verify_v3_campaign_public_projection as projection
from tools.part5 import verify_v3_campaign_public_receipts as receipts
from tools.part5 import verify_v3_campaign_public_bundle_bindings as bindings
from tools.part5 import verify_v3_campaign_public_clock_audit as clock

SCHEMA = 'part5-v3-public-metrics-capsule-v1'
SCOPE = ('arithmetic and published projection only; underlying private report truth '
         'and publisher-validated identity equality are not independently verifiable')
MAX_METRICS_BYTES = 256 * 1024
COUNTS = (0, 1, 2, 5, 10)
SOURCE_FIELDS = set('projection_index_sha256 receipt_index_sha256 sequence_receipt_sha256 matrix_manifest_canonical_sha256 clock_audit_report_sha256 economics_input_manifest_sha256 economics_report_sha256 reconciliation_report_sha256 total_summary_report_sha256 exporter_source_sha256 economics_analyzer_source_sha256 reconciler_source_sha256 total_summarizer_source_sha256'.split())
ROOT_FIELDS = set('schema campaign_id training_only matrix_grid_complete source_hashes slots shared one_time claims'.split())
SLOT_FIELDS = set('sequence repetition target_count mode slot_identity_sha256 slot_receipt_sha256 session_report_sha256 outer_report_sha256 clone_report_sha256 status match_group outer_wall_seconds clone_preparation_seconds'.split())
SHARED_HASHES = set('prepare_status_sha256 prepare_monitor_sha256 stage_status_sha256 stage_monitor_sha256 stage_config_sha256'.split())
ONE_TIME_HASHES = {'setup_manifest_sha256', 'cohort_receipt_sha256'}
CLAIMS = {
    'directly_timed_whole_application_session': False,
    'whole_application_benefit_established': False,
    'complete_tree_cpu_qualified': False,
    'interpolation_or_extrapolation_used': False,
    'identity_join_scope': 'publisher-validated equality; underlying private reports omitted',
}


def _fields(obj, fields, description):
    projection._require_fields(obj, fields, description)


def _equal(actual, expected, description):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError(f'{description} mismatch')


def _seconds(value, positive=False):
    if not clock._number(value) or value < 0 or (positive and value == 0):
        raise ValueError('seconds must be finite nonnegative numbers (positive where required)')
    return value


def _hashes(obj, fields):
    for field in fields:
        projection._require_sha(obj[field], 'source digest')


def _read(path, cap, description):
    path = Path(path).absolute()
    try:
        if path.resolve(strict=True) != path:
            raise ValueError('public input must have no symlink parents')
    except OSError as error:
        raise ValueError('public input unavailable') from error
    return projection._read_regular(path, cap, description)


def _arithmetic(capsule):
    shared = capsule['shared']
    transitions = {row['target_count']: row['seconds'] for row in shared['transitions']}
    groups = {}
    for slot in capsule['slots']:
        groups.setdefault(slot['match_group'], {})[slot['mode']] = slot
    pairs = []
    for group, modes in sorted(groups.items()):
        if set(modes) != {'full', 'anchor', 'coalesced-full'}:
            raise ValueError('each match group must have exactly three modes')
        full, anchor = modes['full'], modes['anchor']
        k = full['target_count']
        common = shared['prepare_seconds'] + shared['stage_seconds'] + transitions.get(k, 0)
        f = _seconds(full['outer_wall_seconds'] + common + full['clone_preparation_seconds'], True)
        a = _seconds(anchor['outer_wall_seconds'] + common + anchor['clone_preparation_seconds'], True)
        delta = f - a
        fraction = delta / f
        if not clock._number(delta) or not clock._number(fraction):
            raise ValueError('derived arithmetic must be finite')
        pairs.append({'match_group': group, 'repetition': full['repetition'], 'target_count': k,
                      'full_total_seconds': f, 'anchor_total_seconds': a,
                      'delta_seconds': delta, 'savings_fraction': fraction})
    summaries = []
    for k in COUNTS:
        rows = [row for row in pairs if row['target_count'] == k]
        summary = {'target_count': k, 'pair_count': len(rows)}
        for field in ('full_total_seconds', 'anchor_total_seconds', 'delta_seconds', 'savings_fraction'):
            summary['median_' + field] = statistics.median(row[field] for row in rows)
            if not clock._number(summary['median_' + field]):
                raise ValueError('derived medians must be finite')
        summary.update(min_savings_fraction=min(row['savings_fraction'] for row in rows),
                       max_savings_fraction=max(row['savings_fraction'] for row in rows),
                       positive_count=sum(row['delta_seconds'] > 0 for row in rows),
                       zero_count=sum(row['delta_seconds'] == 0 for row in rows),
                       negative_count=sum(row['delta_seconds'] < 0 for row in rows),
                       paired_fraction_at_least_20_percent=summary['median_savings_fraction'] >= .20)
        summaries.append(summary)
    def crossing(rows, field):
        for index, k in enumerate(COUNTS):
            if next(row for row in rows if row['target_count'] == k)[field] > 0:
                return {'first_positive_target_count': k,
                        'preceding_sampled_target_count': COUNTS[index - 1] if index else None,
                        'not_crossed_through_k10': False}
        return {'first_positive_target_count': None, 'preceding_sampled_target_count': None,
                'not_crossed_through_k10': True}
    per_repetition = [dict(repetition=repetition, **crossing(
        [row for row in pairs if row['repetition'] == repetition], 'delta_seconds'))
        for repetition in range(1, 5)]
    histogram = [{'first_positive_target_count': k,
                  'repetition_count': sum(row['first_positive_target_count'] == k for row in per_repetition)}
                 for k in (*COUNTS, None)]
    return {'pair_totals': pairs, 'per_target_count': summaries,
            'median_sampled_break_even': crossing(summaries, 'median_delta_seconds'),
            'per_repetition_sampled_break_even': per_repetition,
            'first_crossing_counts': histogram}


def verify_metrics(projection_dir, receipt_dir, metrics_path, expected_sha256, clock_audit_path):
    """Verify public sources and a separately trusted capsule byte digest; read no private input."""
    plan_root, receipt_root = bindings._real_root(projection_dir), bindings._real_root(receipt_dir)
    public = projection.verify_bundle(plan_root)
    chain = receipts.verify_bundle(receipt_root)
    bound = bindings.verify_bundles(plan_root, receipt_root)
    audit_raw = _read(clock_audit_path, clock.MAX_REPORT_BYTES, 'clock audit')
    audit = projection._json_object(audit_raw, 'clock audit')
    audit_result = clock.verify_report(audit)
    if not audit_result['report_passed']:
        raise ValueError('public clock audit must pass')
    projection._require_sha(expected_sha256, 'expected capsule digest')
    raw = _read(metrics_path, MAX_METRICS_BYTES, 'metrics capsule')
    if projection._sha256(raw) != expected_sha256:
        raise ValueError('metrics capsule byte hash mismatch')
    capsule = projection._json_object(raw, 'metrics capsule')
    _fields(capsule, ROOT_FIELDS, 'metrics capsule')
    for field, value in {'schema': SCHEMA, 'campaign_id': 'training-011',
                         'training_only': True, 'matrix_grid_complete': True}.items():
        _equal(capsule[field], value, field)
    _equal(bound['campaign_id'], capsule['campaign_id'], 'campaign')
    sources = capsule['source_hashes']
    _fields(sources, SOURCE_FIELDS, 'source hashes')
    _hashes(sources, SOURCE_FIELDS)
    for field, digest in {'projection_index_sha256': public['index_sha256'],
                          'receipt_index_sha256': chain['index_sha256'],
                          'sequence_receipt_sha256': bound['sequence_receipt_sha256'],
                          'matrix_manifest_canonical_sha256': bound['matrix_manifest_canonical_sha256'],
                          'clock_audit_report_sha256': projection._sha256(audit_raw)}.items():
        _equal(sources[field], digest, field)
    _equal(audit['matrix_manifest_sha256'], sources['matrix_manifest_canonical_sha256'], 'clock manifest')
    _equal(audit['sequence_receipt_sha256'], sources['sequence_receipt_sha256'], 'clock sequence')
    if 'campaign_id' in audit:
        _equal(audit['campaign_id'], capsule['campaign_id'], 'clock campaign')
    sequence = bindings._verified_document(receipt_root, 'sequence-receipt.json',
                                           receipts.MAX_SEQUENCE_BYTES, chain['sequence_receipt_sha256'])
    slots = capsule['slots']
    if type(slots) is not list or len(slots) != 60:
        raise ValueError('exactly 60 metrics slots required')
    for slot, row, expected, audit_slot in zip(slots, sequence['sequence'], receipts._registered_slots(), audit['slots']):
        _fields(slot, SLOT_FIELDS, 'metrics slot')
        for field in ('sequence', 'repetition', 'target_count', 'mode', 'slot_identity_sha256', 'slot_receipt_sha256'):
            _equal(slot[field], row[field], 'slot ' + field)
        _equal(slot['status'], 'valid', 'slot status')
        group = (slot['repetition'] - 1) * 5 + COUNTS.index(slot['target_count']) + 1
        _equal(slot['match_group'], group, 'match group')
        _hashes(slot, {field for field in SLOT_FIELDS if field.endswith('_sha256')})
        slot_raw = _read(receipt_root / expected['path'], receipts.MAX_SLOT_BYTES, 'slot receipt')
        _equal(projection._sha256(slot_raw), row['slot_receipt_sha256'], 'slot receipt bytes')
        receipt = projection._json_object(slot_raw, 'slot receipt')
        for field in ('session_report_sha256', 'outer_report_sha256', 'clone_report_sha256'):
            _equal(slot[field], receipt[field], 'slot ' + field)
        _seconds(slot['clone_preparation_seconds'])
        _seconds(slot['outer_wall_seconds'])
        if slot['clone_preparation_seconds'] != receipt['clone_preparation_wall_seconds']:
            raise ValueError('clone preparation seconds mismatch')
        for field in ('sequence', 'repetition', 'target_count', 'mode', 'slot_receipt_sha256', 'outer_report_sha256'):
            _equal(slot[field], audit_slot[field], 'clock slot ' + field)
        if slot['outer_wall_seconds'] != audit_slot['monotonic_duration_seconds']:
            raise ValueError('clock duration differs from projected outer time')
    shared = capsule['shared']
    _fields(shared, SHARED_HASHES | {'prepare_seconds', 'stage_seconds', 'transitions'}, 'shared')
    _hashes(shared, SHARED_HASHES)
    for field in ('prepare_seconds', 'stage_seconds'):
        _seconds(shared[field], True)
    if type(shared['transitions']) is not list or len(shared['transitions']) != 4:
        raise ValueError('exactly four transitions required')
    for transition, k in zip(shared['transitions'], COUNTS[1:]):
        _fields(transition, {'target_count', 'seconds', 'config_sha256', 'status_sha256', 'monitor_sha256'}, 'transition')
        _equal(transition['target_count'], k, 'transition count')
        _seconds(transition['seconds'], True)
        _hashes(transition, {'config_sha256', 'status_sha256', 'monitor_sha256'})
    one_time = capsule['one_time']
    _fields(one_time, ONE_TIME_HASHES | {'development_setup_seconds', 'cohort_preparation_seconds', 'charged_per_request'}, 'one time')
    _hashes(one_time, ONE_TIME_HASHES)
    for field in ('development_setup_seconds', 'cohort_preparation_seconds'):
        _seconds(one_time[field], True)
    _equal(one_time['charged_per_request'], False, 'one time charge')
    _fields(capsule['claims'], set(CLAIMS), 'claims')
    for field, value in CLAIMS.items():
        _equal(capsule['claims'][field], value, 'claim')
    result = _arithmetic(capsule)
    # Recheck exact public byte pins following all joins.
    for path, cap, digest in [(plan_root / 'index.json', projection.MAX_INDEX_BYTES, public['index_sha256']),
                              (receipt_root / 'index.json', receipts.MAX_INDEX_BYTES, chain['index_sha256']),
                              (metrics_path, MAX_METRICS_BYTES, expected_sha256),
                              (clock_audit_path, clock.MAX_REPORT_BYTES, sources['clock_audit_report_sha256'])]:
        _equal(projection._sha256(_read(path, cap, 'public input')), digest, 'public input changed')
    return dict(status='verified', scope=SCOPE, campaign_id='training-011', slot_count=60,
                matched_pair_count=20, metrics_sha256=expected_sha256,
                one_time_costs=one_time, **result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('projection', type=Path)
    parser.add_argument('receipts', type=Path)
    parser.add_argument('metrics', type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--clock-audit', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify_metrics(args.projection, args.receipts, args.metrics,
                                args.expected_sha256, args.clock_audit)
    except Exception as error:
        raise SystemExit(f'public metrics rejected ({type(error).__name__})') from None
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
