#!/usr/bin/env python3
"""Summarize matched whole-session costs from pinned Part 5 evidence.

The total for each mode/repetition/update count is the directly timed outer
session wall duration plus shared prepare/stage/signed-transition duration and
that slot's separately timed ledger-clone preparation. The shared part is
added to both modes before calculating savings, so it affects the percentage
denominator while canceling from the absolute pair delta.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics


COUNTS = (0, 1, 2, 5, 10)
REPETITIONS = (1, 2, 3, 4)
TARGET_SAVINGS_FRACTION = 0.20
ECONOMICS_SCHEMA = 'part5-v3-campaign-economics-report-v1'
RECONCILIATION_SCHEMA = 'part5-v3-campaign-observed-component-costs-v1'
OUTPUT_SCHEMA = 'part5-v3-campaign-total-cost-summary-v1'
MAX_INPUT_BYTES = 4 * 1024 * 1024


def _finite_nonnegative(value):
    return (type(value) in (int, float) and math.isfinite(value) and value >= 0)


def _sha256(value):
    return (isinstance(value, str) and len(value) == 64
            and all(char in '0123456789abcdef' for char in value))


def _key(row):
    count, repetition = row.get('target_count'), row.get('repetition')
    if type(count) is not int or count not in COUNTS:
        raise ValueError('registered target_count required')
    if type(repetition) is not int or repetition not in REPETITIONS:
        raise ValueError('registered repetition required')
    return repetition, count


def _index(rows, name):
    if not isinstance(rows, list):
        raise ValueError(f'{name} pair array required')
    indexed = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f'{name} pair objects required')
        key = _key(row)
        if key in indexed:
            raise ValueError(f'duplicate {name} pair')
        indexed[key] = row
    return indexed


def _valid_pair(economics_row, cost_row):
    if economics_row.get('status') != 'matched' or cost_row.get('status') != 'derived':
        return False
    fields = ('full_session_wall_seconds', 'anchor_session_wall_seconds')
    if any(not _finite_nonnegative(economics_row.get(field))
           for field in fields):
        raise ValueError('matched session wall durations must be finite and nonnegative')
    for field in ('shared_signed_state_seconds', 'full_clone_seconds',
                  'anchor_clone_seconds', 'full_component_sum_seconds',
                  'anchor_component_sum_seconds'):
        if not _finite_nonnegative(cost_row.get(field)):
            raise ValueError('derived component costs must be finite and nonnegative')
    expected_full = (economics_row['full_session_wall_seconds']
                     + cost_row['shared_signed_state_seconds']
                     + cost_row['full_clone_seconds'])
    expected_anchor = (economics_row['anchor_session_wall_seconds']
                       + cost_row['shared_signed_state_seconds']
                       + cost_row['anchor_clone_seconds'])
    if (not math.isclose(expected_full, cost_row['full_component_sum_seconds'],
                         rel_tol=1e-9, abs_tol=1e-7)
            or not math.isclose(expected_anchor, cost_row['anchor_component_sum_seconds'],
                                rel_tol=1e-9, abs_tol=1e-7)):
        raise ValueError('component total mismatch with pinned direct session and costs')
    if expected_full <= 0 or expected_anchor <= 0:
        raise ValueError('positive total session wall costs required')
    return True


def _summarize_spread(rows):
    if not rows:
        return {'matched_pairs': 0, 'median_full_total_wall_seconds': None,
                'median_anchor_total_wall_seconds': None,
                'median_full_minus_anchor_total_wall_seconds': None,
                'median_total_wall_savings_fraction': None,
                'fraction_min': None, 'fraction_max': None,
                'expected_pairs': len(REPETITIONS),
                'paired_sign_counts': {
                    'full_minus_anchor_positive': 0,
                    'full_minus_anchor_zero': 0,
                    'full_minus_anchor_negative': 0,
                    'matched_pairs': 0,
                    'expected_pairs': len(REPETITIONS)},
                'registered_20_percent_total_wall_target': 'incomplete_pairs'}
    fractions = [row['total_wall_savings_fraction'] for row in rows]
    full = [row['full_total_wall_seconds'] for row in rows]
    anchor = [row['anchor_total_wall_seconds'] for row in rows]
    deltas = [row['full_minus_anchor_total_wall_seconds'] for row in rows]
    median_fraction = statistics.median(fractions)
    complete = len(rows) == len(REPETITIONS)
    paired_sign_counts = {
        'full_minus_anchor_positive': sum(delta > 0 for delta in deltas),
        'full_minus_anchor_zero': sum(delta == 0 for delta in deltas),
        'full_minus_anchor_negative': sum(delta < 0 for delta in deltas),
        'matched_pairs': len(rows),
        'expected_pairs': len(REPETITIONS),
    }
    return {
        'matched_pairs': len(rows),
        'expected_pairs': len(REPETITIONS),
        'median_full_total_wall_seconds': statistics.median(full),
        'median_anchor_total_wall_seconds': statistics.median(anchor),
        'median_full_minus_anchor_total_wall_seconds': statistics.median(deltas),
        'median_total_wall_savings_fraction': median_fraction,
        'fraction_min': min(fractions),
        'fraction_max': max(fractions),
        'paired_sign_counts': paired_sign_counts,
        'per_repetition_total_wall_savings_fraction': {
            str(row['repetition']): row['total_wall_savings_fraction'] for row in rows},
        'registered_20_percent_total_wall_target': (
            'incomplete_pairs' if not complete else
            'met_by_median' if median_fraction >= TARGET_SAVINGS_FRACTION else
            'not_met_by_median'),
    }


def summarize(reconciliation, economics):
    """Build a pair-level total-cost report from reconciled and direct reports."""
    if (not isinstance(reconciliation, dict)
            or reconciliation.get('schema') != RECONCILIATION_SCHEMA
            or reconciliation.get('training_only') is not True
            or reconciliation.get('directly_timed_whole_application_session') is not False):
        raise ValueError('pinned training component reconciliation required')
    if (not _sha256(reconciliation.get('matrix_manifest_sha256'))
            or not _sha256(reconciliation.get('economics_report_sha256'))):
        raise ValueError('reconciler evidence hashes required')
    if (not isinstance(economics, dict) or economics.get('schema') != ECONOMICS_SCHEMA
            or economics.get('training_only') is not True):
        raise ValueError('training campaign economics report required')
    if type(economics.get('grid_complete', False)) is not bool:
        raise ValueError('training matrix grid completeness must be boolean')
    matrix_grid_complete = economics.get('grid_complete') is True

    effect_costs = economics.get('application_effect_costs')
    effect_metric_sessions = 0
    effect_metrics_by_mode = None
    if effect_costs is not None:
        if not isinstance(effect_costs, dict):
            raise ValueError('application effect cost map required')
        confirmed = effect_costs.get('confirmed_rpc_metrics')
        by_mode = confirmed.get('by_mode') if isinstance(confirmed, dict) else None
        if not isinstance(by_mode, dict) or set(by_mode) != {
                'full', 'anchor', 'coalesced-full'}:
            raise ValueError('application effect metrics by mode required')
        effect_metrics_by_mode = {}
        for mode in ('full', 'anchor', 'coalesced-full'):
            row = by_mode[mode]
            count = row.get('available_samples') if isinstance(row, dict) else None
            if type(count) is not int or count < 0:
                raise ValueError('application effect metric sample count required')
            values = row.get('sampled_values')
            if type(values) is not list or len(values) != count:
                raise ValueError('application effect metric sample count differs from values')
            seen = set()
            for value in values:
                if (type(value) is not dict
                        or set(value) != {'target_count', 'repetition',
                                          'transaction_bytes', 'compute_units',
                                          'fee_lamports'}
                        or type(value['target_count']) is not int
                        or value['target_count'] not in COUNTS
                        or type(value['repetition']) is not int
                        or value['repetition'] not in REPETITIONS
                        or type(value['transaction_bytes']) is not int
                        or value['transaction_bytes'] <= 0
                        or any(type(value[field]) is not int or value[field] < 0
                               for field in ('compute_units', 'fee_lamports'))):
                    raise ValueError('invalid confirmed application effect metric sample')
                key = value['target_count'], value['repetition']
                if key in seen:
                    raise ValueError('duplicate confirmed application effect metric sample')
                seen.add(key)
            effect_metric_sessions += count
            effect_metrics_by_mode[mode] = {'available_samples': count,
                                            'sampled_values': values}
        if any(effect_costs.get(field) is not bool(effect_metric_sessions)
               for field in ('transaction_bytes_available',
                             'compute_units_available', 'fee_lamports_available')):
            raise ValueError('application effect availability contradicts samples')

    econ = _index(economics.get('pairs'), 'economics')
    costs = _index(reconciliation.get('pairs'), 'reconciliation')
    if set(econ) != set(costs):
        raise ValueError('economics and reconciliation pair keys differ')

    pair_rows = []
    for repetition, count in sorted(econ):
        source, cost = econ[(repetition, count)], costs[(repetition, count)]
        row = {'repetition': repetition, 'target_count': count,
               'status': 'incomplete'}
        if _valid_pair(source, cost):
            full_total = cost['full_component_sum_seconds']
            anchor_total = cost['anchor_component_sum_seconds']
            delta = full_total - anchor_total
            row.update(status='matched',
                       full_outer_session_wall_seconds=source['full_session_wall_seconds'],
                       anchor_outer_session_wall_seconds=source['anchor_session_wall_seconds'],
                       shared_signed_state_seconds=cost['shared_signed_state_seconds'],
                       full_clone_preparation_seconds=cost['full_clone_seconds'],
                       anchor_clone_preparation_seconds=cost['anchor_clone_seconds'],
                       full_total_wall_seconds=full_total,
                       anchor_total_wall_seconds=anchor_total,
                       full_minus_anchor_total_wall_seconds=delta,
                       total_wall_savings_fraction=delta / full_total)
            for field in ('full_sampled_peak_owned_tree_rss_bytes',
                          'anchor_sampled_peak_owned_tree_rss_bytes',
                          'full_sampled_peak_storage_growth_bytes',
                          'anchor_sampled_peak_storage_growth_bytes'):
                if field in source:
                    value = source[field]
                    if type(value) is not int or value < 0:
                        raise ValueError(f'{field} must be a nonnegative integer')
                    row[field] = value
        pair_rows.append(row)

    by_update_count = {}
    for count in COUNTS:
        group = [row for row in pair_rows if row['target_count'] == count
                 and row['status'] == 'matched']
        by_update_count[str(count)] = _summarize_spread(group)

    if matrix_grid_complete and sum(row['status'] == 'matched' for row in pair_rows) != 20:
        raise ValueError('complete matrix requires all 20 matched Full/Anchor pairs')
    measured_median = {'status': 'incomplete', 'first_sampled_k': None,
                       'previous_sampled_k': None,
                       'basis': ('first sampled k with positive median of four paired '
                                 'Full-minus-Anchor totals')}
    if matrix_grid_complete:
        crossing = next((count for count in COUNTS
                         if by_update_count[str(count)][
                             'median_full_minus_anchor_total_wall_seconds'] > 0), None)
        measured_median.update(
            status='crossed' if crossing is not None else 'not_crossed_through_k10',
            first_sampled_k=crossing,
            previous_sampled_k=(COUNTS[COUNTS.index(crossing) - 1]
                                if crossing is not None and crossing != COUNTS[0] else None))

    by_pair_key = {(row['repetition'], row['target_count']): row for row in pair_rows}
    break_even = {}
    first_crossing_distribution = {str(count): 0 for count in COUNTS}
    first_crossing_distribution.update(not_crossed_through_k10=0, incomplete=0)
    for repetition in REPETITIONS:
        crossing = None
        incomplete_before_crossing = False
        complete_through_max = True
        for count in COUNTS:
            row = by_pair_key.get((repetition, count))
            if row is None or row['status'] != 'matched':
                incomplete_before_crossing = True
                complete_through_max = False
                break
            if row['full_minus_anchor_total_wall_seconds'] > 0:
                crossing = count
                break
        if crossing is not None:
            state, reason = 'crossed', 'first measured sampled count'
            first_crossing_distribution[str(crossing)] += 1
        elif incomplete_before_crossing:
            state, reason = 'incomplete', 'a preceding sampled count is missing'
            first_crossing_distribution['incomplete'] += 1
        elif complete_through_max:
            state, reason = 'not_crossed_through_k10', 'all registered counts measured'
            first_crossing_distribution['not_crossed_through_k10'] += 1
        else:
            state, reason = 'incomplete', 'registered sequence incomplete'
        break_even[str(repetition)] = {
            'first_positive_pair_k': crossing,
            'status': state, 'basis': reason}

    one_time = reconciliation.get('one_time')
    if not isinstance(one_time, dict):
        raise ValueError('separate one-time development costs required')
    return {
        'schema': OUTPUT_SCHEMA,
        'training_only': True,
        'source_hashes': {
            'matrix_manifest_sha256': reconciliation['matrix_manifest_sha256'],
            'economics_report_sha256': reconciliation['economics_report_sha256'],
        },
        'accounting': (
            'Each pair total is directly timed outer session wall plus the same-count '
            'shared prepare/stage/exact R0-to-Rk transition duration plus that mode slot clone '
            'preparation. The shared duration is added to both modes; do not sum separate '
            'run medians.'),
        'matrix_grid_complete': matrix_grid_complete,
        'matched_pairs': sum(row['status'] == 'matched' for row in pair_rows),
        'expected_pairs': len(REPETITIONS) * len(COUNTS),
        'pairs': pair_rows,
        'by_update_count': by_update_count,
        'break_even': {
            'basis': ('measured crossing uses the median of four within-pair total wall '
                      'differences; per-repetition first positive pair is descriptive'),
            'measured_median': measured_median,
            'per_repetition': break_even,
            'first_crossing_distribution': {
                'by_sampled_k': {str(count): first_crossing_distribution[str(count)]
                                 for count in COUNTS},
                'not_crossed_through_k10': first_crossing_distribution[
                    'not_crossed_through_k10'],
                'incomplete': first_crossing_distribution['incomplete'],
                'expected_repetitions': len(REPETITIONS),
            },
            'interpolation_or_extrapolation_used': False,
        },
        'one_time_costs': {
            **one_time,
            'accounting_note': ('Development setup and cohort preparation are disclosed '
                                'separately and are not silently charged per request.'),
        },
        'cpu': {
            'complete_tree_cpu_qualified': False,
            'claim': 'unqualified; leader wait4 and sampled tree self-CPU overlap',
        },
        'resource_limits': {
            'rss_and_storage': 'report per-slot sampled outer peaks from the economics report',
            'transaction_bytes_available': effect_metric_sessions > 0,
            'compute_units_available': effect_metric_sessions > 0,
            'fee_lamports_available': effect_metric_sessions > 0,
            'confirmed_application_effect_metric_sessions': effect_metric_sessions,
            'confirmed_rpc_metric_source': 'economics report application_effect_costs',
            'confirmed_rpc_metrics_by_mode': effect_metrics_by_mode,
        },
        'extrapolation_used': False,
        'whole_application_benefit_established': False,
        'benefit_interpretation': (
            'Training measurements only. The 20 percent indicator applies independently '
            'to each sampled k when all four matched pairs are present; it does not establish '
            'an operator workload or a selected real-world update frequency.'),
    }


def _read_json(path):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('input report exceeds size cap')
    return json.loads(raw), raw


def load_and_summarize(reconciliation_path, matrix_manifest_path, economics_path):
    reconciliation, _ = _read_json(reconciliation_path)
    matrix_manifest, _ = _read_json(matrix_manifest_path)
    economics, economics_raw = _read_json(economics_path)
    matrix_pin = hashlib.sha256(
        (json.dumps(matrix_manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
    ).hexdigest()
    if reconciliation.get('matrix_manifest_sha256') != matrix_pin:
        raise ValueError('matrix manifest pin mismatch')
    economics_pin = hashlib.sha256(economics_raw).hexdigest()
    if reconciliation.get('economics_report_sha256') != economics_pin:
        raise ValueError('economics report pin mismatch')
    return summarize(reconciliation, economics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reconciliation-report', type=Path, required=True)
    parser.add_argument('--matrix-manifest', type=Path, required=True)
    parser.add_argument('--economics-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError('fresh total-cost output path required')
    report = load_and_summarize(args.reconciliation_report,
                                args.matrix_manifest, args.economics_report)
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'matched_pairs': report['matched_pairs'],
                      'expected_pairs': report['expected_pairs']}))


if __name__ == '__main__':
    main()
