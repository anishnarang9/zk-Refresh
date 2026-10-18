#!/usr/bin/env python3
"""Reconcile measured campaign sessions with prior signed-state and clone costs.

Component sums are derived from individually observed bounded commands, not a
directly timed end-to-end request. The one-time development setup and cohort
issuance are disclosed separately rather than silently amortized per action.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import run_v3_campaign_matrix as matrix

COUNTS = (0, 1, 2, 5, 10)
TRANSITIONS = (1, 2, 5, 10)


def _pinned(path, expected):
    value = matrix.read_json(path)
    if matrix.sha256(path) != expected:
        raise ValueError('changed cost evidence pin')
    return value


def _monitored_step(status, monitor, owner, kind, count=None):
    if (monitor.get('schema') != 1 or monitor.get('owner') != owner
            or monitor.get('censored') is not False
            or monitor.get('stop_reason') is not None
            or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False
            or not isinstance(monitor.get('duration_seconds'), (int, float))
            or not math.isfinite(monitor['duration_seconds'])
            or monitor['duration_seconds'] <= 0
            or status.get('error_type') is not None
            or status.get('application_effect') is not False
            or status.get('ledger_reuse_requires_review') is not True):
        raise ValueError('reviewed bounded common step required')
    if kind == 'prepare':
        accepted = (status.get('scope') == 'part5-v3-local-prepare'
                    and status.get('loaded_program', {}).get('elf_match') is True
                    and status.get('cleanup', {}).get('exit_code') == -2
                    and status['cleanup'].get('reaped') is True)
    else:
        accepted = (status.get('scope') == kind and status.get(
            'stage_verified' if kind == 'part5-v3-campaign-stage'
            else 'transition_verified') is True
            and status.get('validator_cleanup', {}).get('exit_code') == -2
            and status['validator_cleanup'].get('reaped') is True
            and status.get('runner_cleanup', {}).get('exit_code') == 0
            and status['runner_cleanup'].get('reaped') is True)
        if count is not None:
            accepted = accepted and status.get('target_count') == count
    if not accepted:
        raise ValueError('verified signed common step required')
    return monitor['duration_seconds']


def by_count_seconds(prepare, stage, transition):
    return {count: prepare + stage + (transition[count] if count else 0.0)
            for count in COUNTS}


def shared_steps(validated):
    paths = validated['evidence_paths']
    stage_config = _pinned(paths['stage_config'],
                           validated['evidence']['stage_config']['sha256'])
    prior_config = _pinned(stage_config['prior_config'], stage_config['prior_config_sha256'])
    prior_status = _pinned(stage_config['prior_status'], stage_config['prior_status_sha256'])
    prior_monitor = _pinned(stage_config['prior_monitor'], stage_config['prior_monitor_sha256'])
    if (prior_status.get('config_sha256') != stage_config['prior_config_sha256']
            or prior_config.get('scope') != 'part5-v3-local-prepare'):
        raise ValueError('stage must pin exact prior prepare')
    prepare = _monitored_step(prior_status, prior_monitor,
                             stage_config['prior_monitor_owner'], 'prepare')
    stage_status = _pinned(paths['stage_status'], validated['evidence']['stage_status']['sha256'])
    stage_monitor = _pinned(paths['stage_monitor'], validated['evidence']['stage_monitor']['sha256'])
    stage = _monitored_step(stage_status, stage_monitor,
                           validated['stage_monitor_owner'], 'part5-v3-campaign-stage')
    if stage_status.get('config_sha256') != validated['evidence']['stage_config']['sha256']:
        raise ValueError('stage status/config mismatch')
    transition = {}
    for count in TRANSITIONS:
        row = validated['transitions'][str(count)]
        config = _pinned(row['config'], validated['evidence']['transitions'][str(count)]['config']['sha256'])
        status = _pinned(row['status'], validated['evidence']['transitions'][str(count)]['status']['sha256'])
        monitor = _pinned(row['monitor'], validated['evidence']['transitions'][str(count)]['monitor']['sha256'])
        if (status.get('config_sha256') != validated['evidence']['transitions'][str(count)]['config']['sha256']
                or config.get('target_count') != count):
            raise ValueError('transition status/config target mismatch')
        transition[count] = _monitored_step(status, monitor, row['monitor_owner'],
                                           'part5-v3-campaign-transition', count)
    by_count = by_count_seconds(prepare, stage, transition)
    return {'prepare_seconds': prepare, 'stage_seconds': stage,
            'transition_seconds': transition, 'by_count_seconds': by_count}


def clone_costs(validated, economics):
    result = {}
    for session in economics['sessions']:
        if session['status'] != 'valid':
            continue
        slot = {key: session[key] for key in ('mode', 'target_count', 'repetition')}
        paths = matrix.output_paths(validated, slot)
        try:
            receipt = matrix.read_json(paths['slot_receipt'])
        except FileNotFoundError:
            continue
        if (receipt.get('schema') != 'part5-v3-campaign-matrix-slot-v1'
                or any(receipt.get(key) != slot[key] for key in slot)
                or receipt.get('session_report_sha256') != session['session_report_sha256']
                or receipt.get('outer_report_sha256') != session['outer_report_sha256']
                or receipt.get('clone_report_sha256') != matrix.sha256(paths['clone_report'])
                or not isinstance(receipt.get('clone_preparation_wall_seconds'), (int, float))
                or not math.isfinite(receipt['clone_preparation_wall_seconds'])
                or receipt['clone_preparation_wall_seconds'] < 0):
            raise ValueError('slot clone cost/evidence mismatch')
        result[(slot['target_count'], slot['repetition'], slot['mode'])] = (
            receipt['clone_preparation_wall_seconds'])
    return result


def derive(pairs, common_by_count, clones):
    """Add actual same-root common work and per-slot clone time to each pair."""
    results = []
    for pair in pairs:
        count, repetition = pair['target_count'], pair['repetition']
        common = common_by_count.get(count)
        full_clone = clones.get((count, repetition, 'full'))
        anchor_clone = clones.get((count, repetition, 'anchor'))
        row = {'target_count': count, 'repetition': repetition,
               'status': 'incomplete', 'shared_signed_state_seconds': common,
               'full_clone_seconds': full_clone, 'anchor_clone_seconds': anchor_clone,
               'full_component_sum_seconds': None, 'anchor_component_sum_seconds': None,
               'full_minus_anchor_component_sum_seconds': None,
               'component_sum_savings_fraction': None}
        if (pair.get('status') == 'matched' and all(
                isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
                for value in (common, full_clone, anchor_clone))):
            full = pair['full_session_wall_seconds'] + common + full_clone
            anchor = pair['anchor_session_wall_seconds'] + common + anchor_clone
            if full <= 0 or anchor <= 0:
                raise ValueError('positive composite costs required')
            row.update(status='derived', full_component_sum_seconds=full,
                       anchor_component_sum_seconds=anchor,
                       full_minus_anchor_component_sum_seconds=full - anchor,
                       component_sum_savings_fraction=(full - anchor) / full)
        results.append(row)
    return results


def one_time_costs(validated):
    setup_path = matrix.REPO / 'artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json'
    setup = matrix.read_json(setup_path)
    freeze = matrix.read_json(validated['evidence_paths']['freeze'])
    cohort = matrix.read_json(validated['evidence_paths']['cohort_receipt'])
    if (matrix.sha256(setup_path) != freeze['identities']['setup_manifest']
            or setup.get('schema') != 'credential-v3-bounded-setup-v1'
            or not isinstance(setup.get('elapsed_ms'), (int, float))
            or setup['elapsed_ms'] <= 0
            or cohort.get('schema') != 'v3-eleven-signed-training-credentials-v1'
            or cohort.get('preparation_completed_unix_ns', 0)
               <= cohort.get('preparation_started_unix_ns', 0)):
        raise ValueError('pinned one-time setup and cohort preparation required')
    return {'development_setup_seconds': setup['elapsed_ms'] / 1000,
            'cohort_preparation_seconds': (
                cohort['preparation_completed_unix_ns']
                - cohort['preparation_started_unix_ns']) / 1e9,
            'charged_per_request': False}


def reconcile(validated, economics):
    if economics.get('schema') != 'part5-v3-campaign-economics-report-v1':
        raise ValueError('campaign economics report required')
    shared = shared_steps(validated)
    clones = clone_costs(validated, economics)
    pairs = derive(economics['pairs'], shared['by_count_seconds'], clones)
    crossing = {}
    for repetition in (1, 2, 3, 4):
        rows = [row for row in pairs if row['repetition'] == repetition]
        crossing[str(repetition)] = (next((row['target_count'] for row in rows
            if row['status'] == 'derived' and row['anchor_component_sum_seconds']
               <= row['full_component_sum_seconds']), None)
            if len(rows) == 5 and all(row['status'] == 'derived' for row in rows)
            else None)
    return {'schema': 'part5-v3-campaign-observed-component-costs-v1',
            'training_only': True, 'matrix_manifest_sha256': validated['manifest_sha256'],
            'economics_report_sha256': None,
            'directly_timed_whole_application_session': False,
            'component_sum_scope': ('For each matched pair, add the actual bounded prepare, '
                'stage, exact R0-to-Rk signed transition and slot-clone durations to each '
                'directly timed source-import-through-effect session. The same preexisting '
                'signed state is shared by both modes; component sums are derived and '
                'do not measure idle gaps, full deployment, or operator churn.'),
            'shared': shared, 'one_time': one_time_costs(validated),
            'pairs': pairs, 'first_sampled_break_even_by_repetition': crossing,
            'whole_application_benefit_established': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix-manifest', type=Path, required=True)
    parser.add_argument('--economics-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError('fresh cost report path required')
    validated = matrix.validate_manifest(args.matrix_manifest)
    economics = matrix.read_json(args.economics_report)
    report = reconcile(validated, economics)
    report['economics_report_sha256'] = matrix.sha256(args.economics_report)
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'derived_pairs': sum(row['status'] == 'derived' for row in report['pairs']),
                      'total_pairs': len(report['pairs'])}))


if __name__ == '__main__':
    main()
