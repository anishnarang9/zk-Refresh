#!/usr/bin/env python3
"""Aggregate explicitly listed, matched v3 Full/Anchor campaign sessions.

Input is a JSON manifest with `sessions` rows containing mode, target_count,
repetition, session_report and outer_report. Paths are relative to the manifest.
`--initialize-manifest` writes all 60 registered Full/Anchor/coalesced-full
slots with expected absolute paths under separate roots:
  <session-root>/rN-kK-MODE/session-report.json
  <outer-root>/rN-kK-MODE/report.json
The initializer creates only the new manifest file. The analyzer never fills
missing measurements or estimates unobserved break-even.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics


COUNTS = (0, 1, 2, 5, 10)
MODES = ('full', 'anchor', 'coalesced-full')
REPETITIONS = (1, 2, 3, 4)
ORDERS = (
    ('full', 'anchor', 'coalesced-full'),
    ('anchor', 'coalesced-full', 'full'),
    ('full', 'coalesced-full', 'anchor'),
    ('coalesced-full', 'anchor', 'full'),
)
INPUT_SCHEMA = 'part5-v3-campaign-economics-input-v1'
SESSION_SCHEMA = 'part5-v3-campaign-session-v1'
OUTER_MEASUREMENT = 'bounded_complete_session'
TARGET_SAVINGS_FRACTION = 0.20
MAX_REPORT_BYTES = 4 * 1024 * 1024


def _number(value, *, positive=False):
    if type(value) not in (int, float) or not math.isfinite(value):
        return False
    return value > 0 if positive else value >= 0


def _is_sha256(value):
    return (isinstance(value, str) and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _read_json(path):
    raw = _read_bounded_file(path)
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def _read_bounded_file(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_REPORT_BYTES:
            raise ValueError('bounded regular report file required')
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode,
                                 info.st_uid, info.st_size, info.st_mtime_ns,
                                 info.st_ctime_ns)
        raw = stream.read(MAX_REPORT_BYTES + 1)
        after = os.fstat(stream.fileno())
    try:
        path_identity = path.lstat()
    except OSError as error:
        raise ValueError('report path changed while reading') from error
    if (len(raw) != before.st_size or len(raw) > MAX_REPORT_BYTES
            or identity(before) != identity(after)
            or identity(before) != identity(path_identity)):
        raise ValueError('report changed while reading')
    return raw


def _read_pinned_json(path, expected_sha256):
    """Check a report pin before parsing the report contents."""
    raw = _read_bounded_file(path)
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError('report identity mismatch')
    return json.loads(raw)


def _is_registered_matrix_slot_path(session_path, slot):
    path = Path(session_path)
    slot_path = path.parent.parent
    campaign_root = slot_path.parent
    prefix = 'v3-matrix-'
    if (path.parent.name != 'work'
            or slot_path.name != (
                f"slot-r{slot['repetition']}-k{slot['target_count']}-{slot['mode']}")
            or not campaign_root.name.startswith(prefix)):
        return False
    campaign_id = campaign_root.name[len(prefix):]
    return bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', campaign_id))


def _application_effect_costs(session_path, session, slot):
    """Read transaction metrics only from the session-pinned private effect report."""
    unavailable = {
        'application_effect_cost_metrics_status': 'effect_config_missing',
        'confirmed_rpc_metrics': None,
        'finalized_effect_scope': None,
    }
    config_sha = session.get('effect_config_sha256')
    if config_sha is None:
        return unavailable
    if not _is_sha256(config_sha):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_config_identity_missing'}
    config_path = Path(session_path).parent / 'effect-config.json'
    try:
        config = _read_pinned_json(config_path, config_sha)
    except FileNotFoundError:
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_config_missing'}
    except ValueError as error:
        status = ('effect_config_identity_mismatch'
                  if str(error) == 'report identity mismatch'
                  else 'effect_config_unreadable')
        return {**unavailable, 'application_effect_cost_metrics_status': status}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_config_unreadable'}

    if (not isinstance(config, dict) or config.get('schema') != 1
            or config.get('scope') != 'part5-v3-campaign-effect'
            or config.get('mode') != slot['mode']
            or config.get('proof_mode') != slot['mode']
            or config.get('target_count') != slot['target_count']):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_config_dimensions_mismatch'}

    # Matrix slots keep private effect output as a sibling of the matrix root.
    # Reconstruct the one permitted path from the pinned session's slot instead
    # of trusting an arbitrary path supplied by effect-config.json.
    slot_path = Path(session_path).parent.parent
    campaign_root = slot_path.parent
    artifact_root = campaign_root.parent
    expected_slot_name = (
        f"slot-r{slot['repetition']}-k{slot['target_count']}-{slot['mode']}")
    campaign_prefix = 'v3-matrix-'
    if (Path(session_path).parent.name != 'work'
            or slot_path.name != expected_slot_name
            or not campaign_root.name.startswith(campaign_prefix)
            or len(campaign_root.name) == len(campaign_prefix)):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_output_path_invalid'}
    campaign_id = campaign_root.name[len(campaign_prefix):]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', campaign_id):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_output_path_invalid'}
    expected_output = artifact_root / (
        f"application-v3-matrix-{campaign_id}-r{slot['repetition']}-"
        f"k{slot['target_count']}-{slot['mode']}-effect")
    try:
        configured_output = Path(config.get('effect_output', ''))
        artifact_root_resolved = artifact_root.resolve(strict=True)
        expected_output_info = expected_output.lstat()
        expected_output_resolved = expected_output.resolve(strict=True)
        configured_output_resolved = configured_output.resolve(strict=True)
        if (not stat.S_ISDIR(expected_output_info.st_mode)
                or expected_output_resolved.parent != artifact_root_resolved
                or not configured_output.is_absolute()
                or configured_output_resolved != expected_output_resolved):
            raise ValueError('effect output path differs')
        output_info = configured_output_resolved.lstat()
        if (not stat.S_ISDIR(output_info.st_mode)
                or output_info.st_uid != os.getuid()
                or stat.S_IMODE(output_info.st_mode) != 0o700):
            raise ValueError('private effect output directory required')
        configured_output = configured_output_resolved
    except (OSError, ValueError, TypeError):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_output_path_invalid'}

    effect_sha = session.get('effect_report_sha256')
    if not _is_sha256(effect_sha):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_report_identity_missing'}
    effect_path = configured_output / 'effect-report.json'
    try:
        effect = _read_pinned_json(effect_path, effect_sha)
    except FileNotFoundError:
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_report_missing'}
    except ValueError as error:
        status = ('effect_report_identity_mismatch'
                  if str(error) == 'report identity mismatch'
                  else 'effect_report_unreadable')
        return {**unavailable, 'application_effect_cost_metrics_status': status}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_report_unreadable'}

    if (not isinstance(effect, dict)
            or effect.get('schema') != 'part5-v3-campaign-effect-v1'
            or effect.get('mode') != slot['mode']
            or effect.get('target_count') != slot['target_count']
            or effect.get('passed') is not True
            or effect.get('training_only') is not True
            or effect.get('application_effect') is not True
            or effect.get('request_consumed') is not True):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_report_scope_mismatch'}
    transactions = effect.get('transactions')
    if not isinstance(transactions, list):
        return {**unavailable,
                'application_effect_cost_metrics_status': 'effect_report_scope_mismatch'}
    scenario = f"v3-campaign-valid-{slot['mode']}"
    selected = [transaction for transaction in transactions
                if isinstance(transaction, dict)
                and transaction.get('scenario') == scenario
                and transaction.get('err') is None]
    if len(selected) != 1:
        return {**unavailable,
                'application_effect_cost_metrics_status':
                    'successful_application_transaction_missing_or_ambiguous'}
    transaction = selected[0]
    finalized_slot = effect.get('finalized_slot')
    bound_finalized_slot = effect.get('bound_finalized_slot')
    effect_count = effect.get('effect_count')
    if (type(finalized_slot) is not int or finalized_slot < 0
            or type(bound_finalized_slot) is not int or bound_finalized_slot < 0
            or type(effect_count) is not int or effect_count != 1):
        return {**unavailable,
                'application_effect_cost_metrics_status':
                    'finalized_effect_scope_invalid'}
    finalized_scope = {
        'finalized_slot': finalized_slot,
        'bound_finalized_slot': bound_finalized_slot,
        'effect_count': effect_count,
    }
    bytes_used = transaction.get('transactionBytes')
    compute_units = transaction.get('computeUnits')
    fee_lamports = transaction.get('feeLamports')
    confirmed_slot = transaction.get('slot')
    signature = transaction.get('signature')
    if (type(bytes_used) is not int or bytes_used <= 0
            or type(compute_units) is not int or compute_units <= 0
            or type(fee_lamports) is not int or fee_lamports < 0
            or type(confirmed_slot) is not int or confirmed_slot < 0
            or not isinstance(signature, str) or not signature):
        return {
            'application_effect_cost_metrics_status':
                'successful_application_transaction_metrics_unavailable',
            'confirmed_rpc_metrics': None,
            'finalized_effect_scope': finalized_scope,
        }
    return {
        'application_effect_cost_metrics_status': 'available',
        'confirmed_rpc_metrics': {
            'transaction_bytes': bytes_used,
            'compute_units': compute_units,
            'fee_lamports': fee_lamports,
            'slot': confirmed_slot,
        },
        'finalized_effect_scope': finalized_scope,
    }


def _input_path(value, base_dir):
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def _session_record(slot, entry, base_dir):
    result = {**slot, 'status': 'missing', 'reason': 'session_not_listed',
              'session_report_sha256': None, 'outer_report_sha256': None,
              'application_effect_cost_metrics_status':
                  'unavailable_session_not_valid',
              'confirmed_rpc_metrics': None, 'finalized_effect_scope': None}
    if entry is None:
        return result

    session_path = _input_path(entry.get('session_report'), base_dir)
    if session_path is None:
        result['reason'] = 'session_report_path_missing'
        return result
    try:
        session, session_sha = _read_json(session_path)
    except FileNotFoundError:
        result['reason'] = 'session_report_file_missing'
        return result
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        result.update(status='invalid', reason='session_report_unreadable')
        return result
    result['session_report_sha256'] = session_sha

    if not isinstance(session, dict) or session.get('schema') != SESSION_SCHEMA:
        result.update(status='invalid', reason='session_schema_mismatch')
        return result
    dimensions = (session.get('mode'), session.get('target_count'),
                  session.get('repetition'))
    expected = (slot['mode'], slot['target_count'], slot['repetition'])
    if dimensions != expected:
        result.update(status='invalid', reason='session_dimensions_mismatch')
        return result
    expected_order = list(ORDERS[slot['repetition'] - 1])
    expected_position = expected_order.index(slot['mode']) + 1
    if (session.get('registered_order') != expected_order
            or session.get('registered_order_position') != expected_position):
        result.update(status='invalid', reason='registered_order_mismatch')
        return result
    if session.get('passed') is not True or session.get('effect_verified') is not True:
        result.update(status='failed', reason='session_or_effect_failed')
        if isinstance(session.get('error_type'), str):
            result['error_type'] = session['error_type'][:80]
        return result
    supervisor_status = session.get('effect_supervisor_status')
    validator_cleanup = session.get('validator_cleanup')
    monitor_path = session_path.parent / 'effect-monitor.json'
    try:
        effect_monitor, effect_monitor_sha = _read_json(monitor_path)
    except FileNotFoundError:
        result.update(status='invalid', reason='effect_monitor_report_missing')
        return result
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        result.update(status='invalid', reason='effect_monitor_report_unreadable')
        return result
    if (not _is_sha256(session.get('effect_monitor_sha256'))
            or session['effect_monitor_sha256'] != effect_monitor_sha):
        result.update(status='invalid', reason='effect_monitor_identity_mismatch')
        return result
    expected_monitor_exit = {'passed': 0, 'failed': 1}.get(supervisor_status)
    expected_monitor_owner = f"v3-campaign-{slot['mode']}-k{slot['target_count']}"
    if (not isinstance(effect_monitor, dict)
            or effect_monitor.get('schema') != 1
            or effect_monitor.get('measurement') != OUTER_MEASUREMENT
            or effect_monitor.get('owner') != expected_monitor_owner
            or effect_monitor.get('censored') is not False
            or effect_monitor.get('stop_reason') is not None
            or effect_monitor.get('runner_error_type') is not None
            or effect_monitor.get('cleanup_remaining_owned_processes') != 0
            or effect_monitor.get('cleanup_status_unknown') is not False):
        result.update(status='invalid', reason='effect_monitor_cleanup_evidence_invalid')
        return result
    if (expected_monitor_exit is None
            or effect_monitor.get('exit_code') != expected_monitor_exit
            or effect_monitor.get('passed') is not (expected_monitor_exit == 0)):
        result.update(status='invalid', reason='effect_monitor_status_exit_mismatch')
        return result
    reviewed_shutdown = (
        supervisor_status == 'failed'
        and session.get('ledger_reuse_requires_review') is True
        and isinstance(validator_cleanup, dict)
        and validator_cleanup.get('exit_code') == -2
        and validator_cleanup.get('reaped') is True)
    clean_shutdown = (
        supervisor_status == 'passed'
        and session.get('ledger_reuse_requires_review') is False
        and isinstance(validator_cleanup, dict)
        and validator_cleanup.get('exit_code') == 0
        and validator_cleanup.get('reaped') is True
        and validator_cleanup.get('graceful') is True)
    if not (reviewed_shutdown or clean_shutdown):
        result.update(status='invalid', reason='effect_cleanup_evidence_invalid')
        return result

    wall = session.get('total_command_wall_seconds')
    stage_wall = session.get('stage_wall_seconds_sum')
    child_cpu = session.get('waited_child_cpu_seconds_sum')
    stages = session.get('stages')
    common_cost_fields = (
        'preexisting_signed_history_preparation_charged',
        'preexisting_ledger_clone_charged',
        'preexisting_state_wait_charged',
        'shared_public_setup_material_charged',
    )
    if (not _number(wall, positive=True) or not _number(stage_wall)
            or not _number(child_cpu) or not isinstance(stages, list)
            or not stages
            or any(type(session.get(key, False)) is not bool
                   for key in common_cost_fields)
            or (session.get('coalesced_state_wait_seconds_observed') is not None
                and not _number(session['coalesced_state_wait_seconds_observed']))
            or any(not isinstance(stage, dict)
                   or not isinstance(stage.get('stage'), str)
                   or not stage['stage']
                   or stage.get('exit_code') not in (
                       (0, 1) if stage.get('stage') == 'application' else (0,))
                   or not _number(stage.get('wall_seconds'))
                   or not _number(stage.get('waited_child_cpu_seconds'))
                   for stage in stages)):
        result.update(status='invalid', reason='session_timing_fields_invalid')
        return result
    stage_names = [stage['stage'] for stage in stages]
    application_stages = [stage for stage in stages if stage['stage'] == 'application']
    if (len(set(stage_names)) != len(stage_names) or len(application_stages) != 1
            or (application_stages[0]['exit_code'] == 1 and not reviewed_shutdown)):
        result.update(status='invalid', reason='session_stage_sequence_invalid')
        return result
    stage_sum = sum(stage['wall_seconds'] for stage in stages)
    if not math.isclose(stage_sum, stage_wall, rel_tol=1e-7, abs_tol=1e-7):
        result.update(status='invalid', reason='session_stage_sum_mismatch')
        return result

    outer_path = _input_path(entry.get('outer_report'), base_dir)
    if outer_path is None:
        result.update(status='missing', reason='outer_report_path_missing')
        return result
    try:
        outer, outer_sha = _read_json(outer_path)
    except FileNotFoundError:
        result.update(status='missing', reason='outer_report_file_missing')
        return result
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        result.update(status='invalid', reason='outer_report_unreadable')
        return result
    result['outer_report_sha256'] = outer_sha
    if (not isinstance(outer, dict) or outer.get('schema') != 1
            or outer.get('measurement') != OUTER_MEASUREMENT):
        result.update(status='invalid', reason='outer_report_schema_mismatch')
        return result
    owner = outer.get('owner')
    owner_prefix = f"v3-campaign-{slot['mode']}-k{slot['target_count']}"
    if not isinstance(owner, str) or not owner.startswith(owner_prefix):
        result.update(status='invalid', reason='outer_owner_mismatch')
        return result
    if (outer.get('passed') is not True or outer.get('censored') is not False
            or outer.get('stop_reason') is not None
            or outer.get('runner_error_type') is not None
            or outer.get('cleanup_remaining_owned_processes') != 0
            or outer.get('cleanup_status_unknown') is not False):
        result.update(status='failed', reason='outer_measurement_or_cleanup_failed')
        return result
    outer_wall = outer.get('duration_seconds')
    limits = outer.get('limits')
    environment = outer.get('environment')
    peak_rss = outer.get('sampled_peak_owned_tree_rss_bytes')
    peak_storage = outer.get('sampled_peak_storage_growth_bytes')
    cpu = outer.get('cpu')
    if (not _number(outer_wall, positive=True) or outer_wall + 1e-6 < wall
            or not isinstance(limits, dict) or not isinstance(environment, dict)
            or type(peak_rss) is not int or peak_rss < 0
            or type(peak_storage) is not int or peak_storage < 0
            or not isinstance(cpu, dict)):
        result.update(status='invalid', reason='outer_measurement_fields_invalid')
        return result

    # These identity fields make two reports comparable at the campaign, state,
    # and request level. In particular, never infer the action from mode/count.
    identity_fields = ('freeze_sha256', 'cohort_receipt_sha256', 'current_root',
                       'current_report_sha256', 'source_identities',
                       'exact_request_sha256')
    if any(session.get(key) in (None, '', {}) for key in identity_fields):
        result.update(status='invalid', reason='matched_identity_missing')
        result['missing_identity_fields'] = [
            key for key in identity_fields if session.get(key) in (None, '', {})]
        return result
    if (not isinstance(session['source_identities'], dict)
            or not session['source_identities']
            or not all(_is_sha256(value)
                       for value in session['source_identities'].values())
            or not isinstance(session['current_root'], str)
            or not session['current_root']
            or any(not _is_sha256(session[key]) for key in (
                'freeze_sha256', 'cohort_receipt_sha256',
                'current_report_sha256', 'exact_request_sha256'))):
        result.update(status='invalid', reason='matched_identity_malformed')
        return result
    if not _is_sha256(session.get('effect_report_sha256')):
        result.update(status='invalid', reason='effect_report_identity_missing')
        return result

    effect_costs = _application_effect_costs(session_path, session, slot)
    if (('effect_config_sha256' in session
         or _is_registered_matrix_slot_path(session_path, slot))
            and effect_costs['application_effect_cost_metrics_status'] not in (
                'available', 'successful_application_transaction_metrics_unavailable')):
        result.update(status='invalid', reason='application_effect_metrics_invalid',
                      **effect_costs)
        return result

    result.update({
        'status': 'valid', 'reason': None,
        'freeze_sha256': session['freeze_sha256'],
        'cohort_receipt_sha256': session['cohort_receipt_sha256'],
        'current_root': session['current_root'],
        'current_report_sha256': session['current_report_sha256'],
        'source_identities': session['source_identities'],
        'exact_request_sha256': session['exact_request_sha256'],
        'effect_report_sha256': session['effect_report_sha256'],
        'outer_wall_seconds': outer_wall,
        'session_command_wall_seconds': wall,
        'stage_wall_seconds_sum': stage_wall,
        'stage_wall_seconds_by_name': {
            stage['stage']: stage['wall_seconds'] for stage in stages
        },
        'waited_child_cpu_seconds_sum': child_cpu,
        'preexisting_signed_history_preparation_charged':
            session['preexisting_signed_history_preparation_charged'],
        'preexisting_ledger_clone_charged': session['preexisting_ledger_clone_charged'],
        'preexisting_state_wait_charged': session['preexisting_state_wait_charged'],
        'shared_public_setup_material_charged':
            session.get('shared_public_setup_material_charged', False),
        'coalesced_state_wait_seconds_observed':
            session.get('coalesced_state_wait_seconds_observed'),
        'effect_supervisor_status': supervisor_status,
        'ledger_reuse_requires_review': session['ledger_reuse_requires_review'],
        'validator_cleanup': validator_cleanup,
        'sampled_peak_owned_tree_rss_bytes': peak_rss,
        'sampled_peak_storage_growth_bytes': peak_storage,
        'outer_limits': limits,
        'outer_environment': environment,
        'complete_tree_cpu_qualified': False,
        **effect_costs,
    })
    return result


def _pair(slot, full, anchor, coalesced):
    if full['status'] != 'valid' or anchor['status'] != 'valid':
        return {**slot, 'status': 'incomplete', 'mismatch_fields': [],
                'full_status': full['status'], 'anchor_status': anchor['status'],
                'coalesced_status': coalesced['status']}
    identity_fields = ('freeze_sha256', 'cohort_receipt_sha256', 'current_root',
                       'current_report_sha256', 'source_identities',
                       'exact_request_sha256', 'outer_environment',
                       'preexisting_signed_history_preparation_charged',
                       'preexisting_ledger_clone_charged',
                       'preexisting_state_wait_charged',
                       'shared_public_setup_material_charged',
                       'coalesced_state_wait_seconds_observed')
    mismatches = [key for key in identity_fields if full[key] != anchor[key]]
    if coalesced['status'] == 'valid':
        mismatches.extend('coalesced.' + key for key in identity_fields
                          if full[key] != coalesced[key])
    if mismatches:
        return {**slot, 'status': 'unmatched', 'mismatch_fields': mismatches,
                'full_status': full['status'], 'anchor_status': anchor['status'],
                'coalesced_status': coalesced['status']}
    difference = full['outer_wall_seconds'] - anchor['outer_wall_seconds']
    return {
        **slot, 'status': 'matched', 'mismatch_fields': [],
        'full_session_wall_seconds': full['outer_wall_seconds'],
        'anchor_session_wall_seconds': anchor['outer_wall_seconds'],
        'full_minus_anchor_session_wall_seconds': difference,
        'session_wall_savings_fraction': difference / full['outer_wall_seconds'],
        'full_sampled_peak_owned_tree_rss_bytes':
            full['sampled_peak_owned_tree_rss_bytes'],
        'anchor_sampled_peak_owned_tree_rss_bytes':
            anchor['sampled_peak_owned_tree_rss_bytes'],
        'full_outer_limits': full['outer_limits'],
        'anchor_outer_limits': anchor['outer_limits'],
        'coalesced_outer_limits': coalesced.get('outer_limits'),
        'full_sampled_peak_storage_growth_bytes':
            full['sampled_peak_storage_growth_bytes'],
        'anchor_sampled_peak_storage_growth_bytes':
            anchor['sampled_peak_storage_growth_bytes'],
        'coalesced_status': coalesced['status'],
        'coalesced_full_wall_seconds': (
            coalesced['outer_wall_seconds'] if coalesced['status'] == 'valid' else None),
        'exact_request_sha256': full['exact_request_sha256'],
    }


def _median_or_none(values):
    return statistics.median(values) if values else None


def make_manifest(session_root, outer_root):
    """Return the complete registered grid with explicit absolute report paths."""
    session_root, outer_root = Path(session_root), Path(outer_root)
    if not session_root.is_absolute() or not outer_root.is_absolute():
        raise ValueError('absolute session and outer report roots required')
    session_root = session_root.resolve(strict=False)
    outer_root = outer_root.resolve(strict=False)
    if (session_root == outer_root or session_root in outer_root.parents
            or outer_root in session_root.parents):
        raise ValueError('session and outer report roots must be disjoint')
    sessions = []
    for repetition in REPETITIONS:
        for count in COUNTS:
            for mode in MODES:
                stem = f'r{repetition}-k{count}-{mode}'
                sessions.append({
                    'mode': mode,
                    'target_count': count,
                    'repetition': repetition,
                    'session_report': str(session_root / stem / 'session-report.json'),
                    'outer_report': str(outer_root / stem / 'report.json'),
                })
    return {'schema': INPUT_SCHEMA, 'sessions': sessions}


def aggregate(manifest, base_dir='.'):
    """Build a scrubbed report without extrapolating missing or unobserved runs."""
    if not isinstance(manifest, dict) or manifest.get('schema') != INPUT_SCHEMA:
        raise ValueError('v3 campaign economics input manifest required')
    entries = manifest.get('sessions')
    if not isinstance(entries, list):
        raise ValueError('sessions array required')
    base_dir = Path(base_dir)
    indexed = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('each session manifest row must be an object')
        mode, count, repetition = (entry.get('mode'), entry.get('target_count'),
                                   entry.get('repetition'))
        if (mode not in MODES or type(count) is not int or count not in COUNTS
                or type(repetition) is not int or repetition not in REPETITIONS):
            raise ValueError('registered Full/Anchor mode, k, and repetition required')
        key = (mode, count, repetition)
        if key in indexed:
            raise ValueError('duplicate session manifest row')
        indexed[key] = entry

    sessions = []
    by_key = {}
    for repetition in REPETITIONS:
        for count in COUNTS:
            for mode in MODES:
                slot = {'mode': mode, 'target_count': count,
                        'repetition': repetition}
                row = _session_record(slot, indexed.get((mode, count, repetition)),
                                      base_dir)
                sessions.append(row)
                by_key[(mode, count, repetition)] = row

    pairs = []
    for repetition in REPETITIONS:
        for count in COUNTS:
            slot = {'target_count': count, 'repetition': repetition}
            pairs.append(_pair(slot,
                by_key[('full', count, repetition)],
                by_key[('anchor', count, repetition)],
                by_key[('coalesced-full', count, repetition)]))

    three_mode_groups = []
    for pair in pairs:
        coalesced = by_key[('coalesced-full', pair['target_count'],
                            pair['repetition'])]
        if pair['status'] != 'matched':
            status = 'full_anchor_incomplete_or_unmatched'
        elif coalesced['status'] != 'valid':
            status = 'coalesced_incomplete'
        else:
            status = 'matched'
        three_mode_groups.append({
            'target_count': pair['target_count'],
            'repetition': pair['repetition'],
            'status': status,
            'coalesced_status': coalesced['status'],
            'coalesced_mismatch_fields': [
                field for field in pair.get('mismatch_fields', [])
                if field.startswith('coalesced.')],
        })

    by_update_count = {}
    for count in COUNTS:
        complete = [row for row in pairs
                    if row['target_count'] == count and row['status'] == 'matched']
        fractions = [row['session_wall_savings_fraction'] for row in complete]
        differences = [row['full_minus_anchor_session_wall_seconds'] for row in complete]
        full_wall = [row['full_session_wall_seconds'] for row in complete]
        anchor_wall = [row['anchor_session_wall_seconds'] for row in complete]
        if len(complete) != len(REPETITIONS):
            target_status = 'incomplete_pairs'
        elif _median_or_none(fractions) >= TARGET_SAVINGS_FRACTION:
            target_status = 'met_by_median'
        else:
            target_status = 'not_met_by_median'
        by_update_count[str(count)] = {
            'matched_pairs': len(complete),
            'expected_pairs': len(REPETITIONS),
            'median_full_session_wall_seconds': _median_or_none(full_wall),
            'median_anchor_session_wall_seconds': _median_or_none(anchor_wall),
            'median_full_minus_anchor_session_wall_seconds': _median_or_none(differences),
            'median_session_wall_savings_fraction': _median_or_none(fractions),
            'session_wall_savings_fraction_min': min(fractions) if fractions else None,
            'session_wall_savings_fraction_max': max(fractions) if fractions else None,
            'registered_20_percent_session_wall_threshold': target_status,
            'per_repetition_session_wall_savings_fraction': {
                str(row['repetition']): row['session_wall_savings_fraction']
                for row in complete
            },
        }

    break_even_values, break_even_status = [], []
    for repetition in REPETITIONS:
        sequence = [row for row in pairs if row['repetition'] == repetition]
        if any(row['status'] != 'matched' for row in sequence):
            break_even_values.append(None)
            break_even_status.append('incomplete')
            continue
        crossing = next((row['target_count'] for row in sequence
                         if row['full_minus_anchor_session_wall_seconds'] > 0), None)
        break_even_values.append(crossing)
        break_even_status.append('crossed' if crossing is not None
                                  else 'not_crossed_through_k10')
    crossing_counts = {str(count): sum(value == count for value in break_even_values)
                       for count in COUNTS}

    valid_sessions = [row for row in sessions if row['status'] == 'valid']
    full_anchor_grid_complete = all(row['status'] == 'matched' for row in pairs)
    grid_complete = (len(valid_sessions) == len(MODES) * len(COUNTS) * len(REPETITIONS)
                     and full_anchor_grid_complete
                     and all(row['status'] == 'matched' for row in three_mode_groups))
    common_cost_labels = {
        'preexisting_signed_history_preparation_charged':
            'preexisting signed-history preparation',
        'preexisting_ledger_clone_charged': 'preexisting ledger clone',
        'preexisting_state_wait_charged': 'preexisting state wait',
        'shared_public_setup_material_charged': 'shared public setup/material',
    }
    unresolved_costs = [label for field, label in common_cost_labels.items()
                        if not valid_sessions
                        or any(row[field] is not True for row in valid_sessions)]
    shared_setup_charged = bool(valid_sessions) and all(
        row['shared_public_setup_material_charged'] is True for row in valid_sessions)
    effect_metric_sessions = [
        row for row in valid_sessions
        if row['application_effect_cost_metrics_status'] == 'available']
    finalized_scope_sessions = [
        row for row in valid_sessions if row['finalized_effect_scope'] is not None]
    confirmed_rpc_by_mode = {}
    finalized_scope_by_mode = {}
    for mode in MODES:
        mode_rows = [row for row in effect_metric_sessions if row['mode'] == mode]
        confirmed_rpc_by_mode[mode] = {
            'available_samples': len(mode_rows),
            'sampled_values': [
                {'target_count': row['target_count'],
                 'repetition': row['repetition'],
                 'transaction_bytes': row['confirmed_rpc_metrics']['transaction_bytes'],
                 'compute_units': row['confirmed_rpc_metrics']['compute_units'],
                 'fee_lamports': row['confirmed_rpc_metrics']['fee_lamports']}
                for row in mode_rows],
        }
        scope_rows = [row for row in finalized_scope_sessions if row['mode'] == mode]
        finalized_scope_by_mode[mode] = {
            'available_samples': len(scope_rows),
            'sampled_values': [
                {'target_count': row['target_count'],
                 'repetition': row['repetition'],
                 **row['finalized_effect_scope']}
                for row in scope_rows],
        }
    session_status_counts = {
        status: sum(row['status'] == status for row in sessions)
        for status in ('valid', 'missing', 'failed', 'invalid')
    }
    pair_status_counts = {
        status: sum(row['status'] == status for row in pairs)
        for status in ('matched', 'incomplete', 'unmatched')
    }
    return {
        'schema': 'part5-v3-campaign-economics-report-v1',
        'training_only': True,
        'modes_compared': list(MODES),
        'update_counts': list(COUNTS),
        'repetitions': len(REPETITIONS),
        'measurement_scope': (
            'The measured value is bounded-session wall time: source import through '
            'application reconciliation, launch, monitoring, and cleanup. It excludes '
            'initial metadata writes, report writes, and preexisting ledger clone, '
            'signed history preparation, and state wait. Shared public setup/material '
            'is not included by the current session runner.'),
        'whole_application_benefit_established': False,
        'whole_application_benefit_unresolved_costs': unresolved_costs,
        'whole_application_savings_fraction': None,
        'grid_complete': grid_complete,
        'full_anchor_grid_complete': full_anchor_grid_complete,
        'complete_pairs': sum(row['status'] == 'matched' for row in pairs),
        'expected_pairs': len(pairs),
        'session_status_counts': session_status_counts,
        'full_anchor_pair_status_counts': pair_status_counts,
        'matched_three_mode_groups': sum(row['status'] == 'matched'
                                         for row in three_mode_groups),
        'expected_three_mode_groups': len(three_mode_groups),
        'sessions': sessions,
        'pairs': pairs,
        'three_mode_groups': three_mode_groups,
        'by_update_count': by_update_count,
        'break_even': {
            'basis': ('session-only first sampled k with positive Full-minus-Anchor outer wall'),
            'per_repetition': break_even_values,
            'per_repetition_status': break_even_status,
            'crossing_repetitions_by_sampled_k': crossing_counts,
            'not_crossed_through_k10': break_even_status.count('not_crossed_through_k10'),
            'incomplete_repetitions': break_even_status.count('incomplete'),
            'interpolation_or_extrapolation_used': False,
        },
        'cpu': {
            'complete_tree_savings_claimed': False,
            'qualified_complete_tree_cpu_sessions': 0,
            'reason': ('The bounded runner reports leader wait4 usage and a sampled '
                       'tree self-CPU lower bound; neither qualifies complete-tree CPU, '
                       'and those fields overlap.'),
        },
        'application_effect_costs': {
            'effect_execution_in_outer_wall': True,
            'transaction_bytes_available': bool(effect_metric_sessions),
            'compute_units_available': bool(effect_metric_sessions),
            'fee_lamports_available': bool(effect_metric_sessions),
            'confirmed_rpc_metrics': {
                'source': ('session-pinned effect-report successful mode-specific '
                           'application transaction fields transactionBytes, computeUnits, '
                           'feeLamports, and slot'),
                'by_mode': confirmed_rpc_by_mode,
            },
            'finalized_effect_scope': {
                'source': ('separate finalized effect-report scope: finalized_slot, '
                           'bound_finalized_slot, and effect_count'),
                'by_mode': finalized_scope_by_mode,
            },
            'unavailable_valid_sessions': sum(
                row['status'] == 'valid'
                and row['application_effect_cost_metrics_status'] != 'available'
                for row in sessions),
        },
        'common_cost_accounting': {
            'reported_fields': [
                'preexisting_signed_history_preparation_charged',
                'preexisting_ledger_clone_charged',
                'preexisting_state_wait_charged',
                'coalesced_state_wait_seconds_observed'],
            'session_report_values': {
                key: list(dict.fromkeys(row[key] for row in valid_sessions))
                for key in (
                    'preexisting_signed_history_preparation_charged',
                    'preexisting_ledger_clone_charged',
                    'preexisting_state_wait_charged',
                    'shared_public_setup_material_charged',
                    'coalesced_state_wait_seconds_observed')
            },
            'shared_public_setup_material_charged': shared_setup_charged,
            'whole_application_savings_fraction': None,
        },
        'workload_note': (
            'No operator update-rate or action-lifetime distribution is supplied. '
            'Results are conditional on the directly sampled k values only.'),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--initialize-manifest', action='store_true',
                        help='write the complete 60-slot input manifest')
    parser.add_argument('--session-root', type=Path,
                        help='absolute root for session-report.json paths')
    parser.add_argument('--outer-root', type=Path,
                        help='absolute root for bounded runner report.json paths')
    parser.add_argument('--manifest', type=Path,
                        help='input manifest to aggregate')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError('fresh output required')
    if args.initialize_manifest:
        if args.manifest is not None or args.session_root is None or args.outer_root is None:
            parser.error('--initialize-manifest requires both roots and no --manifest')
        result = make_manifest(args.session_root, args.outer_root)
        summary = {'manifest_slots': len(result['sessions']),
                   'manifest': str(args.output.absolute())}
    else:
        if args.manifest is None or args.session_root is not None or args.outer_root is not None:
            parser.error('aggregation requires --manifest and no report roots')
        manifest, manifest_sha = _read_json(args.manifest)
        result = aggregate(manifest, args.manifest.absolute().parent)
        result['input_manifest_sha256'] = manifest_sha
        summary = {'grid_complete': result['grid_complete'],
                   'complete_pairs': result['complete_pairs'],
                   'expected_pairs': result['expected_pairs']}
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
