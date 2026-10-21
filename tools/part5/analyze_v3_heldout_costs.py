#!/usr/bin/env python3
"""Recompute matched heldout request-B wall costs from pinned run journals.

This is a post-run accounting tool. It does not run application jobs, infer CPU
cost, or classify an economic winner.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from statistics import median

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5.assemble_v3_heldout_acceptance import MANIFEST_SCHEMA

JOURNAL_SCHEMA = 'credential-v3-heldout-case-run-journal-v1'
RUN_MANIFEST_SCHEMA = 'credential-v3-heldout-case-run-v1'
ACCEPTANCE_SCHEMA = 'credential-v3-heldout-application-report-v1'
OUTPUT_SCHEMA = 'credential-v3-heldout-cost-analysis-v1'
VARIANTS = set(range(8))
BRANCHES = {'full', 'unrelated_full', 'anchor', 'own_revocation'}
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAX_JSON = 16 * 1024 * 1024
DISABLED_CONFIG_SIDECAR_SCHEMA = 'credential-v3-heldout-disabled-config-negative-v2'
DISABLED_CONFIG_REPORT_SCHEMA = 'part5-v3-disabled-config-negative-report-v2'
DISABLED_CONFIG_SIDECAR_KEYS = {
    'schema', 'variant', 'stage_report_sha256', 'stage_plan_sha256',
    'r0_source_receipt_sha256', 'full_proof_receipt_sha256', 'clone_receipt',
    'full_wire', 'config', 'rust_config', 'status', 'outer', 'report',
    'eligible_accounts', 'before_accounts', 'after_accounts',
    'issuer_eligible_accounts', 'issuer_before_accounts', 'issuer_after_accounts'}
NEGATIVE_ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')
DISABLED_CONFIG_ACCOUNT_GROUPS = (
    'eligible_accounts', 'before_accounts', 'after_accounts',
    'issuer_eligible_accounts', 'issuer_before_accounts', 'issuer_after_accounts')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(path, *, cap=MAX_JSON):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or before.st_mode & 0o022
            or before.st_size <= 0 or before.st_size > cap):
        raise ValueError('canonical bounded owner-controlled file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if _identity(opened) != _identity(before):
            raise ValueError('input changed at open')
        raw = stream.read(cap + 1)
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError('input changed during read')
    if len(raw) != before.st_size or _identity(path.lstat()) != _identity(before):
        raise ValueError('input changed while reading')
    return raw


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _json_bytes(raw):
    return json.loads(raw, object_pairs_hook=_unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError('non-finite JSON number')))


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _close(actual, expected):
    return math.isclose(float(actual), float(expected), rel_tol=1e-9, abs_tol=1e-6)


def _read_ref(ref, *, cap=MAX_JSON):
    if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
            or type(ref['path']) is not str or not Path(ref['path']).is_absolute()
            or type(ref['sha256']) is not str or HEX64.fullmatch(ref['sha256']) is None):
        raise ValueError('absolute pinned artifact reference required')
    raw = _read(ref['path'], cap=cap)
    if _sha(raw) != ref['sha256']:
        raise ValueError('artifact SHA-256 pin mismatch')
    return raw


def _load_pinned_json(ref, label):
    try:
        return _json_bytes(_read_ref(ref))
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f'{label} pin or JSON invalid: {error}') from None


def _load_input_ref(ref, label):
    try:
        raw = _read_ref(ref)
    except (OSError, ValueError) as error:
        raise ValueError(f'{label} pin invalid: {error}') from None
    try:
        value = _json_bytes(raw)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f'{label} JSON invalid: {error}') from None
    if type(value) is not dict:
        raise ValueError(f'{label} JSON object required')
    return value, _sha(raw)


def _step_names():
    names = ['pair-view']
    request_modes = {
        'positive_full': ('full',),
        'unrelated_compare': ('full', 'anchor'),
        'own_revocation': ('anchor',),
    }
    for request, modes in request_modes.items():
        names.extend(f'{request}:{suffix}' for suffix in
                     ('prepare', 'stage', 'transition', 'source-R0', 'source-R1'))
        names.extend(f'{request}:proof-{mode}' for mode in modes)
    names.append('positive_full:proof-full-fresh-replay')
    names.extend((
        'positive_full:r0-clone', 'positive_full:execute',
        'positive_full:disabled-config-clone',
        'positive_full:disabled-config-negative',
        'positive_full:ambiguous-restart-clone',
        'positive_full:ambiguous-restart',
        'unrelated_compare:unrelated_full:clone',
        'unrelated_compare:unrelated_full:effect',
        'unrelated_compare:anchor:clone', 'unrelated_compare:anchor:effect',
        'own_revocation:r1-clone', 'own_revocation:effect',
        'own_revocation:r2-active-witness'))
    return set(names)


def _duration_map(journal, manifest_sha256):
    if (type(journal) is not dict or journal.get('schema') != JOURNAL_SCHEMA
            or type(journal.get('manifest_sha256')) is not str
            or HEX64.fullmatch(journal['manifest_sha256']) is None
            or journal['manifest_sha256'] != manifest_sha256):
        raise ValueError('heldout case journal schema/identity required')
    steps = journal.get('steps')
    if type(steps) is not dict or set(steps) != _step_names():
        raise ValueError('journal step-map does not match registered heldout run')
    durations = {}
    for name, row in steps.items():
        if (type(row) is not dict or row.get('status') != 'passed'
                or not _number(row.get('wall_seconds'))):
            raise ValueError(f'passed finite journal duration required for {name}')
        durations[name] = float(row['wall_seconds'])
    costs = journal.get('costs')
    if (type(costs) is not dict
            or set(costs) != {'shared_stage_seconds', 'shared_transition_seconds'}
            or any(not _number(value) for value in costs.values())):
        raise ValueError('journal shared cost totals required')
    for kind, key in (('stage', 'shared_stage_seconds'),
                      ('transition', 'shared_transition_seconds')):
        actual = sum(durations[f'{req}:{kind}'] for req in
                     ('positive_full', 'unrelated_compare', 'own_revocation'))
        if not _close(costs[key], actual):
            raise ValueError(f'journal {kind} aggregate does not equal step map')
    return durations


def _check_order(case, variant):
    branch_order = (['unrelated_full', 'anchor'] if variant % 2 == 0
                    else ['anchor', 'unrelated_full'])
    proof_order = ['full', 'anchor'] if variant % 2 == 0 else ['anchor', 'full']
    if (case.get('branch_order') != branch_order
            or case.get('proof_order') != {'unrelated_compare': proof_order}):
        raise ValueError('recorded branch/proof order does not match registered parity')


def _verify_expired_status_audit(case, journal, accepted):
    from tools.part5 import verify_v3_heldout_acceptance as verifier
    sidecar, sha, manifest, finalized = verifier._replay_expired_status_sidecar(case['expired_status_negative'])
    names = ('positive_full:expired-status-clone', 'positive_full:expired-status-negative',
             'positive_full:expired-status-finalize')
    clone, run, final = (journal['steps'][name] for name in names)
    if (sidecar['variant'] != case['variant']
            or clone.get('receipt_sha256') != sidecar['clone_receipt']['sha256']
            or run.get('refs') != manifest['refs']
            or final.get('sidecar') != case['expired_status_negative']['path']
            or final.get('sidecar_sha256') != sha
            or final.get('inputs') != {'finalizer_manifest': manifest}
            or accepted.get('expired_status_negative', {}).get('sidecar_sha256') != sha
            or accepted.get('expired_status_negative_wall_seconds') != case['expired_status_negative_wall_seconds']):
        raise ValueError('expiry journal, accepted sidecar and finalizer inputs differ')


def _expired_status_cost(case, journal):
    names = ('positive_full:expired-status-clone', 'positive_full:expired-status-negative',
             'positive_full:expired-status-finalize')
    steps = journal.get('steps', {})
    if any(type(steps.get(name)) is not dict or steps[name].get('status') != 'passed'
           or not _number(steps[name].get('wall_seconds')) for name in names):
        raise ValueError('three completed expired-status journal steps required')
    total = sum(steps[name]['wall_seconds'] for name in names)
    if (not _number(case.get('expired_status_negative_wall_seconds'))
            or not _close(case['expired_status_negative_wall_seconds'], total)):
        raise ValueError('expired-status separate cost disagrees with journal')
    return total


def _check_summary(case, journal, durations):
    wall_map = case.get('all_step_wall_seconds')
    if (type(wall_map) is not dict or set(wall_map) != set(durations)
            or any(not _number(value) or not _close(value, durations[name])
                   for name, value in wall_map.items())):
        raise ValueError('journal timing summaries disagree with pinned journal')
    if type(case.get('shared_costs')) is not dict:
        raise ValueError('journal timing summaries disagree with pinned journal')
    shared_costs = case['shared_costs']
    if set(shared_costs) != {'shared_stage_seconds', 'shared_transition_seconds'}:
        raise ValueError('journal timing summaries disagree with pinned journal')
    for key, value in shared_costs.items():
        if (not _number(value) or not _close(value, journal['costs'][key])):
            raise ValueError('journal timing summaries disagree with pinned journal')

    disabled_negative_seconds = sum(durations[name] for name in (
        'positive_full:disabled-config-clone',
        'positive_full:disabled-config-negative'))
    if (not _number(case.get('disabled_config_negative_wall_seconds'))
            or not _close(case['disabled_config_negative_wall_seconds'],
                          disabled_negative_seconds)):
        raise ValueError('disabled-config audit cost disagrees with journal')

    ambiguous_restart_seconds = sum(durations[name] for name in (
        'positive_full:ambiguous-restart-clone',
        'positive_full:ambiguous-restart'))
    if (not _number(case.get('ambiguous_restart_wall_seconds'))
            or not _close(case['ambiguous_restart_wall_seconds'],
                          ambiguous_restart_seconds)):
        raise ValueError('ambiguous-restart audit cost disagrees with journal')

    stage_transition = case.get('shared_stage_transition_wall_seconds')
    if type(stage_transition) is not dict or set(stage_transition) != {'stage', 'transition'}:
        raise ValueError('journal timing summaries disagree with pinned journal')
    req_for_slot = {'A': 'positive_full', 'B': 'unrelated_compare',
                    'C': 'own_revocation'}
    for kind in ('stage', 'transition'):
        row = stage_transition[kind]
        if type(row) is not dict or set(row) != set(req_for_slot):
            raise ValueError('journal timing summaries disagree with pinned journal')
        for slot, req in req_for_slot.items():
            if not _number(row[slot]) or not _close(row[slot], durations[f'{req}:{kind}']):
                raise ValueError('journal timing summaries disagree with pinned journal')

    expected = {
        'full': ('positive_full:proof-full', 'positive_full:r0-clone',
                 'positive_full:execute'),
        'unrelated_full': ('unrelated_compare:proof-full',
                           'unrelated_compare:unrelated_full:clone',
                           'unrelated_compare:unrelated_full:effect'),
        'anchor': ('unrelated_compare:proof-anchor',
                   'unrelated_compare:anchor:clone',
                   'unrelated_compare:anchor:effect'),
        'own_revocation': ('own_revocation:proof-anchor',
                           'own_revocation:r1-clone', 'own_revocation:effect',
                           'own_revocation:r2-active-witness'),
    }
    components = case.get('branch_wall_components')
    totals = case.get('branch_wall_seconds')
    if type(components) is not dict or set(components) != BRANCHES or \
            type(totals) is not dict or set(totals) != BRANCHES:
        raise ValueError('branch cost summaries disagree with pinned journal')
    for branch, steps in expected.items():
        values = tuple(durations[step] for step in steps)
        recorded = components[branch]
        component_names = ('proof_seconds', 'clone_seconds', 'effect_seconds')
        if branch == 'own_revocation':
            component_names += ('r2_active_witness_seconds',)
        expected_component_names = set(component_names) | {'total_seconds'}
        if (type(recorded) is not dict
                or set(recorded) != expected_component_names
                or not all(_number(value) for value in recorded.values())
                or not all(_close(recorded[key], value) for key, value in
                           zip(component_names, values))
                or not _close(recorded['total_seconds'], sum(values))
                or not _number(totals[branch])
                or not _close(totals[branch], sum(values))):
            raise ValueError('branch cost summaries disagree with pinned journal')


def _verify_disabled_config_audit(case, journal):
    step_name = 'positive_full:disabled-config-negative'
    step = journal['steps'][step_name]
    sidecar_ref = case.get('disabled_config_negative')
    if (type(sidecar_ref) is not dict or set(sidecar_ref) != {'path', 'sha256'}
            or step.get('sidecar') != sidecar_ref.get('path')
            or step.get('sidecar_sha256') != sidecar_ref.get('sha256')):
        raise ValueError('disabled-config sidecar differs from journal step result')
    sidecar, _ = _load_input_ref(sidecar_ref, 'disabled-config negative sidecar')
    if (set(sidecar) != DISABLED_CONFIG_SIDECAR_KEYS
            or sidecar.get('schema') != DISABLED_CONFIG_SIDECAR_SCHEMA
            or type(sidecar.get('variant')) is not int
            or sidecar['variant'] != case.get('variant')
            or any(type(sidecar.get(field)) is not str
                   or HEX64.fullmatch(sidecar[field]) is None
                   for field in ('stage_report_sha256', 'stage_plan_sha256',
                                 'r0_source_receipt_sha256',
                                 'full_proof_receipt_sha256'))):
        raise ValueError('pinned v2 disabled-config and issuer sidecar required')
    artifact_fields = ('clone_receipt', 'full_wire', 'config', 'rust_config',
                       'status', 'outer', 'report')
    artifact_refs = {}
    for field in artifact_fields:
        ref = sidecar[field]
        if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
                or type(ref.get('path')) is not str
                or not Path(ref['path']).is_absolute()
                or type(ref.get('sha256')) is not str
                or HEX64.fullmatch(ref['sha256']) is None):
            raise ValueError(f'pinned disabled-config {field} artifact reference required')
        artifact_refs[field] = ref
    for field in ('clone_receipt', 'config', 'rust_config'):
        _load_input_ref(artifact_refs[field], f'disabled-config {field}')
    _read_ref(artifact_refs['full_wire'], cap=32 * 1024 * 1024)

    monitor_ref = {'path': step.get('monitor'), 'sha256': step.get('monitor_sha256')}
    if monitor_ref != artifact_refs['outer']:
        raise ValueError('disabled-config journal monitor differs from sidecar outer ref')
    owner = step.get('monitor_owner')
    if type(owner) is not str or not owner:
        raise ValueError('disabled-config journal monitor owner required')
    outer, _ = _load_input_ref(artifact_refs['outer'], 'disabled-config outer monitor')
    if outer.get('owner') != owner:
        raise ValueError('disabled-config outer monitor owner differs from journal')

    status, _ = _load_input_ref(artifact_refs['status'], 'disabled-config status')
    report, report_sha = _load_input_ref(artifact_refs['report'], 'disabled-config report')
    status_true_fields = (
        'config_disabled', 'execute_rejected', 'accounts_unchanged',
        'issuer_disabled', 'issuer_execute_rejected',
        'issuer_accounts_unchanged', 'effect_verified')
    if (status.get('scope') != 'part5-v3-disabled-config-negative'
            or status.get('status') != 'failed'
            or status.get('error_type') is not None
            or status.get('application_effect') is not False
            or any(status.get(field) is not True for field in status_true_fields)
            or status.get('config_sha256') != artifact_refs['config']['sha256']
            or status.get('rust_config_path') != artifact_refs['rust_config']['path']
            or status.get('rust_config_sha256') != artifact_refs['rust_config']['sha256']
            or status.get('report_path') != artifact_refs['report']['path']
            or status.get('report_sha256') != report_sha):
        raise ValueError('disabled-config and issuer status fields do not bind to sidecar')

    report_true_fields = (
        'config_disabled', 'execute_rejected', 'refresh_and_bind_succeeded',
        'disable_changed_only_enabled_and_epoch',
        'accounts_unchanged_after_rejection', 'issuer_disabled',
        'issuer_execute_rejected',
        'issuer_disable_changed_only_enabled_epoch_status',
        'issuer_accounts_unchanged_after_rejection')
    if (report.get('schema') != DISABLED_CONFIG_REPORT_SCHEMA
            or report.get('passed') is not True
            or type(report.get('variant')) is not int
            or report.get('variant') != sidecar['variant']
            or report.get('stage_report_sha256') != sidecar['stage_report_sha256']
            or report.get('stage_plan_sha256') != sidecar['stage_plan_sha256']
            or report.get('full_wire_sha256') != artifact_refs['full_wire']['sha256']
            or report.get('clone_receipt_sha256') != artifact_refs['clone_receipt']['sha256']
            or type(report.get('expected_custom_error')) is not int
            or report['expected_custom_error'] != 713
            or type(report.get('issuer_eligible_clock')) is not int
            or report['issuer_eligible_clock'] < 0
            or any(report.get(field) is not True for field in report_true_fields)):
        raise ValueError('disabled-config and issuer report fields do not bind to sidecar')

    group_hashes = {}
    for sidecar_group in DISABLED_CONFIG_ACCOUNT_GROUPS:
        refs = sidecar[sidecar_group]
        report_group = sidecar_group.removesuffix('_accounts')
        rows = report.get(report_group + '_accounts')
        hashes = report.get(report_group + '_sha256')
        if (type(refs) is not dict or set(refs) != set(NEGATIVE_ACCOUNT_NAMES)
                or type(rows) is not list or len(rows) != len(NEGATIVE_ACCOUNT_NAMES)
                or type(hashes) is not list or len(hashes) != len(NEGATIVE_ACCOUNT_NAMES)):
            raise ValueError(f'pinned {report_group} account snapshot group required')
        ordered_hashes = []
        for name, row, expected_hash in zip(NEGATIVE_ACCOUNT_NAMES, rows, hashes):
            ref = refs[name]
            if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
                    or type(ref.get('path')) is not str
                    or not Path(ref['path']).is_absolute()
                    or type(ref.get('sha256')) is not str
                    or HEX64.fullmatch(ref['sha256']) is None
                    or type(row) is not dict
                    or set(row) != {'name', 'path', 'sha256'}
                    or row.get('name') != name
                    or row.get('path') != ref['path']
                    or row.get('sha256') != ref['sha256']
                    or expected_hash != ref['sha256']):
                raise ValueError(f'{report_group} account refs differ from sidecar/report')
            _read_ref(ref, cap=4096)
            ordered_hashes.append(ref['sha256'])
        group_hashes[report_group] = ordered_hashes
    if (group_hashes['before'] != group_hashes['after']
            or group_hashes['issuer_before'] != group_hashes['issuer_after']):
        raise ValueError('config and issuer rejected Execute snapshots must remain unchanged')


def _outer(ref, owner=None, expected_exit=None):
    outer, _ = _load_input_ref(ref, 'bounded monitor')
    duration = outer.get('duration_seconds')
    if (outer.get('schema') != 1 or not _number(duration) or duration <= 0
            or type(outer.get('sample_count')) is not int or outer['sample_count'] <= 0
            or outer.get('stop_reason') is not None
            or outer.get('runner_error_type') is not None
            or outer.get('cleanup_remaining_owned_processes') != 0
            or outer.get('cleanup_status_unknown') is not False
            or (owner is not None and outer.get('owner') != owner)):
        raise ValueError('pinned bounded monitor report shape/owner required')
    if expected_exit is None:
        accepted_stop = (outer.get('passed') is False and outer.get('exit_code') == 1)
        accepted_success = (outer.get('passed') is True and outer.get('exit_code') == 0)
        accepted = accepted_stop or accepted_success
    else:
        accepted = (outer.get('exit_code') == expected_exit
                    and outer.get('passed') is (expected_exit == 0))
    if not accepted:
        raise ValueError('bounded monitor did not record a complete reviewed run')
    rss = outer.get('sampled_peak_owned_tree_rss_bytes')
    storage = outer.get('sampled_peak_storage_growth_bytes')
    if type(rss) is not int or rss < 0 or type(storage) is not int or storage < 0:
        raise ValueError('sampled monitor RSS/storage values required')
    return float(duration), rss, storage


def _verify_monitor_durations(case, journal, durations):
    monitor_refs = {}
    samples_by_step = {}
    for step, row in journal['steps'].items():
        if step == 'pair-view' or ':proof-' in step:
            continue
        if (type(row.get('monitor')) is not str
                or type(row.get('monitor_sha256')) is not str):
            raise ValueError(f'pinned bounded monitor reference required for {step}')
        monitor_refs[step] = {'path': row['monitor'], 'sha256': row['monitor_sha256']}
        owner = row.get('monitor_owner')
        if step == 'own_revocation:r2-active-witness':
            if (type(row.get('generator_monitor')) is not str
                    or type(row.get('generator_monitor_sha256')) is not str):
                raise ValueError('pinned generator monitor reference required for R2 active witness')
            measured, rss, storage = _outer(
                monitor_refs[step], owner, expected_exit=0)
            generator_ref = {'path': row['generator_monitor'],
                             'sha256': row['generator_monitor_sha256']}
            generator_measured, generator_rss, generator_storage = _outer(
                generator_ref, expected_exit=2)
            if durations[step] + 1e-6 < measured + generator_measured:
                raise ValueError('journal wall time is below combined R2 witness monitor durations')
            samples_by_step[step] = ((rss, storage),
                                     (generator_rss, generator_storage))
            continue
        measured, rss, storage = _outer(monitor_refs[step], owner)
        if durations[step] + 1e-6 < measured:
            raise ValueError('journal wall time is below monitor duration')
        samples_by_step[step] = (rss, storage)

    r2_step = 'own_revocation:r2-active-witness'
    r2_row = journal['steps'][r2_step]
    rejection_ref = case['branches']['own_revocation'].get(
        'current_r2_witness_rejection')
    journal_receipt_ref = {'path': r2_row.get('receipt'),
                           'sha256': r2_row.get('receipt_sha256')}
    if (type(rejection_ref) is not dict
            or rejection_ref != journal_receipt_ref
            or type(journal_receipt_ref['path']) is not str
            or type(journal_receipt_ref['sha256']) is not str):
        raise ValueError('R2 witness receipt reference differs from run journal')
    rejection, _ = _load_input_ref(rejection_ref, 'R2 active witness rejection receipt')
    generator_ref = {'path': r2_row['generator_monitor'],
                     'sha256': r2_row['generator_monitor_sha256']}
    if (type(rejection.get('generator_attempt')) is not dict
            or rejection['generator_attempt'].get('supervisor_ref') != generator_ref
            or type(rejection.get('relation_supervisor')) is not dict
            or rejection['relation_supervisor'].get('ref') != monitor_refs[r2_step]):
        raise ValueError('R2 witness receipt supervisor refs differ from run journal')

    # The normalized acceptance case must retain the same monitor references
    # for stage, transition, and application outcomes.
    explicit = []
    for slot, request in (('A', 'positive_full'), ('B', 'unrelated_compare'),
                          ('C', 'own_revocation')):
        stage = case['stage'][slot]
        transition = case['transition'][slot]
        explicit.append((stage.get('monitor'), f'{request}:stage',
                         stage.get('monitor_owner')))
        explicit.append((transition.get('monitor'), f'{request}:transition',
                         transition.get('monitor_owner')))
    effect_steps = {
        'full': 'positive_full:execute',
        'unrelated_full': 'unrelated_compare:unrelated_full:effect',
        'anchor': 'unrelated_compare:anchor:effect',
        'own_revocation': 'own_revocation:effect',
    }
    for branch, step in effect_steps.items():
        result = case['branches'][branch]['result']
        explicit.append((result.get('outer'), step, result.get('monitor_owner')))
    for ref, step, owner in explicit:
        if ref is None:
            raise ValueError('normalized stage/transition/effect monitor reference required')
        if (ref.get('path') != monitor_refs[step]['path']
                or ref.get('sha256') != monitor_refs[step]['sha256']):
            raise ValueError('normalized monitor ref differs from run journal')
        _outer(ref, owner)

    return samples_by_step


def _verify_b_request(report_case, case):
    branches = report_case.get('branches')
    if type(branches) is not dict or not BRANCHES.issubset(branches):
        raise ValueError('independent acceptance report branches required')
    full = branches['unrelated_full']
    anchor = branches['anchor']
    identity_fields = ('action_hash', 'current_root', 'finalized_request_sha256',
                       'request_account_sha256', 'source_receipt_sha256',
                       'r1_source_receipt_sha256')
    if (full.get('request_slot') != 'B' or anchor.get('request_slot') != 'B'
            or any(full.get(key) is None or full.get(key) != anchor.get(key)
                   for key in identity_fields)
            or full.get('effect_count') != 1 or anchor.get('effect_count') != 1
            or full.get('request_consumed') is not True
            or anchor.get('request_consumed') is not True):
        raise ValueError('Full and Anchor must share the same B request identity')
    full_clone = case['branches']['unrelated_full'].get('r1_clone', {}).get('receipt')
    anchor_clone = case['branches']['anchor'].get('r1_clone', {}).get('receipt')
    if (type(full_clone) is not dict or type(anchor_clone) is not dict
            or full_clone.get('path') == anchor_clone.get('path')
            or full_clone.get('sha256') == anchor_clone.get('sha256')):
        raise ValueError('matched B outcomes require separate R1 clone receipts')
    clone_receipts = []
    for ref in (full_clone, anchor_clone):
        receipt = _load_pinned_json(ref, 'R1 clone receipt')
        if (receipt.get('schema') != 'part5-v3-r1-ledger-clone-v1'
                or receipt.get('training_only') is not True
                or receipt.get('source_stable') is not True
                or receipt.get('copy_identical') is not True
                or receipt.get('application_effect') is not False
                or receipt.get('request_unconsumed') not in (None, True)):
            raise ValueError('verified independent unconsumed R1 clone required')
        clone_receipts.append(receipt)
    left, right = clone_receipts
    if (left.get('source') != right.get('source')
            or left.get('transition_report_sha256') != right.get('transition_report_sha256')
            or left.get('destination') == right.get('destination')
            or left.get('tree_sha256') != right.get('tree_sha256')
            or left.get('entry_count') != right.get('entry_count')):
        raise ValueError('matched B outcomes require equal-source distinct R1 clones')


def _canonical_manifest_sha256(manifest):
    raw = (json.dumps(manifest, sort_keys=True, separators=(',', ':'),
                      allow_nan=False) + '\n').encode()
    return _sha(raw)


def _verify_run_manifest(case):
    run_manifest, raw_sha = _load_input_ref(case.get('run_manifest'), 'run manifest')
    variant = case.get('variant')
    if (run_manifest.get('schema') != RUN_MANIFEST_SCHEMA
            or type(run_manifest.get('variant')) is not int
            or run_manifest['variant'] != variant):
        raise ValueError('pinned per-variant heldout run manifest required')
    return _canonical_manifest_sha256(run_manifest), raw_sha


def _verify_current_head_evidence(report_case):
    evidence = report_case.get('current_head_evidence')
    if type(evidence) is not dict or set(evidence) != {'R0', 'R1', 'R2'}:
        raise ValueError('complete current-head evidence for R0/R1/R2 required')
    expected_fields = {
        'evidence_scope', 'independent_production_freshness', 'root', 'root_version',
        'source_sequence', 'source_digest', 'publisher_sequence', 'publisher_digest',
        'publisher_key_sha256', 'history_sha256', 'report_sha256',
        'finalized_head_account_sha256', 'finalized_config_account_sha256',
    }
    roots = report_case.get('roots')
    if type(roots) is not dict or set(roots) != {'R0', 'R1', 'R2'}:
        raise ValueError('current-head evidence requires accepted R0/R1/R2 roots')
    digest_fields = (
        'root', 'source_digest', 'publisher_digest', 'publisher_key_sha256',
        'history_sha256', 'report_sha256', 'finalized_head_account_sha256',
        'finalized_config_account_sha256',
    )
    for label in ('R0', 'R1', 'R2'):
        row = evidence[label]
        expected_version = {'R0': 0, 'R1': 1, 'R2': 2}[label]
        expected_sequence = {'R0': 1, 'R1': 3, 'R2': 3}[label]
        if (type(row) is not dict or set(row) != expected_fields
                or row.get('evidence_scope') != 'controlled_local_signed_publisher_current_head'
                or row.get('independent_production_freshness') is not False
                or row.get('root') != roots[label]
                or any(type(row.get(name)) is not str
                       or HEX64.fullmatch(row[name]) is None
                       for name in digest_fields)
                or type(row.get('root_version')) is not int
                or row['root_version'] != expected_version
                or type(row.get('source_sequence')) is not int
                or row['source_sequence'] != expected_sequence
                or type(row.get('publisher_sequence')) is not int
                or row['publisher_sequence'] != expected_sequence):
            raise ValueError(f'incomplete or inconsistent current-head evidence for {label}')
    branches = report_case.get('branches')
    for label, branch in (('R1', 'anchor'), ('R2', 'own_revocation')):
        accepted = branches.get(branch) if type(branches) is dict else None
        if (type(accepted) is not dict
                or evidence[label]['report_sha256'] != accepted.get('result_report_sha256')):
            raise ValueError(f'current-head evidence report pin differs for {label}')


def _verify_case_identity(report_case, case):
    context = _load_pinned_json(case.get('case_context'), 'case context')
    target = context.get('target') if type(context) is dict else None
    roots = context.get('membership') if type(context) is dict else None
    if (type(target) is not dict or type(roots) is not dict
            or target.get('variant') != case.get('variant')
            or target.get('credential_sha256') != report_case.get('target_credential_sha256')
            or target.get('tbs_sha256') != report_case.get('target_tbs_sha256')
            or target.get('issuer_index') != report_case.get('issuer_index')
            or target.get('holder_index') != report_case.get('holder_index')
            or report_case.get('roots') != {key: roots.get(key) for key in ('R0', 'R1', 'R2')}):
        raise ValueError('accepted target identity differs from assembled case context')

    expected = {
        'full': ('A', 'R0', 'R0'),
        'unrelated_full': ('B', 'R1', 'R1'),
        'anchor': ('B', 'R1', 'R1'),
        'own_revocation': ('C', 'R1', 'R2'),
    }
    branches = report_case.get('branches')
    if type(branches) is not dict or set(branches) != BRANCHES:
        raise ValueError('accepted branch identities required')
    for branch, (slot, action_root, result_root) in expected.items():
        accepted = branches[branch]
        slot_sources = case.get('sources', {}).get(slot)
        slot_stage = case.get('stage', {}).get(slot)
        if (type(accepted) is not dict or type(slot_sources) is not dict
                or type(slot_stage) is not dict):
            raise ValueError('assembled source and stage slot identities required')
        refs = {name: slot_sources.get(name, {}).get('receipt')
                for name in ('R0', 'R1')}
        receipts = {name: _load_pinned_json(refs[name], f'{slot} {name} source receipt')
                    for name in ('R0', 'R1')}
        request_ref = slot_stage.get('accounts', {}).get('request')
        request_sha = _sha(_read_ref(request_ref))
        expected_finalized = receipts[action_root]['finalized_request_sha256']
        expected_action = receipts['R0']['action_hash']
        if (accepted.get('request_slot') != slot
                or accepted.get('source_receipt_sha256') != refs['R0'].get('sha256')
                or accepted.get('r1_source_receipt_sha256') != refs['R1'].get('sha256')
                or accepted.get('finalized_request_sha256') != expected_finalized
                or accepted.get('action_hash') != expected_action
                or receipts['R1'].get('action_hash') != expected_action
                or accepted.get('request_account_sha256') != request_sha
                or accepted.get('current_root') != roots.get(result_root)
                or any(receipt.get('target_der_sha256') != target.get('credential_sha256')
                       or receipt.get('target_tbs_sha256') != target.get('tbs_sha256')
                       for receipt in receipts.values())):
            raise ValueError(f'accepted {branch} request/source identity differs from assembled case')


def _verify_analyzer_frozen_source(manifest):
    relative = 'tools/part5/analyze_v3_heldout_costs.py'
    rows = manifest.get('frozen_bundles', {}).get('client')
    if type(rows) is not list:
        raise ValueError('frozen client bundle required for cost analyzer provenance')
    matches = [row for row in rows if type(row) is dict and row.get('path') == relative]
    source_path = ROOT / relative
    if len(matches) != 1 or Path(matches[0].get('artifact', {}).get('path', '')) != source_path:
        raise ValueError('cost analyzer must be a pinned frozen client bundle member')
    ref = matches[0]['artifact']
    raw = _read_ref(ref)
    if raw != _read(source_path):
        raise ValueError('frozen cost analyzer source differs from live analyzer')


def _load_proof_report(bundle):
    if type(bundle) is not dict or set(bundle) != {'receipt', 'artifacts'}:
        raise ValueError('proof receipt bundle required for pinned proof report')
    receipt = _load_pinned_json(bundle['receipt'], 'proof receipt')
    if receipt.get('schema') != 'credential-v3-heldout-proof-evidence-v1':
        raise ValueError('heldout proof receipt schema required for pinned proof report')
    mode = receipt.get('mode')
    expected_mode = {'full': 'matched-full-k1', 'anchor': 'matched-anchor-k1'}.get(mode)
    report_ref = receipt.get('proof_report')
    if (expected_mode is None or receipt.get('proof_mode') != expected_mode
            or type(report_ref) is not dict):
        raise ValueError('proof receipt mode and report reference required')
    report = _load_pinned_json(report_ref, 'proof report')
    if (report.get('schema') != 'credential-v3-matched-k1-proof-v1'
            or report.get('passed') is not True
            or report.get('mode') != expected_mode):
        raise ValueError('pinned proof report mode/schema mismatch')
    return receipt, report


def _unavailable(reason):
    return {'status': 'unavailable', 'reason': reason}


def _effect_transaction_metrics(case, report_case, journal, branch):
    """Read metrics from the exact successful application-effect event only."""
    scenarios = {
        'full': ('positive_full:execute', 'v3-valid-full-execute'),
        'unrelated_full': ('unrelated_compare:unrelated_full:effect',
                           'v3-valid-full-R1'),
        'anchor': ('unrelated_compare:anchor:effect', 'v3-valid-anchor-R1'),
        'own_revocation': ('own_revocation:effect', None),
    }
    step, scenario = scenarios[branch]
    if scenario is None:
        return _unavailable('acceptance branch records no successful application effect')

    result = case.get('branches', {}).get(branch, {}).get('result')
    ref = result.get('report') if type(result) is dict else None
    if ref is None:
        return _unavailable('pinned effect report reference absent')
    if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
            or type(ref.get('path')) is not str
            or type(ref.get('sha256')) is not str):
        raise ValueError(f'{branch} effect report pin required for transaction metrics')

    accepted = report_case.get('branches', {}).get(branch)
    if type(accepted) is not dict or accepted.get('result_report_sha256') != ref['sha256']:
        raise ValueError(f'{branch} effect report differs from independent acceptance')
    step_row = journal.get('steps', {}).get(step)
    if type(step_row) is not dict:
        return _unavailable('effect report journal reference absent')
    if (step_row.get('report') != ref['path']
            or step_row.get('report_sha256') != ref['sha256']):
        raise ValueError(f'{branch} effect report differs from pinned run journal')

    report = _load_pinned_json(ref, f'{branch} effect report')
    expected = {
        'full': ('part5-v3-local-execute-v1', 'Full'),
        'unrelated_full': ('part5-v3-r1-branch-v1', 'full'),
        'anchor': ('part5-v3-r1-branch-v1', 'anchor'),
    }[branch]
    mode_field = 'proof_mode' if branch == 'full' else 'mode'
    if (report.get('schema') != expected[0] or report.get('passed') is not True
            or report.get('training_only') is not True
            or report.get(mode_field) != expected[1]):
        raise ValueError(f'{branch} effect report schema/mode required for transaction metrics')
    if report.get('application_effect') is not True or report.get('effect_count') != 1:
        raise ValueError(f'{branch} effect report does not record one successful effect')

    transactions = report.get('transactions')
    if type(transactions) is not list:
        raise ValueError(f'{branch} transaction event list required')
    matches = [row for row in transactions
               if type(row) is dict and row.get('scenario') == scenario]
    if len(matches) != 1 or matches[0].get('err') is not None:
        raise ValueError(f'{branch} exact successful effect transaction required')
    event = matches[0]
    for event_name in ('transactionBytes', 'computeUnits'):
        value = event.get(event_name)
        if type(value) is not int or value <= 0:
            raise ValueError(
                f'{branch} successful effect transaction {event_name} must be a positive integer')
    values = {}
    for output_name, event_name in (
            ('transaction_bytes', 'transactionBytes'),
            ('compute_units', 'computeUnits'),
            ('fee_lamports', 'feeLamports')):
        value = event.get(event_name)
        if type(value) is int and value >= 0:
            values[output_name] = value
        else:
            values[output_name] = None
    return {'status': 'available', 'scenario': scenario,
            'source_report_sha256': ref['sha256'], **values,
            'unavailable_fields': [name for name, value in values.items()
                                   if value is None],
            'field_source': 'direct transport event fields'}


def _artifact_privacy_class(name):
    if (name.endswith('.proof') or name.endswith('-public.bin')
            or name.endswith('/public.json') or name.endswith('solana-wire.bin')):
        return 'public'
    if name.endswith('/input.json') or name.endswith('/output.wtns'):
        return 'private'
    return 'unclassified'


def _proof_artifact_bytes(bundle):
    if type(bundle) is not dict or set(bundle) != {'receipt', 'artifacts'}:
        return _unavailable('proof receipt bundle absent')
    receipt, _ = _load_proof_report(bundle)
    artifacts = receipt.get('artifacts')
    if artifacts is None:
        return _unavailable('proof receipt artifact references absent')
    if type(artifacts) is not dict:
        raise ValueError('proof receipt artifact reference map required')
    if not artifacts:
        return _unavailable('proof receipt artifact reference map is empty')
    if bundle.get('artifacts') is not None and bundle['artifacts'] != artifacts:
        raise ValueError('proof bundle artifact refs differ from pinned proof receipt')

    files = {}
    totals = {'public': 0, 'private': 0, 'unclassified': 0}
    proof_payload_bytes = 0
    proof_public_input_bytes = 0
    solana_wire_bytes = 0
    for name, ref in sorted(artifacts.items()):
        if type(name) is not str or not name:
            raise ValueError('proof artifact name required')
        try:
            raw = _read_ref(ref, cap=32 * 1024 * 1024)
        except (OSError, ValueError) as error:
            raise ValueError(f'proof artifact pin invalid: {error}') from None
        privacy = _artifact_privacy_class(name)
        size = len(raw)
        totals[privacy] += size
        if name.endswith('.proof'):
            proof_payload_bytes += size
        elif name.endswith('-public.bin'):
            proof_public_input_bytes += size
        elif name.endswith('solana-wire.bin'):
            solana_wire_bytes += size
        files[name] = {'bytes': size, 'privacy_class': privacy,
                       'presence': 'verified_present_at_analysis',
                       'retention_lifecycle': 'unavailable_no_receipt_field'}
    total = sum(totals.values())
    return {
        'status': 'available',
        'current_pinned_file_bytes': total,
        'current_pinned_file_bytes_by_privacy_class': totals,
        'proof_payload_bytes': proof_payload_bytes,
        'proof_public_input_bytes': proof_public_input_bytes,
        'solana_wire_bytes': solana_wire_bytes,
        'retained_bytes': None,
        'temporary_bytes': None,
        'lifecycle_note': ('Files are pinned and present during analysis; the receipt has no '
                           'retained-versus-temporary lifecycle field.'),
        'files': files,
    }


def _available_summary(values):
    values = [value for value in values if _number(value)]
    if not values:
        return {'median': None, 'min': None, 'max': None, 'spread': None, 'n': 0}
    return {'median': median(values), 'min': min(values), 'max': max(values),
            'spread': max(values) - min(values), 'n': len(values)}


def _anchor_preparation_seconds(bundle):
    receipt, report = _load_proof_report(bundle)
    if receipt.get('mode') != 'anchor' or report.get('mode') != 'matched-anchor-k1':
        raise ValueError('Anchor proof report must use matched-anchor-k1 mode')
    public_ms = report.get('public_material_prepare_ms')
    cases = report.get('cases')
    if (not _number(public_ms) or type(cases) is not list or len(cases) != 1
            or type(cases[0]) is not dict
            or not _number(cases[0].get('private_anchor_prepare_ms'))):
        raise ValueError('Anchor proof report must contain finite nonnegative preparation times')
    public_seconds = float(public_ms) / 1000.0
    private_seconds = float(cases[0]['private_anchor_prepare_ms']) / 1000.0
    return {
        'public_material_prepare': public_seconds,
        'private_anchor_prepare': private_seconds,
        'total': public_seconds + private_seconds,
    }


def _proof_bundle_seconds(bundle):
    if type(bundle) is not dict or set(bundle) != {'receipt', 'artifacts'}:
        raise ValueError('proof receipt bundle required for bounded duration accounting')
    receipt, _ = _load_proof_report(bundle)
    reports = receipt.get('supervisor_reports')
    expected = {'r0-witness', 'r0-relation', 'r1-witness', 'r1-relation',
                'proof', 'adapter'}
    if type(reports) is not dict or set(reports) != expected:
        raise ValueError('complete proof supervisor report set required')
    total = 0.0
    sampled = []
    for name, row in reports.items():
        if type(row) is not dict or set(row) != {'path', 'sha256', 'limits'}:
            raise ValueError(f'pinned {name} proof supervisor report required')
        report = _load_pinned_json({'path': row['path'], 'sha256': row['sha256']},
                                   f'{name} proof supervisor report')
        duration = report.get('duration_seconds')
        if (report.get('schema') != 1 or report.get('passed') is not True
                or report.get('exit_code') != 0
                or report.get('censored', False) is not False
                or type(report.get('sample_count')) is not int
                or report['sample_count'] <= 0 or not _number(duration)
                or duration <= 0 or report.get('stop_reason') is not None
                or report.get('runner_error_type') is not None
                or report.get('cleanup_remaining_owned_processes') != 0
                or report.get('cleanup_status_unknown') is not False):
            raise ValueError(f'completed {name} proof supervisor duration required')
        rss = report.get('sampled_peak_owned_tree_rss_bytes')
        storage = report.get('sampled_peak_storage_growth_bytes')
        if type(rss) is not int or rss < 0 or type(storage) is not int or storage < 0:
            raise ValueError(f'{name} proof supervisor RSS/storage samples required')
        total += float(duration)
        sampled.append((rss, storage))
    return total, sampled


def _verify_proof_durations(case, journal, durations):
    branch_proofs = case['branches']
    mappings = (
        (branch_proofs['full'].get('proof'), 'positive_full:proof-full'),
        (branch_proofs['full'].get('replay_proof'),
         'positive_full:proof-full-fresh-replay'),
        (branch_proofs['unrelated_full'].get('proof', {}).get('full'),
         'unrelated_compare:proof-full'),
        (branch_proofs['unrelated_full'].get('proof', {}).get('anchor'),
         'unrelated_compare:proof-anchor'),
        (branch_proofs['own_revocation'].get('proof'), 'own_revocation:proof-anchor'),
    )
    sampled = {}
    for bundle, step in mappings:
        if bundle is None:
            raise ValueError('proof receipt required for bounded duration accounting')
        step_row = journal.get('steps', {}).get(step)
        receipt_ref = bundle.get('receipt') if type(bundle) is dict else None
        if (type(step_row) is not dict or type(receipt_ref) is not dict
                or step_row.get('receipt') != receipt_ref.get('path')
                or step_row.get('receipt_sha256') != receipt_ref.get('sha256')):
            raise ValueError(f'proof receipt journal identity mismatch for {step}')
        total, proof_samples = _proof_bundle_seconds(bundle)
        if total > durations[step] + 1e-6:
            raise ValueError('journal proof wall time is below bounded supervisor durations')
        sampled[step] = proof_samples
    b_anchor = branch_proofs['anchor'].get('proof')
    full_anchor = branch_proofs['unrelated_full'].get('proof', {}).get('anchor')
    if (type(b_anchor) is not dict or type(full_anchor) is not dict
            or b_anchor.get('receipt') != full_anchor.get('receipt')):
        raise ValueError('B Anchor timing must use the proof shared by both outcomes')
    return sampled


def _summary(rows, field):
    values = [row[field] for row in rows]
    return {'median': median(values), 'min': min(values), 'max': max(values),
            'spread': max(values) - min(values), 'n': len(values)}


def _sampled_peak(samples):
    if not samples:
        raise ValueError('sampled resource observations required for each B mode')
    return {
        'monitor_report_count': len(samples),
        'sampled_peak_owned_tree_rss_bytes': max(row[0] for row in samples),
        'sampled_peak_storage_growth_bytes': max(row[1] for row in samples),
    }


def _accepted_runtime_identity(acceptance):
    """Recover the common loaded identity from the pinned verified case results."""
    frozen = acceptance.get('frozen_identities')
    frozen_elf = frozen.get('loaded_elf_sha256') if type(frozen) is dict else None
    if type(frozen_elf) is not str or HEX64.fullmatch(frozen_elf) is None:
        raise ValueError('verified runtime identity requires the frozen ELF digest')
    identity = None
    for case in acceptance['cases']:
        branches = case.get('branches')
        if type(branches) is not dict or set(branches) != BRANCHES:
            raise ValueError('verified runtime identity required for all branches')
        for branch in branches.values():
            runtime = branch.get('runtime_identity') if type(branch) is dict else None
            if (type(runtime) is not dict
                    or any(type(runtime.get(key)) is not str or not runtime[key]
                           for key in ('program', 'programdata', 'genesis'))
                    or any(type(runtime.get(key)) is not str
                           or HEX64.fullmatch(runtime[key]) is None
                           for key in ('elf_sha256', 'program_account_sha256',
                                       'programdata_account_sha256'))
                    or runtime['elf_sha256'] != frozen_elf):
                raise ValueError('verified runtime identity missing or differs from frozen ELF')
            if identity is None:
                identity = dict(runtime)
            if runtime != identity:
                raise ValueError('verified runtime identity differs across heldout branches')
    return identity


def analyze(manifest_ref, acceptance_ref):
    manifest, manifest_sha = _load_input_ref(manifest_ref, 'assembled manifest')
    acceptance, acceptance_sha = _load_input_ref(acceptance_ref, 'acceptance report')
    final_acceptance = manifest.get('schema') == MANIFEST_SCHEMA
    if manifest.get('schema') not in (MANIFEST_SCHEMA, 'credential-v3-heldout-acceptance-manifest-v1'):
        raise ValueError('assembled heldout acceptance manifest required')
    if (acceptance.get('schema') != ACCEPTANCE_SCHEMA
            or acceptance.get('verified') is not True
            or acceptance.get('heldout_acceptance') is not final_acceptance
            or (not final_acceptance and acceptance.get('evidence_scope') != 'legacy-core-path-only')
            or acceptance.get('internal_training_mode_reused') is not True):
        raise ValueError('independent verified heldout acceptance receipt required')
    if acceptance.get('manifest_sha256') != manifest_sha:
        raise ValueError('acceptance report does not pin the exact assembled manifest')
    if final_acceptance:
        if (acceptance.get('counts', {}).get('loaded_expired_status_negatives') != 8
                or acceptance.get('counts', {}).get('loaded_queue_capacity_negatives') != 1):
            raise ValueError('eight expiry and one capacity loaded negatives required')
    _verify_analyzer_frozen_source(manifest)
    freeze_ref, cohort_ref = manifest.get('freeze_receipt'), manifest.get('cohort_receipt')
    if (type(freeze_ref) is not dict or type(cohort_ref) is not dict
            or acceptance.get('freeze_sha256') != freeze_ref.get('sha256')
            or acceptance.get('cohort_receipt_sha256') != cohort_ref.get('sha256')):
        raise ValueError('manifest and independent acceptance pins differ')
    cases = manifest.get('cases')
    accepted_cases = acceptance.get('cases')
    if (type(cases) is not list or len(cases) != 8
            or type(accepted_cases) is not list or len(accepted_cases) != 8
            or acceptance.get('counts', {}).get('variants') != 8):
        raise ValueError('eight verified heldout cases required')
    by_variant = {}
    for row in accepted_cases:
        variant = row.get('variant') if type(row) is dict else None
        if type(variant) is not int or variant not in VARIANTS or variant in by_variant:
            raise ValueError('unique independent acceptance variants 0 through 7 required')
        by_variant[variant] = row
    if set(by_variant) != VARIANTS:
        raise ValueError('independent acceptance report must cover variants 0 through 7')

    if final_acceptance:
        from tools.part5 import verify_v3_heldout_acceptance as verifier
        runtime_identity = _accepted_runtime_identity(acceptance)
        capacity = verifier._verify_queue_capacity_negative(manifest, runtime_identity)
        if acceptance.get('queue_capacity_negative') != capacity:
            raise ValueError('capacity acceptance differs from independently reopened evidence')

    output_rows = []
    sampled = []
    for case in cases:
        if type(case) is not dict:
            raise ValueError('assembled heldout case object required')
        variant = case.get('variant')
        if type(variant) is not int or variant not in VARIANTS:
            raise ValueError('assembled variant 0 through 7 required')
        report_case = by_variant[variant]
        if (report_case.get('target_tbs_sha256') is None
                or case.get('variant') != report_case.get('variant')):
            raise ValueError('assembled and accepted case identity mismatch')
        run_manifest_sha, _ = _verify_run_manifest(case)
        journal, _ = _load_input_ref(case.get('run_journal'), 'run journal')
        durations = _duration_map(journal, run_manifest_sha)
        _check_order(case, variant)
        _check_summary(case, journal, durations)
        if final_acceptance:
            _expired_status_cost(case, journal)
            _verify_expired_status_audit(case, journal, report_case)
        _verify_disabled_config_audit(case, journal)
        _verify_case_identity(report_case, case)
        _verify_current_head_evidence(report_case)
        _verify_b_request(report_case, case)
        proof_samples = _verify_proof_durations(case, journal, durations)
        monitor_samples = _verify_monitor_durations(case, journal, durations)
        effect_transactions = {
            branch: _effect_transaction_metrics(case, report_case, journal, branch)
            for branch in ('full', 'unrelated_full', 'anchor', 'own_revocation')
        }
        branch_proofs = case['branches']
        proof_artifact_accounting = {
            'full_A_initial': _proof_artifact_bytes(
                branch_proofs['full'].get('proof')),
            'full_A_fresh_replay_test_only': _proof_artifact_bytes(
                branch_proofs['full'].get('replay_proof')),
            'full_B': _proof_artifact_bytes(
                branch_proofs['unrelated_full'].get('proof', {}).get('full')),
            'anchor_B': _proof_artifact_bytes(
                branch_proofs['anchor'].get('proof')),
            'anchor_C_own_revocation': _proof_artifact_bytes(
                branch_proofs['own_revocation'].get('proof')),
        }
        anchor_preparation = {
            'B': _anchor_preparation_seconds(case['branches']['anchor'].get('proof')),
            'C': _anchor_preparation_seconds(
                case['branches']['own_revocation'].get('proof')),
        }
        for observations in proof_samples.values():
            sampled.extend(observations)
        for observations in monitor_samples.values():
            if (type(observations) is tuple and len(observations) == 2
                    and type(observations[0]) is int):
                sampled.append(observations)
            else:
                sampled.extend(observations)

        shared = sum(durations[f'unrelated_compare:{name}'] for name in
                     ('prepare', 'stage', 'transition', 'source-R0', 'source-R1'))
        full = shared + sum(durations[name] for name in
            ('unrelated_compare:proof-full',
             'unrelated_compare:unrelated_full:clone',
             'unrelated_compare:unrelated_full:effect'))
        anchor = shared + sum(durations[name] for name in
            ('unrelated_compare:proof-anchor',
             'unrelated_compare:anchor:clone',
             'unrelated_compare:anchor:effect'))
        pair_view = durations['pair-view']
        shared_b_steps = [f'unrelated_compare:{suffix}' for suffix in
                          ('prepare', 'stage', 'transition', 'source-R0', 'source-R1')]
        full_b_steps = shared_b_steps + ['unrelated_compare:unrelated_full:clone',
                                         'unrelated_compare:unrelated_full:effect']
        anchor_b_steps = shared_b_steps + ['unrelated_compare:anchor:clone',
                                           'unrelated_compare:anchor:effect']
        full_samples = [monitor_samples[step] for step in shared_b_steps]
        full_samples.extend(proof_samples['unrelated_compare:proof-full'])
        full_samples.extend(monitor_samples[step] for step in full_b_steps[5:])
        anchor_samples = [monitor_samples[step] for step in shared_b_steps]
        anchor_samples.extend(proof_samples['unrelated_compare:proof-anchor'])
        anchor_samples.extend(monitor_samples[step] for step in anchor_b_steps[5:])
        output_rows.append({
            'variant': variant,
            'expired_status_negative_wall_seconds': case.get('expired_status_negative_wall_seconds'),
            'disabled_config_negative_wall_seconds': case[
                'disabled_config_negative_wall_seconds'],
            'disabled_config_negative_components_seconds': {
                'clone': durations['positive_full:disabled-config-clone'],
                'negative_effect': durations['positive_full:disabled-config-negative'],
            },
            'ambiguous_restart_wall_seconds': case['ambiguous_restart_wall_seconds'],
            'ambiguous_restart_components_seconds': {
                'clone': durations['positive_full:ambiguous-restart-clone'],
                'reconciliation': durations['positive_full:ambiguous-restart'],
            },
            'pair_view_one_time_seconds': pair_view,
            'full_A_fresh_replay_test_only_seconds': durations[
                'positive_full:proof-full-fresh-replay'],
            'shared_B_seconds': shared,
            'full_B_branch_only_seconds': full - shared,
            'anchor_B_branch_only_seconds': anchor - shared,
            'full_B_seconds': full,
            'anchor_B_seconds': anchor,
            'anchor_minus_full_B_seconds': anchor - full,
            'full_B_plus_pair_view_seconds': full + pair_view,
            'anchor_B_plus_pair_view_seconds': anchor + pair_view,
            'B_total_wall_savings_fraction': (full - anchor) / full,
            'B_plus_pair_view_wall_savings_fraction': (
                full - anchor) / (full + pair_view),
            'anchor_preparation_seconds': anchor_preparation,
            'B_sampled_resources': {
                'full': _sampled_peak(full_samples),
                'anchor': _sampled_peak(anchor_samples),
            },
            'effect_transaction_metrics': effect_transactions,
            'proof_artifact_accounting': proof_artifact_accounting,
            'action_hash': report_case['branches']['anchor']['action_hash'],
            'current_root': report_case['branches']['anchor']['current_root'],
        })
    if {row['variant'] for row in output_rows} != VARIANTS:
        raise ValueError('assembled manifest must cover variants 0 through 7')
    output_rows.sort(key=lambda row: row['variant'])
    summary = {field: _summary(output_rows, field) for field in
               ('shared_B_seconds', 'full_B_seconds', 'anchor_B_seconds',
                'anchor_minus_full_B_seconds', 'pair_view_one_time_seconds',
                'full_B_plus_pair_view_seconds', 'anchor_B_plus_pair_view_seconds',
                'B_total_wall_savings_fraction',
                'B_plus_pair_view_wall_savings_fraction')}
    if final_acceptance:
        summary['expired_status_negative_wall_seconds'] = _summary(output_rows, 'expired_status_negative_wall_seconds')
    summary['disabled_config_negative_wall_seconds'] = _summary(
        output_rows, 'disabled_config_negative_wall_seconds')
    summary['ambiguous_restart_wall_seconds'] = _summary(
        output_rows, 'ambiguous_restart_wall_seconds')
    summary['anchor_preparation_seconds'] = {
        slot: {
            field: _summary([
                {'value': row['anchor_preparation_seconds'][slot][field]}
                for row in output_rows], 'value')
            for field in ('public_material_prepare', 'private_anchor_prepare', 'total')
        }
        for slot in ('B', 'C')
    }
    summary['effect_transaction_metrics'] = {
        branch: {
            field: _available_summary([
                row['effect_transaction_metrics'][branch].get(field)
                for row in output_rows])
            for field in ('transaction_bytes', 'compute_units', 'fee_lamports')
        }
        for branch in ('full', 'unrelated_full', 'anchor', 'own_revocation')
    }
    summary['proof_artifact_current_file_bytes'] = {
        role: _available_summary([
            row['proof_artifact_accounting'][role].get('current_pinned_file_bytes')
            for row in output_rows])
        for role in ('full_A_initial', 'full_A_fresh_replay_test_only',
                     'full_B', 'anchor_B', 'anchor_C_own_revocation')
    }
    summary['proof_artifact_components_bytes'] = {
        role: {
            field: _available_summary([
                row['proof_artifact_accounting'][role].get(field)
                for row in output_rows])
            for field in ('proof_payload_bytes', 'proof_public_input_bytes',
                          'solana_wire_bytes')
        }
        for role in ('full_A_initial', 'full_A_fresh_replay_test_only',
                     'full_B', 'anchor_B', 'anchor_C_own_revocation')
    }
    rss_values = [row[0] for row in sampled]
    storage_values = [row[1] for row in sampled]
    return {
        'schema': OUTPUT_SCHEMA,
        'heldout_acceptance': final_acceptance,
        'evidence_scope': 'final-acceptance' if final_acceptance else 'legacy-core-path-only',
        'assembled_manifest_sha256': manifest_sha,
        'acceptance_report_sha256': acceptance_sha,
        'queue_capacity_negative_wall_seconds': manifest.get('queue_capacity_negative_wall_seconds'),
        'negative_accounting': 'Expired status and shared capacity are separate audit overhead, excluded from matched B totals.',
        'basis': 'request-B preparation, stage, transition, source, proof, clone, and effect wall time',
        'shared_B_formula': 'B:prepare+B:stage+B:transition+B:source-R0+B:source-R1',
        'full_B_formula': 'shared_B+B:proof-full+B:unrelated_full:clone+B:unrelated_full:effect',
        'anchor_B_formula': 'shared_B+B:proof-anchor+B:anchor:clone+B:anchor:effect',
        'pair_view_accounting': ('timed credential preparation reported once per case; '
                                 'the plus-pair-view totals charge it once to each B mode'),
        'fresh_replay_accounting': ('A:proof-full-fresh-replay is a test-only second '
                                    'Full proof bundle; reported per case and excluded from matched B totals'),
        'disabled_config_negative_accounting': (
            'A:disabled-config-clone plus A:disabled-config-negative are reported per case '
            'and in the summary as separate audit overhead; excluded from matched B totals.'),
        'ambiguous_restart_accounting': (
            'A:ambiguous-restart-clone plus A:ambiguous-restart are reported per case '
            'and in the summary as separate recovery audit overhead; excluded from matched B totals.'),
        'transaction_metric_accounting': (
            'Transaction bytes, compute units, and fee lamports are direct fields from the '
            'unique successful effect event in the pinned application report. They are '
            'reported separately from wall time; own-revocation has no successful effect event.'),
        'proof_artifact_accounting': (
            'Artifact bytes sum raw files whose paths and SHA-256 values are pinned by each '
            'proof receipt and verified present during analysis. Privacy classes are conservative; '
            'retained-versus-temporary lifecycle is unavailable because receipts record no lifecycle field.'),
        'spread_definition': 'maximum minus minimum across the eight heldout variants',
        'pairs': output_rows,
        'summary': summary,
        'resource_observations': {
            'monitor_report_count': len(sampled),
            'sampled_peak_owned_tree_rss_bytes_max': max(rss_values) if sampled else None,
            'sampled_peak_storage_growth_bytes_max': max(storage_values) if sampled else None,
            'caveat': ('Supervisor samples are discrete RSS/storage observations from available '
                       'bounded monitors; they are not continuous maxima or complete resource '
                       'accounting.'),
        },
        'claims': {'cpu_savings': False, 'whole_application_benefit': False,
                   'independent_production_freshness': False},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, help='assembled manifest PATH:SHA256')
    parser.add_argument('--acceptance-report', required=True,
                        help='independent verifier report PATH:SHA256')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        def parse_ref(value):
            path, separator, pin = value.rpartition(':')
            if not separator or HEX64.fullmatch(pin) is None:
                raise ValueError('input must be PATH:SHA256')
            return {'path': path, 'sha256': pin}
        result = analyze(parse_ref(args.manifest), parse_ref(args.acceptance_report))
        raw = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        output = args.output
        if (not output.is_absolute() or output.exists() or output.is_symlink()
                or output.parent.resolve(strict=True) != output.parent):
            raise ValueError('fresh absolute output path required')
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        raise SystemExit('heldout cost analysis rejected') from None
    print(json.dumps({'path': str(output), 'sha256': _sha(raw),
                      'pairs': len(result['pairs'])}, sort_keys=True))


if __name__ == '__main__':
    main()
