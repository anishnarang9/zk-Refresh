#!/usr/bin/env python3
"""Run one heldout v3 certificate through the serialized local application gate.

The input is a pinned manifest, never a command vector. This driver creates
three distinct request/stage/transition chains and records resumable evidence.
All validator, clone, proof, and application children run under the bounded
session monitor; only one child may run at a time.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import stat
import sys
import time
import uuid
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO / 'artifacts/dynark/part5'
LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}
DISABLED_CONFIG_LIMITS = {
    'runtime_seconds': 270, 'rss_bytes': LIMITS['rss_bytes'],
    'storage_growth_bytes': LIMITS['storage_growth_bytes']}
JOURNAL_SCHEMA = 'credential-v3-heldout-case-run-journal-v1'
RUN_SCHEMA = 'credential-v3-heldout-case-run-v1'
DISABLED_CONFIG_REPORT_SCHEMA = 'part5-v3-disabled-config-negative-report-v2'
DISABLED_CONFIG_SIDECAR_SCHEMA = 'credential-v3-heldout-disabled-config-negative-v2'
NEGATIVE_ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')
DISABLED_CONFIG_SIDECAR_KEYS = {
    'schema', 'variant', 'stage_report_sha256', 'stage_plan_sha256',
    'r0_source_receipt_sha256', 'full_proof_receipt_sha256', 'clone_receipt',
    'full_wire', 'config', 'rust_config', 'status', 'outer', 'report',
    'eligible_accounts', 'before_accounts', 'after_accounts',
    'issuer_eligible_accounts', 'issuer_before_accounts', 'issuer_after_accounts'}
EXPIRED_STATUS_SIDECAR_SCHEMA = 'credential-v3-heldout-expired-status-negative-v1'
CASE_FRAGMENT_SCHEMA = 'credential-v3-heldout-acceptance-case-fragment-v2'
EXPIRED_STATUS_SIDECAR_KEYS = {
    'schema', 'variant', 'stage_report_sha256', 'stage_plan_sha256',
    'r0_source_receipt_sha256', 'full_proof_receipt_sha256', 'clone_receipt',
    'full_wire', 'config', 'status', 'outer', 'monitor_invocation', 'candidate',
    'finalizer_manifest', 'finalization', 'report'}
EXPIRED_STATUS_STEP_NAMES = (
    'positive_full:expired-status-clone',
    'positive_full:expired-status-negative',
    'positive_full:expired-status-finalize')
AMBIGUOUS_RESTART_SIDECAR_SCHEMA = 'credential-v3-heldout-ambiguous-restart-v1'
AMBIGUOUS_RESTART_SIDECAR_KEYS = {
    'schema', 'variant', 'stage_report_sha256', 'stage_plan_sha256',
    'r0_source_receipt_sha256', 'full_proof_receipt_sha256',
    'replay_proof_receipt_sha256', 'clone_receipt', 'full_wire',
    'replay_full_wire', 'config', 'status', 'outer', 'proxy_receipt',
    'finality_receipt', 'pre_submit_report', 'pre_submit_accounts', 'final_accounts',
    'pre_restart_finality_receipt', 'pre_stop_accounts'}
AMBIGUOUS_ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')
AMBIGUOUS_RESTART_SUPERVISOR = 'harness/tests/queue_v3_local_ambiguous_restart.py'
AMBIGUOUS_RESTART_PROXY = 'harness/tests/queue_v3_ambiguous_rpc_proxy.py'
ROLE_NAMES = ('profile', 'r1cs', 'witness_executable', 'setup_manifest',
              'ordinary_vk', 'proof_runner', 'signer_interface',
              'ordinary_adapter', 'loaded_elf')
FROZEN_PATHS = {
    'profile': 'circuits/credential-v3-bounded/profile.json',
    'r1cs': 'artifacts/dynark/part5/v3-compile-001/credential.r1cs',
    'witness_executable': 'artifacts/dynark/part5/v3-compile-001/credential_js/credential.wasm',
    'setup_manifest': 'artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json',
    'ordinary_vk': 'artifacts/dynark/part5/v3-development-setup-001/ordinary.vk',
    'proof_runner': 'circuits/credential-v3-bounded/qualification/proof-runner-v1/target/release/credential-v3-bounded-proof-qualification-v1',
    'signer_interface': 'tools/part5/prepare_v3_request_fixture.py',
    'loaded_elf': 'artifacts/dynark/part5/application-v3-sbf-build-002/elf/zk_fresh_program.so',
}
FROZEN_ROLE_CAPS = {'r1cs': 256 * 1024 * 1024}
SOURCE_FILE_ROLES = ('heldout_source_tool', 'training_helper', 'exporter',
                     'request_fixture_bridge')
SOURCE_PATHS = {
    'heldout_source_tool': 'tools/part5/prepare_v3_heldout_source.py',
    'training_helper': 'crates/dynark-native-client/tests/support/prepare_v3_request_bound_training.py',
    'exporter': 'program/target/debug/examples/export_v3_request_fixture',
    'request_fixture_bridge': 'tools/part5/prepare_v3_request_fixture.py',
}
HEX = frozenset('0123456789abcdef')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def status_artifact(path):
    path = Path(path)
    return {'status_path': str(path), 'status_sha256': digest(_read(path))}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def run_manifest_identity(path, raw, manifest):
    """Pin the exact run-config file and its canonical journal identity."""
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute run manifest path required')
    try:
        loaded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('valid run manifest JSON required') from error
    if loaded != manifest:
        raise ValueError('run manifest bytes differ from loaded configuration')
    return ({'path': str(path), 'sha256': digest(raw)}, digest(encoded(manifest)))


def _hash(value):
    return (type(value) is str and len(value) == 64
            and all(c in HEX for c in value))


def reviewed_application_outer(outer):
    return (type(outer) is dict and outer.get('schema') == 1
        and (outer.get('measurement') is None
             or outer.get('measurement') == 'bounded_complete_session')
        and outer.get('passed') is False and outer.get('exit_code') == 1
        and (outer.get('censored') is None or outer.get('censored') is False)
        and outer.get('stop_reason') is None
        and outer.get('runner_error_type') is None
        and outer.get('cleanup_remaining_owned_processes') == 0
        and outer.get('cleanup_status_unknown') is False
        and type(outer.get('duration_seconds')) in (int, float)
        and outer.get('duration_seconds') > 0
        and type(outer.get('sample_count')) is int and outer.get('sample_count') > 0)


def reviewed_validator_sigint(cleanup):
    return (type(cleanup) is dict and cleanup.get('spawned') is True
        and cleanup.get('reaped') is True and cleanup.get('graceful') is False
        and cleanup.get('exit_code') == -2)


def reviewed_runner_exit(cleanup):
    return (type(cleanup) is dict and cleanup.get('spawned') is True
        and cleanup.get('reaped') is True and cleanup.get('exit_code') == 0)


def reviewed_r1_branch(outer, status, report, mode):
    expected_effect = mode != 'own-revocation'
    return (reviewed_application_outer(outer)
        and report.get('schema') == 'part5-v3-r1-branch-v1'
        and report.get('passed') is True and report.get('mode') == mode
        and report.get('application_effect') is expected_effect
        and report.get('effect_count') == int(expected_effect)
        and report.get('request_consumed') is expected_effect
        and status.get('status') == 'failed' and status.get('error_type') is None
        and status.get('branch_verified') is True and status.get('mode') == mode
        and status.get('application_effect') is expected_effect
        and status.get('effect_count') == int(expected_effect)
        and _hash(status.get('branch_report_sha256'))
        and reviewed_validator_sigint(status.get('validator_cleanup'))
        and reviewed_runner_exit(status.get('runner_cleanup')))


def _read(path, expected=None, cap=16 * 1024 * 1024, *, executable=False):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_size <= 0 or before.st_size > cap
            or (executable and not before.st_mode & stat.S_IXUSR)):
        message = ('canonical bounded owner-controlled executable required'
                   if executable else 'canonical bounded owner-controlled input required')
        raise ValueError(message)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        ident = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_size,
                           s.st_mtime_ns, s.st_ctime_ns)
        if ident(before) != ident(opened):
            raise ValueError('input changed at open')
        raw = stream.read(cap + 1)
        if ident(opened) != ident(os.fstat(stream.fileno())):
            raise ValueError('input changed during read')
    if (len(raw) != before.st_size or ident(before) != ident(path.lstat())
            or (expected is not None and digest(raw) != expected)):
        raise ValueError('input pin mismatch')
    return raw


def _read_ambiguous_runner_log(path, cap=65536):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size < 0 or before.st_size > cap):
        raise ValueError('canonical bounded owner-only ambiguous runner log required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        ident = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                               value.st_nlink, value.st_size, value.st_mtime_ns,
                               value.st_ctime_ns)
        if ident(before) != ident(opened):
            raise ValueError('ambiguous runner log changed at open')
        raw = stream.read(cap + 1)
        if ident(opened) != ident(os.fstat(stream.fileno())):
            raise ValueError('ambiguous runner log changed during read')
    if (len(raw) != before.st_size or ident(before) != ident(path.lstat())):
        raise ValueError('ambiguous runner log changed while reading')
    return raw


def validate_proof_runner_reference(frozen_ref, proof_ref, expected_hash):
    if (type(frozen_ref) is not dict or set(frozen_ref) != {'path', 'sha256'}
            or type(proof_ref) is not dict or set(proof_ref) != {'path', 'sha256'}
            or not isinstance(frozen_ref.get('path'), str)
            or not isinstance(proof_ref.get('path'), str)
            or not _hash(expected_hash)
            or frozen_ref['path'] != proof_ref['path']
            or frozen_ref.get('sha256') != expected_hash
            or proof_ref.get('sha256') != expected_hash):
        raise ValueError('same frozen proof runner reference required')
    _read(frozen_ref['path'], expected_hash, 128 * 1024 * 1024)
    return {'path': frozen_ref['path'], 'sha256': expected_hash}


def _json(path, expected=None, cap=65536):
    return json.loads(_read(path, expected, cap))


def verified_stage_ledger(config, config_sha256, status, report, report_sha256):
    """Check stage evidence pins and derive its ledger from the pinned prepare run."""
    if config.get('scope') != 'part5-v3-local-stage':
        raise ValueError('pinned local stage config required')
    prior_config = _json(config['prior_config'], config['prior_config_sha256'])
    prior_status = _json(config['prior_status'], config['prior_status_sha256'])
    runtime = prior_config.get('runtime_output')
    prepared_identity = prior_status.get('loaded_program')
    staged_identity = status.get('loaded_program')
    loaded_genesis = prepared_identity.get('genesis') if isinstance(prepared_identity, dict) else None
    identity_fields = ('genesis', 'elf_sha256', 'program', 'programdata',
                       'program_account_sha256', 'programdata_account_sha256')
    if (not isinstance(runtime, str) or not Path(runtime).is_absolute()
            or Path(runtime).resolve() != Path(runtime)
            or not isinstance(loaded_genesis, str) or not loaded_genesis
            or prior_status.get('config_sha256') != config['prior_config_sha256']
            or prior_status.get('ledger') != str(Path(runtime) / 'ledger')
            or config.get('ledger') != str(Path(runtime) / 'ledger')
            or config.get('expected_genesis') != loaded_genesis
            or report.get('schema') != 'part5-v3-local-stage-v1'
            or report.get('passed') is not True
            or report.get('genesis') != loaded_genesis
            or status.get('status') != 'failed'
            or status.get('stage_verified') is not True
            or status.get('ledger_reuse_requires_review') is not True
            or status.get('config_sha256') != config_sha256
            or status.get('stage_report_sha256') != report_sha256
            or status.get('stage_output') != config.get('stage_output')
            or not reviewed_validator_sigint(status.get('validator_cleanup'))
            or not reviewed_runner_exit(status.get('runner_cleanup'))
            or not isinstance(staged_identity, dict)
            or any(not isinstance(prepared_identity.get(key), str)
                   or not prepared_identity.get(key)
                   or staged_identity.get(key) != prepared_identity[key]
                   for key in identity_fields)):
        raise ValueError('stage status/config/report binding or prepare provenance mismatch')
    return config['ledger']


def transition_ledger(stage):
    """Derive the ledger from the pinned stage config and verify its status/report."""
    config = _json(stage['config'], stage['config_sha256'])
    status = _json(stage['status_path'], stage['status_sha256'])
    report = _json(stage['report'], stage['report_sha256'])
    if report.get('genesis') != config.get('expected_genesis'):
        raise ValueError('stage ledger/genesis differs from pinned prepare')
    return verified_stage_ledger(config, stage['config_sha256'], status,
                                 report, stage['report_sha256'])


def validate_runner_bundle(runner_path, runner_sha256, registry_bundle):
    """Require the executable role to be the queue test binary frozen in registry."""
    from tools.part5 import freeze_v3_heldout_cohort as freeze_tools

    expected_path = REPO / freeze_tools.RUNNER_BINARY
    if Path(runner_path) != expected_path:
        raise ValueError('runner must use the frozen heldout queue runner path')
    for item in registry_bundle:
        if type(item) is not dict or item.get('path') != freeze_tools.RUNNER_BINARY:
            continue
        artifact = item.get('artifact')
        if (type(artifact) is dict and artifact.get('path') == str(expected_path)
                and artifact.get('sha256') == runner_sha256):
            return
        break
    raise ValueError('runner identity missing from frozen registry bundle')


def _write_new(path, raw, mode=0o600):
    path = Path(path)
    if (not path.is_absolute() or path.parent.resolve(strict=True) != path.parent
            or path.exists() or path.is_symlink()):
        raise ValueError('fresh canonical output required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return digest(raw)


def _private_dir(path, *, fresh=False, ignored=False):
    path = Path(path)
    if fresh:
        if path.exists() or path.is_symlink():
            raise ValueError('fresh output directory required')
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('canonical owner0700 directory required')
    if ignored:
        from tools.part5 import generate_v3_heldout_keys as keygen
        if not keygen._ignored(path):
            raise ValueError('heldout output must be Git-ignored')
    return path


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def request_matrix():
    """Stable protocol roles; each request gets independent stage/source data."""
    return [
        {'name': 'positive_full', 'request_slot': 'A', 'proof_modes': ['full'],
         'branches': [{'name': 'full', 'clone': 'r0_full_clone', 'mode': 'execute'}]},
        {'name': 'unrelated_compare', 'request_slot': 'B', 'proof_modes': ['full', 'anchor'],
         'branches': [
             {'name': 'unrelated_full', 'clone': 'r1_full_clone', 'mode': 'full'},
             {'name': 'anchor', 'clone': 'r1_anchor_clone', 'mode': 'anchor'},
         ]},
        {'name': 'own_revocation', 'request_slot': 'C', 'proof_modes': ['anchor'],
         'branches': [{'name': 'own_revocation', 'clone': 'r1_own_clone',
                       'mode': 'own-revocation'}]},
    ]


def application_artifact_name(variant, run_id, request, label):
    if (type(variant) is not int or not 0 <= variant < 8
            or type(run_id) is not str or len(run_id) != 32
            or any(c not in HEX for c in run_id)
            or type(request) is not str or not request
            or type(label) is not str or not label
            or any(not (c.isascii() and (c.isalnum() or c in '-_'))
                   for c in request + label)):
        raise ValueError('canonical variant, run id, and output role required')
    return f'application-v3-heldout-{variant:02d}-{run_id}-{request}-{label}'


def acceptance_slot_bundles(requests, *, stage_bundle, transition_bundle,
                            source_bundle):
    """Build the verifier's shared A/B/C stage, transition, and source maps."""
    names = {'A': 'positive_full', 'B': 'unrelated_compare',
             'C': 'own_revocation'}
    if type(requests) is not dict or set(requests) != set(names.values()):
        raise ValueError('exact positive, unrelated, and own-revocation request slots required')
    stage, transition, sources = {}, {}, {}
    for slot, name in names.items():
        row = requests[name]
        stage[slot] = stage_bundle(row['stage'])
        transition[slot] = transition_bundle(row['transition'])
        sources[slot] = {'R0': source_bundle(row['r0_source']),
                         'R1': source_bundle(row['r1_source'])}
    return {'stage': stage, 'transition': transition, 'sources': sources}


def acceptance_branch_bundles(branches, *, result_bundle, proof_bundle,
                              clone_bundle):
    """Detach proof evidence from raw app results for the verifier contract."""
    expected = ('full', 'unrelated_full', 'anchor', 'own_revocation')
    if type(branches) is not dict or set(branches) != set(expected):
        raise ValueError('four heldout application branch results required')
    out = {}
    for name in expected:
        row = branches[name]
        effect = row['effect']
        clone_role = 'r0_clone' if name == 'full' else 'r1_clone'
        out[name] = {'result': result_bundle(effect),
                     'proof': proof_bundle(effect['proof'])}
        if name == 'full':
            out[name]['replay_proof'] = proof_bundle(effect['replay_proof'])
        if name == 'own_revocation':
            out[name]['current_r2_witness_rejection'] = effect[
                'current_r2_witness_rejection']
        clone = effect.get(clone_role, row.get('clone'))
        out[name][clone_role] = clone_bundle(clone)
    return out


def acceptance_wall_costs(steps):
    """Summarize per-outcome wall time and the shared slot setup time."""
    def elapsed(name):
        row = steps.get(name)
        if type(row) is not dict or type(row.get('wall_seconds')) not in (int, float):
            raise ValueError(f'completed journal wall time required for {name}')
        return float(row['wall_seconds'])

    components = {
        'full': {'proof_seconds': elapsed('positive_full:proof-full'),
                 'clone_seconds': elapsed('positive_full:r0-clone'),
                 'effect_seconds': elapsed('positive_full:execute')},
        'unrelated_full': {'proof_seconds': elapsed('unrelated_compare:proof-full'),
                 'clone_seconds': elapsed('unrelated_compare:unrelated_full:clone'),
                 'effect_seconds': elapsed('unrelated_compare:unrelated_full:effect')},
        'anchor': {'proof_seconds': elapsed('unrelated_compare:proof-anchor'),
                 'clone_seconds': elapsed('unrelated_compare:anchor:clone'),
                 'effect_seconds': elapsed('unrelated_compare:anchor:effect')},
        'own_revocation': {'proof_seconds': elapsed('own_revocation:proof-anchor'),
                 'clone_seconds': elapsed('own_revocation:r1-clone'),
                 'effect_seconds': elapsed('own_revocation:effect'),
                 'r2_active_witness_seconds': elapsed('own_revocation:r2-active-witness')},
    }
    for row in components.values():
        row['total_seconds'] = sum(row.values())
    shared = {
        'stage': {slot: elapsed(f'{request}:stage') for slot, request in
                  (('A', 'positive_full'), ('B', 'unrelated_compare'),
                   ('C', 'own_revocation'))},
        'transition': {slot: elapsed(f'{request}:transition') for slot, request in
                       (('A', 'positive_full'), ('B', 'unrelated_compare'),
                        ('C', 'own_revocation'))},
    }
    return {'branch_wall_components': components,
            'branch_wall_seconds': {name: row['total_seconds']
                                    for name, row in components.items()},
            'shared_stage_transition_wall_seconds': shared}


def disabled_config_negative_wall_seconds(steps):
    """Report the independent A-clone negative cost outside matched branches."""
    names = ('positive_full:disabled-config-clone',
             'positive_full:disabled-config-negative')
    total = 0.0
    for name in names:
        row = steps.get(name)
        wall = row.get('wall_seconds') if type(row) is dict else None
        if (type(row) is not dict or row.get('status') != 'passed'
                or type(wall) not in (int, float) or not math.isfinite(wall)
                or wall < 0):
            raise ValueError(f'completed disabled-config journal wall time required for {name}')
        total += float(wall)
    return total


def expired_status_negative_wall_seconds(steps):
    """Count the independent clone, loaded supervisor, and finalizer once each."""
    total = 0.0
    for name in EXPIRED_STATUS_STEP_NAMES:
        row = steps.get(name)
        wall = row.get('wall_seconds') if type(row) is dict else None
        if (type(row) is not dict or row.get('status') != 'passed'
                or type(wall) not in (int, float) or not math.isfinite(wall)
                or wall < 0):
            raise ValueError(f'completed expired-status journal wall time required for {name}')
        total += float(wall)
    return total


def ambiguous_restart_wall_seconds(steps):
    """Report the independent A-clone plus supervisor cost outside branch totals."""
    names = ('positive_full:ambiguous-restart-clone',
             'positive_full:ambiguous-restart')
    total = 0.0
    for name in names:
        row = steps.get(name)
        wall = row.get('wall_seconds') if type(row) is dict else None
        if (type(row) is not dict or row.get('status') != 'passed'
                or type(wall) not in (int, float) or not math.isfinite(wall)
                or wall < 0):
            raise ValueError(f'completed ambiguous-restart journal wall time required for {name}')
        total += float(wall)
    return total


def reviewed_ambiguous_restart_outer(outer, expected_owner):
    limits = outer.get('limits') if type(outer) is dict else None
    return (type(outer) is dict and outer.get('schema') == 1
        and outer.get('measurement') == 'bounded_complete_session'
        and outer.get('owner') == expected_owner and outer.get('passed') is True
        and outer.get('exit_code') == 0 and outer.get('stop_reason') is None
        and outer.get('runner_error_type') is None
        and outer.get('cleanup_remaining_owned_processes') == 0
        and outer.get('cleanup_status_unknown') is False
        and type(outer.get('duration_seconds')) in (int, float)
        and math.isfinite(outer.get('duration_seconds'))
        and outer.get('duration_seconds') > 0
        and type(outer.get('sample_count')) is int and outer.get('sample_count') > 0
        and limits == {'runtime_seconds': LIMITS['runtime_seconds'],
                       'owned_tree_rss_bytes': LIMITS['rss_bytes'],
                       'storage_growth_bytes': LIMITS['storage_growth_bytes'],
                       'poll_seconds': limits.get('poll_seconds') if type(limits) is dict else None}
        and type(limits.get('poll_seconds')) in (int, float)
        and math.isfinite(limits['poll_seconds']) and limits['poll_seconds'] > 0)


def all_step_wall_seconds(journal_doc):
    steps = journal_doc.get('steps')
    if type(steps) is not dict or not steps:
        raise ValueError('completed run journal steps required')
    costs = {}
    for name, row in steps.items():
        wall = row.get('wall_seconds') if type(row) is dict else None
        if (not name or type(row) is not dict or row.get('status') != 'passed'
                or type(wall) not in (int, float) or not math.isfinite(wall) or wall < 0):
            raise ValueError('every journal step must have a verified wall duration')
        costs[name] = float(wall)
    return costs


def _validate_observation_location(path, cohort_root):
    path, cohort_root = Path(path), Path(cohort_root)
    parent = path.parent
    try:
        parent_info = parent.lstat()
        file_info = path.lstat()
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or parent != cohort_root.parent
                or parent.resolve(strict=True) != parent
                or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != os.getuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700
                or not stat.S_ISREG(file_info.st_mode)
                or file_info.st_uid != os.getuid()
                or stat.S_IMODE(file_info.st_mode) != 0o600
                or file_info.st_nlink != 1):
            raise ValueError('private sibling observation required')
    except OSError as error:
        raise ValueError('private sibling observation required') from error


def validate_cohort_observation(manifest, freeze_doc, cohort_doc):
    reference = manifest.get('cohort_observation') if type(manifest) is dict else None
    if (type(reference) is not dict or set(reference) != {'path', 'sha256'}
            or not isinstance(reference.get('path'), str)
            or not _hash(reference.get('sha256'))):
        raise ValueError('pinned cohort observation reference required')
    try:
        _validate_observation_location(reference['path'], manifest.get('cohort_root'))
        observation = json.loads(_read(reference['path'], reference['sha256'], 65536))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ValueError('pinned cohort observation could not be read') from error
    required_fields = {
        'schema', 'freeze_sha256', 'prior_key_inventory_sha256',
        'wall_started_unix_ns', 'wall_completed_unix_ns',
        'monotonic_started_ns', 'monotonic_completed_ns', 'child_exit_code',
        'builder_source_sha256', 'observer_source_sha256', 'output_path_sha256',
        'cohort_receipt_sha256', 'preexisting_output', 'creation_time_basis',
        'openssl_invocation_observed',
    }
    if (type(freeze_doc) is not dict
            or freeze_doc.get('schema') != 'credential-v3-frozen-holdout-boundary-v1'
            or type(cohort_doc) is not dict
            or cohort_doc.get('schema') != 'credential-v3-heldout-issuance-cohort-v1'
            or type(manifest.get('cohort_root')) is not str
            or type(observation) is not dict or set(observation) != required_fields
            or observation.get('schema') != 'credential-v3-heldout-cohort-parent-observation-v1'
            or observation.get('freeze_sha256') != manifest.get('freeze_sha256')
            or observation.get('freeze_sha256') != cohort_doc.get('freeze_sha256')
            or observation.get('cohort_receipt_sha256') != manifest.get('cohort_sha256')
            or not _hash(observation.get('prior_key_inventory_sha256'))
            or observation.get('prior_key_inventory_sha256') != cohort_doc.get(
                'prior_key_inventory_sha256')
            or not _hash(observation.get('builder_source_sha256'))
            or not _hash(observation.get('observer_source_sha256'))
            or observation.get('output_path_sha256') != digest(
                str(Path(manifest.get('cohort_root'))).encode())
            or any(type(observation.get(field)) is not int or observation[field] <= 0
                   for field in ('wall_started_unix_ns', 'wall_completed_unix_ns',
                                 'monotonic_started_ns', 'monotonic_completed_ns'))
            or observation['wall_started_unix_ns'] > observation['wall_completed_unix_ns']
            or observation['monotonic_started_ns'] > observation['monotonic_completed_ns']
            or type(observation.get('child_exit_code')) is not int
            or observation.get('child_exit_code') != 0
            or observation.get('preexisting_output') is not False
            or observation.get('creation_time_basis') != 'observer_parent_started_child_after_freeze'
            or observation.get('openssl_invocation_observed') is not False):
        raise ValueError('cohort observation does not pin successful cohort output')
    return reference


def validate_manifest(manifest):
    if (type(manifest) is not dict or manifest.get('schema') != RUN_SCHEMA
            or type(manifest.get('variant')) is not int
            or not 0 <= manifest['variant'] < 8):
        raise ValueError('pinned heldout application run manifest required')
    for name in ('freeze_sha256', 'cohort_sha256', 'base_prepare_config_sha256',
                 'runner_sha256'):
        if not _hash(manifest.get(name)):
            raise ValueError(f'{name} pin required')
    freeze = Path(manifest['freeze_receipt'])
    cohort = Path(manifest['cohort_root']) / 'cohort-receipt.json'
    freeze_doc = json.loads(_read(freeze, manifest['freeze_sha256'], 65536))
    cohort_doc = json.loads(_read(cohort, manifest['cohort_sha256'], 65536))
    if (freeze_doc.get('schema') != 'credential-v3-frozen-holdout-boundary-v1'
            or cohort_doc.get('schema') != 'credential-v3-heldout-issuance-cohort-v1'
            or cohort_doc.get('freeze_sha256') != manifest['freeze_sha256']):
        raise ValueError('freeze receipt and issued cohort provenance mismatch')
    validate_cohort_observation(manifest, freeze_doc, cohort_doc)
    template = Path(manifest['base_prepare_config'])
    base = json.loads(_read(template, manifest['base_prepare_config_sha256'], 65536))
    if (base.get('schema') != 1 or base.get('scope') != 'part5-v3-local-prepare'
            or base.get('outer_limits_required') != LIMITS):
        raise ValueError('pinned local prepare template required')
    prepare_keys = {'schema', 'scope', 'build_plan', 'build_plan_sha256',
                    'elf', 'elf_sha256', 'validator', 'validator_sha256',
                    'program', 'mint', 'runtime_output', 'control_output',
                    'outer_limits_required'}
    if set(base) != prepare_keys:
        raise ValueError('local prepare template has unexpected configuration fields')
    runner = Path(manifest['runner'])
    _read(runner, manifest['runner_sha256'], 128 * 1024 * 1024, executable=True)
    roles = manifest.get('frozen_files')
    identities = freeze_doc.get('identities')
    if type(roles) is not dict or type(identities) is not dict:
        raise ValueError('frozen direct-role map required')
    if set(roles) != set(ROLE_NAMES):
        raise ValueError('all nine frozen direct roles are required')
    for role in ROLE_NAMES:
        ref = roles[role]
        if (type(ref) is not dict or not _hash(ref.get('sha256'))
                or identities.get(role) != ref['sha256']):
            raise ValueError('frozen identity and direct-role pins differ')
        if (role in FROZEN_PATHS and role != 'proof_runner'
                and Path(ref['path']) != REPO / FROZEN_PATHS[role]):
            raise ValueError(f'{role} must use its frozen product path')
        _read(ref['path'], ref['sha256'],
              FROZEN_ROLE_CAPS.get(role, 128 * 1024 * 1024))
    if (not isinstance(base.get('build_plan'), str)
            or not _hash(base.get('build_plan_sha256'))
            or not isinstance(base.get('elf'), str)
            or not _hash(base.get('elf_sha256'))
            or not isinstance(base.get('validator'), str)
            or not _hash(base.get('validator_sha256'))
            or not isinstance(base.get('program'), str) or not base['program']
            or not isinstance(base.get('mint'), str) or not base['mint']):
        raise ValueError('build, ELF, validator, program, and mint pins required')
    _read(base['build_plan'], base['build_plan_sha256'], 1024 * 1024)
    _read(base['validator'], base['validator_sha256'], 128 * 1024 * 1024)
    if (base['elf'] != roles['loaded_elf']['path']
            or base['elf_sha256'] != roles['loaded_elf']['sha256']):
        raise ValueError('prepare template ELF differs from frozen loaded program')
    proof_inputs = manifest.get('proof_inputs')
    proof_roles = ('packet_template', 'witness_js', 'relation_checker', 'node',
                   'proof_runner', 'adapter_binary', 'bounded_supervisor', 'exporter')
    if type(proof_inputs) is not dict or set(proof_inputs) != set(proof_roles):
        raise ValueError('complete frozen proof/helper input map required')
    for role in proof_roles:
        ref = proof_inputs[role]
        if type(ref) is not dict or not _hash(ref.get('sha256')):
            raise ValueError('proof input path and SHA-256 required')
        _read(ref['path'], ref['sha256'], 128 * 1024 * 1024)
    proof_caps = manifest.get('proof_caps')
    if (type(proof_caps) is not dict
            or proof_caps.get('full') != {'runtime_seconds': 1800, 'rss_bytes': 4294967296,
                                         'storage_bytes': 536870912}
            or proof_caps.get('anchor') != {'runtime_seconds': 3600, 'rss_bytes': 4294967296,
                                           'storage_bytes': 536870912}):
        raise ValueError('explicit pinned per-mode Full/Anchor proof caps required')
    # The request driver accepts the freeze-time source-manifest artifact and
    # confirms its exact canonical document hash before any local job starts.
    source = manifest.get('application_source_manifest')
    if type(source) is not dict or not _hash(source.get('sha256')):
        raise ValueError('frozen application source manifest pin required')
    source_doc = json.loads(_read(source['path'], source['sha256'], 1024 * 1024))
    if digest(json.dumps(source_doc, sort_keys=True).encode()) != identities.get('application_source'):
        raise ValueError('application source manifest differs from freeze identity')
    source_pins = source_doc.get('source_pins') if type(source_doc) is dict else None
    if type(source_pins) is not dict or not source_pins:
        raise ValueError('application source file inventory required')
    for relative, expected in source_pins.items():
        rel = Path(relative)
        if (type(relative) is not str or not relative or rel.is_absolute()
                or '..' in rel.parts or not _hash(expected)):
            raise ValueError('safe relative application source pin required')
        _read(REPO / rel, expected, 128 * 1024 * 1024)
    app_files = manifest.get('application_source_files')
    if type(app_files) is not dict or set(app_files) != set(source_pins):
        raise ValueError('complete frozen application source file references required')
    for relative, expected in source_pins.items():
        ref = app_files[relative]
        if (type(ref) is not dict or ref.get('path') != str(REPO / relative)
                or ref.get('sha256') != expected):
            raise ValueError('application source file references differ from source manifest')
    bundles = manifest.get('frozen_bundles')
    if type(bundles) is not dict or set(bundles) != {'registry', 'client'}:
        raise ValueError('frozen registry and client bundle references required')
    if not _hash(identities.get('registry')) or not _hash(identities.get('client')):
        raise ValueError('registry/client freeze identities required')
    from tools.part5 import freeze_v3_heldout_cohort as freeze_tools
    bundle_roles = {'registry': freeze_tools.REGISTRY_FILES,
                    'client': freeze_tools.CLIENT_FILES}
    for role in ('registry', 'client'):
        if type(bundles[role]) is not list or not bundles[role]:
            raise ValueError('ordered frozen bundle file references required')
        expected_paths = sorted(bundle_roles[role])
        if [item.get('path') for item in bundles[role]] != expected_paths:
            raise ValueError('frozen source bundle membership/order differs')
        hashing = hashlib.sha256(b'part5-v3-campaign-identity-bundle-v1\0')
        for item in bundles[role]:
            if (type(item) is not dict or not isinstance(item.get('path'), str)
                    or not item['path'] or type(item.get('artifact')) is not dict
                    or not _hash(item['artifact'].get('sha256'))):
                raise ValueError('repo-relative bundled artifact reference required')
            expected_path = (REPO / item['path']).resolve(strict=True)
            artifact_path = Path(item['artifact']['path'])
            raw = _read(artifact_path, item['artifact']['sha256'], 128 * 1024 * 1024)
            if artifact_path != expected_path:
                raise ValueError('bundle artifact path differs from frozen repository member')
            path_bytes = item['path'].encode()
            hashing.update(len(path_bytes).to_bytes(4, 'big'))
            hashing.update(path_bytes)
            hashing.update(len(raw).to_bytes(8, 'big'))
            hashing.update(raw)
        if hashing.hexdigest() != identities[role]:
            raise ValueError('current registry/client bundle differs from freeze')
    validate_runner_bundle(manifest['runner'], manifest['runner_sha256'], bundles['registry'])
    client_refs = {item['path']: item['artifact'] for item in bundles['client']}
    source_files = manifest.get('source_files')
    if type(source_files) is not dict or set(source_files) != set(SOURCE_FILE_ROLES):
        raise ValueError('four heldout source/tool pins required')
    for role in SOURCE_FILE_ROLES:
        ref = source_files[role]
        if type(ref) is not dict or not _hash(ref.get('sha256')):
            raise ValueError('heldout tool path and SHA-256 required')
        expected_path = (REPO / SOURCE_PATHS[role]).resolve(strict=True) if role in SOURCE_PATHS else None
        if expected_path is not None and Path(ref['path']) != expected_path:
            raise ValueError(f'{role} must use its live repository path')
        _read(ref['path'], ref['sha256'], 128 * 1024 * 1024)
        bundled = client_refs.get(SOURCE_PATHS[role])
        if bundled is None or bundled['sha256'] != ref['sha256']:
            raise ValueError(f'{role} differs from frozen client source bundle')
    if source_files['request_fixture_bridge']['sha256'] != roles['signer_interface']['sha256']:
        raise ValueError('request fixture bridge differs from frozen signer interface')
    validate_proof_runner_reference(
        roles['proof_runner'], proof_inputs['proof_runner'], identities['proof_runner'])
    if (Path(source_files['exporter']['path']) != Path(proof_inputs['exporter']['path'])
            or source_files['exporter']['sha256'] != proof_inputs['exporter']['sha256']
            or proof_inputs['adapter_binary']['sha256'] != roles['ordinary_adapter']['sha256']
            or proof_inputs['proof_runner']['sha256'] != roles['proof_runner']['sha256']):
        raise ValueError('request exporter and frozen proof/adapter identities differ')
    client_by_path = {item['path']: item['artifact'] for item in bundles['client']}
    bounded_ref = client_by_path.get('results/dynark/part5/session_runner.py')
    if (bounded_ref is None
            or proof_inputs['bounded_supervisor']['sha256'] != bounded_ref['sha256']):
        raise ValueError('bounded supervisor differs from frozen client source')
    from harness.tests import queue_v3_build_prep as build_prep
    current_source = build_prep.source_manifest(REPO)
    current_source_sha = digest(json.dumps(current_source, sort_keys=True).encode())
    if current_source_sha != identities.get('application_source') or current_source != source_doc:
        raise ValueError('current application source inventory differs from freeze')
    return base, cohort_doc, freeze_doc


class RunJournal:
    """Atomic resumable journal; a flock serializes cooperating invocations."""
    def __init__(self, path, manifest_sha256):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + '.lock')
        self.manifest_sha256 = manifest_sha256
        self.active = False

    def _read(self):
        if not self.path.exists():
            return {'schema': JOURNAL_SCHEMA, 'manifest_sha256': self.manifest_sha256,
                    'steps': {}, 'costs': {'shared_stage_seconds': 0.0,
                                           'shared_transition_seconds': 0.0}}
        value = json.loads(_read(self.path, cap=4 * 1024 * 1024))
        if value.get('schema') != JOURNAL_SCHEMA or value.get('manifest_sha256') != self.manifest_sha256:
            raise ValueError('journal belongs to another manifest')
        return value

    def _save(self, value):
        raw = encoded(value)
        temp = self.path.with_name(self.path.name + '.new')
        if temp.exists():
            temp.unlink()
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, self.path)

    def run_step(self, name, *, inputs, job, reuse=None, category=None):
        if not self.active:
            raise RuntimeError('journal lock must be held for every step')
        document = self._read()
        prior = document['steps'].get(name)
        failed_attempt_wall_seconds = []
        started_monotonic = time.monotonic()
        started_unix_ns = time.time_ns()
        if prior is not None:
            if prior.get('inputs') != inputs:
                raise ValueError(f'resumable step {name} inputs changed')
            if (prior.get('status') == 'failed'
                    and 'failed_attempt_wall_seconds' not in prior):
                raise ValueError(f'resumable step {name} has an unmeasured prior failed attempt')
            failed_attempt_wall_seconds = prior.get('failed_attempt_wall_seconds', [])
            if (type(failed_attempt_wall_seconds) is not list
                    or any(type(value) not in (int, float) or not math.isfinite(value)
                           or value < 0 for value in failed_attempt_wall_seconds)
                    or (prior.get('failed_attempt_count') is not None
                        and prior['failed_attempt_count'] != len(failed_attempt_wall_seconds))):
                raise ValueError(f'resumable step {name} failed-attempt timing is invalid')
            if prior.get('status') == 'passed':
                if reuse is None or not reuse(prior):
                    raise ValueError(f'resumable step {name} evidence no longer verifies')
                return prior
            if prior.get('status') == 'running':
                # The gap until restart may include idle time after a crash.
                raise ValueError(f'resumable step {name} interrupted attempt has unknown work time')
            if prior.get('status') != 'failed':
                raise ValueError(f'resumable step {name} has unknown prior status')
        row = {'status': 'running', 'inputs': inputs,
               'started_monotonic': started_monotonic,
               'started_unix_ns': started_unix_ns,
               'failed_attempt_wall_seconds': list(failed_attempt_wall_seconds),
               'failed_attempt_count': len(failed_attempt_wall_seconds)}
        document['steps'][name] = row
        self._save(document)
        began = time.monotonic()
        try:
            result = job()
            if type(result) is not dict or result.get('status') != 'passed':
                raise RuntimeError(f'step {name} did not return verified success')
            measured_wall = result.get('wall_seconds')
            row.update(result)
            row['status'] = 'passed'
        except BaseException as error:
            failed_attempt_wall_seconds.append(time.monotonic() - began)
            row.update({'status': 'failed', 'error_type': type(error).__name__,
                        'failed_attempt_wall_seconds': failed_attempt_wall_seconds,
                        'failed_attempt_count': len(failed_attempt_wall_seconds)})
            self._save(document)
            raise
        elapsed = time.monotonic() - began
        if failed_attempt_wall_seconds:
            # Charge measured failed/interrupted calls and this recovery call.
            # Do not add supervisor timings from recovered artifacts again.
            elapsed += sum(failed_attempt_wall_seconds)
        elif (type(measured_wall) in (int, float) and math.isfinite(measured_wall)
                and measured_wall >= 0):
            # On an uninterrupted call, retain the larger helper-level timing.
            elapsed = max(elapsed, float(measured_wall))
        row['wall_seconds'] = elapsed
        row['completed_monotonic'] = time.monotonic()
        if category in ('stage', 'transition'):
            key = 'shared_' + category + '_seconds'
            document['costs'][key] += row['wall_seconds']
        self._save(document)
        return row

    def __enter__(self):
        fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.lock_fd = fd
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.active = True
        return self

    def __exit__(self, *_):
        self.active = False
        fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        os.close(self.lock_fd)


class HeldoutCaseRunner:
    """Per-certificate driver; job injection exists only for focused unit tests."""
    def __init__(self, manifest, output_root, *, run_manifest_ref,
                 manifest_sha256, bounded_run=None):
        self.manifest = manifest
        if (type(run_manifest_ref) is not dict
                or set(run_manifest_ref) != {'path', 'sha256'}
                or not Path(run_manifest_ref['path']).is_absolute()
                or not _hash(run_manifest_ref['sha256'])
                or manifest_sha256 != digest(encoded(manifest))):
            raise ValueError('pinned run manifest identity required')
        self.run_manifest_ref = run_manifest_ref
        self.manifest_sha256 = manifest_sha256
        self.base_prepare, self.cohort_doc, self.freeze_doc = validate_manifest(manifest)
        output_root = Path(output_root)
        fresh_root = not output_root.exists()
        if output_root.exists():
            self.output_root = _private_dir(output_root, ignored=True)
        else:
            self.output_root = _private_dir(output_root, fresh=True, ignored=True)
        fragment_path = self.output_root / 'acceptance-case-fragment.json'
        if fragment_path.exists():
            existing_fragment = _json(fragment_path, cap=4 * 1024 * 1024)
            if existing_fragment.get('schema') != CASE_FRAGMENT_SCHEMA:
                raise ValueError('prior fragment schema requires a fresh case root')
        self.variant = manifest['variant']
        run_id_path = self.output_root / 'run-id.json'
        journal_path = self.output_root / 'run-journal.json'
        if run_id_path.exists():
            run_doc = _json(run_id_path, cap=1024)
            run_id = run_doc.get('run_id') if type(run_doc) is dict else None
            if (run_doc.get('schema') != 'credential-v3-heldout-run-id-v1'
                    or type(run_id) is not str or len(run_id) != 32
                    or any(c not in HEX for c in run_id)):
                raise ValueError('canonical persisted run id required')
            if not journal_path.exists() and any(
                    item.name != run_id_path.name for item in self.output_root.iterdir()):
                raise ValueError('nonempty output root without journal requires review')
        else:
            if any(self.output_root.iterdir()):
                raise ValueError('fresh or resumable owner-only output root required')
            run_id = uuid.uuid4().hex
            _write_new(run_id_path, encoded({'schema': 'credential-v3-heldout-run-id-v1',
                                             'run_id': run_id}))
        self.run_id = run_id
        self.bounded_run = bounded_run or self._bounded_run
        self.journal = RunJournal(journal_path,
                                  self.manifest_sha256)
        self._active_job = False
        self.toolpaths = {
            'prepare': REPO / 'harness/tests/queue_v3_local_prepare.py',
            'stage': REPO / 'harness/tests/queue_v3_local_stage.py',
            'transition': REPO / 'harness/tests/queue_v3_local_transition.py',
            'execute': REPO / 'harness/tests/queue_v3_local_execute.py',
            'branch': REPO / 'harness/tests/queue_v3_local_branch.py',
            'r0_clone': REPO / 'harness/tests/queue_v3_clone_heldout_r0.py',
            'r1_clone': REPO / 'harness/tests/queue_v3_clone_ledger.py',
            'disabled_config_negative': REPO / 'harness/tests/queue_v3_local_disabled_config_negative.py',
            'ambiguous_restart': REPO / AMBIGUOUS_RESTART_SUPERVISOR,
            'expired_status_negative': REPO / 'harness/tests/queue_v3_local_expired_status_negative.py',
        }

    def _bounded_run(self, owner, command, output, report, *, runtime, storage_paths=(), env=None):
        if self._active_job:
            raise RuntimeError('only one bounded child may run at a time')
        self._active_job = True
        try:
            monitor = _load_module('heldout_session_runner', REPO / 'results/dynark/part5/session_runner.py')
            return monitor.run(owner=owner, command=command, cwd=str(REPO),
                               private_output=str(output), report=str(report),
                               runtime_seconds=runtime, rss_bytes=LIMITS['rss_bytes'],
                               storage_bytes=LIMITS['storage_growth_bytes'],
                               storage_paths=[str(p) for p in storage_paths],
                               environment=env or {})
        finally:
            self._active_job = False

    def _layout(self, request):
        base = self.output_root / request
        if not base.exists():
            base.mkdir(mode=0o700)
        else:
            _private_dir(base)
        return base

    def _art(self, request, label):
        path = ARTIFACTS / application_artifact_name(
            self.variant, self.run_id, request, label)
        if path.is_symlink():
            raise ValueError('application output cannot be a symlink')
        if path.parent != ARTIFACTS or not path.name.startswith('application-v3-'):
            raise ValueError('application outputs must be fresh direct artifact children')
        return str(path)

    def _write_config(self, path, value):
        raw = encoded(value)
        path = Path(path)
        if path.exists():
            if _read(path) != raw:
                raise ValueError('existing configuration differs from pinned inputs')
            return digest(raw)
        return _write_new(path, raw)

    @staticmethod
    def _verify_record(record, path_fields=(), hash_fields=()):
        try:
            for field in path_fields:
                path = Path(record[field])
                if not path.is_file():
                    return False
                expected = record.get(field + '_sha256')
                if expected is None and field.endswith('_path'):
                    expected = record.get(field.removesuffix('_path') + '_sha256')
                if expected is not None and digest(_read(path)) != expected:
                    return False
            for field in hash_fields:
                if not _hash(record.get(field)):
                    return False
                # A matching path field is required for receipt identities.
                path_field = field.removesuffix('_sha256')
                if path_field + '_path' in record:
                    path_field += '_path'
                if path_field in record and digest(_read(record[path_field])) != record[field]:
                    return False
            return True
        except (OSError, ValueError, KeyError, TypeError):
            return False

    @staticmethod
    def _recovered_control(control, output, status_name, report_name, expected_scope,
                           expected_report_schema):
        status_path = Path(control) / status_name
        report_path = Path(output) / report_name
        if not status_path.exists() or not report_path.exists():
            raise ValueError('incomplete prior supervisor output requires manual review')
        status, report = _json(status_path), _json(report_path)
        if status.get('scope') != expected_scope or report.get('schema') != expected_report_schema:
            raise ValueError('prior supervisor output does not match this request')
        return status_path, report_path, status, report

    def _prepare(self, req, root, case_root, stage_context):
        runtime, control = self._art(req, 'runtime'), self._art(req, 'prepare-control')
        config_path = root / 'prepare-config.json'
        config = dict(self.base_prepare)
        config.update(runtime_output=runtime, control_output=control)
        config_sha = self._write_config(config_path, config)
        status_path = Path(control) / 'status.json'
        monitor_dir, monitor_path = root / 'prepare-monitor', root / 'prepare-monitor.json'
        owner = f'heldout-v{self.variant:02d}-{req}-prepare'
        if status_path.exists() and monitor_path.exists():
            outer = _json(monitor_path)
            status = _json(status_path)
        elif Path(control).exists() or Path(runtime).exists() or monitor_dir.exists() or monitor_path.exists():
            raise ValueError('partial prior prepare output requires manual review')
        else:
            outer = self.bounded_run(owner, [sys.executable, str(self.toolpaths['prepare']),
                '--config', str(config_path), '--config-sha256', config_sha], monitor_dir, monitor_path,
                runtime=LIMITS['runtime_seconds'], storage_paths=(Path(runtime),),
                env={'P5_V3_PREPARE_SCOPE': 'local-validator-prepare'})
            status = _json(status_path)
        if (not reviewed_application_outer(outer)
                or status.get('scope') != 'part5-v3-local-prepare'
                or status.get('status') != 'failed' or status.get('error_type') is not None
                or status.get('loaded_program', {}).get('elf_match') is not True
                or not reviewed_validator_sigint(status.get('cleanup'))):
            raise ValueError('fresh prepare and reviewed SIGINT evidence required')
        return {'config': str(config_path), 'config_sha256': config_sha,
                **status_artifact(status_path),
                'monitor': str(monitor_path), 'monitor_sha256': digest(_read(monitor_path)),
                'monitor_owner': owner, 'runtime': runtime, 'control': control}

    def _stage(self, req, root, case_root, stage_context, prepared):
        stage_output, control = self._art(req, 'stage'), self._art(req, 'stage-control')
        config_path = root / 'stage-config.json'
        config = {'schema': 1, 'scope': 'part5-v3-local-stage',
            'prior_config': str(prepared['config']), 'prior_config_sha256': prepared['config_sha256'],
            'prior_status': prepared['status_path'], 'prior_status_sha256': prepared['status_sha256'],
            'prior_monitor': str(prepared['monitor']), 'prior_monitor_sha256': prepared['monitor_sha256'],
            'prior_monitor_owner': prepared['monitor_owner'],
            'expected_genesis': _json(prepared['status_path'])['loaded_program']['genesis'],
            'ledger': str(Path(prepared['runtime']) / 'ledger'),
            'context': str(case_root / 'stage-context.json'),
            'context_sha256': digest(_read(case_root / 'stage-context.json')),
            'runner': self.manifest['runner'], 'runner_sha256': self.manifest['runner_sha256'],
            'stage_output': stage_output, 'control_output': control,
            'outer_limits_required': LIMITS}
        config_sha = self._write_config(config_path, config)
        monitor_dir, monitor_path = root / 'stage-monitor', root / 'stage-monitor.json'
        owner = f'heldout-v{self.variant:02d}-{req}-stage'
        status_path, report_path = Path(control) / 'status.json', Path(stage_output) / 'stage-report.json'
        if status_path.exists() and report_path.exists() and monitor_path.exists():
            outer = _json(monitor_path)
            status, report = _json(status_path), _json(report_path)
        elif Path(control).exists() or Path(stage_output).exists() or monitor_dir.exists() or monitor_path.exists():
            raise ValueError('partial prior stage output requires manual review')
        else:
            outer = self.bounded_run(owner, [sys.executable, str(self.toolpaths['stage']),
                '--config', str(config_path), '--config-sha256', config_sha], monitor_dir, monitor_path,
                runtime=LIMITS['runtime_seconds'], storage_paths=(Path(stage_output),),
                env={'P5_V3_STAGE_SUPERVISOR': 'local-ledger-review-and-stage'})
            status, report = _json(status_path), _json(report_path)
        report_sha = digest(_read(report_path))
        verified_stage_ledger(config, config_sha, status, report, report_sha)
        if (not reviewed_application_outer(outer)
                or status.get('stage_verified') is not True or status.get('error_type') is not None
                or not reviewed_validator_sigint(status.get('validator_cleanup'))
                or not reviewed_runner_exit(status.get('runner_cleanup'))
                or report.get('schema') != 'part5-v3-local-stage-v1' or report.get('passed') is not True):
            raise ValueError('verified finalized stage and reviewed SIGINT evidence required')
        return {'config': str(config_path), 'config_sha256': config_sha,
                **status_artifact(status_path),
                'monitor': str(monitor_path), 'monitor_sha256': digest(_read(monitor_path)),
                'monitor_owner': owner, 'root': stage_output,
                'report': str(report_path), 'report_sha256': digest(_read(report_path)),
                'plan': str(Path(stage_output) / 'plan.json'),
                'plan_sha256': digest(_read(Path(stage_output) / 'plan.json')),
                'control': control, 'wall_seconds': outer['duration_seconds']}

    def _transition(self, req, root, case_root, stage):
        context_path = root / 'transition-context.json'
        context_builder = _load_module('heldout_context', REPO / 'tools/part5/prepare_v3_heldout_context.py')
        if context_path.exists():
            recheck = root / ('transition-context-recheck-' + uuid.uuid4().hex + '.json')
            receipt_recheck = context_builder.prepare_transition(case_root, stage['root'], recheck)
            same = _read(recheck) == _read(context_path)
            recheck.unlink()
            if not same:
                raise ValueError('saved transition context differs from recomputed stage binding')
            context_receipt = dict(receipt_recheck)
            context_receipt['transition_context_sha256'] = digest(_read(context_path))
        else:
            context_receipt = context_builder.prepare_transition(case_root, stage['root'], context_path)
        output, control = self._art(req, 'transition'), self._art(req, 'transition-control')
        config_path = root / 'transition-config.json'
        ledger = transition_ledger(stage)
        config = {'schema': 1, 'scope': 'part5-v3-local-unrelated-transition',
            'prior_stage_config': str(stage['config']), 'prior_stage_config_sha256': stage['config_sha256'],
            'prior_stage_status': stage['status_path'], 'prior_stage_status_sha256': stage['status_sha256'],
            'prior_stage_monitor': str(stage['monitor']), 'prior_stage_monitor_sha256': stage['monitor_sha256'],
            'prior_monitor_owner': stage['monitor_owner'], 'stage_root': stage['root'],
            'stage_report_sha256': stage['report_sha256'], 'stage_plan_sha256': stage['plan_sha256'],
            'cohort_root': str(case_root), 'expected_genesis': _json(stage['report'])['genesis'],
            'transition_context': str(context_path),
            'transition_context_sha256': context_receipt['transition_context_sha256'],
            'ledger': ledger, 'runner': self.manifest['runner'],
            'runner_sha256': self.manifest['runner_sha256'], 'transition_output': output,
            'control_output': control, 'outer_limits_required': LIMITS}
        config_sha = self._write_config(config_path, config)
        monitor_dir, monitor_path = root / 'transition-monitor', root / 'transition-monitor.json'
        owner = f'heldout-v{self.variant:02d}-{req}-transition'
        status_path = Path(control) / 'status.json'
        report_path = Path(output) / 'transition-report.json'
        if status_path.exists() and report_path.exists() and monitor_path.exists():
            outer = _json(monitor_path)
            status, report = _json(status_path), _json(report_path)
        elif Path(control).exists() or Path(output).exists() or monitor_dir.exists() or monitor_path.exists():
            raise ValueError('partial prior transition output requires manual review')
        else:
            outer = self.bounded_run(owner, [sys.executable, str(self.toolpaths['transition']),
                '--config', str(config_path), '--config-sha256', config_sha], monitor_dir, monitor_path,
                runtime=LIMITS['runtime_seconds'], storage_paths=(Path(output),),
                env={'P5_V3_TRANSITION_SUPERVISOR': 'local-ledger-review-and-transition'})
            status, report = _json(status_path), _json(report_path)
        if (not reviewed_application_outer(outer)
                or status.get('transition_verified') is not True or status.get('error_type') is not None
                or status.get('status') != 'failed'
                or not reviewed_validator_sigint(status.get('validator_cleanup'))
                or not reviewed_runner_exit(status.get('runner_cleanup'))
                or report.get('schema') != 'part5-v3-unrelated-local-transition-v1'
                or report.get('passed') is not True or report.get('request_unconsumed') is not True):
            raise ValueError('verified unrelated R1 transition and reviewed stop evidence required')
        return {'config': str(config_path), 'config_sha256': config_sha,
                'context': str(context_path), 'context_sha256': context_receipt['transition_context_sha256'],
                'context_receipt': context_receipt, **status_artifact(status_path),
                'monitor': str(monitor_path),
                'monitor_sha256': digest(_read(monitor_path)), 'monitor_owner': owner,
                'root': output, 'report': str(report_path), 'report_sha256': digest(_read(report_path)),
                'control': control, 'wall_seconds': outer['duration_seconds']}

    def _proof(self, req, mode, root, case_root, stage, transition, r0_source, r1_source,
               *, label=None):
        from tools.part5 import prepare_v3_heldout_proof as proof_tool
        output = root / ('proof-' + mode + (('-' + label) if label else ''))
        receipt_path = output / 'proof-receipt.json'
        if receipt_path.exists():
            receipt = _json(receipt_path)
            if (receipt.get('schema') != 'credential-v3-heldout-proof-evidence-v1'
                    or receipt.get('case') != f'heldout_v{self.variant:02d}_{req}'
                    or receipt.get('mode') != mode
                    or receipt.get('stage_report_sha256') != stage['report_sha256']
                    or receipt.get('transition_report_sha256') != transition['report_sha256']
                    or receipt.get('source_receipts', {}).get('R0', {}).get('sha256')
                        != r0_source['receipt_sha256']
                    or receipt.get('source_receipts', {}).get('R1', {}).get('sha256')
                        != r1_source['receipt_sha256']):
                raise ValueError('saved proof receipt belongs to another request/source')
            for ref in receipt.get('artifacts', {}).values():
                _read(ref['path'], ref['sha256'], 32 * 1024 * 1024)
            for ref in receipt.get('wires', {}).values():
                _read(ref['path'], ref['sha256'], 1024)
            return {'status': 'passed', 'root': str(output), 'receipt': str(receipt_path),
                'receipt_sha256': digest(_read(receipt_path)), 'wires': receipt['wires'],
                'proof_report': receipt['proof_report'], 'artifacts': receipt['artifacts'],
                'mode': mode, 'wall_seconds': self._proof_wall_seconds(receipt)}
        if not output.exists():
            output.mkdir(mode=0o700)
        proof = self.manifest['proof_inputs']
        frozen = self.manifest['frozen_files']
        args = {
            'case_name': f'heldout_v{self.variant:02d}_{req}',
            'r0_source_root': r0_source['root'],
            'r0_source_sha256': r0_source['receipt_sha256'],
            'r1_source_root': r1_source['root'],
            'r1_source_sha256': r1_source['receipt_sha256'],
            'freeze_receipt': self.manifest['freeze_receipt'],
            'freeze_sha256': self.manifest['freeze_sha256'],
            'stage_root': stage['root'], 'transition_root': transition['root'],
            'packet_template': proof['packet_template']['path'],
            'packet_template_sha256': proof['packet_template']['sha256'],
            'setup_manifest': frozen['setup_manifest']['path'],
            'ordinary_vk': frozen['ordinary_vk']['path'],
            'witness_js': proof['witness_js']['path'],
            'relation_checker': proof['relation_checker']['path'],
            'node': proof['node']['path'],
            'node_sha256': proof['node']['sha256'],
            'proof_runner': proof['proof_runner']['path'],
            'adapter_binary': proof['adapter_binary']['path'],
            'bounded_supervisor': proof['bounded_supervisor']['path'],
            'bounded_supervisor_sha256': proof['bounded_supervisor']['sha256'],
            'mode': mode, 'output': output,
        }
        # This API owns its fixed bounded witness/proof/adapter jobs and runs
        # synchronously under the case journal lock. No command text comes from
        # the caller; executable paths are frozen manifest roles.
        receipt = proof_tool.prepare(**args)
        if (receipt.get('schema') != 'credential-v3-heldout-proof-evidence-v1'
                or receipt.get('proof_created') is not True
                or receipt.get('application_verified') is not False
                or receipt.get('validator_run') is not False
                or receipt.get('action_hash') != _json(Path(r0_source['receipt']))['action_hash']
                or receipt.get('stage_report_sha256') != stage['report_sha256']
                or receipt.get('transition_report_sha256') != transition['report_sha256']):
            raise ValueError('pinned heldout proof receipt does not bind this request/transition')
        wires = receipt.get('wires')
        if type(wires) is not dict or set(wires) != {'r0_full_wire', 'r1_wire'}:
            raise ValueError('proof helper did not return both R0/R1 wire pins')
        for ref in wires.values():
            _read(ref['path'], ref['sha256'], 1024)
        return {'status': 'passed', 'root': str(output), 'receipt': str(receipt_path),
                'receipt_sha256': digest(_read(receipt_path)), 'wires': wires,
                'proof_report': receipt['proof_report'], 'artifacts': receipt['artifacts'],
                'mode': mode, 'wall_seconds': self._proof_wall_seconds(receipt)}

    @staticmethod
    def _proof_wall_seconds(receipt):
        reports = receipt.get('supervisor_reports')
        if type(reports) is not dict or not reports:
            raise ValueError('proof helper supervisor timing receipts required')
        total = 0.0
        for row in reports.values():
            report = _json(row['path'], row['sha256'], 1024 * 1024)
            duration = report.get('duration_seconds')
            if type(duration) not in (int, float) or not math.isfinite(duration) or duration < 0:
                raise ValueError('proof stage supervisor duration required')
            total += float(duration)
        return total

    @staticmethod
    def _artifact(path):
        path = Path(path)
        return {'path': str(path), 'sha256': digest(_read(path))}

    def _clone_r0(self, request, root, stage, *, label='r0'):
        clone_root = root / (label + '-clone')
        if not clone_root.exists():
            clone_root.mkdir(mode=0o700)
        destination = clone_root / 'ledger'
        receipt_path = clone_root / 'clone-report.json'
        if receipt_path.exists():
            receipt = _json(receipt_path)
            if (receipt.get('schema') != 'part5-v3-heldout-r0-ledger-clone-v1'
                    or receipt.get('stage_report_sha256') != stage['report_sha256']):
                raise ValueError('existing R0 clone receipt is not this request')
            return {'root': str(clone_root), 'ledger': str(destination),
                    'receipt': str(receipt_path), 'receipt_sha256': digest(_read(receipt_path)),
                    'label': label,
                    'monitor': str(root / (label + '-clone-monitor.json')),
                    'monitor_sha256': digest(_read(root / (label + '-clone-monitor.json'))),
                    'monitor_owner': f'heldout-v{self.variant:02d}-{request}-clone-{label}',
                    'wall_seconds': _json(root / (label + '-clone-monitor.json'))['duration_seconds']}
        command = [sys.executable, str(self.toolpaths['r0_clone']),
            '--stage-config', stage['config'], '--config-sha', stage['config_sha256'],
            '--stage-report', stage['report'], '--report-sha', stage['report_sha256'],
            '--stage-status', stage['status_path'], '--status-sha', stage['status_sha256'],
            '--stage-monitor', stage['monitor'], '--monitor-sha', stage['monitor_sha256'],
            '--monitor-owner', stage['monitor_owner'], '--destination', str(destination)]
        monitor_dir = root / (label + '-clone-monitor')
        monitor_path = root / (label + '-clone-monitor.json')
        owner = f'heldout-v{self.variant:02d}-{request}-clone-{label}'
        outer = self.bounded_run(owner, command, monitor_dir, monitor_path,
            runtime=LIMITS['runtime_seconds'], storage_paths=(clone_root,))
        receipt = _json(receipt_path)
        if (outer.get('passed') is not True or receipt.get('copy_identical') is not True
                or receipt.get('loaded_identity_rechecked_after_restart') is not False):
            raise ValueError('bounded heldout R0 clone failed review')
        return {'root': str(clone_root), 'ledger': str(destination),
                'receipt': str(receipt_path), 'receipt_sha256': digest(_read(receipt_path)),
                'label': label,
                'monitor': str(monitor_path), 'monitor_sha256': digest(_read(monitor_path)),
                'monitor_owner': owner, 'wall_seconds': outer['duration_seconds']}

    def _stage_transition(self, req, root, case_root, request_inputs, prepared):
        stage_inputs = {**request_inputs, 'prepare_status_sha256': prepared['status_sha256']}
        stage = self.journal.run_step(req + ':stage', inputs=stage_inputs,
            job=lambda: {'status': 'passed', **self._stage(
                req, root, case_root, case_root / 'stage-context.json', prepared)},
            reuse=lambda saved: self._verify_record(
                saved, ('config', 'status_path', 'monitor', 'report', 'plan')),
            category='stage')
        positive_full_clones = None
        if req == 'positive_full':
            positive_full_clones = self._positive_full_r0_clones(root, stage)
        transition_inputs = {**stage_inputs, 'stage_report_sha256': stage['report_sha256']}
        transition = self.journal.run_step(req + ':transition', inputs=transition_inputs,
            job=lambda: {'status': 'passed', **self._transition(req, root, case_root, stage)},
            reuse=lambda saved: self._verify_record(
                saved, ('config', 'context', 'status_path', 'monitor', 'report')),
            category='transition')
        return stage, transition, positive_full_clones

    def _positive_full_r0_clones(self, root, stage):
        """Clone the staged A ledger before the transition can mutate its source."""
        stage_report_sha256 = stage['report_sha256']
        clone = self.journal.run_step('positive_full:r0-clone',
            inputs={'stage_report_sha256': stage_report_sha256},
            job=lambda: {'status': 'passed', **self._clone_r0('positive_full', root, stage)},
            reuse=lambda saved: self._verify_record(
                saved, ('receipt',), ('receipt_sha256',)))
        disabled_clone = self.journal.run_step('positive_full:disabled-config-clone',
            inputs={'stage_report_sha256': stage_report_sha256,
                    'label': 'disabled-config-r0'},
            job=lambda: {'status': 'passed', **self._clone_r0(
                'positive_full', root, stage, label='disabled-config-r0')},
            reuse=lambda saved: self._verify_record(
                saved, ('receipt',), ('receipt_sha256',)))
        ambiguous_clone = self.journal.run_step('positive_full:ambiguous-restart-clone',
            inputs={'stage_report_sha256': stage_report_sha256,
                    'label': 'ambiguous-restart-r0'},
            job=lambda: {'status': 'passed', **self._clone_r0(
                'positive_full', root, stage, label='ambiguous-restart-r0')},
            reuse=lambda saved: self._verify_record(
                saved, ('receipt',), ('receipt_sha256',))
                and saved.get('label') == 'ambiguous-restart-r0'
                and _json(saved['receipt']).get('stage_report_sha256')
                    == stage_report_sha256)
        clones = {'r0': clone, 'disabled_config': disabled_clone,
                  'ambiguous_restart': ambiguous_clone}
        label = 'expired-status-r0'

        def verified_expired_status_clone(saved):
            try:
                return (self._verify_record(
                    saved, ('receipt', 'monitor'),
                    ('receipt_sha256', 'monitor_sha256'))
                    and saved.get('label') == label
                    and _json(saved['receipt']).get('stage_report_sha256')
                        == stage_report_sha256)
            except (OSError, ValueError, KeyError, TypeError):
                return False

        def create_expired_status_clone():
            saved = self._clone_r0('positive_full', root, stage, label=label)
            if not verified_expired_status_clone(saved):
                raise ValueError('expired-status R0 clone failed review')
            return {'status': 'passed', **saved}

        expired_status_clone = self.journal.run_step(
            'positive_full:expired-status-clone',
            inputs={'stage_report_sha256': stage_report_sha256,
                    'label': label},
            job=create_expired_status_clone,
            reuse=verified_expired_status_clone)
        clones['expired_status'] = expired_status_clone
        if self.variant == 0:
            capacity_label = 'capacity-baseline-r0'

            def verified_capacity_clone(saved):
                try:
                    return (self._verify_record(
                        saved, ('receipt', 'monitor'),
                        ('receipt_sha256', 'monitor_sha256'))
                        and saved.get('label') == capacity_label
                        and _json(saved['receipt']).get('stage_report_sha256')
                            == stage_report_sha256)
                except (OSError, ValueError, KeyError, TypeError):
                    return False

            def create_capacity_clone():
                saved = self._clone_r0('positive_full', root, stage,
                                       label=capacity_label)
                if not verified_capacity_clone(saved):
                    raise ValueError('capacity baseline R0 clone failed review')
                return {'status': 'passed', **saved}

            clones['capacity_baseline'] = self.journal.run_step(
                'positive_full:capacity-baseline-clone',
                inputs={'stage_report_sha256': stage_report_sha256,
                        'label': capacity_label},
                job=create_capacity_clone,
                reuse=verified_capacity_clone)
        return clones

    def _expired_status_inputs(self, request, root, stage, source, proof, clone, positive):
        from harness.tests import queue_v3_local_expired_status_negative as supervisor
        from tools.part5 import finalize_v3_expired_status_negative as finalizer
        from tools.part5.build_v3_expired_status_negative_inputs import _frozen_bundle_source_pins

        if (request != 'positive_full' or clone.get('label') != 'expired-status-r0'
                or clone['ledger'] == _json(positive['config'])['ledger']):
            raise ValueError('independent expired-status A/R0 clone required')
        negative_root = root / 'expired-status-negative'
        if not negative_root.exists():
            negative_root.mkdir(mode=0o700)
        else:
            _private_dir(negative_root)
        frozen = _frozen_bundle_source_pins(self.manifest, self.freeze_doc, REPO)
        source_pins = {}
        for relative in finalizer.SOURCE_PATHS:
            expected = frozen.get(relative)
            if not _hash(expected):
                raise ValueError('expired-status finalizer source absent from frozen bundles')
            _read(REPO / relative, expected, 128 * 1024 * 1024)
            source_pins[relative] = expected
        proof_doc = _json(proof['receipt'], proof['receipt_sha256'], cap=2 * 1024 * 1024)
        raw_proof = proof_doc['artifacts']['proof/request_bound_training_full_base.proof']
        _read(raw_proof['path'], raw_proof['sha256'], 32 * 1024 * 1024)
        wire = proof['wires']['r0_full_wire']
        if (proof_doc.get('target_variant') != self.variant
                or proof_doc.get('wires', {}).get('r0_full_wire') != wire):
            raise ValueError('expired-status Full proof variant or wire differs')
        stage_report = _json(stage['report'], stage['report_sha256'])
        elf = self.manifest['frozen_files']['loaded_elf']
        config = {
            'schema': supervisor.CONFIG_SCHEMA, 'scope': supervisor.SCOPE,
            'variant': self.variant, 'request_slot': 'A',
            'freeze_report': self.manifest['freeze_receipt'],
            'freeze_sha256': self.manifest['freeze_sha256'],
            'stage_config': stage['config'], 'stage_config_sha256': stage['config_sha256'],
            'stage_status': stage['status_path'], 'stage_status_sha256': stage['status_sha256'],
            'stage_report': stage['report'], 'stage_report_sha256': stage['report_sha256'],
            'stage_plan': stage['plan'], 'stage_plan_sha256': stage['plan_sha256'],
            'source_receipt': source['receipt'], 'source_receipt_sha256': source['receipt_sha256'],
            'clone_receipt': clone['receipt'], 'clone_receipt_sha256': clone['receipt_sha256'],
            'full_proof_receipt': proof['receipt'], 'full_proof_receipt_sha256': proof['receipt_sha256'],
            'full_proof': raw_proof['path'], 'full_proof_sha256': raw_proof['sha256'],
            'full_wire': wire['path'], 'full_wire_sha256': wire['sha256'],
            'runner': self.manifest['runner'], 'runner_sha256': self.manifest['runner_sha256'],
            'expected_elf': elf['path'], 'expected_elf_sha256': elf['sha256'],
            'expected_program': stage_report['program'], 'expected_genesis': stage_report['genesis'],
            'expected_genesis_sha256': digest(_read(Path(clone['ledger']) / 'genesis.bin',
                                                       cap=16 * 1024 * 1024)),
            'ledger': clone['ledger'], 'stage_root': stage['root'],
            'output_dir': self._art(request, 'expired-status-negative'),
            'control_output': self._art(request, 'expired-status-negative-control'),
            'owner': f'heldout-v{self.variant:02d}-expired-status-negative-{self.run_id}',
            'observation_lifetime_seconds': 20, 'wait_deadline_seconds': 45,
            'owner_process_limits': supervisor.PROCESS_LIMITS,
            'outer_limits_required': supervisor.LIMITS}
        supervisor._validate_config(config)
        config_path = negative_root / 'supervisor-config.json'
        config_ref = {'path': str(config_path),
                      'sha256': self._write_config(config_path, config)}
        positive_refs = {
            'config': self._artifact(positive['config']),
            'report': self._artifact(positive['report']),
            'status': self._artifact(positive['status_path']),
            'monitor': self._artifact(positive['monitor']),
            'monitor_invocation': self._artifact(
                Path(positive['monitor']).with_suffix('') / 'invocation.json'),
            'monitor_owner': positive['monitor_owner']}
        return {'config': config, 'config_ref': config_ref, 'source_pins': source_pins,
                'positive_full': positive_refs, 'monitor': negative_root / 'outer.json',
                'monitor_dir': negative_root / 'monitor'}

    def _expired_status_negative(self, request, root, stage, source, proof, clone, positive):
        from harness.tests import queue_v3_local_expired_status_negative as supervisor
        from tools.part5 import finalize_v3_expired_status_negative as finalizer

        setup_started = time.monotonic()
        prepared = self._expired_status_inputs(request, root, stage, source, proof, clone, positive)
        setup_wall = time.monotonic() - setup_started
        config, config_ref = prepared['config'], prepared['config_ref']
        monitor, monitor_dir = prepared['monitor'], prepared['monitor_dir']
        paths = {'config': Path(config_ref['path']),
                 'candidate': Path(config['output_dir']) / supervisor.REPORT_NAME,
                 'supervisor_status': Path(config['control_output']) / 'status.json',
                 'monitor': monitor, 'monitor_invocation': monitor_dir / 'invocation.json'}
        inputs = {'config': config_ref, 'source_pins': prepared['source_pins'],
                  'positive_full': prepared['positive_full']}

        def verify_loaded(saved):
            try:
                refs = saved['refs']
                if (type(refs) is not dict or set(refs) != set(paths)
                        or any(refs[key]['path'] != str(path) for key, path in paths.items())
                        or refs['config'] != config_ref):
                    return False
                checked = finalizer.Inputs()
                for ref in refs.values():
                    checked.raw(ref)
                outer, invocation = finalizer.monitor_pair(
                    checked, refs['monitor'], refs['monitor_invocation'])
                finalizer.check_monitor(outer, invocation, config['owner'],
                    finalizer.REPO / 'harness/tests/queue_v3_local_expired_status_negative.py',
                    config_ref, [config[p] for p in ('ledger', 'output_dir', 'control_output')],
                    finalizer.REPO, private_output=monitor_dir)
                checked.recheck()
                return True
            except (OSError, ValueError, KeyError, TypeError):
                return False

        def loaded_job():
            existing = [paths[key].exists() for key in paths if key != 'config']
            if all(existing):
                outer = _json(monitor)
            elif (any(existing) or monitor_dir.exists()
                    or Path(config['output_dir']).exists()
                    or Path(config['control_output']).exists()):
                raise ValueError('partial expired-status output requires manual review')
            else:
                outer = self.bounded_run(config['owner'],
                    [sys.executable, str(self.toolpaths['expired_status_negative']),
                     '--config', config_ref['path'], '--config-sha256', config_ref['sha256']],
                    monitor_dir, monitor, runtime=supervisor.LIMITS['runtime_seconds'],
                    storage_paths=tuple(Path(config[p]) for p in
                                        ('ledger', 'output_dir', 'control_output')),
                    env={'P5_V3_EXPIRED_STATUS_NEGATIVE_SCOPE': supervisor.SCOPE})
            missing = [name for name, path in paths.items()
                       if name != 'config' and not path.is_file()]
            if missing:
                exit_code = outer.get('exit_code') if type(outer) is dict else None
                if type(exit_code) is not int:
                    exit_code = 'unknown'
                stop_reason = outer.get('stop_reason') if type(outer) is dict else None
                if stop_reason not in (None, 'runtime_seconds',
                        'owned_tree_rss_bytes', 'storage_growth_bytes', 'runner_error'):
                    stop_reason = 'unrecognized'
                raise ValueError(
                    'bounded expired-status child missing '
                    f'{", ".join(missing)} artifact(s); exit_code={exit_code}; '
                    f'stop_reason={stop_reason}; monitor={monitor}; '
                    f'bounded_stderr={monitor_dir / "stderr.log"}; '
                    f'status={paths["supervisor_status"]}; candidate={paths["candidate"]}')
            saved = {'status': 'passed', 'refs': {key: self._artifact(path)
                                                  for key, path in paths.items()},
                     'setup_wall_seconds': setup_wall,
                     'supervisor_wall_seconds': outer['duration_seconds'],
                     'wall_seconds': setup_wall + outer['duration_seconds']}
            if not verify_loaded(saved):
                raise ValueError('bounded expired-status loaded supervisor evidence required')
            return saved

        loaded = self.journal.run_step(EXPIRED_STATUS_STEP_NAMES[1], inputs=inputs,
                                      job=loaded_job, reuse=verify_loaded)
        finalizer_manifest = {'schema': finalizer.MANIFEST_SCHEMA, 'refs': loaded['refs'],
                              'source_pins': prepared['source_pins'],
                              'positive_full': prepared['positive_full']}
        negative_root = Path(config_ref['path']).parent
        return self.journal.run_step(EXPIRED_STATUS_STEP_NAMES[2],
            inputs={'finalizer_manifest': finalizer_manifest},
            job=lambda: self._finalize_expired_status(negative_root, finalizer_manifest),
            reuse=lambda saved: self._expired_status_sidecar_verified(
                saved['sidecar'], saved['sidecar_sha256'], finalizer_manifest))

    def _finalize_expired_status(self, root, manifest):
        from tools.part5 import finalize_v3_expired_status_negative as finalizer

        # This read-only finalizer reopens bounded post-exit monitor evidence and
        # the independent identical-wire loaded success before emitting a report.
        finalized = finalizer.finalize(manifest)
        config = _json(manifest['refs']['config']['path'], manifest['refs']['config']['sha256'])
        manifest_path, final_path, report_path = (root / 'finalizer-manifest.json',
            root / 'finalization.json', root / 'evidence-report.json')
        for path, value in ((manifest_path, manifest), (final_path, finalized),
                            (report_path, finalized['evidence'])):
            self._write_config(path, value)
        sidecar = {'schema': EXPIRED_STATUS_SIDECAR_SCHEMA, 'variant': config['variant'],
            'stage_report_sha256': config['stage_report_sha256'],
            'stage_plan_sha256': config['stage_plan_sha256'],
            'r0_source_receipt_sha256': config['source_receipt_sha256'],
            'full_proof_receipt_sha256': config['full_proof_receipt_sha256'],
            'clone_receipt': {'path': config['clone_receipt'], 'sha256': config['clone_receipt_sha256']},
            'full_wire': {'path': config['full_wire'], 'sha256': config['full_wire_sha256']},
            'config': manifest['refs']['config'], 'status': manifest['refs']['supervisor_status'],
            'outer': manifest['refs']['monitor'],
            'monitor_invocation': manifest['refs']['monitor_invocation'],
            'candidate': manifest['refs']['candidate'],
            'finalizer_manifest': self._artifact(manifest_path),
            'finalization': self._artifact(final_path), 'report': self._artifact(report_path)}
        sidecar_path = root / 'sidecar.json'
        sidecar_sha = self._write_config(sidecar_path, sidecar)
        return {'status': 'passed', 'sidecar': str(sidecar_path), 'sidecar_sha256': sidecar_sha}

    @staticmethod
    def _expired_status_sidecar_verified(path, expected_sha256, expected_manifest=None):
        from tools.part5 import finalize_v3_expired_status_negative as finalizer

        try:
            sidecar = _json(path, expected_sha256)
            if (set(sidecar) != EXPIRED_STATUS_SIDECAR_KEYS
                    or sidecar['schema'] != EXPIRED_STATUS_SIDECAR_SCHEMA
                    or type(sidecar['variant']) is not int or not 0 <= sidecar['variant'] < 8):
                return False
            inputs = finalizer.Inputs()
            for role in ('clone_receipt', 'full_wire', 'config', 'status', 'outer',
                         'monitor_invocation', 'candidate', 'finalizer_manifest',
                         'finalization', 'report'):
                inputs.raw(sidecar[role])
            manifest = inputs.doc(sidecar['finalizer_manifest'])
            if expected_manifest is not None and manifest != expected_manifest:
                return False
            mapping = {'config': 'config', 'status': 'supervisor_status', 'outer': 'monitor',
                       'monitor_invocation': 'monitor_invocation', 'candidate': 'candidate'}
            if any(sidecar[key] != manifest['refs'][role] for key, role in mapping.items()):
                return False
            config = inputs.doc(sidecar['config'])
            for field, config_field in (
                    ('variant', 'variant'), ('stage_report_sha256', 'stage_report_sha256'),
                    ('stage_plan_sha256', 'stage_plan_sha256'),
                    ('r0_source_receipt_sha256', 'source_receipt_sha256'),
                    ('full_proof_receipt_sha256', 'full_proof_receipt_sha256')):
                if sidecar[field] != config[config_field]:
                    return False
            for field in ('clone_receipt', 'full_wire'):
                if sidecar[field] != finalizer.config_ref(config, field, field + '_sha256'):
                    return False
            regenerated = finalizer.finalize(manifest)
            if (inputs.doc(sidecar['finalization']) != regenerated
                    or inputs.doc(sidecar['report']) != regenerated['evidence']):
                return False
            inputs.recheck()
            return True
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return False

    def _disabled_account_bundle(self, report, output_dir, group):
        rows = report.get(group + '_accounts')
        if (type(rows) is not list or len(rows) != len(NEGATIVE_ACCOUNT_NAMES)
                or [row.get('name') if type(row) is dict else None for row in rows]
                    != list(NEGATIVE_ACCOUNT_NAMES)):
            raise ValueError(f'pinned {group} account snapshot rows required')
        refs = {}
        for name, row in zip(NEGATIVE_ACCOUNT_NAMES, rows):
            path = Path(output_dir) / group / (name + '.bin')
            if row.get('path') != str(path) or not _hash(row.get('sha256')):
                raise ValueError(f'pinned {group} {name} account output path required')
            refs[name] = self._artifact(path)
            if refs[name]['sha256'] != row['sha256']:
                raise ValueError(f'{group} {name} account snapshot hash mismatch')
        return refs

    def _disabled_config_negative(self, request, root, stage, source, proof, clone):
        negative_root = root / 'disabled-config-negative'
        if not negative_root.exists():
            negative_root.mkdir(mode=0o700)
        else:
            _private_dir(negative_root)
        output, control = (self._art(request, 'disabled-config-negative'),
                           self._art(request, 'disabled-config-negative-control'))
        wire = proof['wires']['r0_full_wire']
        stage_report = _json(Path(stage['report']), stage['report_sha256'])
        rust_config = {'schema': 'part5-v3-disabled-config-negative-config-v1',
            'variant': self.variant, 'request_slot': 'A',
            'stage_root': stage['root'], 'stage_report': stage['report'],
            'stage_report_sha256': stage['report_sha256'],
            'stage_plan': stage['plan'], 'stage_plan_sha256': stage['plan_sha256'],
            'ledger': clone['ledger'],
            'heldout_r0_clone_report': clone['receipt'],
            'heldout_r0_clone_report_sha256': clone['receipt_sha256'],
            'full_wire': wire['path'], 'full_wire_sha256': wire['sha256'],
            'expected_program': stage_report['program'],
            'expected_genesis': stage_report['genesis'],
            'expected_elf_sha256': self.manifest['frozen_files']['loaded_elf']['sha256'],
            'output_dir': output, 'control_output': control,
            'runner': self.manifest['runner'],
            'runner_sha256': self.manifest['runner_sha256']}
        rust_config_path = negative_root / 'rust-config.json'
        rust_config_sha = self._write_config(rust_config_path, rust_config)
        wrapper_config = {'schema': 'credential-v3-disabled-config-negative-supervisor-v1',
            'scope': 'part5-v3-disabled-config-negative',
            'variant': self.variant, 'request_slot': 'A',
            'prior_stage_config': stage['config'],
            'prior_stage_config_sha256': stage['config_sha256'],
            'prior_stage_status': stage['status_path'],
            'prior_stage_status_sha256': stage['status_sha256'],
            'prior_stage_monitor': stage['monitor'],
            'prior_stage_monitor_sha256': stage['monitor_sha256'],
            'prior_monitor_owner': stage['monitor_owner'],
            'stage_root': stage['root'],
            'stage_report_sha256': stage['report_sha256'],
            'stage_plan_sha256': stage['plan_sha256'],
            'ledger': clone['ledger'],
            'heldout_r0_clone_report': clone['receipt'],
            'heldout_r0_clone_report_sha256': clone['receipt_sha256'],
            'full_wire': wire['path'], 'full_wire_sha256': wire['sha256'],
            'expected_program': stage_report['program'],
            'expected_genesis': stage_report['genesis'],
            'expected_elf_sha256': rust_config['expected_elf_sha256'],
            'runner': self.manifest['runner'],
            'runner_sha256': self.manifest['runner_sha256'],
            'rust_config_path': str(rust_config_path),
            'rust_config_sha256': rust_config_sha,
            'output_dir': output, 'control_output': control,
            'outer_limits_required': DISABLED_CONFIG_LIMITS}
        wrapper_path = negative_root / 'supervisor-config.json'
        wrapper_sha = self._write_config(wrapper_path, wrapper_config)
        monitor_dir, monitor_path = (negative_root / 'monitor',
                                     negative_root / 'outer.json')
        owner = f'heldout-v{self.variant:02d}-{request}-disabled-config-negative'
        status_path = Path(control) / 'status.json'
        report_path = Path(output) / 'disabled-config-negative-report.json'
        if status_path.exists() and report_path.exists() and monitor_path.exists():
            outer, status, report = (_json(monitor_path), _json(status_path),
                                     _json(report_path))
        elif (Path(control).exists() or Path(output).exists()
              or monitor_dir.exists() or monitor_path.exists()):
            raise ValueError('partial disabled-config negative output requires manual review')
        else:
            outer = self.bounded_run(owner, [sys.executable,
                str(self.toolpaths['disabled_config_negative']),
                '--config', str(wrapper_path), '--config-sha256', wrapper_sha],
                monitor_dir, monitor_path,
                runtime=DISABLED_CONFIG_LIMITS['runtime_seconds'],
                storage_paths=(Path(output), Path(control)),
                env={'P5_V3_DISABLED_CONFIG_NEGATIVE_SCOPE':
                     'part5-v3-disabled-config-negative'})
            missing = [name for name, path in (
                ('status', status_path), ('report', report_path))
                if not path.is_file()]
            if missing:
                exit_code = outer.get('exit_code') if type(outer) is dict else None
                if type(exit_code) is not int:
                    exit_code = 'unknown'
                stop_reason = outer.get('stop_reason') if type(outer) is dict else None
                if stop_reason not in (None, 'runtime_seconds',
                        'owned_tree_rss_bytes', 'storage_growth_bytes', 'runner_error'):
                    stop_reason = 'unrecognized'
                raise ValueError(
                    'bounded disabled-config child missing '
                    f'{", ".join(missing)} artifact(s); exit_code={exit_code}; '
                    f'stop_reason={stop_reason}; monitor={monitor_path}; '
                    f'bounded_stderr={monitor_dir / "stderr.log"}; '
                    f'child_stderr={Path(control) / "runner.stderr.log"}; '
                    f'status={status_path}; report={report_path}')
            status, report = _json(status_path), _json(report_path)
        if (not reviewed_application_outer(outer)
                or outer.get('exit_code') != 1
                or status.get('scope') != 'part5-v3-disabled-config-negative'
                or status.get('status') != 'failed'
                or status.get('error_type') is not None
                or status.get('config_sha256') != wrapper_sha
                or status.get('rust_config_path') != str(rust_config_path)
                or status.get('rust_config_sha256') != rust_config_sha
                or status.get('config_disabled') is not True
                or status.get('execute_rejected') is not True
                or status.get('accounts_unchanged') is not True
                or status.get('issuer_disabled') is not True
                or status.get('issuer_execute_rejected') is not True
                or status.get('issuer_accounts_unchanged') is not True
                or status.get('effect_verified') is not True
                or status.get('application_effect') is not False
                or status.get('report_path') != str(report_path)
                or status.get('report_sha256') != digest(_read(report_path))
                or not reviewed_validator_sigint(status.get('validator_cleanup'))
                or not reviewed_runner_exit(status.get('runner_cleanup'))
                or report.get('schema') != DISABLED_CONFIG_REPORT_SCHEMA
                or report.get('passed') is not True
                or report.get('variant') != self.variant
                or report.get('program') != stage_report['program']
                or report.get('genesis') != stage_report['genesis']
                or report.get('loaded_elf_sha256') != rust_config['expected_elf_sha256']
                or report.get('stage_report_sha256') != stage['report_sha256']
                or report.get('stage_plan_sha256') != stage['plan_sha256']
                or report.get('full_wire_sha256') != wire['sha256']
                or report.get('clone_receipt_sha256') != clone['receipt_sha256']
                or report.get('config_disabled') is not True
                or report.get('execute_rejected') is not True
                or report.get('issuer_disabled') is not True
                or report.get('issuer_execute_rejected') is not True
                or report.get('issuer_disable_changed_only_enabled_epoch_status') is not True
                or report.get('issuer_accounts_unchanged_after_rejection') is not True
                or report.get('expected_custom_error') != 713):
            raise ValueError('pinned loaded-ELF disabled-config rejection required')
        accounts = {group: self._disabled_account_bundle(report, output, group)
                    for group in ('eligible', 'before', 'after',
                                  'issuer_eligible', 'issuer_before', 'issuer_after')}
        sidecar = {'schema': DISABLED_CONFIG_SIDECAR_SCHEMA,
            'variant': self.variant,
            'stage_report_sha256': stage['report_sha256'],
            'stage_plan_sha256': stage['plan_sha256'],
            'r0_source_receipt_sha256': source['receipt_sha256'],
            'full_proof_receipt_sha256': proof['receipt_sha256'],
            'clone_receipt': self._artifact(clone['receipt']),
            'full_wire': self._artifact(wire['path']),
            'config': self._artifact(wrapper_path),
            'rust_config': self._artifact(rust_config_path),
            'status': self._artifact(status_path),
            'outer': self._artifact(monitor_path),
            'report': self._artifact(report_path),
            **{group + '_accounts': refs for group, refs in accounts.items()}}
        if set(sidecar) != DISABLED_CONFIG_SIDECAR_KEYS:
            raise ValueError('disabled-config sidecar schema mismatch')
        sidecar_path = negative_root / 'sidecar.json'
        raw = json.dumps(sidecar, sort_keys=True, indent=2).encode() + b'\n'
        if sidecar_path.exists():
            if _read(sidecar_path) != raw:
                raise ValueError('saved disabled-config sidecar differs from evidence')
        else:
            _write_new(sidecar_path, raw)
        return {'status': 'passed', 'sidecar': str(sidecar_path),
            'sidecar_sha256': digest(_read(sidecar_path)),
            'monitor': str(monitor_path),
            'monitor_sha256': digest(_read(monitor_path)),
            'monitor_owner': owner,
            'wall_seconds': outer['duration_seconds']}

    def _frozen_registry_source(self, relative):
        registry = self.manifest['frozen_bundles']['registry']
        rows = [item for item in registry
                if type(item) is dict and item.get('path') == relative]
        if len(rows) != 1:
            raise ValueError('ambiguous-restart source missing from frozen registry bundle')
        artifact = rows[0].get('artifact')
        expected_path = REPO / relative
        if (type(artifact) is not dict or artifact.get('path') != str(expected_path)
                or not _hash(artifact.get('sha256'))):
            raise ValueError('ambiguous-restart source freeze reference malformed')
        _read(expected_path, artifact['sha256'], 128 * 1024 * 1024)
        return {'path': str(expected_path), 'sha256': artifact['sha256']}

    def _ambiguous_restart(self, request, root, stage, source, proof,
                           replay_proof, clone, main_clone):
        from harness.tests import queue_v3_local_ambiguous_restart as supervisor
        from harness.tests import queue_v3_ambiguous_rpc_proxy as proxy_tools

        if (request != 'positive_full' or clone.get('label') != 'ambiguous-restart-r0'
                or clone['receipt_sha256'] == main_clone['receipt_sha256']
                or clone['ledger'] == main_clone['ledger']
                or clone['receipt'] == main_clone['receipt']):
            raise ValueError('independent positive A/R0 ambiguous-restart clone required')
        supervisor_ref = self._frozen_registry_source(AMBIGUOUS_RESTART_SUPERVISOR)
        proxy_ref = self._frozen_registry_source(AMBIGUOUS_RESTART_PROXY)
        supervisor_path = Path(supervisor_ref['path'])
        if supervisor_path != self.toolpaths['ambiguous_restart']:
            raise ValueError('ambiguous-restart supervisor differs from its frozen path')

        side_root = root / 'ambiguous-restart'
        if not side_root.exists():
            side_root.mkdir(mode=0o700)
        else:
            _private_dir(side_root)
        output = self._art(request, 'ambiguous-restart')
        control = self._art(request, 'ambiguous-restart-control')
        config_path = side_root / 'supervisor-config.json'
        outer_path = side_root / 'outer.json'
        monitor_dir = side_root / 'monitor'
        owner = f'heldout-v{self.variant:02d}-{request}-ambiguous-restart'
        status_path = Path(control) / 'status.json'
        proxy_receipt_path = Path(control) / 'proxy-receipt.json'
        finality_receipt_path = Path(control) / 'finality-receipt.json'
        pre_finality_path = Path(control) / 'pre-restart-finality-receipt.json'
        pre_stop_paths = {name: Path(output) / f'pre-stop-{name}.bin'
                          for name in AMBIGUOUS_ACCOUNT_NAMES}
        pre_submit_report_path = Path(output) / 'pre-submit-report.json'
        pre_submit_paths = {name: Path(output) / f'pre-submit-{name}.bin'
                            for name in AMBIGUOUS_ACCOUNT_NAMES}
        final_paths = {name: Path(output) / f'final-{name}.bin'
                       for name in AMBIGUOUS_ACCOUNT_NAMES}

        stage_report = _json(Path(stage['report']), stage['report_sha256'])
        context_path = self.output_root / 'pair-view' / 'stage-context.json'
        full_wire = proof['wires']['r0_full_wire']
        replay_wire = replay_proof['wires']['r0_full_wire']
        config = {
            'schema': supervisor.SCHEMA,
            'scope': supervisor.SCOPE,
            'outer_limits_required': LIMITS,
            'proxy_script': proxy_ref['path'],
            'proxy_script_sha256': proxy_ref['sha256'],
            'proxy_port': 19500 + self.variant,
            'expected_program': stage_report['program'],
            'expected_genesis': stage_report['genesis'],
            'expected_elf_sha256': self.manifest['frozen_files']['loaded_elf']['sha256'],
            'prior_monitor_owner': stage['monitor_owner'],
            'execute_output': output,
            'control_output': control,
            'prior_stage_config': stage['config'],
            'prior_stage_config_sha256': stage['config_sha256'],
            'prior_stage_status': stage['status_path'],
            'prior_stage_status_sha256': stage['status_sha256'],
            'prior_stage_monitor': stage['monitor'],
            'prior_stage_monitor_sha256': stage['monitor_sha256'],
            'stage_root': stage['root'],
            'stage_report_sha256': stage['report_sha256'],
            'stage_plan_sha256': stage['plan_sha256'],
            'ledger': clone['ledger'],
            'heldout_r0_clone_report': clone['receipt'],
            'heldout_r0_clone_report_sha256': clone['receipt_sha256'],
            'runner': self.manifest['runner'],
            'runner_sha256': self.manifest['runner_sha256'],
            'context': str(context_path),
            'context_sha256': digest(_read(context_path)),
            'full_wire': full_wire['path'],
            'full_wire_sha256': full_wire['sha256'],
            'replay_full_wire': replay_wire['path'],
            'replay_full_wire_sha256': replay_wire['sha256'],
        }
        supervisor._validate_config(config)
        config_sha = digest(encoded(config))
        inputs = {
            'variant': self.variant,
            'stage_report_sha256': stage['report_sha256'],
            'stage_plan_sha256': stage['plan_sha256'],
            'r0_source_receipt_sha256': source['receipt_sha256'],
            'full_proof_receipt_sha256': proof['receipt_sha256'],
            'replay_proof_receipt_sha256': replay_proof['receipt_sha256'],
            'clone_receipt_sha256': clone['receipt_sha256'],
            'full_wire_sha256': full_wire['sha256'],
            'replay_full_wire_sha256': replay_wire['sha256'],
            'supervisor_script_sha256': supervisor_ref['sha256'],
            'proxy_script_sha256': proxy_ref['sha256'],
            'frozen_elf_sha256': self.manifest['frozen_files']['loaded_elf']['sha256'],
            'config_sha256': config_sha,
            'proxy_port': config['proxy_port'],
        }
        artifacts = (config_path, outer_path, monitor_dir, Path(output), Path(control),
                     status_path, proxy_receipt_path, finality_receipt_path, pre_finality_path,
                     pre_submit_report_path,
                     *pre_submit_paths.values(), *pre_stop_paths.values(), *final_paths.values())
        present = [path.exists() or path.is_symlink() for path in artifacts]
        if any(present) and not all(present):
            raise ValueError('partial ambiguous-restart output requires manual review')
        if not any(present):
            self._write_config(config_path, config)
            outer = self.bounded_run(owner,
                [sys.executable, str(supervisor_path), '--config', str(config_path),
                 '--config-sha256', config_sha], monitor_dir, outer_path,
                runtime=LIMITS['runtime_seconds'],
                storage_paths=(Path(clone['ledger']), Path(output), Path(control)),
                env={'P5_V3_AMBIGUOUS_RESTART_SUPERVISOR': supervisor.SCOPE})
            status = _json(status_path)
            if not reviewed_ambiguous_restart_outer(outer, owner):
                raise ValueError('bounded ambiguous-restart supervisor did not exit cleanly')
        else:
            if _read(config_path) != encoded(config):
                raise ValueError('saved ambiguous-restart config differs from pinned inputs')
            outer = _json(outer_path)
            status = _json(status_path)

        sidecar = {
            'schema': AMBIGUOUS_RESTART_SIDECAR_SCHEMA,
            'variant': self.variant,
            'stage_report_sha256': stage['report_sha256'],
            'stage_plan_sha256': stage['plan_sha256'],
            'r0_source_receipt_sha256': source['receipt_sha256'],
            'full_proof_receipt_sha256': proof['receipt_sha256'],
            'replay_proof_receipt_sha256': replay_proof['receipt_sha256'],
            'clone_receipt': self._artifact(clone['receipt']),
            'full_wire': self._artifact(full_wire['path']),
            'replay_full_wire': self._artifact(replay_wire['path']),
            'config': self._artifact(config_path),
            'status': self._artifact(status_path),
            'outer': self._artifact(outer_path),
            'proxy_receipt': self._artifact(proxy_receipt_path),
            'finality_receipt': self._artifact(finality_receipt_path),
            'pre_restart_finality_receipt': self._artifact(pre_finality_path),
            'pre_stop_accounts': {name: self._artifact(path)
                                  for name, path in pre_stop_paths.items()},
            'pre_submit_report': self._artifact(pre_submit_report_path),
            'pre_submit_accounts': {name: self._artifact(path)
                                   for name, path in pre_submit_paths.items()},
            'final_accounts': {name: self._artifact(path)
                               for name, path in final_paths.items()},
        }
        sidecar_path = side_root / 'sidecar.json'
        sidecar_raw = json.dumps(sidecar, sort_keys=True, indent=2).encode() + b'\n'
        if sidecar_path.exists():
            if _read(sidecar_path) != sidecar_raw:
                raise ValueError('saved ambiguous-restart sidecar differs from evidence')
        else:
            _write_new(sidecar_path, sidecar_raw)
        if not self._ambiguous_restart_sidecar_verified(
                sidecar_path, digest(sidecar_raw), inputs):
            raise ValueError('ambiguous-restart sidecar did not verify pinned evidence')
        return {'status': 'passed', 'sidecar': str(sidecar_path),
                'sidecar_sha256': digest(sidecar_raw),
                'monitor': str(outer_path),
                'monitor_sha256': digest(_read(outer_path)),
                'monitor_owner': owner,
                'wall_seconds': outer['duration_seconds']}

    @staticmethod
    def _ambiguous_restart_sidecar_verified(path, expected_sha256, inputs):
        try:
            sidecar = _json(path, expected_sha256, 1024 * 1024)
            if (type(sidecar) is not dict
                    or set(sidecar) != AMBIGUOUS_RESTART_SIDECAR_KEYS
                    or sidecar.get('schema') != AMBIGUOUS_RESTART_SIDECAR_SCHEMA
                    or type(sidecar.get('variant')) is not int
                    or not 0 <= sidecar['variant'] < 8):
                return False
            expected_sidecar = {
                'variant': 'variant',
                'stage_report_sha256': 'stage_report_sha256',
                'stage_plan_sha256': 'stage_plan_sha256',
                'r0_source_receipt_sha256': 'r0_source_receipt_sha256',
                'full_proof_receipt_sha256': 'full_proof_receipt_sha256',
                'replay_proof_receipt_sha256': 'replay_proof_receipt_sha256',
            }
            if any(sidecar[field] != inputs[key]
                   for field, key in expected_sidecar.items()):
                return False
            for field in ('stage_report_sha256', 'stage_plan_sha256',
                          'r0_source_receipt_sha256', 'full_proof_receipt_sha256',
                          'replay_proof_receipt_sha256'):
                if not _hash(sidecar.get(field)):
                    return False
            refs = ('clone_receipt', 'full_wire', 'replay_full_wire', 'config',
                    'status', 'outer', 'proxy_receipt', 'finality_receipt',
                    'pre_restart_finality_receipt',
                    'pre_submit_report')
            loaded = {}
            for field in refs:
                ref = sidecar[field]
                if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
                        or not _hash(ref.get('sha256'))):
                    return False
                raw = _read(ref['path'], ref['sha256'], 32 * 1024 * 1024)
                loaded[field] = json.loads(raw) if field in {
                    'clone_receipt', 'config', 'status', 'outer',
                    'proxy_receipt', 'finality_receipt', 'pre_restart_finality_receipt',
                    'pre_submit_report'} else None
            config = loaded['config']
            status = loaded['status']
            outer = loaded['outer']
            proxy_receipt = loaded['proxy_receipt']
            finality_receipt = loaded['finality_receipt']
            pre_report = loaded['pre_submit_report']
            clone = loaded['clone_receipt']
            if (sidecar['variant'] != inputs['variant']
                    or config.get('schema') != 'part5-v3-local-ambiguous-restart-supervisor-v1'
                    or config.get('scope') != 'part5-v3-local-ambiguous-restart'
                    or config.get('proxy_port') != 19500 + sidecar['variant']
                    or config.get('proxy_script_sha256') != inputs['proxy_script_sha256']
                    or config.get('expected_elf_sha256') != inputs['frozen_elf_sha256']
                    or config.get('stage_report_sha256') != sidecar['stage_report_sha256']
                    or config.get('stage_plan_sha256') != sidecar['stage_plan_sha256']
                    or config.get('heldout_r0_clone_report_sha256')
                        != sidecar['clone_receipt']['sha256']
                    or config.get('heldout_r0_clone_report_sha256')
                        != inputs['clone_receipt_sha256']
                    or config.get('full_wire_sha256') != sidecar['full_wire']['sha256']
                    or config.get('replay_full_wire_sha256')
                        != sidecar['replay_full_wire']['sha256']
                    or config.get('full_wire_sha256') != inputs['full_wire_sha256']
                    or config.get('replay_full_wire_sha256')
                        != inputs['replay_full_wire_sha256']
                    or clone.get('schema') != 'part5-v3-heldout-r0-ledger-clone-v1'
                    or clone.get('stage_report_sha256') != sidecar['stage_report_sha256']
                    or clone.get('heldout_acceptance') is not False
                    or clone.get('copy_identical') is not True
                    or clone.get('destination') != config.get('ledger')
                    or clone.get('application_effect') is not False
                    or clone.get('loaded_identity_rechecked_after_restart') is not False
                    or status.get('schema') != 1
                    or status.get('scope') != 'part5-v3-local-ambiguous-restart'
                    or status.get('status') != 'passed'
                    or status.get('heldout_acceptance') is not True
                    or status.get('error_type') is not None
                    or status.get('config_sha256') != sidecar['config']['sha256']
                    or status.get('proxy_receipt_sha256') != sidecar['proxy_receipt']['sha256']
                    or status.get('finality_receipt_path')
                        != sidecar['finality_receipt']['path']
                    or status.get('finality_receipt_sha256')
                        != sidecar['finality_receipt']['sha256']
                    or status.get('pre_submit_report_sha256')
                        != sidecar['pre_submit_report']['sha256']
                    or status.get('stage_report_sha256') != sidecar['stage_report_sha256']
                    or status.get('stage_plan_sha256') != sidecar['stage_plan_sha256']
                    or status.get('heldout_r0_clone_report_sha256')
                        != sidecar['clone_receipt']['sha256']
                    or status.get('full_wire_sha256') != sidecar['full_wire']['sha256']
                    or status.get('replay_full_wire_sha256')
                        != sidecar['replay_full_wire']['sha256']
                    or status.get('proxy_script_sha256') != inputs['proxy_script_sha256']
                    or status.get('expected_elf_sha256') != inputs['frozen_elf_sha256']
                    or status.get('proxy_receipt_verified') is not True
                    or status.get('expected_transport_failure') is not True
                    or status.get('runner_exit_code') == 0
                    or status.get('proxy_status') != 'response_dropped'
                    or status.get('matching_submissions') != 1
                    or status.get('retry_count') != 0
                    or status.get('pre_restart_signature_finalized_success') is not True
                    or status.get('pre_stop_accounts_reconciliation_verified') is not True
                    or status.get('restart_accounts_persisted') is not True
                    or status.get('restart_identity_verified') is not True
                    or not _hash(status.get('ledger_genesis_sha256_after_stop'))
                    or status.get('signature_finalized_success') is not True
                    or status.get('five_account_reconciliation_verified') is not True
                    or status.get('prepositive_snapshot_saved_by_runner') is not True
                    or status.get('cleanup_verified') is not True
                    or status.get('effect_count') != 1
                    or status.get('request_consumed') is not True
                    or status.get('queue_appends') != 1
                    or status.get('application_effect') is not True
                    or not _hash(status.get('signature_sha256'))
                    or type(status.get('signature_finalized_slot')) is not int
                    or status['signature_finalized_slot'] <= 0
                    or not reviewed_ambiguous_restart_outer(
                        outer, f"heldout-v{sidecar['variant']:02d}-positive_full-ambiguous-restart")):
                return False
            expected_context = Path(config['context'])
            if (status.get('context_sha256') != config.get('context_sha256')
                    or status.get('expected_program') != config.get('expected_program')
                    or status.get('expected_genesis') != config.get('expected_genesis')
                    or status.get('expected_elf_sha256') != config.get('expected_elf_sha256')
                    or status.get('runner_sha256') != config.get('runner_sha256')
                    or status.get('ledger_path_sha256') != digest(
                        str(Path(config['ledger'])).encode())
                    or not expected_context.is_file()):
                return False
            before, after = status.get('loaded_program_before'), status.get('loaded_program_after')
            if (type(before) is not dict or type(after) is not dict
                    or any(before.get(key) != after.get(key)
                           for key in ('program', 'genesis', 'elf_sha256'))
                    or before.get('program') != config['expected_program']
                    or before.get('genesis') != config['expected_genesis']
                    or before.get('elf_sha256') != config['expected_elf_sha256']
                    or before.get('elf_match') is not True
                    or after.get('elf_match') is not True):
                return False
            if (type(sidecar.get('pre_submit_accounts')) is not dict
                    or set(sidecar['pre_submit_accounts']) != set(AMBIGUOUS_ACCOUNT_NAMES)
                    or type(sidecar.get('final_accounts')) is not dict
                    or set(sidecar['final_accounts']) != set(AMBIGUOUS_ACCOUNT_NAMES)
                    or type(sidecar.get('pre_stop_accounts')) is not dict
                    or set(sidecar['pre_stop_accounts']) != set(AMBIGUOUS_ACCOUNT_NAMES)):
                return False
            pre_hashes = []
            final_hashes = []
            pre_stop_hashes = []
            pre_stop_paths = []
            pre_paths = []
            final_paths = []
            for name in AMBIGUOUS_ACCOUNT_NAMES:
                for group, prefix, hash_list, paths in (
                        ('pre_submit_accounts', 'pre-submit-', pre_hashes, pre_paths),
                        ('pre_stop_accounts', 'pre-stop-', pre_stop_hashes, pre_stop_paths),
                        ('final_accounts', 'final-', final_hashes, final_paths)):
                    ref = sidecar[group][name]
                    if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
                            or not _hash(ref.get('sha256'))
                            or Path(ref['path']).parent != Path(config['execute_output'])
                            or Path(ref['path']).name != f'{prefix}{name}.bin'):
                        return False
                    _read(ref['path'], ref['sha256'], 4096)
                    hash_list.append(ref['sha256'])
                    paths.append(ref['path'])
            if (pre_stop_hashes != final_hashes
                    or status.get('pre_stop_account_sha256') != pre_stop_hashes
                    or status.get('pre_stop_account_paths') != pre_stop_paths):
                return False
            pre_report_ref = sidecar['pre_submit_report']
            if (Path(pre_report_ref['path']) != Path(config['execute_output']) / 'pre-submit-report.json'
                    or pre_report.get('schema') != 'part5-v3-ambiguous-pre-submit-v1'
                    or pre_report.get('training_only') is not True
                    or pre_report.get('application_effect') is not False
                    or pre_report.get('request_consumed') is not False
                    or pre_report.get('stage_report_sha256') != sidecar['stage_report_sha256']
                    or pre_report.get('stage_plan_sha256') != sidecar['stage_plan_sha256']
                    or pre_report.get('wire_sha256') != sidecar['full_wire']['sha256']
                    or pre_report.get('account_sha256') != pre_hashes
                    or status.get('pre_submit_account_sha256') != pre_hashes
                    or status.get('final_account_sha256') != final_hashes
                    or status.get('final_account_paths') != final_paths):
                return False
            if (Path(sidecar['status']['path']) != Path(config['control_output']) / 'status.json'
                    or Path(sidecar['proxy_receipt']['path'])
                        != Path(config['control_output']) / 'proxy-receipt.json'
                    or Path(sidecar['finality_receipt']['path'])
                        != Path(config['control_output']) / 'finality-receipt.json'
                    or Path(sidecar['pre_restart_finality_receipt']['path'])
                        != Path(config['control_output']) / 'pre-restart-finality-receipt.json'
                    or Path(config['proxy_script']) != REPO / AMBIGUOUS_RESTART_PROXY):
                return False
            if (set(proxy_receipt) != {
                    'schema', 'status', 'target_wire_sha256', 'transaction_sha256',
                    'signature', 'matching_submissions', 'duplicate_matching_submissions',
                    'duplicate_rejected', 'forward_attempted', 'forwarded', 'response_dropped'}
                    or proxy_receipt.get('schema') != 'queue-v3-ambiguous-rpc-proxy-receipt-v1'
                    or proxy_receipt.get('status') != 'response_dropped'
                    or proxy_receipt.get('target_wire_sha256') != sidecar['full_wire']['sha256']
                    or proxy_receipt.get('matching_submissions') != 1
                    or proxy_receipt.get('duplicate_matching_submissions') != 0
                    or proxy_receipt.get('duplicate_rejected') is not False
                    or proxy_receipt.get('forward_attempted') != 1
                    or proxy_receipt.get('forwarded') != 1
                    or proxy_receipt.get('response_dropped') is not True
                    or not _hash(proxy_receipt.get('transaction_sha256'))):
                return False
            from harness.tests import queue_v3_ambiguous_rpc_proxy as proxy_tools
            proxy_tools.decode_base58_signature(proxy_receipt.get('signature'))
            if (status.get('signature_sha256') != digest(proxy_receipt['signature'].encode())
                    or status.get('transaction_sha256')
                        != proxy_receipt['transaction_sha256']):
                return False
            if (type(finality_receipt) is not dict
                    or set(finality_receipt) != {
                        'schema', 'signature', 'signature_status', 'transaction'}
                    or finality_receipt.get('schema')
                        != 'part5-v3-ambiguous-finality-receipt-v1'
                    or finality_receipt.get('signature') != proxy_receipt['signature']):
                return False
            finality_status = finality_receipt.get('signature_status')
            finality_transaction = finality_receipt.get('transaction')
            finality_slot = status.get('signature_finalized_slot')
            if (type(finality_status) is not dict
                    or set(finality_status) != {'slot', 'confirmationStatus', 'err'}
                    or finality_status.get('confirmationStatus') != 'finalized'
                    or finality_status.get('err') is not None
                    or type(finality_status.get('slot')) is not int
                    or type(finality_slot) is not int
                    or finality_status.get('slot') != finality_slot
                    or type(finality_transaction) is not dict
                    or set(finality_transaction) != {'slot', 'meta', 'signatures'}
                    or type(finality_transaction.get('slot')) is not int
                    or finality_transaction.get('slot') != finality_slot
                    or type(finality_transaction.get('meta')) is not dict
                    or set(finality_transaction['meta']) != {'err'}
                    or finality_transaction['meta'].get('err') is not None
                    or finality_transaction.get('signatures')
                        != [proxy_receipt['signature']]):
                return False
            if (loaded['pre_restart_finality_receipt'] != finality_receipt
                    or status.get('pre_restart_finality_receipt_path')
                        != sidecar['pre_restart_finality_receipt']['path']
                    or status.get('pre_restart_finality_receipt_sha256')
                        != sidecar['pre_restart_finality_receipt']['sha256']
                    or status.get('pre_restart_signature_finalized_slot') != finality_slot
                    or type(status.get('pre_stop_accounts_slot')) is not int
                    or type(status.get('finalized_accounts_slot')) is not int
                    or not finality_slot <= status['pre_stop_accounts_slot']
                        <= status['finalized_accounts_slot']):
                return False
            chronology = [status.get(name) for name in (
                'pre_restart_finality_elapsed_seconds', 'pre_stop_accounts_elapsed_seconds',
                'first_validator_stop_elapsed_seconds', 'restart_identity_elapsed_seconds',
                'post_restart_finality_elapsed_seconds', 'final_accounts_elapsed_seconds',
                'elapsed_seconds')]
            if (any(type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    for value in chronology)
                    or chronology != sorted(chronology)
                    or chronology[-1] > outer['duration_seconds']):
                return False
            control = Path(config['control_output'])
            stdout = _read_ambiguous_runner_log(control / 'runner.stdout.log')
            stderr = _read_ambiguous_runner_log(control / 'runner.stderr.log')
            marker = b'RPC sendTransaction transport failed'
            if marker not in stdout and marker not in stderr:
                return False
            return True
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return False

    def _clone_r1(self, request, label, root, transition):
        clone_root = root / (label + '-clone')
        if not clone_root.exists():
            clone_root.mkdir(mode=0o700)
        destination, receipt_path = clone_root / 'ledger', clone_root / 'clone-report.json'
        if receipt_path.exists():
            receipt = _json(receipt_path)
            if (receipt.get('schema') != 'part5-v3-r1-ledger-clone-v1'
                    or receipt.get('transition_report_sha256') != transition['report_sha256']):
                raise ValueError('existing R1 clone receipt is not this transition')
            return {'root': str(clone_root), 'ledger': str(destination),
                    'receipt': str(receipt_path), 'receipt_sha256': digest(_read(receipt_path)),
                    'monitor': str(root / (label + '-clone-monitor.json')),
                    'monitor_sha256': digest(_read(root / (label + '-clone-monitor.json'))),
                    'monitor_owner': f'heldout-v{self.variant:02d}-{request}-clone-{label}',
                    'wall_seconds': _json(root / (label + '-clone-monitor.json'))['duration_seconds']}
        command = [sys.executable, str(self.toolpaths['r1_clone']),
            '--source', _json(Path(transition['config']))['ledger'],
            '--destination', str(destination), '--transition-report', transition['report'],
            '--transition-sha', transition['report_sha256'],
            '--transition-status', transition['status_path'], '--status-sha', transition['status_sha256'],
            '--transition-monitor', transition['monitor'], '--monitor-sha', transition['monitor_sha256']]
        monitor_dir, monitor_path = root / (label + '-clone-monitor'), root / (label + '-clone-monitor.json')
        owner = f'heldout-v{self.variant:02d}-{request}-clone-{label}'
        outer = self.bounded_run(owner, command, monitor_dir, monitor_path,
            runtime=LIMITS['runtime_seconds'], storage_paths=(clone_root,))
        receipt = _json(receipt_path)
        if (outer.get('passed') is not True or receipt.get('copy_identical') is not True
                or receipt.get('loaded_identity_rechecked_after_restart') is not False):
            raise ValueError('bounded heldout R1 clone failed review')
        return {'root': str(clone_root), 'ledger': str(destination),
                'receipt': str(receipt_path), 'receipt_sha256': digest(_read(receipt_path)),
                'monitor': str(monitor_path), 'monitor_sha256': digest(_read(monitor_path)),
                'monitor_owner': owner, 'wall_seconds': outer['duration_seconds']}

    def _execute_full(self, request, root, stage, clone, proof, replay_proof):
        output, control = self._art(request, 'execute'), self._art(request, 'execute-control')
        wire = proof['wires']['r0_full_wire']
        replay_wire = replay_proof['wires']['r0_full_wire']
        original_raw = _read(wire['path'], wire['sha256'], 1024)
        replay_raw = _read(replay_wire['path'], replay_wire['sha256'], 1024)
        if (len(original_raw) != 448 or len(replay_raw) != 448
                or original_raw[:192] != replay_raw[:192]
                or original_raw[192:] == replay_raw[192:]):
            raise ValueError('fresh replay Full proof must differ under identical six publics')
        config_path = root / 'execute-config.json'
        config = {'schema': 1, 'scope': 'part5-v3-local-execute',
            'prior_stage_config': stage['config'], 'prior_stage_config_sha256': stage['config_sha256'],
            'prior_stage_status': stage['status_path'], 'prior_stage_status_sha256': stage['status_sha256'],
            'prior_stage_monitor': stage['monitor'], 'prior_stage_monitor_sha256': stage['monitor_sha256'],
            'prior_monitor_owner': stage['monitor_owner'], 'stage_root': stage['root'],
            'stage_report_sha256': stage['report_sha256'], 'stage_plan_sha256': stage['plan_sha256'],
            'ledger': clone['ledger'], 'heldout_r0_clone_report': clone['receipt'],
            'heldout_r0_clone_report_sha256': clone['receipt_sha256'],
            'expected_genesis': _json(Path(stage['report']))['genesis'],
            'context': str(self.output_root / 'pair-view' / 'stage-context.json'),
            'context_sha256': digest(_read(self.output_root / 'pair-view' / 'stage-context.json')),
            'runner': self.manifest['runner'], 'runner_sha256': self.manifest['runner_sha256'],
            'full_wire': wire['path'], 'full_wire_sha256': wire['sha256'],
            'replay_full_wire': replay_wire['path'],
            'replay_full_wire_sha256': replay_wire['sha256'],
            'execute_output': output, 'control_output': control,
            'outer_limits_required': LIMITS}
        config_sha = self._write_config(config_path, config)
        monitor_dir, monitor_path = root / 'execute-monitor', root / 'execute-monitor.json'
        owner = f'heldout-v{self.variant:02d}-{request}-execute-full'
        report_path, status_path = Path(output) / 'execute-report.json', Path(control) / 'status.json'
        if report_path.exists() and status_path.exists() and monitor_path.exists():
            outer = _json(monitor_path)
            report, status = _json(report_path), _json(status_path)
        elif Path(output).exists() or Path(control).exists() or monitor_dir.exists() or monitor_path.exists():
            raise ValueError('partial prior Full effect output requires manual review')
        else:
            outer = self.bounded_run(owner, [sys.executable, str(self.toolpaths['execute']),
                '--config', str(config_path), '--config-sha256', config_sha], monitor_dir, monitor_path,
                runtime=LIMITS['runtime_seconds'],
                storage_paths=(Path(clone['ledger']), Path(output), Path(control)),
                env={'P5_V3_EXEC_SUPERVISOR': 'local-ledger-review-and-execute'})
            report, status = _json(report_path), _json(status_path)
        if (not reviewed_application_outer(outer)
                or report.get('schema') != 'part5-v3-local-execute-v1'
                or report.get('passed') is not True or report.get('effect_count') != 1
                or report.get('request_consumed') is not True
                or report.get('replay_wire_sha256') != replay_wire['sha256']
                or status.get('status') != 'failed'
                or status.get('error_type') is not None
                or status.get('effect_verified') is not True
                or status.get('application_effect') is not True
                or status.get('effect_count') != 1
                or status.get('execute_report_sha256') != digest(_read(report_path))
                or not reviewed_validator_sigint(status.get('validator_cleanup'))
                or not reviewed_runner_exit(status.get('runner_cleanup'))):
            raise ValueError('pinned Full R0 Execute result required')
        return {'status': 'passed', 'report': str(report_path),
            'report_sha256': digest(_read(report_path)), 'status_path': str(status_path),
            'status_sha256': digest(_read(status_path)), 'config': str(config_path),
            'config_sha256': config_sha, 'outer': str(monitor_path),
            'outer_sha256': digest(_read(monitor_path)), 'monitor': str(monitor_path),
            'monitor_sha256': digest(_read(monitor_path)), 'monitor_owner': owner,
            'accounts': {name: str(Path(output) / f'{name}.bin')
                         for name in ('config', 'issuer', 'head', 'request', 'queue')},
            'wires': {'full': wire, 'replay_full': replay_wire},
            'wall_seconds': outer['duration_seconds']}

    def _run_branch(self, request, label, mode, root, stage, transition, clone,
                    proof_bundles, wires):
        output, control = self._art(request, label), self._art(request, label + '-control')
        config_path = root / (label + '-config.json')
        from tools.part5 import create_v3_branch_config as branch_config
        proof_receipt = (proof_bundles['full'] if mode == 'full'
                         else proof_bundles.get('anchor'))
        kwargs = dict(mode=mode,
            transition_config=transition['config'], transition_report=transition['report'],
            transition_status=transition['status_path'], transition_monitor=transition['monitor'],
            clone_report=clone['receipt'], full_wire=wires['full']['path'],
            anchor_wire=wires['anchor']['path'], runner=self.manifest['runner'],
            branch_output=output, control_output=control, output=str(config_path),
            full_near_wire=wires.get('full_near', {}).get('path'),
            full_near_proof_report=(proof_bundles['full']['proof_report']['path']
                if mode == 'full' else None),
            matched_proof_report=(proof_receipt['proof_report']['path']
                if mode in ('full', 'anchor') else None))
        if config_path.exists():
            config_sha = digest(_read(config_path))
            existing = _json(config_path, config_sha)
            if (existing.get('mode') != mode or existing.get('ledger') != clone['ledger']
                    or existing.get('transition_report_sha256') != transition['report_sha256']):
                raise ValueError('saved R1 branch config belongs to another clone/transition')
        else:
            config_sha = branch_config.create(SimpleNamespace(**kwargs))
        monitor_dir, monitor_path = root / (label + '-monitor'), root / (label + '-monitor.json')
        owner = f'heldout-v{self.variant:02d}-{request}-{label}'
        report_path, status_path = Path(output) / 'branch-report.json', Path(control) / 'status.json'
        if report_path.exists() and status_path.exists() and monitor_path.exists():
            outer = _json(monitor_path)
            report, status = _json(report_path), _json(status_path)
        elif Path(output).exists() or Path(control).exists() or monitor_dir.exists() or monitor_path.exists():
            raise ValueError('partial prior R1 branch output requires manual review')
        else:
            outer = self.bounded_run(owner, [sys.executable, str(self.toolpaths['branch']),
                '--config', str(config_path), '--config-sha256', config_sha], monitor_dir, monitor_path,
                runtime=LIMITS['runtime_seconds'], storage_paths=(Path(output),),
                env={'P5_V3_BRANCH_SUPERVISOR': 'reviewed-r1-clone'})
            report, status = _json(report_path), _json(status_path)
        if (not reviewed_r1_branch(outer, status, report, mode)
                or status.get('branch_report_sha256') != digest(_read(report_path))):
            raise ValueError(f'pinned {label} R1 branch result required')
        refs = {name: str(Path(output) / f'{name}.bin')
                for name in ('config', 'issuer', 'head', 'request', 'queue')}
        proof_bundle = ({name: self._proof_bundle(value) for name, value in proof_bundles.items()}
                        if mode == 'full' else self._proof_bundle(proof_receipt))
        result = {'status': 'passed', 'report': str(report_path),
            'report_sha256': digest(_read(report_path)), 'status_path': str(status_path),
            'status_sha256': digest(_read(status_path)), 'config': str(config_path),
            'config_sha256': config_sha, 'outer': str(monitor_path),
            'outer_sha256': digest(_read(monitor_path)), 'monitor': str(monitor_path),
            'monitor_sha256': digest(_read(monitor_path)), 'monitor_owner': owner,
            'accounts': refs, 'wires': wires,
            'signed_history': str(Path(output) / 'signed-history.json'),
            'proof': proof_bundle, 'wall_seconds': outer['duration_seconds']}
        return result

    def _r2_active_witness_rejection(self, root, case_root, r1_source, proof, effect):
        """Record the current-R2 failed witness and an independent R1CS counterfactual."""
        from tools.part5 import prepare_v3_heldout_proof as proof_tool

        branch = _json(effect['report'], effect['report_sha256'])
        membership = _json(case_root / 'membership.json')
        unrelated_root = membership.get('unrelated_root')
        own_revoked_root = membership.get('own_revoked_root')
        if (type(unrelated_root) is not int or not 0 <= unrelated_root < proof_tool.FR
                or type(own_revoked_root) is not int
                or not 0 <= own_revoked_root < proof_tool.FR):
            raise ValueError('canonical unrelated R1 and own-revoked R2 field elements required')
        r1_root = f'{unrelated_root:064x}'
        r2_root = f'{own_revoked_root:064x}'
        if (branch.get('mode') != 'own-revocation'
                or branch.get('application_effect') is not False
                or branch.get('current_root') != r2_root
                or branch.get('request_consumed') is not False):
            raise ValueError('loaded own-revocation R2 denial required before witness check')
        source = _json(r1_source['receipt'], r1_source['receipt_sha256'])
        proof_receipt = _json(proof['receipt'], proof['receipt_sha256'])
        if (source.get('selected_root') != r1_root
                or proof_receipt.get('source_receipts', {}).get('R1', {}).get('sha256')
                   != r1_source['receipt_sha256']):
            raise ValueError('C R1 witness source and proof required')
        source_input_path = Path(r1_source['root']) / 'input.json'
        source_input = _json(source_input_path, source['artifacts_sha256']['input.json'])
        near_input_ref = proof_receipt['artifacts']['near/input.json']
        if _json(near_input_ref['path'], near_input_ref['sha256']) != source_input:
            raise ValueError('C R1 proof input differs from C source input')
        coordinates_path = Path(r1_source['root']) / 'input-coordinates.bin'
        coordinates_ref = {'path': str(coordinates_path),
                           'sha256': source['artifacts_sha256']['input-coordinates.bin']}
        coordinates = _read(coordinates_path, coordinates_ref['sha256'], 4096)
        r1_witness_ref = proof_receipt['artifacts']['near/output.wtns']
        r1_witness = _read(r1_witness_ref['path'], r1_witness_ref['sha256'],
                           32 * 1024 * 1024)
        siblings = membership['own_revoked_siblings']
        candidate_input = proof_tool.build_r2_active_witness_input(
            source_input, r2_root, siblings)
        if (source_input['root'] != str(int(r1_root, 16))
                or candidate_input['actionHash'] != str(int(source['action_hash'], 16))):
            raise ValueError('R2 candidate must preserve C R1 root and action')

        work = root / 'r2-active-witness'
        if work.exists() or work.is_symlink():
            raise ValueError('partial R2 witness rejection output requires manual review')
        _private_dir(work, fresh=True, ignored=True)
        candidate_dir = _private_dir(work / 'candidate', fresh=True)
        relation_dir = _private_dir(work / 'relation', fresh=True)
        supervision = _private_dir(work / 'supervisor', fresh=True)
        base_path, candidate_path = work / 'base-r1-input.json', candidate_dir / 'input.json'
        base_ref = {'path': str(base_path), 'sha256': _write_new(base_path, encoded(source_input))}
        candidate_ref = {'path': str(candidate_path),
                         'sha256': _write_new(candidate_path, encoded(candidate_input))}
        frozen = self.manifest['frozen_files']
        proof_inputs = self.manifest['proof_inputs']
        session_runner = _load_module('heldout_r2_session_runner',
                                      REPO / 'results/dynark/part5/session_runner.py')

        def supervised(label, command, limits, storage_path):
            if self._active_job:
                raise RuntimeError('only one bounded child may run at a time')
            owner = f'heldout-v{self.variant:02d}-own-r2-{label}'
            monitor_dir = supervision / (label + '-monitor')
            report_path = supervision / (label + '-report.json')
            self._active_job = True
            try:
                outer = session_runner.run(owner=owner, command=[str(v) for v in command],
                    cwd=str(REPO), private_output=str(monitor_dir), report=str(report_path),
                    runtime_seconds=limits['runtime_seconds'],
                    rss_bytes=limits['rss_bytes'], storage_bytes=limits['storage_bytes'],
                    storage_paths=[str(storage_path)], poll_seconds=0.25,
                    environment={'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1',
                                 'TZ': 'UTC'})
            finally:
                self._active_job = False
            if (outer.get('stop_reason') is not None or outer.get('censored') is not False
                    or outer.get('runner_error_type') is not None
                    or outer.get('cleanup_remaining_owned_processes') != 0
                    or outer.get('cleanup_status_unknown') is not False):
                raise ValueError(f'bounded R2 {label} did not complete cleanly')
            return (outer, {'path': str(report_path),
                            'sha256': digest(_read(report_path, cap=1024 * 1024))},
                    {'path': str(monitor_dir / 'invocation.json'),
                     'sha256': digest(_read(monitor_dir / 'invocation.json'))}, owner)

        generated, generator_ref, generator_invocation_ref, _ = supervised('generator', [
            proof_inputs['node']['path'], proof_inputs['witness_js']['path'],
            candidate_dir], proof_tool.WITNESS_LIMITS, candidate_dir)
        if (generated.get('exit_code') != 2 or generated.get('passed') is not False
                or (candidate_dir / 'output.wtns').exists()
                or (candidate_dir / 'output.wtns').is_symlink()):
            raise ValueError('pinned R2 active witness generator did not reject without WTNS')
        patched = proof_tool.patch_r1_wtns_for_r2_counterfactual(
            r1_witness, coordinates, r2_root, siblings)
        patched_path = work / 'counterfactual.wtns'
        patched_ref = {'path': str(patched_path), 'sha256': _write_new(patched_path, patched)}
        result_path = relation_dir / 'r1cs-result.json'
        checker = REPO / 'tools/part5/check_v3_r2_counterfactual.py'
        checker_ref = self._artifact(checker)
        relation, relation_ref, relation_invocation_ref, relation_owner = supervised('relation', [
            sys.executable, '-B', checker,
            '--candidate-input', candidate_path,
            '--candidate-input-sha256', candidate_ref['sha256'],
            '--witness', patched_path, '--witness-sha256', patched_ref['sha256'],
            '--base-r1-witness', r1_witness_ref['path'],
            '--base-r1-witness-sha256', r1_witness_ref['sha256'],
            '--r1cs', frozen['r1cs']['path'], '--r1cs-sha256', frozen['r1cs']['sha256'],
            '--relation-checker', proof_inputs['relation_checker']['path'],
            '--relation-checker-sha256', proof_inputs['relation_checker']['sha256'],
            '--output', result_path], proof_tool.RELATION_LIMITS, relation_dir)
        if relation.get('exit_code') != 0 or relation.get('passed') is not True:
            raise ValueError('pinned R2 counterfactual relation check did not complete')
        relation_result = _json(result_path)
        result_ref = self._artifact(result_path)
        receipt = proof_tool.r2_active_witness_rejection_receipt(
            base_input=source_input, candidate_input=candidate_input,
            r2_root=r2_root, own_revoked_siblings=siblings,
            action_hash=source['action_hash'],
            target_credential_sha256=source['target_der_sha256'],
            target_tbs_sha256=source['target_tbs_sha256'],
            witness_generator_sha256=proof_inputs['witness_js']['sha256'],
            relation_checker_sha256=proof_inputs['relation_checker']['sha256'],
            r1cs_sha256=frozen['r1cs']['sha256'],
            bounded_supervisor_sha256=proof_inputs['bounded_supervisor']['sha256'],
            generator_supervisor_ref=generator_ref,
            generator_invocation_ref=generator_invocation_ref,
            generator_supervisor_limits=proof_tool.WITNESS_LIMITS,
            generator_exit_code=generated['exit_code'], generated_wtns_present=False,
            base_input_ref=base_ref, candidate_input_ref=candidate_ref,
            input_coordinates_ref=coordinates_ref, r1_witness_ref=r1_witness_ref,
            counterfactual_witness_ref=patched_ref, relation_result=relation_result,
            relation_result_ref=result_ref, relation_supervisor_ref=relation_ref,
            relation_invocation_ref=relation_invocation_ref,
            relation_supervisor_limits=proof_tool.RELATION_LIMITS,
            relation_exit_code=relation['exit_code'])
        receipt_path = work / 'r2-active-witness-rejection.json'
        receipt_ref = {'path': str(receipt_path),
                       'sha256': _write_new(receipt_path, encoded(receipt))}
        return {'status': 'passed', 'receipt': str(receipt_path),
                'receipt_sha256': receipt_ref['sha256'],
                'monitor': relation_ref['path'], 'monitor_sha256': relation_ref['sha256'],
                'monitor_owner': relation_owner,
                'generator_monitor': generator_ref['path'],
                'generator_monitor_sha256': generator_ref['sha256'],
                'counterfactual_checker_sha256': checker_ref['sha256'],
                'wall_seconds': generated['duration_seconds'] + relation['duration_seconds']}

    @staticmethod
    def _proof_bundle(proof):
        receipt = _json(Path(proof['receipt']))
        return {'receipt': {'path': proof['receipt'], 'sha256': proof['receipt_sha256']},
                'artifacts': receipt['artifacts']}

    @staticmethod
    def _disabled_config_sidecar_verified(path, expected_sha256):
        try:
            sidecar = _json(path, expected_sha256, 1024 * 1024)
            if (type(sidecar) is not dict
                    or set(sidecar) != DISABLED_CONFIG_SIDECAR_KEYS
                    or sidecar.get('schema') != DISABLED_CONFIG_SIDECAR_SCHEMA
                    or type(sidecar.get('variant')) is not int
                    or not 0 <= sidecar['variant'] < 8):
                return False
            refs = ('clone_receipt', 'full_wire', 'config', 'rust_config',
                    'status', 'outer', 'report')
            for field in refs:
                ref = sidecar[field]
                if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
                        or not _hash(ref.get('sha256'))):
                    return False
                _read(ref['path'], ref['sha256'], 32 * 1024 * 1024)
            for group in ('eligible_accounts', 'before_accounts', 'after_accounts',
                          'issuer_eligible_accounts', 'issuer_before_accounts',
                          'issuer_after_accounts'):
                rows = sidecar[group]
                if type(rows) is not dict or set(rows) != set(NEGATIVE_ACCOUNT_NAMES):
                    return False
                for ref in rows.values():
                    if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
                            or not _hash(ref.get('sha256'))):
                        return False
                    _read(ref['path'], ref['sha256'], 4096)
            for field in ('stage_report_sha256', 'stage_plan_sha256',
                          'r0_source_receipt_sha256', 'full_proof_receipt_sha256'):
                if not _hash(sidecar.get(field)):
                    return False
            return True
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return False

    def _request_proof(self, req, mode, root, case_root, stage, transition,
                       r0_source, r1_source, *, label=None):
        name = f'{req}:proof-{mode}' + (('-' + label) if label else '')
        inputs = {'mode': mode, 'r0_source_sha256': r0_source['receipt_sha256'],
            'r1_source_sha256': r1_source['receipt_sha256'],
            'transition_report_sha256': transition['report_sha256'],
            'proof_caps': self.manifest['proof_caps'][mode]}
        if label:
            inputs['test_only_label'] = label
        proof = self.journal.run_step(name, inputs=inputs,
            job=lambda: self._proof(req, mode, root, case_root, stage, transition,
                                    r0_source, r1_source, label=label),
            reuse=lambda saved: self._verify_record(saved, ('receipt',), ('receipt_sha256',)))
        # The proof helper records each witness/relation/proof/adapter bounded
        # report inside its receipt; this wall time includes complete refresh.
        return proof

    def _source_bundle(self, source):
        receipt_path = Path(source['receipt'])
        receipt = _json(receipt_path)
        return {'receipt': self._artifact(receipt_path),
                'artifacts': {name: self._artifact(receipt_path.parent / name)
                              for name in receipt['artifacts_sha256']}}

    def _stage_bundle(self, stage):
        root = Path(stage['root'])
        return {'report': self._artifact(stage['report']),
            'plan': self._artifact(stage['plan']),
            'allocations': self._artifact(root / 'initial-allocations.json'),
            'signed_history': self._artifact(root / 'signed-history.json'),
            'accounts': {name: self._artifact(root / (name + '.bin'))
                         for name in ('config', 'issuer', 'head', 'request', 'queue')},
            'config': self._artifact(stage['config']), 'status': self._artifact(stage['status_path']),
            'monitor': self._artifact(stage['monitor']), 'monitor_owner': stage['monitor_owner']}

    def _transition_bundle(self, transition):
        root = Path(transition['root'])
        outer_ref = self._artifact(transition['monitor'])
        return {'report': self._artifact(transition['report']),
            'status': self._artifact(transition['status_path']), 'outer': outer_ref,
            'config': self._artifact(transition['config']), 'monitor': outer_ref,
            'monitor_owner': transition['monitor_owner'],
            'context': self._artifact(transition['context']),
            'signed_history': self._artifact(root / 'signed-history.json'),
            'signed_source': self._artifact(root / 'signed-source.json'),
            'enrolled_source': self._artifact(root / 'enrolled-source.json'),
            'accounts': {name: self._artifact(root / (name + '.bin'))
                         for name in ('config', 'issuer', 'head', 'request', 'queue')}}

    def _full_result_bundle(self, result):
        outer = self._artifact(result['outer'])
        return {'report': self._artifact(result['report']), 'status': self._artifact(result['status_path']),
            'outer': outer, 'monitor': outer, 'monitor_owner': result['monitor_owner'],
            'config': self._artifact(result['config']),
            'wires': {name: self._artifact(result['wires'][name]['path'])
                      for name in ('full', 'replay_full')},
            'accounts': {name: self._artifact(path) for name, path in result['accounts'].items()}}

    def _branch_result_bundle(self, result):
        outer = self._artifact(result['outer'])
        bundle = {'report': self._artifact(result['report']), 'status': self._artifact(result['status_path']),
            'outer': outer, 'monitor': outer, 'monitor_owner': result['monitor_owner'],
            'config': self._artifact(result['config']),
            'wires': {name: self._artifact(ref['path']) for name, ref in result['wires'].items()},
            'accounts': {name: self._artifact(path) for name, path in result['accounts'].items()},
            'signed_history': self._artifact(result['signed_history'])}
        return bundle

    def run(self):
        from tools.part5 import prepare_v3_heldout_context as context_builder
        case_root = self.output_root / 'pair-view'
        def pair_view_receipt():
            _private_dir(case_root)
            pair_doc = _json(case_root / 'cohort-receipt.json')
            case_doc = _json(case_root / 'case-context.json')
            if (case_doc.get('target', {}).get('variant') != self.variant
                    or pair_doc.get('heldout_acceptance') is not False):
                raise ValueError('existing pair view belongs to another heldout variant')
            return {'case_context_sha256': digest(_read(case_root / 'case-context.json')),
                    'pair_receipt_sha256': digest(_read(case_root / 'cohort-receipt.json'))}

        def prepare_pair_view():
            if case_root.exists() or case_root.is_symlink():
                raise ValueError('pair view without completed timed journal step requires review')
            case_root.mkdir(mode=0o700)
            pair = context_builder.prepare(Path(self.manifest['cohort_root']),
                self.manifest['cohort_sha256'], self.variant, case_root)
            receipt = pair_view_receipt()
            if any(pair.get(name) != value for name, value in receipt.items()):
                raise ValueError('prepared pair view differs from its written receipt')
            return {'status': 'passed', **receipt}

        def reuse_pair_view(saved):
            try:
                return all(saved.get(name) == value
                           for name, value in pair_view_receipt().items())
            except (OSError, ValueError, KeyError, TypeError):
                return False

        with self.journal:
            pair_step = self.journal.run_step('pair-view',
                inputs={'cohort': self.manifest['cohort_sha256'], 'variant': self.variant},
                job=prepare_pair_view, reuse=reuse_pair_view)
            context_sha = pair_step['case_context_sha256']
            results = {}
            branch_results = {}
            branch_order = ['unrelated_full', 'anchor'] if self.variant % 2 == 0 else ['anchor', 'unrelated_full']
            for spec in request_matrix():
                req = spec['name']
                root = self._layout(req)
                request_inputs = {'case_context_sha256': context_sha,
                    'prepare_template_sha256': self.manifest['base_prepare_config_sha256'],
                    'request_slot': spec['request_slot']}
                prepare_result = self.journal.run_step(req + ':prepare', inputs=request_inputs,
                    job=lambda req=req, root=root: {'status': 'passed', **self._prepare(
                        req, root, case_root, case_root / 'stage-context.json')},
                    reuse=lambda saved: self._verify_record(saved,
                        ('config', 'status_path', 'monitor')))
                stage, transition, positive_full_clones = self._stage_transition(
                    req, root, case_root, request_inputs, prepare_result)
                # Request preparation is intentionally explicit. The R0 and R1
                # builders are reused unchanged; each request has its own roots.
                def source_call(variant, out):
                    out = Path(out)
                    receipt_path = out / 'source-receipt.json'
                    if receipt_path.exists():
                        receipt = _json(receipt_path)
                        return {'status': 'passed', 'root': str(out), 'receipt': str(receipt_path),
                                'receipt_sha256': digest(_read(receipt_path)), 'schema': receipt.get('schema'),
                                'monitor': str(root / ('source-' + variant + '-monitor.json')),
                                'monitor_sha256': digest(_read(root / ('source-' + variant + '-monitor.json')))}
                    if not out.exists():
                        out.mkdir(mode=0o700)
                    elif any(out.iterdir()):
                        raise ValueError('partial request source output requires review')
                    command = [sys.executable, str(REPO / 'tools/part5/prepare_v3_heldout_source.py'),
                        '--case-root', str(case_root), '--cohort-root', self.manifest['cohort_root'],
                        '--freeze-receipt', self.manifest['freeze_receipt'],
                        '--freeze-sha256', self.manifest['freeze_sha256'], '--stage-root', stage['root'],
                        '--exporter', self.manifest['proof_inputs']['exporter']['path'],
                        '--variant', variant, '--output', str(out)]
                    if variant == 'R0':
                        pass
                    else:
                        command.extend(['--transition-root', transition['root'],
                            '--transition-context', transition['context'],
                            '--transition-context-sha256', transition['context_sha256'],
                            '--r0-source-receipt', r0_source['receipt'],
                            '--r0-source-receipt-sha256', r0_source['receipt_sha256']])
                    monitor_dir = root / ('source-' + variant + '-monitor')
                    monitor_path = root / ('source-' + variant + '-monitor.json')
                    owner = f'heldout-v{self.variant:02d}-{req}-source-{variant}'
                    outer = self.bounded_run(owner, command, monitor_dir, monitor_path,
                        runtime=LIMITS['runtime_seconds'], storage_paths=(out,))
                    if (outer.get('passed') is not True or outer.get('stop_reason') is not None
                            or outer.get('cleanup_remaining_owned_processes') != 0
                            or outer.get('cleanup_status_unknown') is not False):
                        raise ValueError('bounded heldout request source preparation failed')
                    receipt = _json(receipt_path)
                    return {'status': 'passed', 'root': str(out), 'receipt': str(receipt_path),
                            'receipt_sha256': digest(_read(receipt_path)), 'schema': receipt.get('schema'),
                            'monitor': str(monitor_path), 'monitor_sha256': digest(_read(monitor_path)),
                            'monitor_owner': owner}
                source_inputs = {'stage_report_sha256': stage['report_sha256'],
                                 'freeze_sha256': self.manifest['freeze_sha256']}
                r0_source = self.journal.run_step(req + ':source-R0', inputs=source_inputs,
                    job=lambda: source_call('R0', root / 'source-R0'),
                    reuse=lambda saved: self._verify_record(saved, ('receipt', 'monitor'),
                                                           ('receipt_sha256', 'monitor_sha256')))
                r1_source = self.journal.run_step(req + ':source-R1',
                    inputs={**source_inputs, 'transition_report_sha256': transition['report_sha256'],
                            'r0_receipt_sha256': r0_source['receipt_sha256']},
                    job=lambda: source_call('R1', root / 'source-R1'),
                    reuse=lambda saved: self._verify_record(saved, ('receipt', 'monitor'),
                                                           ('receipt_sha256', 'monitor_sha256')))
                results[req] = {'spec': spec, 'root': str(root), 'prepare': prepare_result,
                                'stage': stage, 'transition': transition,
                                'r0_source': r0_source, 'r1_source': r1_source}
                proof_order = list(spec['proof_modes'])
                if req == 'unrelated_compare' and self.variant % 2 == 1:
                    proof_order.reverse()
                proofs = {}
                for mode in proof_order:
                    proofs[mode] = self._request_proof(req, mode, root, case_root,
                        stage, transition, r0_source, r1_source)
                results[req]['proofs'] = proofs

                if req == 'positive_full':
                    replay_proof = self._request_proof(req, 'full', root, case_root,
                        stage, transition, r0_source, r1_source, label='fresh-replay')
                    clone = positive_full_clones['r0']
                    disabled_clone = positive_full_clones['disabled_config']
                    ambiguous_clone = positive_full_clones['ambiguous_restart']
                    full_proof = proofs['full']
                    effect = self.journal.run_step('positive_full:execute',
                        inputs={'stage_report_sha256': stage['report_sha256'],
                                'source_receipt_sha256': r0_source['receipt_sha256'],
                                'proof_receipt_sha256': full_proof['receipt_sha256'],
                                'replay_proof_receipt_sha256': replay_proof['receipt_sha256'],
                                'r0_clone_receipt_sha256': clone['receipt_sha256']},
                        job=lambda req=req, root=root, stage=stage, clone=clone,
                                   proof=full_proof, replay_proof=replay_proof: {
                            **self._execute_full(req, root, stage, clone, proof, replay_proof)},
                        reuse=lambda saved: self._verify_record(saved,
                            ('report', 'status_path', 'config', 'outer'), ('report_sha256', 'status_sha256')))
                    effect['proof'] = self._proof_bundle(full_proof)
                    effect['replay_proof'] = self._proof_bundle(replay_proof)
                    effect['r0_clone'] = clone
                    expiry = self._expired_status_negative(req, root, stage, r0_source,
                        full_proof, positive_full_clones['expired_status'], effect)
                    effect['expired_status_negative'] = {
                        'path': expiry['sidecar'], 'sha256': expiry['sidecar_sha256']}
                    negative_inputs = {
                        'variant': self.variant,
                        'stage_report_sha256': stage['report_sha256'],
                        'stage_plan_sha256': stage['plan_sha256'],
                        'source_receipt_sha256': r0_source['receipt_sha256'],
                        'proof_receipt_sha256': full_proof['receipt_sha256'],
                        'full_wire_sha256': full_proof['wires']['r0_full_wire']['sha256'],
                        'clone_receipt_sha256': disabled_clone['receipt_sha256'],
                        'frozen_elf_sha256': self.manifest['frozen_files']['loaded_elf']['sha256']}
                    disabled_negative = self.journal.run_step(
                        'positive_full:disabled-config-negative', inputs=negative_inputs,
                        job=lambda req=req, root=root, stage=stage, source=r0_source,
                                   proof=full_proof, clone=disabled_clone: {
                            **self._disabled_config_negative(
                                req, root, stage, source, proof, clone)},
                        reuse=lambda saved: self._verify_record(
                            saved, ('sidecar',), ('sidecar_sha256',))
                            and self._disabled_config_sidecar_verified(
                                saved['sidecar'], saved['sidecar_sha256']))
                    effect['disabled_config_negative'] = {
                        'path': disabled_negative['sidecar'],
                        'sha256': disabled_negative['sidecar_sha256']}
                    ambiguous_supervisor_ref = self._frozen_registry_source(
                        AMBIGUOUS_RESTART_SUPERVISOR)
                    ambiguous_proxy_ref = self._frozen_registry_source(
                        AMBIGUOUS_RESTART_PROXY)
                    ambiguous_inputs = {
                        'variant': self.variant,
                        'stage_report_sha256': stage['report_sha256'],
                        'stage_plan_sha256': stage['plan_sha256'],
                        'r0_source_receipt_sha256': r0_source['receipt_sha256'],
                        'full_proof_receipt_sha256': full_proof['receipt_sha256'],
                        'replay_proof_receipt_sha256': replay_proof['receipt_sha256'],
                        'clone_receipt_sha256': ambiguous_clone['receipt_sha256'],
                        'full_wire_sha256': full_proof['wires']['r0_full_wire']['sha256'],
                        'replay_full_wire_sha256': replay_proof['wires']['r0_full_wire']['sha256'],
                        'supervisor_script_sha256': ambiguous_supervisor_ref['sha256'],
                        'proxy_script_sha256': ambiguous_proxy_ref['sha256'],
                        'frozen_elf_sha256': self.manifest['frozen_files']['loaded_elf']['sha256'],
                        'proxy_port': 19500 + self.variant,
                    }
                    ambiguous_owner = (
                        f'heldout-v{self.variant:02d}-{req}-ambiguous-restart')
                    ambiguous_restart = self.journal.run_step(
                        'positive_full:ambiguous-restart',
                        inputs=ambiguous_inputs,
                        job=lambda req=req, root=root, stage=stage, source=r0_source,
                                   proof=full_proof, replay_proof=replay_proof,
                                   ambiguous_clone=ambiguous_clone, clone=clone: {
                            **self._ambiguous_restart(req, root, stage, source, proof,
                                replay_proof, ambiguous_clone, clone)},
                        reuse=lambda saved: self._verify_record(
                            saved, ('sidecar', 'monitor'),
                            ('sidecar_sha256', 'monitor_sha256'))
                            and saved.get('monitor_owner') == ambiguous_owner
                            and self._ambiguous_restart_sidecar_verified(
                                saved['sidecar'], saved['sidecar_sha256'], ambiguous_inputs))
                    effect['ambiguous_restart'] = {
                        'path': ambiguous_restart['sidecar'],
                        'sha256': ambiguous_restart['sidecar_sha256']}
                    branch_results['full'] = {'stage': stage, 'transition': None,
                        'sources': {'R0': r0_source}, 'effect': effect, 'clone': clone}
                elif req == 'unrelated_compare':
                    full_proof, anchor_proof = proofs['full'], proofs['anchor']
                    proof_bundles = {'full': full_proof, 'anchor': anchor_proof}
                    for label in branch_order:
                        branch_name = 'unrelated_full' if label == 'unrelated_full' else 'anchor'
                        mode = 'full' if branch_name == 'unrelated_full' else 'anchor'
                        clone_name = 'r1-full' if mode == 'full' else 'r1-anchor'
                        clone = self.journal.run_step(f'unrelated_compare:{branch_name}:clone',
                            inputs={'transition_report_sha256': transition['report_sha256'],
                                    'label': clone_name},
                            job=lambda req=req, clone_name=clone_name, root=root, transition=transition: {
                                'status': 'passed', **self._clone_r1(req, clone_name, root, transition)},
                            reuse=lambda saved: self._verify_record(saved, ('receipt',), ('receipt_sha256',)))
                        wires = {'full': full_proof['wires']['r0_full_wire'],
                                 'anchor': anchor_proof['wires']['r1_wire']}
                        if mode == 'full':
                            wires['full_near'] = full_proof['wires']['r1_wire']
                        selected_proofs = ({'full': full_proof, 'anchor': anchor_proof}
                                           if mode == 'full' else {'anchor': anchor_proof})
                        effect = self.journal.run_step(f'unrelated_compare:{branch_name}:effect',
                            inputs={'transition_report_sha256': transition['report_sha256'],
                                    'source_r0_sha256': r0_source['receipt_sha256'],
                                    'source_r1_sha256': r1_source['receipt_sha256'],
                                    'proof_mode': mode, 'clone_receipt_sha256': clone['receipt_sha256']},
                            job=lambda req=req, branch_name=branch_name, mode=mode, root=root,
                                stage=stage, transition=transition, clone=clone,
                                selected_proofs=selected_proofs, wires=wires: {
                                    **self._run_branch(req, branch_name, mode, root, stage,
                                        transition, clone, selected_proofs, wires)},
                            reuse=lambda saved: self._verify_record(saved,
                                ('report', 'status_path', 'config', 'outer', 'signed_history'),
                                ('report_sha256', 'status_sha256')))
                        effect['r1_clone'] = clone
                        branch_results[branch_name] = {'stage': stage, 'transition': transition,
                            'sources': {'R0': r0_source, 'R1': r1_source}, 'effect': effect,
                            'clone': clone}
                else:
                    anchor_proof = proofs['anchor']
                    clone = self.journal.run_step('own_revocation:r1-clone',
                        inputs={'transition_report_sha256': transition['report_sha256']},
                        job=lambda req=req, root=root, transition=transition: {
                            'status': 'passed', **self._clone_r1(req, 'r1-own', root, transition)},
                        reuse=lambda saved: self._verify_record(saved, ('receipt',), ('receipt_sha256',)))
                    wires = {'full': anchor_proof['wires']['r0_full_wire'],
                             'anchor': anchor_proof['wires']['r1_wire']}
                    effect = self.journal.run_step('own_revocation:effect',
                        inputs={'transition_report_sha256': transition['report_sha256'],
                                'source_r0_sha256': r0_source['receipt_sha256'],
                                'source_r1_sha256': r1_source['receipt_sha256'],
                                'proof_receipt_sha256': anchor_proof['receipt_sha256'],
                                'clone_receipt_sha256': clone['receipt_sha256']},
                        job=lambda req=req, root=root, stage=stage, transition=transition,
                            clone=clone, anchor_proof=anchor_proof, wires=wires: {
                                **self._run_branch(req, 'own_revocation', 'own-revocation', root,
                                    stage, transition, clone, {'anchor': anchor_proof}, wires)},
                        reuse=lambda saved: self._verify_record(saved,
                            ('report', 'status_path', 'config', 'outer', 'signed_history'),
                            ('report_sha256', 'status_sha256')))
                    r2_rejection = self.journal.run_step('own_revocation:r2-active-witness',
                        inputs={'effect_report_sha256': effect['report_sha256'],
                                'r1_source_receipt_sha256': r1_source['receipt_sha256'],
                                'anchor_proof_receipt_sha256': anchor_proof['receipt_sha256'],
                                'membership_sha256': digest(_read(case_root / 'membership.json')),
                                'frozen_client_sha256': self.freeze_doc['identities']['client']},
                        job=lambda root=root, case_root=case_root, r1_source=r1_source,
                                   anchor_proof=anchor_proof, effect=effect:
                            self._r2_active_witness_rejection(
                                root, case_root, r1_source, anchor_proof, effect),
                        reuse=lambda saved: self._verify_record(saved,
                            ('receipt', 'monitor', 'generator_monitor'),
                            ('receipt_sha256', 'monitor_sha256',
                             'generator_monitor_sha256')))
                    effect['current_r2_witness_rejection'] = {
                        'path': r2_rejection['receipt'],
                        'sha256': r2_rejection['receipt_sha256']}
                    effect['r1_clone'] = clone
                    branch_results['own_revocation'] = {'stage': stage, 'transition': transition,
                        'sources': {'R0': r0_source, 'R1': r1_source}, 'effect': effect,
                        'clone': clone}

            # Keep shared setup/source artifacts at their request slot. The two
            # B outcomes then reference the same evidence while using distinct
            # clone receipts and application result files.
            slots = acceptance_slot_bundles(results,
                stage_bundle=self._stage_bundle,
                transition_bundle=self._transition_bundle,
                source_bundle=self._source_bundle)
            branch_bundles = acceptance_branch_bundles(branch_results,
                result_bundle=lambda effect: (self._full_result_bundle(effect)
                    if effect.get('r0_clone') is not None
                    else self._branch_result_bundle(effect)),
                proof_bundle=lambda value: value,
                clone_bundle=lambda clone: {'receipt': self._artifact(clone['receipt'])})
            case_context = self.output_root / 'pair-view'
            def global_ref(role):
                ref = self.manifest['frozen_files'][role]
                return {'path': ref['path'], 'sha256': ref['sha256']}
            journal_doc = self.journal._read()
            wall_costs = acceptance_wall_costs(journal_doc['steps'])
            all_wall_times = all_step_wall_seconds(journal_doc)
            disabled_negative_wall = disabled_config_negative_wall_seconds(
                journal_doc['steps'])
            ambiguous_restart_wall = ambiguous_restart_wall_seconds(
                journal_doc['steps'])
            expiry_wall = expired_status_negative_wall_seconds(journal_doc['steps'])
            fragment = {'schema': CASE_FRAGMENT_SCHEMA,
                'variant': self.variant,
                'run_manifest': self.run_manifest_ref,
                'case_context': self._artifact(case_context / 'case-context.json'),
                'stage_context': self._artifact(case_context / 'stage-context.json'),
                'pair_receipt': self._artifact(case_context / 'cohort-receipt.json'),
                'membership': self._artifact(case_context / 'membership.json'),
                'branches': branch_bundles,
                'expired_status_negative': branch_results['full']['effect']['expired_status_negative'],
                'disabled_config_negative': {
                    'path': branch_results['full']['effect']['disabled_config_negative']['path'],
                    'sha256': branch_results['full']['effect']['disabled_config_negative']['sha256']},
                'ambiguous_restart': {
                    'path': branch_results['full']['effect']['ambiguous_restart']['path'],
                    'sha256': branch_results['full']['effect']['ambiguous_restart']['sha256']},
                **slots,
                'shared_costs': journal_doc['costs'], **wall_costs,
                'expired_status_negative_wall_seconds': expiry_wall,
                'disabled_config_negative_wall_seconds': disabled_negative_wall,
                'ambiguous_restart_wall_seconds': ambiguous_restart_wall,
                'run_journal': self._artifact(self.journal.path),
                'all_step_wall_seconds': all_wall_times,
                'branch_order': branch_order,
                'proof_order': {'unrelated_compare': list(
                    ['full', 'anchor'] if self.variant % 2 == 0 else ['anchor', 'full'])},
                'freeze_receipt': self._artifact(self.manifest['freeze_receipt']),
                'cohort_receipt': self._artifact(
                    Path(self.manifest['cohort_root']) / 'cohort-receipt.json'),
                'cohort_observation': self.manifest['cohort_observation'],
                'source_files': self.manifest['source_files'],
                'proof_inputs': self.manifest['proof_inputs'],
                'frozen_files': {role: global_ref(role) for role in ROLE_NAMES},
                'frozen_bundles': self.manifest['frozen_bundles'],
                'application_source_manifest': self.manifest['application_source_manifest'],
                'application_source_files': self.manifest['application_source_files']}
            if journal_doc.get('manifest_sha256') != self.manifest_sha256:
                raise ValueError('run journal identity differs from pinned run manifest')
            fragment_path = self.output_root / 'acceptance-case-fragment.json'
            if fragment_path.exists():
                if json.loads(_read(fragment_path)) != fragment:
                    raise ValueError('saved acceptance fragment differs from current evidence')
            else:
                _write_new(fragment_path, json.dumps(fragment, sort_keys=True, indent=2).encode() + b'\n')
            return {'pair_view': pair_step, 'requests': results,
                    'branches': branch_bundles, 'fragment': str(fragment_path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output-root', required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest_raw = _read(args.manifest, cap=1024 * 1024)
        manifest = json.loads(manifest_raw)
        run_manifest_ref, manifest_sha256 = run_manifest_identity(
            args.manifest, manifest_raw, manifest)
        result = HeldoutCaseRunner(manifest, args.output_root,
            run_manifest_ref=run_manifest_ref,
            manifest_sha256=manifest_sha256).run()
    except Exception as error:
        raise SystemExit(f'heldout application case rejected: {type(error).__name__}: {str(error)[:180]}') from None
    print(json.dumps({'schema': RUN_SCHEMA, 'variant': manifest['variant'],
                      'request_names': list(result['requests']), 'journal': str(args.output_root / 'run-journal.json')}))


if __name__ == '__main__':
    main()
