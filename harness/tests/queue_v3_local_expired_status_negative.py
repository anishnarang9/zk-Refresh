#!/usr/bin/env python3
"""Supervise a pinned loaded expired-status candidate on a separate R0 clone.

The external bounded runner owns whole-tree limits and final cleanup evidence.
This supervisor verifies candidate RPC/snapshot facts and reaps its direct children;
it does not construct final external evidence or establish heldout acceptance.
"""
import argparse
import hashlib
import json
import os
import re
import math
import signal
import subprocess
from pathlib import Path
import sys
import stat
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from harness.tests import queue_v3_local_execute as execute
from harness.tests.queue_v3_clone_ledger import inventory as ledger_inventory
from harness.tests.queue_v3_clone_ledger import stale_admin_socket
from tools.part5 import heldout_expired_status_evidence as expired_evidence

LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}
PROCESS_LIMITS = {'validators': 1, 'runners': 1}
MAX_STATUS_AGE = 300
RUST_TEST = 'root_pinned_queue_v3_expired_status_negative'
REPORT_NAME = 'expired-status-negative-report.json'
SCOPE = 'part5-v3-expired-status-negative'
CONFIG_SCHEMA = 'credential-v3-expired-status-negative-supervisor-v1'
REPORT_SCHEMA = expired_evidence.SCHEMA
CANDIDATE_SCHEMA = 'credential-v3-expired-status-negative-rust-candidate-v1'
SUPERVISOR_BUDGET_SECONDS = 150
RUNNER_BUDGET_SECONDS = 140
ACCOUNT_NAMES = expired_evidence.checks.ACCOUNT_NAMES
CANDIDATE_FIELDS = {
    'schema', 'config_ref', 'identities', 'input_refs', 'source_refs',
    'program', 'genesis', 'loaded_program_before', 'loaded_program_after',
    'clock', 'clock_observations', 'preconditions', 'transaction',
    'publisher_transactions', 'account_slots', 'snapshots',
    'runner_observations', 'external_finalization_required',
    'full_proof_verified_in_rust', 'application_effect',
}

# Rust publishes candidate facts; external finalization remains a separate step.
RUST_REPORT_CONTRACT = {
    'entrypoint': RUST_TEST,
    'runner_arguments': [RUST_TEST, '--exact', '--ignored', '--test-threads=1'],
    'config_environment': 'P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG',
    'config_hash_environment': 'P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG_SHA256',
    'scope_environment': 'P5_V3_EXPIRED_STATUS_NEGATIVE_SCOPE',
    'config_schema': CONFIG_SCHEMA,
    'report_name': REPORT_NAME,
    'report_schema': CANDIDATE_SCHEMA,
    'report_fields': sorted(CANDIDATE_FIELDS),
    'identity_roles': list(expired_evidence.IDENTITY_ROLES),
    'full_proof_identity': 'raw SHA-256 of externally pinned Full proof receipt JSON',
    'full_wire_identity': 'raw SHA-256 of separately pinned complete Full wire',
    'transaction_instruction_index': 1,
    'transaction_custom_error': 705,
    'finalized_rpc_required': True,
    'account_names': list(ACCOUNT_NAMES),
    'report_validator': 'harness.tests.queue_v3_local_expired_status_negative._validate_candidate',
    'external_monitor_required': True,
    'unresolved_protocol': (
        'Bind final owner resource measurements and post-exit whole-tree cleanup '
        'from the external bounded runner to the exact Rust report and supervisor '
        'status; Rust cannot assert its own reaping or supervisor validator cleanup.'),
}
PIN_FIELDS = (
    'freeze_sha256', 'expected_genesis_sha256', 'stage_report_sha256', 'stage_plan_sha256',
    'stage_config_sha256', 'stage_status_sha256',
    'source_receipt_sha256', 'clone_receipt_sha256',
    'full_proof_receipt_sha256', 'full_proof_sha256', 'full_wire_sha256',
    'runner_sha256', 'expected_elf_sha256',
)
CONFIG_PATH_FIELDS = (
    'freeze_report', 'stage_config', 'stage_status', 'stage_report', 'stage_plan', 'source_receipt',
    'clone_receipt', 'full_proof_receipt', 'full_proof', 'full_wire',
    'runner', 'expected_elf', 'ledger', 'stage_root', 'output_dir', 'control_output',
)
INPUT_ARTIFACTS = (
    ('freeze_report', 'freeze_sha256', 1024 * 1024),
    ('stage_config', 'stage_config_sha256', 65536),
    ('stage_status', 'stage_status_sha256', 65536),
    ('stage_report', 'stage_report_sha256', 65536),
    ('stage_plan', 'stage_plan_sha256', 65536),
    ('source_receipt', 'source_receipt_sha256', 65536),
    ('clone_receipt', 'clone_receipt_sha256', 65536),
    ('full_proof_receipt', 'full_proof_receipt_sha256', 65536),
    ('full_proof', 'full_proof_sha256', 32 * 1024 * 1024),
    ('full_wire', 'full_wire_sha256', 448),
    ('expected_elf', 'expected_elf_sha256', 4 * 1024 * 1024),
)


class IntegrationRequired(RuntimeError):
    pass


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _is_sha256(value):
    return (type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value))


def _decode(raw, label):
    try:
        value = execute.base.decode_json(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ValueError(f'pinned {label} JSON required') from None
    if type(value) is not dict:
        raise ValueError(f'pinned {label} object required')
    return value


def _private_directory(path, label):
    path = Path(path)
    try:
        meta = path.lstat()
    except OSError:
        raise ValueError(f'private {label} directory required') from None
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid()
            or stat.S_IMODE(meta.st_mode) != 0o700):
        raise ValueError(f'private {label} directory required')
    return path


def _plan_key_bytes(plan, field):
    value = plan.get(field)
    if (type(value) is not list or len(value) != 32
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in value)):
        raise ValueError('pinned 32-byte stage program/genesis arrays required')
    return bytes(value)


def _check_provenance(config, artifacts):
    """Bind all externally pinned artifacts to one heldout stage and clone."""
    freeze = _decode(artifacts['freeze_report'], 'heldout freeze')
    if (freeze.get('schema') != 'credential-v3-frozen-holdout-boundary-v1'
            or type(freeze.get('identities')) is not dict
            or freeze['identities'].get('loaded_elf') != config['expected_elf_sha256']):
        raise ValueError('pinned freeze does not bind the accepted loaded ELF')

    stage_root = _private_directory(config['stage_root'], 'stage root')
    stage_report_path, stage_plan_path = Path(config['stage_report']), Path(config['stage_plan'])
    if (stage_report_path != stage_root / 'stage-report.json'
            or stage_plan_path != stage_root / 'plan.json'):
        raise ValueError('pinned stage report and plan must be in the configured stage root')
    stage_report = _decode(artifacts['stage_report'], 'stage report')
    stage_plan = _decode(artifacts['stage_plan'], 'stage plan')
    program = execute.base.b58(_plan_key_bytes(stage_plan, 'program'))
    genesis = execute.base.b58(_plan_key_bytes(stage_plan, 'genesis'))
    loaded = stage_report.get('loaded_program')
    if (stage_report.get('schema') != 'part5-v3-local-stage-v1'
            or stage_report.get('passed') is not True
            or stage_report.get('training_only') is not True
            or stage_report.get('application_effect') is not False
            or stage_report.get('proof_created') is not False
            or stage_report.get('registry_history_authenticated') is not True
            or stage_report.get('allocation_history_authenticated') is not True
            or stage_report.get('plan_sha256') != config['stage_plan_sha256']
            or stage_report.get('program') != program
            or stage_report.get('genesis') != genesis
            or program != config['expected_program']
            or genesis != config['expected_genesis']
            or type(loaded) is not dict or loaded.get('elf_match') is not True
            or loaded.get('elf_sha256') != config['expected_elf_sha256']):
        raise ValueError('pinned stage report and plan identity provenance mismatch')

    stage_config = _decode(artifacts['stage_config'], 'stage config')
    stage_status = _decode(artifacts['stage_status'], 'stage status')
    stage_status_path = Path(config['stage_status'])
    stage_control = Path(stage_config.get('control_output', ''))
    if (stage_config.get('schema') != 1
            or stage_config.get('scope') != 'part5-v3-local-stage'
            or stage_config.get('stage_output') != str(stage_root)
            or stage_config.get('expected_genesis') != config['expected_genesis']
            or stage_control != stage_status_path.parent
            or stage_status_path != stage_control / 'status.json'
            or stage_status.get('schema') != 1
            or stage_status.get('scope') != 'part5-v3-local-stage'
            # The local stage runner intentionally leaves this status failed
            # after the validator's SIGINT shutdown, even when staging passed.
            or stage_status.get('status') != 'failed'
            or stage_status.get('stage_verified') is not True
            or stage_status.get('ledger_reuse_requires_review') is not True
            or stage_status.get('application_effect') is not False
            or stage_status.get('devnet') is not False
            or stage_status.get('config_sha256') != config['stage_config_sha256']
            or stage_status.get('stage_report_sha256') != config['stage_report_sha256']
            or stage_status.get('stage_output') != str(stage_root)
            or type(stage_status.get('validator_cleanup')) is not dict
            or stage_status['validator_cleanup'].get('spawned') is not True
            or stage_status['validator_cleanup'].get('reaped') is not True
            or stage_status['validator_cleanup'].get('graceful') is not False
            or stage_status['validator_cleanup'].get('exit_code') != -2
            or type(stage_status.get('runner_cleanup')) is not dict
            or stage_status['runner_cleanup'].get('spawned') is not True
            or stage_status['runner_cleanup'].get('reaped') is not True):
        raise ValueError('pinned stage status does not bind the verified report and config')
    if stage_status['runner_cleanup'].get('exit_code') != 0:
        raise ValueError('pinned stage status runner cleanup is not verified')

    source = _decode(artifacts['source_receipt'], 'heldout source receipt')
    if (source.get('schema') != 'credential-v3-heldout-request-source-v1'
            or source.get('variant') != 'R0'
            or type(source.get('case_index')) is not int
            or type(source.get('target_variant')) is not int
            or source.get('case_index') != config['variant']
            or source.get('target_variant') != config['variant']
            or source.get('freeze_sha256') != config['freeze_sha256']
            or source.get('stage_report_sha256') != config['stage_report_sha256']
            or source.get('stage_plan_sha256') != config['stage_plan_sha256']
            or source.get('proof_created') is not False
            or source.get('application_effect') is not False
            or source.get('live_state_authenticated') is not False):
        raise ValueError('pinned R0 source receipt provenance mismatch')

    proof = _decode(artifacts['full_proof_receipt'], 'Full proof receipt')
    proof_source = proof.get('source_receipts', {}).get('R0')
    proof_artifacts = proof.get('artifacts')
    proof_wires = proof.get('wires')
    proof_artifact_matches = (type(proof_artifacts) is dict and any(
        type(ref) is dict and ref.get('path') == config['full_proof']
        and ref.get('sha256') == config['full_proof_sha256']
        for ref in proof_artifacts.values()))
    full_wire = proof_wires.get('r0_full_wire') if type(proof_wires) is dict else None
    if (proof.get('schema') != 'credential-v3-heldout-proof-evidence-v1'
            or proof.get('mode') != 'full'
            or proof.get('target_variant') != config['variant']
            or proof.get('freeze_sha256') != config['freeze_sha256']
            or proof.get('stage_report_sha256') != config['stage_report_sha256']
            or proof.get('stage_plan_sha256') != config['stage_plan_sha256']
            or type(proof_source) is not dict
            or proof_source.get('path') != config['source_receipt']
            or proof_source.get('sha256') != config['source_receipt_sha256']
            or not proof_artifact_matches
            or type(full_wire) is not dict
            or full_wire.get('path') != config['full_wire']
            or full_wire.get('sha256') != config['full_wire_sha256']
            or proof.get('proof_created') is not True
            or proof.get('application_verified') is not False
            or proof.get('validator_run') is not False
            or proof.get('application_effect') is not False):
        raise ValueError('pinned Full proof receipt does not bind its source, proof, and wire')

    ledger = _private_directory(config['ledger'], 'cloned ledger')
    receipt_path = Path(config['clone_receipt'])
    if ledger.name != 'ledger' or receipt_path != ledger.parent / 'clone-report.json':
        raise ValueError('pinned clone receipt must be the cloned ledger sibling receipt')
    clone = _decode(artifacts['clone_receipt'], 'ledger clone receipt')
    source_path = Path(clone.get('source')) if type(clone.get('source')) is str else None
    if (clone.get('schema') != 'part5-v3-heldout-r0-ledger-clone-v1'
            or clone.get('heldout_acceptance') is not False
            or clone.get('stage_report_sha256') != config['stage_report_sha256']
            or clone.get('stage_status_sha256') != config['stage_status_sha256']
            or clone.get('destination') != str(ledger)
            or source_path is None or not source_path.is_absolute()
            or source_path.resolve(strict=True) != source_path or source_path.name != 'ledger'
            or source_path == ledger or source_path in ledger.parents or ledger in source_path.parents
            or clone.get('source_stable') is not True or clone.get('copy_identical') is not True
            or clone.get('loaded_identity_rechecked_after_restart') is not False
            or clone.get('application_effect') is not False
            or type(clone.get('excluded_stale_admin_socket')) is not bool
            or not _is_sha256(clone.get('stage_status_sha256'))
            or not _is_sha256(clone.get('stage_monitor_sha256'))):
        raise ValueError('pinned separate R0 clone receipt provenance mismatch')
    source_path = _private_directory(source_path, 'stage source ledger')
    if stage_config.get('ledger') != str(source_path):
        raise ValueError('pinned stage ledger differs from clone source')
    clone_rows = ledger_inventory(ledger)
    tree_sha = _sha(json.dumps(clone_rows, separators=(',', ':')).encode())
    if (type(clone.get('entry_count')) is not int
            or clone.get('entry_count') != len(clone_rows)
            or clone.get('tree_sha256') != tree_sha
            or type(clone.get('excluded_stale_admin_socket')) is not bool):
        raise ValueError('cloned ledger inventory differs from pinned clone receipt')
    for candidate in (source_path, ledger):
        _, genesis_sha = execute.stage.snapshot_generated(candidate / 'genesis.bin', 16 * 1024 * 1024)
        if genesis_sha != config['expected_genesis_sha256']:
            raise ValueError('pinned ledger genesis bytes differ from the external genesis pin')


def _validate_config(config):
    required = {
        'schema', 'scope', 'variant', 'request_slot', *CONFIG_PATH_FIELDS,
        *PIN_FIELDS, 'expected_program', 'expected_genesis', 'owner',
        'observation_lifetime_seconds', 'wait_deadline_seconds',
        'owner_process_limits', 'outer_limits_required',
    }
    if (type(config) is not dict or set(config) != required
            or config.get('schema') != CONFIG_SCHEMA or config.get('scope') != SCOPE
            or type(config.get('variant')) is not int
            or isinstance(config.get('variant'), bool)
            or not 0 <= config['variant'] < 8 or config.get('request_slot') != 'A'
            or config.get('outer_limits_required') != LIMITS
            or config.get('owner_process_limits') != PROCESS_LIMITS):
        raise ValueError('explicit bounded expired-status negative contract required')
    if (type(config.get('observation_lifetime_seconds')) is not int
            or not 15 <= config['observation_lifetime_seconds'] <= 30
            or config['observation_lifetime_seconds'] > MAX_STATUS_AGE
            or type(config.get('wait_deadline_seconds')) is not int
            or not 1 <= config['wait_deadline_seconds'] <= 60):
        raise ValueError('finite observation lifetime and expiry wait required')
    if (type(config.get('owner')) is not str or not config['owner']
            or type(config.get('expected_program')) is not str
            or not config['expected_program']
            or type(config.get('expected_genesis')) is not str
            or not config['expected_genesis']):
        raise ValueError('pinned program, genesis, and owner required')
    for field in PIN_FIELDS:
        value = config.get(field)
        if (type(value) is not str or len(value) != 64
                or any(char not in '0123456789abcdef' for char in value)):
            raise ValueError(f'{field} pin required')
    for field in CONFIG_PATH_FIELDS:
        path = Path(config[field]) if type(config.get(field)) is str else None
        if path is None or not path.is_absolute() or path.resolve() != path:
            raise ValueError(f'canonical absolute {field} path required')
    if config['output_dir'] == config['control_output']:
        raise ValueError('separate negative output and control directories required')


def _check_input_pins(config):
    artifacts = {}
    for path_field, hash_field, cap in INPUT_ARTIFACTS:
        if path_field == 'expected_elf':
            raw = execute.base.checked(config[path_field], config[hash_field], cap)
            actual = _sha(raw)
        else:
            raw, actual = execute.stage.snapshot_generated(Path(config[path_field]), cap)
        if actual != config[hash_field]:
            raise ValueError(f'{path_field} input pin mismatch')
        artifacts[path_field] = raw
        if path_field == 'full_wire' and len(raw) != cap:
            raise ValueError('pinned 448-byte Full wire required')
        if path_field == 'full_proof' and not raw:
            raise ValueError('nonempty externally pinned Full proof required')
    execute.base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
    _check_provenance(config, artifacts)


def _wait_for_finalized_expiry(rpc, observed_at, expires_at,
                               wait_deadline_seconds, monotonic=time.monotonic,
                               sleep=time.sleep):
    if (type(observed_at) is not int or isinstance(observed_at, bool)
            or type(expires_at) is not int or isinstance(expires_at, bool)
            or expires_at <= observed_at or expires_at - observed_at > MAX_STATUS_AGE
            or type(wait_deadline_seconds) is not int
            or not 1 <= wait_deadline_seconds <= 60):
        raise ValueError('bounded signed issuer observation required')
    deadline = monotonic() + wait_deadline_seconds
    while True:
        slot = rpc('getSlot', [{'commitment': 'finalized'}])
        now = rpc('getBlockTime', [slot])
        if (type(slot) is not int or isinstance(slot, bool) or slot <= 0
                or type(now) is not int or isinstance(now, bool)):
            raise ValueError('finalized RPC slot and block time required')
        age = now - observed_at
        if age < 0 or age > MAX_STATUS_AGE:
            raise ValueError('finalized observation age exceeds 300 seconds')
        if now >= expires_at:
            return {'slot': slot, 'unix_time': now, 'age_seconds': age}
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError('finalized RPC expiry wait deadline')
        sleep(min(0.25, remaining))


def _expected_identities(config):
    return {
        'freeze': config['freeze_sha256'],
        'genesis': config['expected_genesis_sha256'],
        'loaded_elf': config['expected_elf_sha256'],
        'stage': config['stage_report_sha256'],
        'clone': config['clone_receipt_sha256'],
        # The evidence contract pins the Full proof receipt bytes as this identity.
        'full_proof': config['full_proof_receipt_sha256'],
        'full_wire': config['full_wire_sha256'],
    }


def _validate_report(report, config):
    limits = report.get('limits') if type(report) is dict else None
    expected_limits = {
        'owner_wall_seconds': LIMITS['runtime_seconds'],
        'rss_bytes': LIMITS['rss_bytes'],
        'storage_growth_bytes': LIMITS['storage_growth_bytes'],
        'clock_wait_seconds': config['wait_deadline_seconds'],
    }
    if type(limits) is not dict or any(limits.get(key) != value
                                       for key, value in expected_limits.items()):
        raise ValueError('report limits must match supervisor limit and configured wait')
    return expired_evidence.validate_report(report, _expected_identities(config))


def _rust_source_parts(source):
    """Separate declaration text and string values for this conservative source gate."""
    token_start = re.compile(r'//|/\*|(?<![A-Za-z0-9_])(?:br|cr|r)(#{0,255})"|"')
    code, strings, position = [], [], 0
    while match := token_start.search(source, position):
        code.append(source[position:match.start()])
        start, token = match.start(), match.group()
        if token == '//':
            end = source.find('\n', match.end())
            end = len(source) if end < 0 else end
        elif token == '/*':
            depth, end = 1, match.end()
            while depth:
                nested = re.search(r'/\*|\*/', source[end:])
                if nested is None:
                    raise IntegrationRequired('Rust source contains an unterminated block comment')
                depth += 1 if nested.group() == '/*' else -1
                end += nested.end()
        elif token != '"':
            closing = '"' + match.group(1)
            finish = source.find(closing, match.end())
            if finish < 0:
                raise IntegrationRequired('Rust source contains an unterminated raw string')
            strings.append(source[match.end():finish])
            end = finish + len(closing)
        else:
            end = match.end()
            while end < len(source):
                if source[end] == '\\':
                    end += 2
                elif source[end] == '"':
                    strings.append(source[match.end():end])
                    end += 1
                    break
                else:
                    end += 1
            else:
                raise IntegrationRequired('Rust source contains an unterminated string')
        code.append(re.sub(r'[^\n]', ' ', source[start:end]))
        position = end
    code.append(source[position:])
    return ''.join(code), strings


def _require_rust_entrypoint():
    test_path = REPO / 'harness/tests/queue_v3.rs'
    module_path = REPO / 'harness/src/solana/queue_v3/expired_status_negative.rs'
    parent_path = REPO / 'harness/src/solana/queue_v3.rs'
    test_source = test_path.read_text() if test_path.is_file() else ''
    parent_source = parent_path.read_text() if parent_path.is_file() else ''
    module_source = module_path.read_text() if module_path.is_file() else ''
    # Strings and comments cannot supply executable declarations.
    test_source, _ = _rust_source_parts(test_source)
    parent_source, _ = _rust_source_parts(parent_source)
    module_source, module_strings = _rust_source_parts(module_source)
    present = (
        re.search(r'#\[test\]\s*#\[ignore[^\n]*\]\s*fn\s+' + RUST_TEST
                  + r'\s*\(\s*\)\s*\{\s*'
                    r'zk_fresh_benchmark::solana::queue_v3::'
                    r'expired_status_negative_from_env\(\)\.unwrap\(\);\s*\}', test_source)
        and re.search(r'(?m)^\s*mod expired_status_negative;', parent_source)
        and re.search(r'(?m)^\s*pub use expired_status_negative::expired_status_negative_from_env;', parent_source)
        and re.search(r'(?m)^\s*pub fn expired_status_negative_from_env\(\)', module_source)
        and CANDIDATE_SCHEMA in module_strings
        and 'P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG_SHA256' in module_strings
        and REPORT_NAME in module_strings
    )
    if not present:
        raise IntegrationRequired(
            'Rust integration required: add and freeze a dedicated expired-status '
            'module/test that publishes and finalizes the active bound publisher '
            'observation, waits on finalized RPC block time, submits the Full Execute, '
            'and reports finalized error 705 at instruction 1 plus five before/after '
            'account snapshots. No validator or proof runner was started.')


def _write_blocked_status(config, config_sha256, config_path, reason=None):
    root = REPO / 'artifacts/dynark/part5'
    output = execute.base.fresh_child(config['output_dir'], root)
    control = execute.base.fresh_child(config['control_output'], root)
    if output == control:
        raise ValueError('separate negative output and control directories required')
    control.mkdir(mode=0o700)
    status = {
        'schema': 1, 'scope': SCOPE, 'status': 'blocked_integration',
        'error_type': 'IntegrationRequired',
        'integration_required': reason or (
            'Add an isolated Rust publisher/expiry/Execute entry point and report '
            'before any loaded stale-status result can be claimed.'),
        'rust_report_contract': RUST_REPORT_CONTRACT,
        'outer_monitor_required': True,
        'whole_tree_cleanup_authority': 'external bounded_runner',
        'config_path': str(config_path), 'config_sha256': config_sha256,
        'effect_verified': False, 'application_effect': False,
        'loaded_execution_claimed': False,
        'validator_cleanup': {'spawned': False, 'reaped': True},
        'runner_cleanup': {'spawned': False, 'reaped': True},
        'remaining_owned_processes': 0, 'output_dir': str(output),
        'outer_limits_required': LIMITS,
    }
    status_path = control / 'status.json'
    execute.base.write_new(status_path, status)
    meta = status_path.lstat()
    directory_meta = control.lstat()
    if (meta.st_uid != os.getuid() or meta.st_mode & 0o777 != 0o600
            or directory_meta.st_uid != os.getuid()
            or directory_meta.st_mode & 0o777 != 0o700):
        raise ValueError('owner-only expired-status control output required')
    return status_path


def _same_json(actual, expected, message):
    if json.dumps(actual, sort_keys=True, allow_nan=False) != json.dumps(
            expected, sort_keys=True, allow_nan=False):
        raise ValueError(message)


def _integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError('candidate bounded integer required')
    return value


def _validate_candidate(report, config, config_path, config_sha256, output,
                        loaded, runner_pid):
    if (type(report) is not dict or set(report) != CANDIDATE_FIELDS
            or report.get('schema') != CANDIDATE_SCHEMA
            or report.get('external_finalization_required') is not True
            or report.get('full_proof_verified_in_rust') is not False
            or report.get('application_effect') is not False):
        raise ValueError('exact Rust candidate without external evidence required')
    _same_json(report['config_ref'], {'path': str(config_path), 'sha256': config_sha256},
               'candidate supervisor config provenance mismatch')
    _same_json(report['identities'], _expected_identities(config),
               'candidate identity provenance mismatch')
    refs = {path: {'path': config[path], 'sha256': config[digest]}
            for path, digest, _ in INPUT_ARTIFACTS}
    refs['runner'] = {'path': config['runner'], 'sha256': config['runner_sha256']}
    _same_json(report['input_refs'], refs, 'candidate input provenance mismatch')
    _same_json(report['source_refs'], {
        'full_proof': refs['full_proof_receipt'], 'full_wire': refs['full_wire']},
        'candidate Full source provenance mismatch')
    if (report['program'] != config['expected_program']
            or report['genesis'] != config['expected_genesis']):
        raise ValueError('candidate program or genesis mismatch')
    rust_loaded = report['loaded_program_before']
    if (type(rust_loaded) is not dict or set(rust_loaded) != {
            'elf_match', 'elf_sha256', 'local_bytes', 'remote_bytes', 'loader'}
            or rust_loaded.get('elf_match') is not True
            or rust_loaded.get('elf_sha256') != config['expected_elf_sha256']
            or rust_loaded.get('loader') != loaded['loader']
            or _integer(rust_loaded.get('local_bytes'), 1) != loaded['elf_bytes']
            or _integer(rust_loaded.get('remote_bytes'), 1) < rust_loaded['local_bytes']):
        raise ValueError('candidate loaded identity mismatch')
    _same_json(report['loaded_program_after'], rust_loaded,
               'candidate loaded identity changed')
    _same_json(report['preconditions'], {
        'status_active': True, 'issuer_active': True, 'head_bound': True,
        'request_live': True, 'full_wire_statement_matches': True},
        'candidate clean expiry preconditions required')
    clock = report['clock']
    if type(clock) is not dict or set(clock) != {'observed_at', 'expires_at', 'now', 'rpc_finalized'}:
        raise ValueError('candidate finalized clock required')
    observed, expires, now = [_integer(clock[name])
                              for name in ('observed_at', 'expires_at', 'now')]
    if (clock['rpc_finalized'] is not True
            or expires - observed != config['observation_lifetime_seconds']
            or not observed < expires < now <= observed + MAX_STATUS_AGE):
        raise ValueError('candidate strictly expired finalized clock required')
    clocks = report['clock_observations']
    if type(clocks) is not dict or set(clocks) != {
            'expiry_slot', 'expiry_now', 'submit_slot', 'execution_now'}:
        raise ValueError('candidate clock observations required')
    for name in clocks:
        _integer(clocks[name], 1 if name.endswith('slot') else 0)
    if not expires < clocks['expiry_now'] <= now <= clocks['execution_now'] <= observed + MAX_STATUS_AGE:
        raise ValueError('candidate expiry clock ordering mismatch')
    publishers = report['publisher_transactions']
    if type(publishers) is not dict or set(publishers) != {'source', 'bind'}:
        raise ValueError('candidate publisher transactions required')
    transactions = [publishers['source'], publishers['bind'], report['transaction']]
    slots, signatures = [], []
    for index, tx in enumerate(transactions):
        expected_fields = {'signature', 'slot', 'finalized', 'error'}
        if index < 2:
            expected_fields.add('block_time')
        if (type(tx) is not dict or set(tx) != expected_fields
                or tx.get('finalized') is not True
                or type(tx.get('signature')) is not str
                or re.fullmatch('[1-9A-HJ-NP-Za-km-z]{64,88}', tx['signature']) is None):
            raise ValueError('candidate exact finalized transactions required')
        _same_json(tx['error'], {'InstructionError': [1, {'Custom': 705}]} if index == 2 else None,
                   'candidate exact instruction 1 custom 705 required')
        slots.append(_integer(tx['slot'], 1))
        signatures.append(tx['signature'])
    if slots != sorted(slots) or len(set(signatures)) != 3:
        raise ValueError('candidate distinct ordered transactions required')
    source_now = _integer(transactions[0]['block_time'])
    bind_now = _integer(transactions[1]['block_time'])
    if not observed <= source_now <= bind_now < expires:
        raise ValueError('candidate publisher finality must precede expiry')
    account_slots = report['account_slots']
    if type(account_slots) is not dict or set(account_slots) != {'initial', 'bound', 'before', 'after'}:
        raise ValueError('candidate account slots required')
    initial, bound, before, after = [_integer(account_slots[name], 1)
                                    for name in ('initial', 'bound', 'before', 'after')]
    if not (initial < slots[0] <= slots[1] <= bound <= clocks['expiry_slot']
            <= before <= clocks['submit_slot'] <= slots[2] <= after):
        raise ValueError('candidate finalized account/transaction slot ordering mismatch')
    observations = report['runner_observations']
    if type(observations) is not dict or set(observations) != {'pid', 'elapsed_seconds', 'clock_wait_seconds'}:
        raise ValueError('candidate runner observations required')
    if _integer(observations['pid'], 1) != runner_pid:
        raise ValueError('candidate runner PID mismatch')
    for name in ('elapsed_seconds', 'clock_wait_seconds'):
        value = observations[name]
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('candidate finite runner observation required')
    if not (observations['clock_wait_seconds'] <= config['wait_deadline_seconds']
            and observations['clock_wait_seconds'] <= observations['elapsed_seconds']
            <= RUNNER_BUDGET_SECONDS):
        raise ValueError('candidate runner or clock wait deadline exceeded')
    snapshots = report['snapshots']
    if type(snapshots) is not list or len(snapshots) != 5:
        raise ValueError('candidate five ordered snapshots required')
    hashes, sizes = [], []
    for name, row in zip(ACCOUNT_NAMES, snapshots):
        if type(row) is not dict or set(row) != {'name', 'before', 'after'} or row['name'] != name:
            raise ValueError('candidate five ordered snapshots required')
        saved = []
        for phase in ('before', 'after'):
            ref = row[phase]
            expected_path = output / phase / (name + '.bin')
            if (type(ref) is not dict or set(ref) != {'path', 'sha256'}
                    or ref['path'] != str(expected_path) or not _is_sha256(ref['sha256'])):
                raise ValueError('candidate output snapshot provenance mismatch')
            raw, digest = execute.stage.snapshot_generated(expected_path, 4096)
            if not raw or digest != ref['sha256']:
                raise ValueError('candidate snapshot hash mismatch')
            saved.append(raw)
        if saved[0] != saved[1]:
            raise ValueError('candidate application account changed')
        hashes.append(row['before']['sha256'])
        sizes.append(len(saved[0]))
    return hashes, sizes


def _recheck_candidate(rpc, report, config, stage_report, hashes, sizes):
    for name, tx in [('source', report['publisher_transactions']['source']),
                     ('bind', report['publisher_transactions']['bind']),
                     ('execute', report['transaction'])]:
        signature = tx['signature']
        statuses = rpc('getSignatureStatuses', [[signature], {'searchTransactionHistory': True}])
        rows = statuses.get('value') if type(statuses) is dict else None
        if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
            raise ValueError('candidate live finalized transaction status required')
        status = rows[0]
        recorded = rpc('getTransaction', [signature, {'commitment': 'finalized',
            'encoding': 'json', 'maxSupportedTransactionVersion': 0}])
        if (type(recorded) is not dict or type(recorded.get('meta')) is not dict
                or 'err' not in recorded['meta'] or 'err' not in status
                or status.get('confirmationStatus') != 'finalized'):
            raise ValueError('candidate live finalized transaction required')
        _same_json(status.get('slot'), tx['slot'], 'candidate live transaction slot mismatch')
        _same_json(recorded.get('slot'), tx['slot'], 'candidate live transaction slot mismatch')
        _same_json(status.get('err'), tx['error'], 'candidate live transaction error mismatch')
        _same_json(recorded['meta'].get('err'), tx['error'], 'candidate live transaction error mismatch')
        expected_time = (report['clock_observations']['execution_now']
                         if name == 'execute' else tx['block_time'])
        _same_json(recorded.get('blockTime'), expected_time, 'candidate live transaction time mismatch')
        recorded_signatures = recorded.get('transaction', {}).get('signatures')
        if type(recorded_signatures) is not list or not recorded_signatures or recorded_signatures[0] != signature:
            raise ValueError('candidate live transaction signature mismatch')
    for slot, now in ((report['clock_observations']['expiry_slot'],
                       report['clock_observations']['expiry_now']),
                      (report['clock_observations']['submit_slot'], report['clock']['now'])):
        _same_json(rpc('getBlockTime', [slot]), now, 'candidate live finalized clock mismatch')
    slot = _integer(rpc('getSlot', [{'commitment': 'finalized'}]), 1)
    now = _integer(rpc('getBlockTime', [slot]))
    if (slot < report['account_slots']['after']
            or not report['clock_observations']['execution_now'] <= now
            <= report['clock']['observed_at'] + MAX_STATUS_AGE):
        raise ValueError('candidate live finalized clock regressed or aged out')
    return execute.finalized_accounts(rpc, stage_report, report['account_slots']['after'],
                                      config['expected_program'], hashes, sizes)[0]


def _runtime_inputs(config):
    staged = execute.pinned_json(config['stage_config'], config['stage_config_sha256'])
    prepared = execute.pinned_json(staged['prior_config'], staged['prior_config_sha256'])
    if (prepared.get('program') != config['expected_program']
            or prepared.get('elf_sha256') != config['expected_elf_sha256']):
        raise ValueError('pinned prepared validator target mismatch')
    execute.base.checked(prepared['validator'], prepared['validator_sha256'], 128 * 1024 * 1024)
    execute.base.checked(staged['context'], staged['context_sha256'], 8192)
    report = execute.pinned_json(config['stage_report'], config['stage_report_sha256'])
    plan = execute.pinned_json(config['stage_plan'], config['stage_plan_sha256'])
    execute.check_stage_report(report, plan, config, prepared)
    return prepared, staged, report


def _check_budget(started):
    if time.monotonic() >= started + SUPERVISOR_BUDGET_SECONDS:
        raise TimeoutError('expired-status supervisor deadline')


def _run_loaded(config, config_sha256, config_path):
    prepared, staged, stage_report = _runtime_inputs(config)
    elf = execute.base.checked(config['expected_elf'], config['expected_elf_sha256'], 4 * 1024 * 1024)
    root = REPO / 'artifacts/dynark/part5'
    output = execute.base.fresh_child(config['output_dir'], root)
    control = execute.base.fresh_child(config['control_output'], root)
    validator = runner = None
    streams, handlers = [], {}
    status = {'schema': 1, 'scope': SCOPE, 'status': 'failed', 'error_type': None,
              'config_path': str(config_path), 'config_sha256': config_sha256,
              'owner': config['owner'], 'output_dir': str(output),
              'candidate_verified': False, 'effect_verified': False,
              'loaded_execution_claimed': False, 'application_effect': False,
              'external_finalization_required': True, 'outer_monitor_required': True,
              'whole_tree_cleanup_authority': 'external bounded_runner',
              'ledger_reuse_requires_review': True, 'outer_limits_required': LIMITS}
    started = time.monotonic()
    def interrupted(signum, frame):
        raise InterruptedError('expired-status supervisor interrupted')
    try:
        control.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        execute.base.ports_free(timeout_seconds=execute.base.PORT_WAIT_SECONDS)
        argv = execute.stage.resume_argv(prepared['validator'], config['ledger'])
        command = [config['runner'], *RUST_REPORT_CONTRACT['runner_arguments']]
        execute.base.write_new(control / 'invocation.json', {
            'validator_argv': argv, 'runner_argv': command,
            'config_path': str(config_path), 'config_sha256': config_sha256,
            'runner_sha256': config['runner_sha256'],
            'validator_sha256': prepared['validator_sha256'],
            'outer_limits_required': LIMITS})
        for name in ('validator.stdout.log', 'validator.stderr.log',
                     'runner.stdout.log', 'runner.stderr.log'):
            fd = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            streams.append(os.fdopen(fd, 'wb'))
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        _check_budget(started)
        validator = subprocess.Popen(argv, cwd=REPO, env=env,
            stdin=subprocess.DEVNULL, stdout=streams[0], stderr=streams[1])
        local_rpc = execute.base.LocalRpc()
        def rpc(method, params):
            # Existing readiness helpers retry OSError, including TimeoutError.
            # A supervisor deadline must escape those retries immediately.
            try:
                _check_budget(started)
                result = local_rpc(method, params)
                _check_budget(started)
                return result
            except TimeoutError:
                raise RuntimeError('expired-status supervisor RPC deadline') from None
        loaded = execute.wait_loaded_after_start(rpc, validator, config['expected_program'],
                                                elf, config['expected_elf_sha256'])
        execute.same_loaded(stage_report['loaded_program'], loaded)
        if (loaded.get('elf_match') is not True or loaded.get('program') != config['expected_program']
                or loaded.get('genesis') != config['expected_genesis']):
            raise ValueError('loaded expired-status target mismatch')
        sizes, initial = [], []
        for name, expected in zip(ACCOUNT_NAMES, stage_report['account_sha256']):
            raw, digest = execute.stage.snapshot_generated(Path(config['stage_root']) / (name + '.bin'), 4096)
            if digest != expected:
                raise ValueError('staged account input changed')
            sizes.append(len(raw))
            initial.append(raw)
        _, actual = execute.wait_staged_finality(rpc, stage_report, config['expected_program'],
                                                stage_report['account_sha256'], sizes)
        if actual != initial:
            raise ValueError('loaded clone differs from finalized R0 stage')
        execute.base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
        execute.base.checked(staged['context'], staged['context_sha256'], 8192)
        env.update({'P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG': str(config_path),
                    'P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG_SHA256': config_sha256,
                    'P5_V3_EXPIRED_STATUS_NEGATIVE_SCOPE': SCOPE,
                    'P5_V3_STAGE_ROOT': config['stage_root'],
                    'P5_QUEUE_RPC': execute.base.RPC.rstrip('/'),
                    'P5_QUEUE_PROGRAM': config['expected_program'],
                    'P5_QUEUE_GENESIS': config['expected_genesis'],
                    'P5_QUEUE_ELF': config['expected_elf'],
                    'P5_QUEUE_ELF_SHA256': config['expected_elf_sha256'],
                    'P5_QUEUE_OUTPUT': str(output),
                    'P5_V3_CONTEXT': staged['context'],
                    'P5_V3_CONTEXT_SHA256': staged['context_sha256']})
        _check_budget(started)
        runner = subprocess.Popen(command, cwd=REPO, env=env,
            stdin=subprocess.DEVNULL, stdout=streams[2], stderr=streams[3])
        deadline = min(started + SUPERVISOR_BUDGET_SECONDS,
                       time.monotonic() + RUNNER_BUDGET_SECONDS)
        while runner.poll() is None:
            if validator.poll() is not None:
                raise RuntimeError('validator exited during expired-status candidate')
            if time.monotonic() >= deadline:
                raise TimeoutError('expired-status runner deadline')
            time.sleep(0.1)
        if runner.wait() != 0:
            raise RuntimeError('expired-status Rust runner failed')
        _check_budget(started)
        report_path = output / REPORT_NAME
        raw, candidate_sha = execute.stage.snapshot_generated(report_path, 65536)
        candidate = execute.base.decode_json(raw)
        hashes, sizes = _validate_candidate(candidate, config, config_path, config_sha256,
                                             output, loaded, runner.pid)
        if candidate['account_slots']['initial'] < stage_report['finalized_slot']:
            raise ValueError('candidate starts before stage finality')
        rechecked_slot = _recheck_candidate(rpc, candidate, config, stage_report, hashes, sizes)
        loaded_after = execute.wait_loaded_after_start(rpc, validator, config['expected_program'],
                                                      elf, config['expected_elf_sha256'])
        execute.same_loaded(loaded, loaded_after)
        if validator.poll() is not None:
            raise RuntimeError('validator exited after final expired-status RPC checks')
        # Candidate and immutable provenance must still be the exact pinned bytes.
        _, final_sha = execute.stage.snapshot_generated(report_path, 65536)
        if final_sha != candidate_sha:
            raise ValueError('candidate changed during validation')
        final_config, final_config_sha = execute.stage.snapshot_generated(config_path, 65536)
        if final_config_sha != config_sha256 or execute.base.decode_json(final_config) != config:
            raise ValueError('supervisor config changed during execution')
        _check_budget(started)
        status.update({'candidate_verified': True, 'candidate_path': str(report_path),
                       'candidate_sha256': candidate_sha, 'candidate_schema': CANDIDATE_SCHEMA,
                       'loaded_program': loaded, 'live_rechecked_finalized_slot': rechecked_slot})
    except Exception as error:
        status['error_type'] = type(error).__name__
        status['error_message'] = str(error)[:256]
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            status['validator_alive_before_cleanup'] = (
                validator is not None and validator.poll() is None)
        except Exception:
            status['validator_alive_before_cleanup'] = False
        for name, proc in (('runner', runner), ('validator', validator)):
            try:
                status[name + '_cleanup'] = execute.base.cleanup(proc)
            except Exception as error:
                status[name + '_cleanup'] = {'spawned': proc is not None, 'reaped': False,
                                             'graceful': False, 'error_type': type(error).__name__}
        status['elapsed_seconds'] = time.monotonic() - started
        runner_cleanup = status['runner_cleanup']
        validator_cleanup = status['validator_cleanup']
        expected_cleanup = (
            status['validator_alive_before_cleanup']
            and runner_cleanup.get('spawned') is True
            and runner_cleanup.get('reaped') is True
            and type(runner_cleanup.get('exit_code')) is int
            and runner_cleanup['exit_code'] == 0
            and validator_cleanup.get('spawned') is True
            and validator_cleanup.get('reaped') is True
            and validator_cleanup.get('graceful') is False
            and type(validator_cleanup.get('exit_code')) is int
            and validator_cleanup['exit_code'] == -signal.SIGINT)
        if status['elapsed_seconds'] > SUPERVISOR_BUDGET_SECONDS:
            if status['error_type'] is None:
                status['error_type'] = 'TimeoutError'
                status['error_message'] = 'expired-status supervisor deadline exceeded after cleanup'
        elif not expected_cleanup and status['error_type'] is None:
            status['error_type'] = 'RuntimeError'
            status['error_message'] = 'expired-status unexpected child exit or cleanup outcome'
        if status['candidate_verified'] and expected_cleanup and status['error_type'] is None:
            status['status'] = 'candidate_verified_pending_external_finalization'
        for stream in streams:
            stream.close()
        try:
            execute.base.write_new(control / 'status.json', status)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return 0 if status['status'] == 'candidate_verified_pending_external_finalization' else 1


def run(config, config_sha256, config_path):
    if os.environ.get('P5_V3_EXPIRED_STATUS_NEGATIVE_SCOPE') != SCOPE:
        raise ValueError('explicit bounded expired-status scope required')
    _validate_config(config)
    config_path = Path(config_path)
    if not config_path.is_absolute() or config_path.resolve(strict=True) != config_path:
        raise ValueError('canonical absolute supervisor config path required')
    config_raw, actual_config_sha = execute.stage.snapshot_generated(config_path, 65536)
    if actual_config_sha != config_sha256:
        raise ValueError('expired-status supervisor config hash mismatch')
    if execute.base.decode_json(config_raw) != config:
        raise ValueError('expired-status pinned config bytes decode differently')
    _check_input_pins(config)
    try:
        _require_rust_entrypoint()
    except IntegrationRequired as error:
        _write_blocked_status(config, config_sha256, config_path, str(error))
        return 2
    return _run_loaded(config, config_sha256, config_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    try:
        config = execute.pinned_json(args.config, args.config_sha256, 65536)
        return run(config, args.config_sha256, str(args.config))
    except Exception as error:
        raise SystemExit(f'expired-status negative rejected ({type(error).__name__})') from None


if __name__ == '__main__':
    sys.exit(main())
