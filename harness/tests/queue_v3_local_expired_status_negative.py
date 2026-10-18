#!/usr/bin/env python3
"""Preflight and validate one bounded loaded expired-status negative.

The isolated Rust publisher/Execute entry point is not present yet. Until it is
added and frozen, this supervisor records that integration blocker and starts no
validator or proof runner.
"""
import argparse
import hashlib
import json
import os
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
SCOPE = 'part5-v3-expired-status-negative'
CONFIG_SCHEMA = 'credential-v3-expired-status-negative-supervisor-v1'
REPORT_SCHEMA = expired_evidence.SCHEMA
ACCOUNT_NAMES = expired_evidence.checks.ACCOUNT_NAMES
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
    source_rows, clone_rows = ledger_inventory(source_path), ledger_inventory(ledger)
    tree_sha = _sha(json.dumps(source_rows, separators=(',', ':')).encode())
    if (source_rows != clone_rows or type(clone.get('entry_count')) is not int
            or clone.get('entry_count') != len(clone_rows)
            or clone.get('tree_sha256') != tree_sha
            or clone.get('excluded_stale_admin_socket') != stale_admin_socket(source_path)):
        raise ValueError('cloned ledger inventory differs from pinned stage source')
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


def _require_rust_entrypoint():
    test_path = REPO / 'harness/tests/queue_v3.rs'
    module_path = REPO / 'harness/src/solana/queue_v3/expired_status_negative.rs'
    parent_path = REPO / 'harness/src/solana/queue_v3.rs'
    test_source = test_path.read_text() if test_path.is_file() else ''
    parent_source = parent_path.read_text() if parent_path.is_file() else ''
    module_source = module_path.read_text() if module_path.is_file() else ''
    present = (
        'root_pinned_queue_v3_expired_status_negative' in test_source
        and 'mod expired_status_negative;' in parent_source
        and 'expired_status_negative_from_env' in parent_source
        and 'expired_status_negative_from_env' in module_source
    )
    if not present:
        raise IntegrationRequired(
            'Rust integration required: add and freeze a dedicated expired-status '
            'module/test that publishes and finalizes the active bound publisher '
            'observation, waits on finalized RPC block time, submits the Full Execute, '
            'and reports finalized error 705 at instruction 1 plus five before/after '
            'account snapshots. No validator or proof runner was started.')


def _write_blocked_status(config, config_sha256, config_path):
    root = REPO / 'artifacts/dynark/part5'
    output = execute.base.fresh_child(config['output_dir'], root)
    control = execute.base.fresh_child(config['control_output'], root)
    if output == control:
        raise ValueError('separate negative output and control directories required')
    control.mkdir(mode=0o700)
    status = {
        'schema': 1, 'scope': SCOPE, 'status': 'blocked_integration',
        'error_type': 'IntegrationRequired',
        'integration_required': (
            'Add an isolated Rust publisher/expiry/Execute entry point and report '
            'before any loaded stale-status result can be claimed.'),
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
    except IntegrationRequired:
        _write_blocked_status(config, config_sha256, config_path)
        return 2
    raise IntegrationRequired(
        'Rust entry point exists, but its validator launch/report protocol has not '
        'been integrated into this supervisor; no loaded claim is permitted.')


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
