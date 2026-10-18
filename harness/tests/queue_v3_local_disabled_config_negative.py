#!/usr/bin/env python3
"""Run the pinned disabled-config Execute negative on a separate heldout clone.

This supervisor owns one local validator and the frozen Rust queue runner. The
outer case runner supplies the whole-tree resource and cleanup boundary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from harness.tests import queue_v3_local_execute as execute
from harness.tests.queue_v3_clone_ledger import inventory as ledger_inventory

LIMITS = {'runtime_seconds': 270, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}
SUPERVISOR_BUDGET_SECONDS = 255
RUNNER_BUDGET_SECONDS = 210
ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')
REPORT_SCHEMA = 'part5-v3-disabled-config-negative-report-v2'
SCOPE = 'part5-v3-disabled-config-negative'
SCENARIOS = (
    'v3-disabled-negative-refresh-source',
    'v3-disabled-negative-refresh-head',
    'v3-disabled-negative-disable-config',
    'v3-disabled-negative-valid-full-execute',
    'v3-disabled-negative-reenable-config',
    'v3-disabled-negative-refresh-issuer-source',
    'v3-disabled-negative-rebind-issuer-head',
    'v3-disabled-negative-disable-issuer',
    'v3-disabled-negative-valid-full-execute-issuer',
)
TRANSACTION_SUMMARIES = (
    'refresh_transaction', 'bind_transaction', 'disable_transaction',
    'execute_transaction', 'reenable_transaction',
    'issuer_refresh_transaction', 'issuer_bind_transaction',
    'issuer_disable_transaction', 'issuer_execute_transaction',
)
SNAPSHOT_GROUPS = ('eligible', 'before', 'after', 'issuer_eligible',
                   'issuer_before', 'issuer_after')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _check_supervisor_budget(started):
    if time.monotonic() >= started + SUPERVISOR_BUDGET_SECONDS:
        raise TimeoutError('disabled-config supervisor deadline')


def _pinned(path, expected, cap=65536):
    raw, actual = execute.stage.snapshot_generated(Path(path), cap)
    if actual != expected:
        raise ValueError('disabled-config input pin mismatch')
    return execute.base.decode_json(raw)


def _clone_is_initial(config, stage_config, stage_report, stage_status,
                      stage_monitor):
    receipt_path = Path(config['heldout_r0_clone_report'])
    ledger = Path(config['ledger'])
    source = Path(stage_config['ledger'])
    if (receipt_path != ledger.parent / 'clone-report.json'
            or ledger.name != 'ledger' or source.name != 'ledger'
            or ledger == source or source in ledger.parents or ledger in source.parents):
        raise ValueError('separate A-stage disabled-config clone required')
    receipt = execute.pinned_json(receipt_path,
                                  config['heldout_r0_clone_report_sha256'])
    expected = {'schema': 'part5-v3-heldout-r0-ledger-clone-v1',
        'heldout_acceptance': False,
        'stage_report_sha256': config['stage_report_sha256'],
        'stage_status_sha256': config['prior_stage_status_sha256'],
        'stage_monitor_sha256': config['prior_stage_monitor_sha256'],
        'source': str(source), 'destination': str(ledger),
        'source_stable': True, 'copy_identical': True,
        'loaded_identity_rechecked_after_restart': False,
        'application_effect': False}
    if any(receipt.get(name) != value for name, value in expected.items()):
        raise ValueError('pinned separate disabled-config clone receipt required')
    clone_rows = ledger_inventory(ledger)
    expected_tree = _sha(json.dumps(clone_rows, separators=(',', ':')).encode())
    if (receipt.get('entry_count') != len(clone_rows)
            or receipt.get('tree_sha256') != expected_tree):
        raise ValueError('disabled-config clone must start byte-identical to stage ledger')
    return receipt


def _check_snapshots(report, output):
    hashes = {}
    for group in SNAPSHOT_GROUPS:
        rows = report.get(group + '_accounts')
        expected_hashes = report.get(group + '_sha256')
        if (type(rows) is not list or len(rows) != len(ACCOUNT_NAMES)
                or type(expected_hashes) is not list
                or len(expected_hashes) != len(ACCOUNT_NAMES)):
            raise ValueError('five ordered disabled-config account snapshots required')
        actual_group = []
        for name, row, expected in zip(ACCOUNT_NAMES, rows, expected_hashes):
            path = output / group / (name + '.bin')
            if (type(row) is not dict or set(row) != {'name', 'path', 'sha256'}
                    or row.get('name') != name or row.get('path') != str(path)
                    or row.get('sha256') != expected):
                raise ValueError('pinned disabled-config snapshot ref mismatch')
            raw, actual = execute.stage.snapshot_generated(path, 4096)
            if actual != expected:
                raise ValueError('disabled-config snapshot bytes differ from report')
            actual_group.append(actual)
        hashes[group] = actual_group
    if hashes['before'] != hashes['after']:
        raise ValueError('config-rejected Execute changed finalized account bytes')
    if hashes['issuer_before'] != hashes['issuer_after']:
        raise ValueError('issuer-rejected Execute changed finalized account bytes')
    return hashes


def _validate_report(report, config, stage_report, output):
    if (type(report) is not dict or report.get('schema') != REPORT_SCHEMA
            or report.get('passed') is not True
            or report.get('variant') != config['variant']
            or report.get('request_slot') != 'A'
            or report.get('program') != config['expected_program']
            or report.get('genesis') != config['expected_genesis']
            or report.get('loaded_elf_sha256') != config['expected_elf_sha256']
            or report.get('addresses') != {
                name: stage_report.get(name) for name in ACCOUNT_NAMES}
            or report.get('stage_report_sha256') != config['stage_report_sha256']
            or report.get('stage_plan_sha256') != config['stage_plan_sha256']
            or report.get('full_wire_sha256') != config['full_wire_sha256']
            or report.get('clone_receipt_sha256') != config['heldout_r0_clone_report_sha256']):
        raise ValueError('pinned disabled-config report identity required')
    claims = (
        'config_disabled', 'execute_rejected', 'refresh_and_bind_succeeded',
        'disable_changed_only_enabled_and_epoch',
        'accounts_unchanged_after_rejection', 'issuer_disabled',
        'issuer_execute_rejected',
        'issuer_disable_changed_only_enabled_epoch_status',
        'issuer_accounts_unchanged_after_rejection',
    )
    if any(report.get(name) is not True for name in claims):
        raise ValueError('pinned disabled-config and disabled-issuer claims required')
    if type(report.get('expected_custom_error')) is not int or report['expected_custom_error'] != 713:
        raise ValueError('Policy 713 custom error required')
    if type(report.get('issuer_eligible_clock')) is not int or report['issuer_eligible_clock'] < 0:
        raise ValueError('issuer eligibility clock required')
    if (type(report.get('source_finalized_slot')) is not int
            or isinstance(report['source_finalized_slot'], bool)
            or report['source_finalized_slot'] < stage_report.get('finalized_slot')):
        raise ValueError('staged finalized source slot mismatch')

    transactions = report.get('transactions')
    if type(transactions) is not list or len(transactions) != len(SCENARIOS):
        raise ValueError('exactly nine ordered loaded-ELF transactions required')
    ordered_slots = []
    signatures = set()
    indexed = {}
    for index, (scenario, summary_name, row) in enumerate(
            zip(SCENARIOS, TRANSACTION_SUMMARIES, transactions)):
        summary = report.get(summary_name)
        if (type(summary) is not dict or type(row) is not dict
                or row.get('scenario') != scenario
                or type(row.get('signature')) is not str or not row['signature']
                or type(row.get('slot')) is not int or isinstance(row.get('slot'), bool)
                or row['slot'] <= 0
                or summary.get('signature') != row['signature']
                or type(summary.get('slot')) is not int
                or isinstance(summary.get('slot'), bool)
                or summary['slot'] != row['slot']):
            raise ValueError('ordered transaction summary mismatch')
        error_expected = index in (3, 8)
        expected_err = {'InstructionError': [1, {'Custom': 713}]} if error_expected else None
        if (row.get('customError') != (713 if error_expected else None)
                or row.get('err') != expected_err):
            raise ValueError('both disabled Execute transactions must reject with Policy 713')
        if error_expected and (type(summary.get('custom_error')) is not int
                               or summary['custom_error'] != 713):
            raise ValueError('Policy 713 transaction summary required')
        if not error_expected and 'custom_error' in summary:
            raise ValueError('unexpected policy error in successful transition summary')
        if index in (2, 3, 7, 8):
            if (type(summary.get('finalized_slot')) is not int
                    or isinstance(summary.get('finalized_slot'), bool)
                    or summary['finalized_slot'] < summary['slot']):
                raise ValueError('finalized transition transaction required')
        ordered_slots.append(row['slot'])
        signatures.add(row['signature'])
        indexed[scenario] = row['slot']
    if (ordered_slots != sorted(ordered_slots)
            or len(signatures) != len(ordered_slots)
            or ordered_slots[0] <= report['source_finalized_slot']):
        raise ValueError('distinct ordered transactions must follow staged source finality')

    finalized_slots = {
        'eligible_finalized_slot': (indexed[SCENARIOS[1]], None),
        'disabled_finalized_slot': (indexed[SCENARIOS[2]],
                                    report['disable_transaction']['finalized_slot']),
        'rejected_finalized_slot': (indexed[SCENARIOS[3]],
                                    report['execute_transaction']['finalized_slot']),
        'issuer_eligible_finalized_slot': (indexed[SCENARIOS[6]], None),
        'issuer_disabled_finalized_slot': (indexed[SCENARIOS[7]],
                                           report['issuer_disable_transaction']['finalized_slot']),
        'issuer_rejected_finalized_slot': (indexed[SCENARIOS[8]],
                                           report['issuer_execute_transaction']['finalized_slot']),
    }
    observed_finalized_slots = []
    for name, (minimum, transaction_finalized) in finalized_slots.items():
        value = report.get(name)
        if (type(value) is not int or isinstance(value, bool) or value < minimum
                or (transaction_finalized is not None and value != transaction_finalized)):
            raise ValueError('finalized snapshot slot mismatch: ' + name)
        observed_finalized_slots.append(value)
    if observed_finalized_slots != sorted(observed_finalized_slots):
        raise ValueError('finalized snapshot slots must advance monotonically')
    return _check_snapshots(report, output)


def _validate_config(config):
    required = {
        'schema', 'scope', 'variant', 'request_slot',
        'prior_stage_config', 'prior_stage_config_sha256',
        'prior_stage_status', 'prior_stage_status_sha256',
        'prior_stage_monitor', 'prior_stage_monitor_sha256',
        'prior_monitor_owner', 'stage_root', 'stage_report_sha256',
        'stage_plan_sha256', 'ledger', 'heldout_r0_clone_report',
        'heldout_r0_clone_report_sha256', 'expected_genesis',
        'runner', 'runner_sha256', 'full_wire', 'full_wire_sha256',
        'expected_program', 'expected_elf_sha256', 'output_dir',
        'control_output', 'rust_config_path', 'rust_config_sha256',
        'outer_limits_required'}
    if (type(config) is not dict or set(config) != required
            or config.get('schema') != 'credential-v3-disabled-config-negative-supervisor-v1'
            or config.get('scope') != SCOPE or config.get('request_slot') != 'A'
            or type(config.get('variant')) is not int
            or not 0 <= config['variant'] < 8
            or config.get('outer_limits_required') != LIMITS):
        raise ValueError('explicit pinned disabled-config negative contract required')
    for field in ('prior_stage_config_sha256', 'prior_stage_status_sha256',
                  'prior_stage_monitor_sha256', 'stage_report_sha256',
                  'stage_plan_sha256', 'heldout_r0_clone_report_sha256',
                  'runner_sha256', 'full_wire_sha256', 'expected_elf_sha256'):
        if (type(config.get(field)) is not str or len(config[field]) != 64
                or any(char not in '0123456789abcdef' for char in config[field])):
            raise ValueError(f'{field} pin required')
    for field in ('rust_config_sha256',):
        if (type(config.get(field)) is not str or len(config[field]) != 64
                or any(char not in '0123456789abcdef' for char in config[field])):
            raise ValueError(f'{field} pin required')


def _context_env(stage_config):
    path = Path(stage_config['context'])
    expected = stage_config['context_sha256']
    _, actual = execute.stage.snapshot_generated(path, 8192)
    if not path.is_absolute() or actual != expected:
        raise ValueError('pinned staged training context required')
    return {'P5_V3_CONTEXT': str(path), 'P5_V3_CONTEXT_SHA256': expected}


def run(config, config_sha256, config_path):
    if os.environ.get('P5_V3_DISABLED_CONFIG_NEGATIVE_SCOPE') != SCOPE:
        raise ValueError('explicit bounded disabled-config scope required')
    _validate_config(config)
    config_path = Path(config_path)
    if not config_path.is_absolute() or config_path.resolve(strict=True) != config_path:
        raise ValueError('canonical absolute supervisor config path required')
    encoded = (json.dumps(config, sort_keys=True, separators=(',', ':'),
                          allow_nan=False) + '\n').encode()
    if _sha(encoded) != config_sha256:
        raise ValueError('disabled-config config hash mismatch')

    stage_config = execute.pinned_json(config['prior_stage_config'],
                                       config['prior_stage_config_sha256'])
    prior = execute.pinned_json(config['prior_stage_status'],
                                config['prior_stage_status_sha256'])
    stage_monitor = execute.pinned_json(config['prior_stage_monitor'],
                                        config['prior_stage_monitor_sha256'])
    execute.review_stage(prior, stage_monitor, config)
    prepared = execute.pinned_json(stage_config['prior_config'],
                                   stage_config['prior_config_sha256'])
    stage_report_path = Path(config['stage_root']) / 'stage-report.json'
    stage_plan_path = Path(config['stage_root']) / 'plan.json'
    stage_report = _pinned(stage_report_path, config['stage_report_sha256'])
    stage_plan = _pinned(stage_plan_path, config['stage_plan_sha256'], 8192)
    execute.check_stage_report(stage_report, stage_plan, config, prepared)
    execute.report_loaded(stage_report, prepared)
    _clone_is_initial(config, stage_config, stage_report, prior, stage_monitor)
    rust_config_raw, rust_config_sha = execute.stage.snapshot_generated(
        Path(config['rust_config_path']), 65536)
    if rust_config_sha != config['rust_config_sha256']:
        raise ValueError('pinned Rust disabled-config input config required')
    rust_config = execute.base.decode_json(rust_config_raw)
    expected_rust_fields = {
        'schema', 'variant', 'request_slot', 'stage_root', 'stage_report',
        'stage_report_sha256', 'stage_plan', 'stage_plan_sha256', 'ledger',
        'heldout_r0_clone_report', 'heldout_r0_clone_report_sha256',
        'full_wire', 'full_wire_sha256', 'expected_program', 'expected_genesis',
        'expected_elf_sha256', 'output_dir', 'control_output', 'runner',
        'runner_sha256'}
    expected_config_values = {
        'variant': config['variant'], 'request_slot': 'A',
        'stage_root': config['stage_root'], 'stage_report': str(stage_report_path),
        'stage_report_sha256': config['stage_report_sha256'],
        'stage_plan': str(stage_plan_path),
        'stage_plan_sha256': config['stage_plan_sha256'],
        'ledger': config['ledger'],
        'heldout_r0_clone_report': config['heldout_r0_clone_report'],
        'heldout_r0_clone_report_sha256': config['heldout_r0_clone_report_sha256'],
        'full_wire': config['full_wire'],
        'full_wire_sha256': config['full_wire_sha256'],
        'expected_program': config['expected_program'],
        'expected_genesis': config['expected_genesis'],
        'expected_elf_sha256': config['expected_elf_sha256'],
        'output_dir': config['output_dir'], 'control_output': config['control_output'],
        'runner': config['runner'], 'runner_sha256': config['runner_sha256']}
    if (type(rust_config) is not dict or set(rust_config) != expected_rust_fields
            or rust_config.get('schema') != 'part5-v3-disabled-config-negative-config-v1'
            or any(rust_config.get(key) != value
                   for key, value in expected_config_values.items())):
        raise ValueError('Rust disabled-config config differs from supervised inputs')
    wire, wire_sha = execute.stage.snapshot_generated(config['full_wire'], 448)
    if len(wire) != 448 or wire_sha != config['full_wire_sha256']:
        raise ValueError('pinned Full R0 wire required')
    if (config['runner'] != stage_config['runner']
            or config['runner_sha256'] != stage_config['runner_sha256']
            or config['expected_program'] != prepared['program']
            or config['expected_elf_sha256'] != prepared['elf_sha256']
            or config['expected_genesis'] != stage_report['genesis']):
        raise ValueError('disabled-config expected loader identity differs from stage')
    execute.base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
    elf = execute.base.checked(prepared['elf'], prepared['elf_sha256'], 4 * 1024 * 1024)
    output = execute.base.fresh_child(config['output_dir'], REPO / 'artifacts/dynark/part5')
    control = execute.base.fresh_child(config['control_output'], REPO / 'artifacts/dynark/part5')
    if output == control:
        raise ValueError('separate negative output and control directories required')

    loaded = None
    validator = runner = None
    streams = []
    handlers = {}
    status = {'schema': 1, 'scope': SCOPE, 'status': 'failed',
              'error_type': None, 'config_sha256': config_sha256,
              'config_path': str(config_path),
              'rust_config_path': config['rust_config_path'],
              'rust_config_sha256': rust_config_sha,
              'effect_verified': False,
              'application_effect': False, 'config_disabled': False,
              'execute_rejected': False, 'accounts_unchanged': False,
              'issuer_disabled': False, 'issuer_execute_rejected': False,
              'issuer_accounts_unchanged': False,
              'ledger_reuse_requires_review': True,
              'whole_tree_cleanup_authority': 'external bounded_runner',
              'outer_limits_required': LIMITS}
    started = time.monotonic()
    def interrupted(signum, frame):
        raise InterruptedError('disabled-config supervisor interrupted')
    try:
        control.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        execute.base.ports_free(timeout_seconds=execute.base.PORT_WAIT_SECONDS)
        argv = execute.stage.resume_argv(prepared['validator'], config['ledger'])
        execute.base.write_new(control / 'invocation.json', {
            'validator_argv': argv, 'runner': config['runner'],
            'runner_sha256': config['runner_sha256'],
            'stage_report_sha256': config['stage_report_sha256'],
            'stage_plan_sha256': config['stage_plan_sha256'],
            'full_wire_sha256': config['full_wire_sha256'],
            'outer_limits_required': LIMITS})
        for name in ('validator.stdout.log', 'validator.stderr.log',
                     'runner.stdout.log', 'runner.stderr.log'):
            fd = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            streams.append(os.fdopen(fd, 'wb'))
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        validator = subprocess.Popen(argv, cwd=REPO, env=env,
            stdin=subprocess.DEVNULL, stdout=streams[0], stderr=streams[1])
        rpc = execute.base.LocalRpc()
        loaded = execute.wait_loaded_after_start(
            rpc, validator, prepared['program'], elf, prepared['elf_sha256'])
        execute.same_loaded(prior['loaded_program'], loaded)
        if (loaded.get('program') != config['expected_program']
                or loaded.get('elf_sha256') != config['expected_elf_sha256']
                or loaded.get('genesis') != config['expected_genesis']):
            raise ValueError('loaded disabled-config target identity mismatch')
        sizes, staged_bytes = [], []
        for name, expected_hash in zip(ACCOUNT_NAMES, stage_report['account_sha256']):
            raw, actual_hash = execute.stage.snapshot_generated(
                Path(config['stage_root']) / (name + '.bin'), 4096)
            if actual_hash != expected_hash:
                raise ValueError('pinned staged account bytes changed before negative')
            staged_bytes.append(raw)
            sizes.append(len(raw))
        _, finalized_before = execute.wait_staged_finality(
            rpc, stage_report, config['expected_program'],
            stage_report['account_sha256'], sizes)
        if finalized_before != staged_bytes:
            raise ValueError('loaded clone did not start from exact finalized stage accounts')
        env.update({
            'P5_V3_DISABLED_CONFIG_NEGATIVE_CONFIG': config['rust_config_path'],
            'P5_V3_DISABLED_CONFIG_NEGATIVE_CONFIG_SHA256': rust_config_sha,
            'P5_V3_DISABLED_CONFIG_NEGATIVE_SCOPE': SCOPE,
            'P5_V3_STAGE_ROOT': config['stage_root'],
            'P5_QUEUE_RPC': execute.base.RPC.rstrip('/'),
            'P5_QUEUE_PROGRAM': config['expected_program'],
            'P5_QUEUE_GENESIS': config['expected_genesis'],
            'P5_QUEUE_ELF': prepared['elf'],
            'P5_QUEUE_ELF_SHA256': config['expected_elf_sha256'],
            'P5_QUEUE_OUTPUT': str(output)})
        env.update(_context_env(stage_config))
        command = [config['runner'],
            'root_pinned_queue_v3_disabled_config_negative', '--exact', '--ignored',
            '--test-threads=1']
        runner = subprocess.Popen(command, cwd=REPO, env=env,
            stdin=subprocess.DEVNULL, stdout=streams[2], stderr=streams[3])
        deadline = min(time.monotonic() + RUNNER_BUDGET_SECONDS,
                       started + SUPERVISOR_BUDGET_SECONDS)
        while runner.poll() is None:
            if validator.poll() is not None:
                raise RuntimeError('validator exited during disabled-config Execute')
            if time.monotonic() >= deadline:
                raise TimeoutError('disabled-config runner deadline')
            time.sleep(0.1)
        if runner.wait() != 0:
            raise RuntimeError('disabled-config Rust runner failed')
        _check_supervisor_budget(started)
        report_path = output / 'disabled-config-negative-report.json'
        report_raw, report_sha = execute.stage.snapshot_generated(report_path, 65536)
        report = execute.base.decode_json(report_raw)
        _validate_report(report, config, stage_report, output)
        _check_supervisor_budget(started)
        status.update({'effect_verified': True, 'config_disabled': True,
            'execute_rejected': True, 'accounts_unchanged': True,
            'issuer_disabled': True, 'issuer_execute_rejected': True,
            'issuer_accounts_unchanged': True,
            'report_path': str(report_path), 'report_sha256': report_sha,
            'loaded_program': loaded})
    except Exception as error:
        status['error_type'] = type(error).__name__
        status['error_message'] = str(error)[:256]
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        for name, proc in (('runner', runner), ('validator', validator)):
            try:
                status[name + '_cleanup'] = execute.base.cleanup(proc)
            except Exception as error:
                status[name + '_cleanup'] = {'reaped': False, 'graceful': False,
                                             'error_type': type(error).__name__}
        status['elapsed_seconds'] = time.monotonic() - started
        for stream in streams:
            stream.close()
        try:
            execute.base.write_new(control / 'status.json', status)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    try:
        config = execute.pinned_json(args.config, args.config_sha256, 65536)
        return run(config, args.config_sha256, str(args.config))
    except Exception as error:
        raise SystemExit(f'disabled-config negative rejected: {type(error).__name__}: {str(error)[:180]}') from None


if __name__ == '__main__':
    sys.exit(main())
