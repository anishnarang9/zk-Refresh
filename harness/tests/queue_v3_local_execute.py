#!/usr/bin/env python3
"""Pinned training Full Execute on a reviewed local ledger.

The external bounded runner owns whole-tree resource limits and cleanup. Finalized
application evidence and graceful persistent-ledger shutdown are separate facts.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from harness.tests.queue_v3_clone_ledger import inventory as ledger_inventory

_spec = importlib.util.spec_from_file_location('v3_stage', Path(__file__).with_name('queue_v3_local_stage.py'))
stage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stage)
base = stage.base
LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296, 'storage_growth_bytes': 268435456}
IDENTITY_FIELDS = ('program', 'programdata', 'elf_sha256', 'program_account_sha256',
                   'programdata_account_sha256', 'genesis')
ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')


def pinned_json(path, digest, cap=65536):
    return base.decode_json(base.checked(path, digest, cap))


def same_loaded(expected, actual):
    if any(name not in expected or actual.get(name) != expected[name] for name in IDENTITY_FIELDS):
        raise ValueError('exact loaded program or genesis changed')


def report_loaded(report, original):
    loaded = report.get('loaded_program', {})
    if loaded.get('elf_match') is not True or loaded.get('elf_sha256') != original['elf_sha256']:
        raise ValueError('report ELF identity mismatch')


def private_directory(path):
    path = Path(path)
    meta = path.lstat()
    if (not path.is_absolute() or path.resolve() != path or not stat.S_ISDIR(meta.st_mode)
            or stat.S_IMODE(meta.st_mode) != 0o700 or meta.st_uid != os.getuid()):
        raise ValueError('canonical owner-only directory required')
    return path


def wait_loaded_after_start(rpc, validator, program, elf, elf_sha256):
    deadline = time.monotonic() + 30
    while True:
        try:
            return base.wait_loaded(rpc, validator, program, elf, elf_sha256,
                                    timeout=max(0.1, deadline - time.monotonic()))
        except ValueError as error:
            if str(error) != 'invalid RPC envelope' or time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def review_stage(prior, monitor, config):
    if (prior.get('schema') != 1 or prior.get('scope') != 'part5-v3-local-stage'
            or prior.get('config_sha256') != config['prior_stage_config_sha256']
            or prior.get('stage_report_sha256') != config['stage_report_sha256']
            or prior.get('stage_output') != config['stage_root']
            or prior.get('status') != 'failed' or prior.get('stage_verified') is not True
            or prior.get('application_effect') is not False or prior.get('error_type') is not None
            or prior.get('ledger_reuse_requires_review') is not True
            or prior.get('validator_cleanup', {}).get('reaped') is not True
            or prior['validator_cleanup'].get('graceful') is not False
            or prior['validator_cleanup'].get('exit_code') != -signal.SIGINT
            or prior.get('runner_cleanup', {}).get('reaped') is not True
            or prior['runner_cleanup'].get('exit_code') != 0):
        raise ValueError('verified staging with reviewed SIGINT persistence failure required')
    if (monitor.get('owner') != config['prior_monitor_owner']
            or monitor.get('stop_reason') is not None or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False):
        raise ValueError('prior stage whole-tree cleanup evidence insufficient')


def check_stage_report(report, plan, config, original):
    if (report.get('schema') != 'part5-v3-local-stage-v1' or report.get('passed') is not True
            or report.get('training_only') is not True or report.get('application_effect') is not False
            or report.get('proof_created') is not False
            or report.get('plan_sha256') != config['stage_plan_sha256']
            or report.get('program') != original['program']
            or report.get('genesis') != config['expected_genesis']
            or base.b58(bytes(plan['program'])) != original['program']
            or base.b58(bytes(plan['genesis'])) != config['expected_genesis']
            or type(report.get('finalized_slot')) is not int or report['finalized_slot'] <= 0
            or not isinstance(report.get('account_sha256'), list) or len(report['account_sha256']) != 5):
        raise ValueError('pinned exact finalized stage report required')
    for name in ACCOUNT_NAMES:
        base.key(report[name])
    if len({report[name] for name in ACCOUNT_NAMES}) != 5:
        raise ValueError('distinct stage account addresses required')
    for digest in report['account_sha256']:
        base.prep.canonical_sha(digest)


def finalized_accounts(rpc, report, minimum, program, expected_hashes, sizes):
    keys = [report[name] for name in ACCOUNT_NAMES]
    result = rpc('getMultipleAccounts', [keys, {'encoding': 'base64', 'commitment': 'finalized',
                                              'minContextSlot': minimum}])
    slot, accounts = base.batch_result(result, 5, minimum)
    raw_accounts = []
    for index, account in enumerate(accounts):
        if (not isinstance(account, dict) or account.get('owner') != program
                or account.get('executable') is not False):
            raise ValueError('finalized owner/executable mismatch')
        raw = base.account_bytes(account)
        actual_hash = base.sha(raw)
        if len(raw) != sizes[index] or actual_hash != expected_hashes[index]:
            raise ValueError(
                'finalized exact account bytes mismatch '
                f'role={ACCOUNT_NAMES[index]} context_slot={slot} '
                f'expected_sha256={expected_hashes[index]} actual_sha256={actual_hash} '
                f'expected_size={sizes[index]} actual_size={len(raw)}'
            )
        raw_accounts.append(raw)
    return slot, raw_accounts


def wait_staged_finality(rpc, report, program, expected_hashes, sizes, minimum_slot=None):
    minimum = report['finalized_slot'] if minimum_slot is None else minimum_slot
    if type(minimum) is not int or minimum < report['finalized_slot']:
        raise ValueError('finalized account minimum slot precedes staged finality')
    deadline = time.monotonic() + 30
    while True:
        try:
            return finalized_accounts(rpc, report, minimum, program,
                                      expected_hashes, sizes)
        except base.NotReady:
            pass
        except ValueError as error:
            if str(error) != 'invalid RPC envelope':
                raise
        if time.monotonic() >= deadline:
            raise TimeoutError('staged finalized account readiness deadline')
        time.sleep(0.1)


def check_effect_bytes(before, after, report):
    # Offsets/lengths are the pinned application_v3.rs Request::encode and
    # Queue::encode layouts. Program source inventory is checked at admission.
    if len(before) != 5 or len(after) != 5:
        raise ValueError('five effect account roles required')
    config, request, queue = before[0], before[3], before[4]
    config_key = base.key(report['config'])
    request_key = base.key(report['request'])
    if (len(config) != 381 or config[:8] != b'DYNCONF3'
            or len(request) != 2249 or request[:8] != b'DYNREQ03'
            or request[8:40] != config_key or request[183] != 1
            or len(queue) != 2090 or queue[:8] != b'DYNQUE03'
            or queue[8:40] != config_key or any(queue[40:])):
        raise ValueError('pinned finalized request and empty v3 queue required')
    expected_request = bytearray(request)
    expected_request[183] = 2
    expected_queue = bytearray(queue)
    expected_queue[40:42] = (1).to_bytes(2, 'big')
    expected_queue[42:74] = request_key
    if (after[0] != config or after[3] != expected_request or after[4] != expected_queue):
        raise ValueError('effect must only consume request and append it once')


def review_ledger(config, prior_config, original):
    source = Path(prior_config['ledger'])
    if source != Path(original['runtime_output']) / 'ledger':
        raise ValueError('original persistent ledger required')
    ledger = private_directory(config['ledger'])
    clone_path = config.get('heldout_r0_clone_report')
    if clone_path is None:
        if ledger != source or 'heldout_r0_clone_report_sha256' in config:
            raise ValueError('original persistent ledger required')
    else:
        if (Path(clone_path) != ledger.parent / 'clone-report.json'
                or ledger == source or source in ledger.parents
                or ledger in source.parents):
            raise ValueError('separate R0 clone receipt required')
        clone = pinned_json(clone_path, config['heldout_r0_clone_report_sha256'])
        expected = {'schema': 'part5-v3-heldout-r0-ledger-clone-v1',
                    'heldout_acceptance': False,
                    'stage_report_sha256': config['stage_report_sha256'],
                    'stage_status_sha256': config['prior_stage_status_sha256'],
                    'stage_monitor_sha256': config['prior_stage_monitor_sha256'],
                    'source': str(source), 'destination': str(ledger),
                    'source_stable': True, 'copy_identical': True,
                    'loaded_identity_rechecked_after_restart': False,
                    'application_effect': False}
        if any(clone.get(key) != value for key, value in expected.items()):
            raise ValueError('pinned heldout R0 clone receipt required')
        rows = ledger_inventory(ledger)
        tree_sha = hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()
        if clone.get('entry_count') != len(rows) or clone.get('tree_sha256') != tree_sha:
            raise ValueError('R0 clone byte inventory changed')
    stage.snapshot_generated(ledger / 'genesis.bin', 16 * 1024 * 1024)
    return ledger


def admit(config):
    if (config.get('schema') != 1 or config.get('scope') != 'part5-v3-local-execute'
            or config.get('outer_limits_required') != LIMITS):
        raise ValueError('explicit bounded execute contract required')
    prior_config = pinned_json(config['prior_stage_config'], config['prior_stage_config_sha256'])
    prior = pinned_json(config['prior_stage_status'], config['prior_stage_status_sha256'])
    monitor = pinned_json(config['prior_stage_monitor'], config['prior_stage_monitor_sha256'])
    review_stage(prior, monitor, config)
    original = pinned_json(prior_config['prior_config'], prior_config['prior_config_sha256'])
    build = pinned_json(original['build_plan'], original['build_plan_sha256'])
    base.prep.check_manifest(REPO, build['source_manifest'])
    if base.prep.external_config_pins(REPO) != build['external_cargo_config_pins']:
        raise ValueError('build Cargo configuration changed')
    base.checked(build['argv'][0], build['builder_sha256'], 128 * 1024 * 1024)
    elf = base.checked(original['elf'], original['elf_sha256'], 4 * 1024 * 1024)
    base.prep.compare_elf_payload(elf, elf, original['elf_sha256'])
    base.checked(original['validator'], original['validator_sha256'], 128 * 1024 * 1024)
    base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
    base.checked(config['context'], config['context_sha256'], 8192)
    private_directory(Path(config['full_wire']).parent)
    if Path(config['full_wire']).lstat().st_nlink != 1:
        raise ValueError('private proof wire must have one link')
    wire, wire_hash = stage.snapshot_generated(config['full_wire'], 448)
    if len(wire) != 448 or wire_hash != config['full_wire_sha256']:
        raise ValueError('pinned private six-public proof wire required')
    private_directory(Path(config['replay_full_wire']).parent)
    if Path(config['replay_full_wire']).lstat().st_nlink != 1:
        raise ValueError('private replay proof wire must have one link')
    replay_wire, replay_wire_hash = stage.snapshot_generated(config['replay_full_wire'], 448)
    if replay_wire_hash != config['replay_full_wire_sha256']:
        raise ValueError('pinned private replay proof wire required')
    check_replay_wire(wire, replay_wire)
    root = private_directory(config['stage_root'])
    if str(root) != prior_config['stage_output']:
        raise ValueError('original stage output required')
    raw, digest = stage.snapshot_generated(root / 'stage-report.json', 65536)
    if digest != config['stage_report_sha256']:
        raise ValueError('stage report identity changed')
    report = base.decode_json(raw)
    raw, digest = stage.snapshot_generated(root / 'plan.json', 8192)
    if digest != config['stage_plan_sha256']:
        raise ValueError('stage plan identity changed')
    plan = base.decode_json(raw)
    check_stage_report(report, plan, config, original)
    report_loaded(report, original)
    sizes = []
    for name, expected in zip(ACCOUNT_NAMES, report['account_sha256']):
        data, digest = stage.snapshot_generated(root / (name + '.bin'), 4096)
        if not data or digest != expected:
            raise ValueError('staged account artifact identity changed')
        sizes.append(len(data))
    review_ledger(config, prior_config, original)
    output = base.fresh_child(config['execute_output'], REPO / 'artifacts/dynark/part5')
    control = base.fresh_child(config['control_output'], REPO / 'artifacts/dynark/part5')
    stage.validate_stage_paths(output, control, REPO / 'artifacts/dynark/part5')
    return original, prior, report, elf, sizes, output, control


def check_replay_wire(wire, replay_wire):
    if len(wire) != 448 or len(replay_wire) != 448:
        raise ValueError('replay wire must be 448-byte Full wires')
    if wire[:192] != replay_wire[:192]:
        raise ValueError('replay wire must have the same Full statement')
    if wire[192:] == replay_wire[192:]:
        raise ValueError('replay wire must contain a distinct Full proof')


def check_effect_report(report, config, original):
    if (report.get('schema') != 'part5-v3-local-execute-v1' or report.get('passed') is not True
            or report.get('application_effect') is not True or report.get('effect_count') != 1
            or report.get('request_consumed') is not True or report.get('proof_mode') != 'Full'
            or report.get('stage_report_sha256') != config['stage_report_sha256']
            or report.get('stage_plan_sha256') != config['stage_plan_sha256']
            or report.get('wire_sha256') != config['full_wire_sha256']
            or report.get('replay_wire_sha256') != config['replay_full_wire_sha256']
            or report.get('program') != original['program']
            or report.get('genesis') != config['expected_genesis']
            or type(report.get('finalized_slot')) is not int or report['finalized_slot'] <= 0
            or not isinstance(report.get('account_sha256'), list) or len(report['account_sha256']) != 5):
        raise ValueError('exact finalized Full effect report required')
    for digest in report['account_sha256']:
        base.prep.canonical_sha(digest)


def finish_status(status):
    if (status['effect_verified'] and status['validator_cleanup'].get('graceful') is True
            and status['validator_cleanup'].get('reaped') is True
            and status['validator_cleanup'].get('exit_code') == 0
            and status['runner_cleanup'].get('reaped') is True
            and status['runner_cleanup'].get('exit_code') == 0):
        status['status'] = 'passed'
        status['ledger_reuse_requires_review'] = False


def run(config, config_sha256):
    if os.environ.get('P5_V3_EXEC_SUPERVISOR') != 'local-ledger-review-and-execute':
        raise ValueError('explicit external bounded runner scope required')
    original, prior, staged, elf, sizes, output, control = admit(config)
    started = time.monotonic(); validator = runner = None; logs = []; handlers = {}
    previous_umask = os.umask(0o077)
    status = {'schema': 1, 'scope': 'part5-v3-local-execute', 'status': 'failed',
              'effect_verified': False, 'application_effect': False, 'effect_outcome': 'not_submitted',
              'ledger_reuse_requires_review': True,
              'config_sha256': config_sha256, 'devnet': False, 'training_only': True,
              'outer_limits_required': LIMITS, 'whole_tree_cleanup_authority': 'external bounded_runner'}
    def interrupted(signum, frame):
        raise InterruptedError('execute supervisor interrupted')
    try:
        control.mkdir(mode=0o700); output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        base.ports_free(timeout_seconds=base.PORT_WAIT_SECONDS)
        argv = stage.resume_argv(original['validator'], config['ledger'])
        base.write_new(control / 'invocation.json', {'validator_argv': argv,
            'runner': config['runner'], 'runner_sha256': config['runner_sha256'],
            'prior_stage_status_sha256': config['prior_stage_status_sha256'],
            'stage_report_sha256': config['stage_report_sha256'], 'stage_plan_sha256': config['stage_plan_sha256'],
            'wire_sha256': config['full_wire_sha256'], 'outer_limits_required': LIMITS})
        for name in ('validator.stdout.log', 'validator.stderr.log', 'runner.stdout.log', 'runner.stderr.log'):
            fd = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            logs.append(os.fdopen(fd, 'wb'))
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        validator = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                     stdout=logs[0], stderr=logs[1], start_new_session=False)
        rpc = base.LocalRpc()
        status['phase'] = 'loaded_identity'
        loaded = wait_loaded_after_start(rpc, validator, original['program'], elf, original['elf_sha256'])
        same_loaded(prior['loaded_program'], loaded)
        status['phase'] = 'staged_snapshots'
        staged_bytes = []
        for name, expected in zip(ACCOUNT_NAMES, staged['account_sha256']):
            raw, digest = stage.snapshot_generated(Path(config['stage_root']) / (name + '.bin'), 4096)
            if digest != expected:
                raise ValueError('pinned staged bytes changed before Execute')
            staged_bytes.append(raw)
        status['phase'] = 'staged_finality'
        pre_slot, _ = wait_staged_finality(rpc, staged, original['program'],
                                           staged['account_sha256'], sizes)
        status['phase'] = 'execute_runner'
        env.update({'P5_V3_EXEC_SCOPE': 'part5-v3-local-execute',
                    'P5_V3_STAGE_ROOT': config['stage_root'],
                    'P5_V3_STAGE_REPORT_SHA256': config['stage_report_sha256'],
                    'P5_V3_STAGE_PLAN_SHA256': config['stage_plan_sha256'],
                    'P5_V3_FULL_WIRE': config['full_wire'], 'P5_V3_FULL_WIRE_SHA256': config['full_wire_sha256'],
                    'P5_V3_REPLAY_FULL_WIRE': config['replay_full_wire'],
                    'P5_V3_REPLAY_FULL_WIRE_SHA256': config['replay_full_wire_sha256'],
                    'P5_V3_CONTEXT': config['context'], 'P5_V3_CONTEXT_SHA256': config['context_sha256'],
                    'P5_QUEUE_RPC': base.RPC.rstrip('/'), 'P5_QUEUE_PROGRAM': original['program'],
                    'P5_QUEUE_GENESIS': loaded['genesis'], 'P5_QUEUE_ELF': original['elf'],
                    'P5_QUEUE_ELF_SHA256': original['elf_sha256'], 'P5_QUEUE_OUTPUT': str(output)})
        runner_argv = [config['runner'], 'root_pinned_queue_v3_execute', '--exact', '--ignored', '--test-threads=1']
        status.update({'application_effect': None, 'effect_outcome': 'requires_reconciliation'})
        runner = subprocess.Popen(runner_argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                  stdout=logs[2], stderr=logs[3], start_new_session=False)
        deadline = time.monotonic() + 110
        while runner.poll() is None:
            if validator.poll() is not None:
                raise RuntimeError('validator exited during Execute')
            if time.monotonic() >= deadline:
                raise TimeoutError('Execute runner deadline')
            time.sleep(0.1)
        if runner.wait() != 0:
            raise RuntimeError('Execute runner rejected; effect may require reconciliation')
        raw, report_sha = stage.snapshot_generated(output / 'execute-report.json', 65536)
        report = base.decode_json(raw)
        check_effect_report(report, config, original)
        report_loaded(report, original)
        post_slot, post = finalized_accounts(rpc, staged, max(pre_slot, report['finalized_slot']),
                                             original['program'], report['account_sha256'], sizes)
        check_effect_bytes(staged_bytes, post, staged)
        for name, expected in zip(ACCOUNT_NAMES, post):
            artifact, _ = stage.snapshot_generated(output / (name + '.bin'), 4096)
            if artifact != expected:
                raise ValueError('effect artifact differs from finalized account')
        after = base.wait_loaded(rpc, validator, original['program'], elf, original['elf_sha256'])
        same_loaded(loaded, after)
        base.prep.check_manifest(REPO, pinned_json(original['build_plan'], original['build_plan_sha256'])['source_manifest'])
        status.update({'effect_verified': True, 'application_effect': True, 'effect_outcome': 'verified', 'effect_count': 1,
                       'execute_report_sha256': report_sha, 'finalized_slot': post_slot,
                       'loaded_program': after, 'execute_output': str(output)})
    except Exception as error:
        status['error_type'] = type(error).__name__
        status['error_message'] = str(error)[:256]
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        for name, proc in (('runner', runner), ('validator', validator)):
            try:
                status[name + '_cleanup'] = base.cleanup(proc)
            except Exception as error:
                status[name + '_cleanup'] = {'reaped': False, 'graceful': False, 'error_type': type(error).__name__}
        finish_status(status)
        status['elapsed_seconds'] = time.monotonic() - started
        for stream in logs:
            stream.close()
        try:
            if control.is_dir():
                base.write_new(control / 'status.json', status)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            os.umask(previous_umask)
    print(base.json.dumps({'status': status['status'], 'effect_verified': status['effect_verified'],
                          'report': str(control / 'status.json')}))
    return 0 if status['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    return run(pinned_json(args.config, args.config_sha256), args.config_sha256)


if __name__ == '__main__':
    sys.exit(main())
