#!/usr/bin/env python3
"""Restart a pinned v3 local ledger, stage a request, and retain exact evidence.

This is a training-only local stage. The external bounded runner owns whole-tree
limits. A previously interrupted ledger is a review candidate, never assumed
reusable: finalized loaded identity must be reestablished before any transaction.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location('v3_local_prepare', Path(__file__).with_name('queue_v3_local_prepare.py'))
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
REPO = Path(__file__).resolve().parents[2]
LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}


def review_prior(prior, monitor, original, config):
    if (prior.get('schema') != 1 or prior.get('scope') != 'part5-v3-local-prepare'
            or prior.get('config_sha256') != config['prior_config_sha256']
            or prior.get('application_effect') is not False
            or prior.get('prepared_application_accounts') is not False
            or prior.get('loaded_program', {}).get('elf_match') is not True
            or prior['loaded_program'].get('elf_sha256') != original['elf_sha256']
            or prior['loaded_program'].get('program') != original['program']
            or prior['loaded_program'].get('genesis') != config['expected_genesis']
            or prior.get('ledger') != config['ledger']
            or prior.get('error_type') is not None
            or prior.get('cleanup', {}).get('reaped') is not True
            or prior.get('ledger_reuse_requires_review') is not True
            or prior.get('status') != 'failed'):
        raise ValueError('reviewable interrupted prepare with loaded v3 identity required')
    # The known first run observed SIGINT termination after finalized loaded
    # identity. It did not prove graceful ledger closure; restart is mandatory.
    if prior['cleanup'].get('exit_code') != -signal.SIGINT:
        raise ValueError('unexpected prior validator shutdown')
    if (monitor.get('owner') != config.get('prior_monitor_owner', 'part5-v3-local-prepare-001')
            or monitor.get('stop_reason') is not None
            or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False):
        raise ValueError('prior bounded cleanup or cap evidence insufficient')


def resume_argv(validator, ledger):
    ledger = Path(ledger)
    if not ledger.is_absolute() or ledger.resolve() != ledger or not ledger.is_dir():
        raise ValueError('canonical existing ledger required')
    return [str(validator), '--ledger', str(ledger), '--bind-address', '127.0.0.1',
            '--rpc-port', '18999', '--gossip-port', '18901', '--faucet-port', '19001',
            '--dynamic-port-range', '19002-19028', '--limit-ledger-size', '10000', '--quiet']


def validate_stage_paths(output, control, root):
    if (output == control or output.parent != root or control.parent != root
            or not output.name.startswith('application-v3-')
            or not control.name.startswith('application-v3-')):
        raise ValueError('distinct direct v3 output children required')


def snapshot_generated(path, cap):
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > cap):
        raise ValueError('owner-only bounded generated artifact required')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError('generated artifact changed at open')
        raw = stream.read(cap + 1)
        if identity(before) != identity(os.fstat(stream.fileno())) or len(raw) != before.st_size:
            raise ValueError('generated artifact changed during read')
    if len(raw) > cap:
        raise ValueError('generated artifact cap')
    return raw, base.sha(raw)


def admit(config):
    if (config.get('schema') != 1 or config.get('scope') != 'part5-v3-local-stage'
            or config.get('outer_limits_required') != LIMITS):
        raise ValueError('explicit bounded v3 stage contract required')
    original = base.decode_json(base.checked(config['prior_config'], config['prior_config_sha256'], 65536))
    prior = base.decode_json(base.checked(config['prior_status'], config['prior_status_sha256'], 65536))
    monitor = base.decode_json(base.checked(config['prior_monitor'], config['prior_monitor_sha256'], 65536))
    review_prior(prior, monitor, original, config)
    plan = base.decode_json(base.checked(original['build_plan'], original['build_plan_sha256'], 65536))
    base.prep.check_manifest(REPO, plan['source_manifest'])
    if base.prep.external_config_pins(REPO) != plan['external_cargo_config_pins']:
        raise ValueError('Cargo configuration changed since reviewed build')
    base.checked(plan['argv'][0], plan['builder_sha256'], 128 * 1024 * 1024)
    elf = base.checked(original['elf'], original['elf_sha256'], 4 * 1024 * 1024)
    base.prep.compare_elf_payload(elf, elf, original['elf_sha256'])
    validator = original['validator']
    base.checked(validator, original['validator_sha256'], 128 * 1024 * 1024)
    base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
    base.checked(config['context'], config['context_sha256'], 8192)
    ledger = Path(config['ledger'])
    if ledger != Path(original['runtime_output']) / 'ledger':
        raise ValueError('original protected ledger path required')
    for path, directory in [(ledger, True), (ledger / 'genesis.bin', False)]:
        meta = path.lstat()
        if (path.resolve() != path or meta.st_uid != os.getuid()
                or stat.S_IMODE(meta.st_mode) != (0o700 if directory else 0o600)
                or (not stat.S_ISDIR(meta.st_mode) if directory else not stat.S_ISREG(meta.st_mode))):
            raise ValueError('owner-only persistent ledger required')
    stage_output = base.fresh_child(config['stage_output'], REPO / 'artifacts/dynark/part5')
    control = base.fresh_child(config['control_output'], REPO / 'artifacts/dynark/part5')
    validate_stage_paths(stage_output, control, REPO / 'artifacts/dynark/part5')
    argv = resume_argv(validator, ledger)
    return original, prior, elf, stage_output, control, argv


def run(config, config_sha256):
    if os.environ.get('P5_V3_STAGE_SUPERVISOR') != 'local-ledger-review-and-stage':
        raise ValueError('explicit external bounded runner scope required')
    original, prior, elf, output, control, argv = admit(config)
    started = time.monotonic(); validator = runner = None; logs = []; handlers = {}
    previous_umask = os.umask(0o077)
    status = {'schema': 1, 'scope': 'part5-v3-local-stage', 'status': 'failed',
              'stage_verified': False, 'ledger_reuse_requires_review': True,
              'application_effect': False, 'devnet': False,
              'config_sha256': config_sha256, 'outer_limits_required': LIMITS,
              'whole_tree_cleanup_authority': 'external bounded_runner'}
    def interrupted(signum, frame):
        raise InterruptedError('stage supervisor interrupted')
    try:
        control.mkdir(mode=0o700); output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        base.ports_free()
        for name in ('validator.stdout.log', 'validator.stderr.log', 'runner.stdout.log', 'runner.stderr.log'):
            fd = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            logs.append(os.fdopen(fd, 'wb'))
        base.write_new(control / 'invocation.json', {'validator_argv': argv,
            'runner': config['runner'], 'runner_sha256': config['runner_sha256'],
            'prior_status_sha256': config['prior_status_sha256'],
            'elf_sha256': original['elf_sha256'], 'context_sha256': config['context_sha256'],
            'outer_limits_required': LIMITS})
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        validator = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                     stdout=logs[0], stderr=logs[1], start_new_session=False)
        loaded = base.wait_loaded(base.LocalRpc(), validator, original['program'], elf, original['elf_sha256'])
        for key in ('program', 'programdata', 'elf_sha256', 'program_account_sha256',
                    'programdata_account_sha256', 'genesis'):
            if loaded[key] != prior['loaded_program'][key]:
                raise ValueError('persistent local program or genesis changed on restart')
        env.update({'P5_V3_STAGE_SCOPE': 'part5-v3-local-stage',
                    'P5_QUEUE_RPC': base.RPC.rstrip('/'),
                    'P5_QUEUE_PROGRAM': original['program'],
                    'P5_QUEUE_GENESIS': loaded['genesis'],
                    'P5_QUEUE_ELF': original['elf'],
                    'P5_QUEUE_ELF_SHA256': original['elf_sha256'],
                    'P5_QUEUE_OUTPUT': str(output),
                    'P5_V3_CONTEXT': config['context'],
                    'P5_V3_CONTEXT_SHA256': config['context_sha256']})
        runner_argv = [config['runner'], 'root_pinned_queue_v3_stage', '--exact', '--ignored', '--test-threads=1']
        runner = subprocess.Popen(runner_argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                  stdout=logs[2], stderr=logs[3], start_new_session=False)
        deadline = time.monotonic() + 125
        while runner.poll() is None:
            if validator.poll() is not None:
                raise RuntimeError('validator exited during v3 staging')
            if time.monotonic() >= deadline:
                raise TimeoutError('v3 staging runner deadline')
            time.sleep(0.1)
        if runner.wait() != 0:
            raise RuntimeError('v3 staging runner rejected')
        report_bytes, report_sha256 = snapshot_generated(output / 'stage-report.json', 65536)
        report = base.decode_json(report_bytes)
        if (report.get('schema') != 'part5-v3-local-stage-v1' or report.get('passed') is not True
                or report.get('proof_created') is not False
                or report.get('application_effect') is not False
                or report.get('genesis') != loaded['genesis']
                or report.get('program') != original['program']
                or report.get('loaded_program', {}).get('elf_match') is not True):
            raise ValueError('exact finalized staging report required')
        after = base.wait_loaded(base.LocalRpc(), validator, original['program'], elf, original['elf_sha256'])
        if any(after[key] != loaded[key] for key in ('program', 'programdata', 'elf_sha256',
                        'program_account_sha256', 'programdata_account_sha256', 'genesis')):
            raise ValueError('program identity changed during staging')
        status.update({'stage_verified': True, 'stage_report_sha256': report_sha256,
                       'loaded_program': after, 'stage_output': str(output)})
    except Exception as error:
        status['error_type'] = type(error).__name__
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        for name, proc in (('runner', runner), ('validator', validator)):
            try:
                status[name + '_cleanup'] = base.cleanup(proc)
            except Exception as error:
                status[name + '_cleanup'] = {'reaped': False, 'graceful': False,
                                             'error_type': type(error).__name__}
        # Finalized staging can be established while ledger persistence still
        # requires independent review after the observed SIGINT exit.
        if status['stage_verified'] and status['validator_cleanup'].get('graceful'):
            status['status'] = 'passed'
            status['ledger_reuse_requires_review'] = False
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
    print(json.dumps({'status': status['status'], 'stage_verified': status['stage_verified'],
                      'report': str(control / 'status.json')}))
    return 0 if status['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    config = base.decode_json(base.checked(args.config, args.config_sha256, 65536))
    return run(config, args.config_sha256)


if __name__ == '__main__':
    sys.exit(main())
