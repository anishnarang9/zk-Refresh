#!/usr/bin/env python3
"""One externally bounded, training-only observation of a fresh R1 ledger copy.

The launcher must hold the global heavy lock through owner cleanup. Environment
attestations are a launch contract, not independent proof of enforced limits.
No runner, proof, program load, reset, or application transaction is invoked.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from harness.tests import queue_v3_local_execute as execute
from harness.tests.queue_v3_clone_ledger import clone, inventory

base = execute.base
stage = execute.stage
PART5 = REPO / 'artifacts/dynark/part5'
CASE = PART5 / 'v3-heldout-case-training-024-00/own_revocation'
OWNER = 'training-024-own-r1-replay-diagnostic-001'
LIMITS = {'runtime_seconds': 120, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 536870912}
BRANCH_SHA = '635b70cc1f8be7c64d021115351a39eb586288b9564ae2005bf97333bb370ce5'
PREPARE_SHA = '098c4a0b5e1442db89a6129319769265900f7394d5e3cc6efc5ca8d8cf9e7b21'
SOURCE = PART5 / 'application-v3-heldout-00-0b25fceb11894d2bac475f732a0da57d-own_revocation-runtime/ledger'
FAILED_CLONE = CASE / 'r1-own-clone/ledger'


def require_owner():
    if os.environ.get('P5_R1_DIAGNOSTIC_OWNER') != OWNER:
        raise ValueError('explicit external owner required')
    if json.loads(os.environ.get('P5_R1_DIAGNOSTIC_LIMITS', '{}')) != LIMITS:
        raise ValueError('exact external limits required')
    if os.environ.get('P5_R1_DIAGNOSTIC_GLOBAL_LOCK') != str(PART5 / '.v3-heldout-heavy.lock'):
        raise ValueError('stable primary global lock attestation required')


def fresh_root(path):
    path = Path(path)
    if (not path.is_absolute() or path.parent != PART5 or path.resolve() != path
            or not path.name.startswith('v3-r1-replay-diagnostic-')
            or path.exists() or path.is_symlink()):
        raise ValueError('fresh diagnostic direct child of primary part5 required')
    return path


def tree_sha(value):
    return hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()


def observe_accounts(rpc, staged, program, changed, sizes):
    return execute.wait_staged_finality(rpc, staged, program,
        changed['account_sha256'], sizes, minimum_slot=changed['finalized_slot'])


def admit(config):
    require_owner()
    if config.get('schema') != 1 or config.get('owner') != OWNER or config.get('limits') != LIMITS:
        raise ValueError('diagnostic owner/limits contract')
    output = fresh_root(config['output'])
    branch = execute.pinned_json(CASE / 'own_revocation-config.json', BRANCH_SHA)
    original = execute.pinned_json(CASE / 'prepare-config.json', PREPARE_SHA)
    staged = execute.pinned_json(Path(branch['stage_root']) / 'stage-report.json', branch['stage_report_sha256'])
    report_path = Path(branch['transition_root']) / 'transition-report.json'
    changed = execute.pinned_json(report_path, branch['transition_report_sha256'])
    status = execute.pinned_json(branch['transition_status'], branch['transition_status_sha256'])
    execute.pinned_json(branch['transition_monitor'], branch['transition_monitor_sha256'])
    execute.pinned_json(branch['clone_report'], branch['clone_report_sha256'])
    failed_monitor = execute.pinned_json(CASE / 'own_revocation-monitor.json',
        '5eb81a1737fe4a609a71a1327a9b8ba78edd843416cf122a87a4c0abeac960b8')
    failed_status = execute.pinned_json(Path(branch['control_output']) / 'status.json',
        'f2a3bcb8e3b5afcc375addded6e4aa4fbd7a13a670bdfd3203c6ef38a98bf233')
    if (failed_monitor.get('cleanup_remaining_owned_processes') != 0
            or failed_monitor.get('cleanup_status_unknown') is not False
            or failed_monitor.get('stop_reason') is not None
            or failed_status.get('validator_cleanup', {}).get('reaped') is not True
            or failed_status.get('runner_cleanup', {}).get('spawned') is not False):
        raise ValueError('preserved failed clone stopped cleanup evidence required')
    if changed['finalized_slot'] != 81 or staged['finalized_slot'] != 45:
        raise ValueError('exact Training-024 R0/R1 slots required')
    if Path(branch['ledger']) != FAILED_CLONE or Path(original['runtime_output']) / 'ledger' != SOURCE:
        raise ValueError('preserved ledger path identity mismatch')
    elf = base.checked(original['elf'], original['elf_sha256'], 4 * 1024 * 1024)
    base.checked(original['validator'], original['validator_sha256'], 128 * 1024 * 1024)
    source_before, failed_before = inventory(SOURCE), inventory(FAILED_CLONE)
    if (tree_sha(source_before) != config['source_inventory_sha256']
            or tree_sha(failed_before) != config['failed_clone_inventory_sha256']):
        raise ValueError('preserved ledger inventory pin mismatch')
    if sum(row[2] for row in source_before if row[1] == 'file') > 268435456:
        raise ValueError('source copy exceeds storage admission')
    sizes = [len(base.checked(Path(branch['transition_root']) / (name + '.bin'), digest, 4096))
             for name, digest in zip(execute.ACCOUNT_NAMES, changed['account_sha256'])]
    if len(sizes) != 5:
        raise ValueError('five pinned R1 accounts required')
    return output, branch, original, staged, changed, status, report_path, elf, source_before, failed_before, sizes


def run(config, config_sha):
    values = admit(config)
    output, branch, original, staged, changed, status, report_path, elf, source_before, failed_before, sizes = values
    os.umask(0o077)
    output.mkdir(mode=0o700)
    receipt = {'schema': 'part5-v3-r1-replay-diagnostic-v1', 'training_only': True,
               'case_acceptance': False, 'application_effect': False,
               'application_transactions_submitted': 0, 'proof_created': False,
               'config_sha256': config_sha, 'owner': OWNER, 'limits': LIMITS,
               'minimum_context_slot': changed['finalized_slot'], 'status': 'failed',
               'ledger_reuse_requires_review': True}
    proc = None
    logs = []
    handlers = {}
    def interrupted(signum, frame):
        raise InterruptedError('diagnostic interrupted')
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        clone(SOURCE, output / 'ledger', report_path, branch['transition_report_sha256'],
              branch['transition_status'], branch['transition_status_sha256'],
              branch['transition_monitor'], branch['transition_monitor_sha256'])
        base.ports_free(timeout_seconds=base.PORT_WAIT_SECONDS)
        argv = stage.resume_argv(original['validator'], output / 'ledger')
        base.write_new(output / 'invocation.json', {'argv': argv, 'no_runner': True})
        for name in ('validator.stdout.log', 'validator.stderr.log'):
            fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            logs.append(os.fdopen(fd, 'wb'))
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        proc = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                stdout=logs[0], stderr=logs[1], start_new_session=False)
        rpc = base.LocalRpc()
        loaded = execute.wait_loaded_after_start(rpc, proc, original['program'], elf, original['elf_sha256'])
        execute.same_loaded(status['loaded_program'], loaded)
        slot, accounts = observe_accounts(rpc, staged, original['program'], changed, sizes)
        receipt.update(status='observed', context_slot=slot, loaded_program=loaded,
                       account_sha256=[base.sha(raw) for raw in accounts],
                       expected_account_sha256=changed['account_sha256'])
    except Exception as error:
        receipt.update(error_type=type(error).__name__, error=str(error))
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            receipt['validator_cleanup'] = base.cleanup(proc)
        except Exception as error:
            receipt.update(status='failed', cleanup_error_type=type(error).__name__)
        try:
            receipt['source_unchanged'] = inventory(SOURCE) == source_before
            receipt['failed_clone_unchanged'] = inventory(FAILED_CLONE) == failed_before
            if not receipt['source_unchanged'] or not receipt['failed_clone_unchanged']:
                receipt['status'] = 'failed'
        except Exception as error:
            receipt.update(status='failed', inventory_error_type=type(error).__name__)
        if not receipt.get('validator_cleanup', {}).get('reaped'):
            receipt['status'] = 'failed'
        for log in logs:
            log.close()
        base.write_new(output / 'diagnostic-receipt.json', receipt)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    return 0 if receipt['status'] == 'observed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    config = execute.pinned_json(args.config, args.config_sha256)
    return run(config, args.config_sha256)


if __name__ == '__main__':
    sys.exit(main())
