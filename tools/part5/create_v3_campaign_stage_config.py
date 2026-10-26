#!/usr/bin/env python3
"""Pin a fresh deployment-only local ledger to one frozen campaign R0 stage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

from tools.part5.prepare_v3_campaign_context import derive, encoded


ROOT = Path(__file__).resolve().parents[2] / 'artifacts/dynark/part5'


LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}


def snapshot(path, cap):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute campaign input required')
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_size > cap):
        raise ValueError('bounded owner-controlled regular campaign input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid,
                          s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(fd, 'rb') as stream:
        if identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError('campaign input changed at open')
        raw = stream.read(cap + 1)
        if (identity(before) != identity(os.fstat(stream.fileno()))
                or len(raw) != before.st_size):
            raise ValueError('campaign input changed during read')
    return raw, hashlib.sha256(raw).hexdigest()


def fresh(path):
    path = Path(path)
    if (not path.is_absolute() or path.parent.resolve(strict=True) != path.parent
            or path.exists() or path.is_symlink()):
        raise ValueError('fresh canonical campaign output required')
    return path


def create(args):
    inputs = {name: snapshot(getattr(args, name), cap) for name, cap in (
        ('prior_config', 65536), ('prior_status', 65536), ('prior_monitor', 65536),
        ('context', 8192), ('runner', 128 * 1024 * 1024))}
    previous = json.loads(inputs['prior_config'][0])
    status = json.loads(inputs['prior_status'][0])
    monitor = json.loads(inputs['prior_monitor'][0])
    context_raw = inputs['context'][0]
    context = json.loads(context_raw)
    allocations = context.get('initial_allocations')
    if not isinstance(allocations, dict):
        raise ValueError('campaign initial allocations required')
    if (previous.get('scope') != 'part5-v3-local-prepare'
            or previous.get('schema') != 1
            or status.get('scope') != 'part5-v3-local-prepare'
            or status.get('schema') != 1
            or status.get('status') != 'failed'
            or status.get('config_sha256') != inputs['prior_config'][1]
            or status.get('application_effect') is not False
            or status.get('prepared_application_accounts') is not False
            or status.get('loaded_program', {}).get('elf_match') is not True
            or status['loaded_program'].get('elf_sha256') != previous['elf_sha256']
            or status['loaded_program'].get('program') != previous['program']
            or not status['loaded_program'].get('genesis')
            or status.get('ledger_reuse_requires_review') is not True
            or status.get('cleanup', {}).get('exit_code') != -2
            or status.get('cleanup', {}).get('reaped') is not True
            or status.get('error_type') is not None
            or not args.prior_monitor_owner
            or monitor.get('owner') != args.prior_monitor_owner
            or monitor.get('stop_reason') is not None
            or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False
            or status.get('ledger') != str(Path(previous['runtime_output']) / 'ledger')
            or context.get('schema') != 'part5-v3-campaign-context-v1'
            or context.get('training_only') is not True
            or context_raw != encoded(derive(Path(args.campaign_cohort),
                allocations.get('cohort_receipt_sha256'), allocations.get('membership_sha256')))):
        raise ValueError('reviewed fresh prepare and frozen campaign cohort required')
    ledger = Path(status['ledger'])
    for path, directory in ((ledger, True), (ledger / 'genesis.bin', False)):
        meta = path.lstat()
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or meta.st_uid != os.getuid()
                or stat.S_IMODE(meta.st_mode) != (0o700 if directory else 0o600)
                or (not stat.S_ISDIR(meta.st_mode) if directory else not stat.S_ISREG(meta.st_mode))):
            raise ValueError('owner-only canonical persistent ledger required')
    output = fresh(args.output)
    paths = [fresh(getattr(args, name)) for name in ('stage_output', 'control_output')]
    if any(path.parent != ROOT or not path.name.startswith('application-v3-') for path in paths):
        raise ValueError('fresh direct campaign stage output required')
    if len(set([output, *paths])) != 3:
        raise ValueError('distinct config, stage and control paths required')
    config = {'schema': 1, 'scope': 'part5-v3-campaign-stage',
              'prior_config': args.prior_config,
              'prior_config_sha256': inputs['prior_config'][1],
              'prior_status': args.prior_status,
              'prior_status_sha256': inputs['prior_status'][1],
              'prior_monitor': args.prior_monitor,
              'prior_monitor_sha256': inputs['prior_monitor'][1],
              'prior_monitor_owner': args.prior_monitor_owner,
              'expected_genesis': status['loaded_program']['genesis'],
              'ledger': status['ledger'],
              'context': args.context, 'context_sha256': inputs['context'][1],
              'campaign_cohort': args.campaign_cohort,
              'runner': args.runner, 'runner_sha256': inputs['runner'][1],
              'stage_output': args.stage_output,
              'control_output': args.control_output,
              'outer_limits_required': LIMITS}
    raw = (json.dumps(config, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prior_config', 'prior_status', 'prior_monitor',
                 'prior_monitor_owner', 'context', 'campaign_cohort',
                 'runner', 'stage_output', 'control_output', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    args = parser.parse_args()
    print(json.dumps({'config_sha256': create(args), 'path': args.output}))


if __name__ == '__main__':
    main()
