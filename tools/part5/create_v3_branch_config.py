#!/usr/bin/env python3
"""Pin one stopped v3 R1 ledger clone and proof pair for a local branch run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def sha(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute input required')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('owner-controlled regular input required')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def create(args):
    transition_config = Path(args.transition_config)
    source = json.loads(transition_config.read_bytes())
    if source.get('scope') != 'part5-v3-local-unrelated-transition':
        raise ValueError('v3 R1 transition config required')
    stage_config = json.loads(Path(source['prior_stage_config']).read_bytes())
    if stage_config.get('scope') != 'part5-v3-local-stage':
        raise ValueError('v3 finalized stage config required')
    clone = json.loads(Path(args.clone_report).read_bytes())
    if clone.get('schema') != 'part5-v3-r1-ledger-clone-v1':
        raise ValueError('R1 ledger clone report required')
    for name in ('branch_output', 'control_output', 'output'):
        path = Path(getattr(args, name))
        if (not path.is_absolute() or path.exists() or path.is_symlink()
                or path.parent.resolve(strict=True) != path.parent):
            raise ValueError('fresh canonical branch path required')
    fields = ('prior_stage_config', 'prior_stage_config_sha256',
              'prior_stage_status', 'prior_stage_status_sha256',
              'prior_stage_monitor', 'prior_stage_monitor_sha256',
              'prior_monitor_owner', 'stage_root', 'stage_report_sha256',
              'stage_plan_sha256', 'cohort_root', 'expected_genesis',
              'transition_context', 'transition_context_sha256',
              'outer_limits_required')
    config = {name: source[name] for name in fields}
    config.update({'schema': 1, 'scope': 'part5-v3-r1-branch',
        'mode': args.mode, 'ledger': clone['destination'],
        'clone_report': args.clone_report, 'clone_report_sha256': sha(args.clone_report),
        'transition_root': source['transition_output'],
        'transition_report_sha256': sha(args.transition_report),
        'transition_status': args.transition_status,
        'transition_status_sha256': sha(args.transition_status),
        'transition_monitor': args.transition_monitor,
        'transition_monitor_sha256': sha(args.transition_monitor),
        'runner': args.runner, 'runner_sha256': sha(args.runner),
        'context': stage_config['context'], 'context_sha256': stage_config['context_sha256'],
        'full_wire': args.full_wire, 'full_wire_sha256': sha(args.full_wire),
        'anchor_wire': args.anchor_wire, 'anchor_wire_sha256': sha(args.anchor_wire),
        'branch_output': args.branch_output, 'control_output': args.control_output})
    if (Path(config['transition_root']) / 'transition-report.json' != Path(args.transition_report)
            or Path(config['ledger']).name != 'ledger'
            or Path(config['ledger']).parent / 'clone-report.json' != Path(args.clone_report)
            or config['outer_limits_required'] != {'runtime_seconds': 180,
                                                    'rss_bytes': 4294967296,
                                                    'storage_growth_bytes': 268435456}):
        raise ValueError('R1 branch roles or envelope mismatch')
    encoded = (json.dumps(config, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(encoded).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('anchor', 'own-revocation'), required=True)
    for name in ('transition_config', 'transition_report', 'transition_status',
                 'transition_monitor', 'clone_report', 'full_wire', 'anchor_wire',
                 'runner', 'branch_output', 'control_output', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    args = parser.parse_args()
    print(json.dumps({'config_sha256': create(args), 'path': args.output}))


if __name__ == '__main__':
    main()
