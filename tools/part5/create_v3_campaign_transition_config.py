#!/usr/bin/env python3
"""Pin one stopped R0 campaign clone and exact signed R0-to-Rk inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

LIMITS = {'runtime_seconds': 420, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}


def sha(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute campaign input required')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('owner-controlled regular campaign input required')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def create(args):
    if args.target_count not in (1, 2, 5, 10):
        raise ValueError('registered campaign count required')
    stage_config = json.loads(Path(args.stage_config).read_bytes())
    if stage_config.get('scope') != 'part5-v3-campaign-stage':
        raise ValueError('signed campaign R0 stage required')
    stage_root = Path(stage_config['stage_output'])
    stage_report = stage_root / 'stage-report.json'
    stage = json.loads(stage_report.read_bytes())
    clone = json.loads(Path(args.clone_report).read_bytes())
    context = json.loads(Path(stage_config['context']).read_bytes())
    if (stage.get('schema') != 'part5-v3-campaign-stage-v1'
            or stage.get('passed') is not True
            or clone.get('schema') != 'part5-v3-campaign-r0-ledger-clone-v1'
            or clone.get('copy_identical') is not True
            or clone.get('source') != stage_config['ledger']
            or clone.get('stage_report_sha256') != sha(stage_report)
            or Path(clone['destination']).name != 'ledger'
            or context.get('schema') != 'part5-v3-campaign-context-v1'
            or len(context.get('root_sequence', [])) != 11):
        raise ValueError('stage, context and R0 clone roles differ')
    for name in ('transition_output', 'control_output', 'output'):
        path = Path(getattr(args, name))
        if (not path.is_absolute() or path.exists() or path.is_symlink()
                or path.parent.resolve(strict=True) != path.parent):
            raise ValueError('fresh canonical campaign output required')
    if args.transition_output == args.control_output:
        raise ValueError('distinct campaign output and control paths required')
    config = {'schema': 1, 'scope': 'part5-v3-campaign-transition',
              'target_count': args.target_count,
              'stage_config': args.stage_config,
              'stage_config_sha256': sha(args.stage_config),
              'stage_status': args.stage_status,
              'stage_status_sha256': sha(args.stage_status),
              'stage_monitor': args.stage_monitor,
              'stage_monitor_sha256': sha(args.stage_monitor),
              'stage_monitor_owner': args.stage_monitor_owner,
              'stage_root': str(stage_root),
              'stage_report_sha256': sha(stage_report),
              'stage_plan_sha256': sha(stage_root / 'plan.json'),
              'context': stage_config['context'],
              'context_sha256': stage_config['context_sha256'],
              'cohort_root': args.cohort_root,
              'clone_report': args.clone_report,
              'clone_report_sha256': sha(args.clone_report),
              'ledger': clone['destination'],
              'expected_genesis': stage_config['expected_genesis'],
              'runner': args.runner, 'runner_sha256': sha(args.runner),
              'transition_output': args.transition_output,
              'control_output': args.control_output,
              'outer_limits_required': LIMITS}
    raw = (json.dumps(config, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-count', type=int, required=True)
    for name in ('stage_config', 'stage_status', 'stage_monitor',
                 'stage_monitor_owner', 'clone_report', 'cohort_root',
                 'runner', 'transition_output', 'control_output', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    args = parser.parse_args()
    print(json.dumps({'config_sha256': create(args), 'path': args.output}))


if __name__ == '__main__':
    main()
