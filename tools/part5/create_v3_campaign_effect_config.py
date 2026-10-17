#!/usr/bin/env python3
"""Pin a stopped signed Rk campaign clone and its final proof for one effect."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

COUNTS = (0, 1, 2, 5, 10)
MODES = ('full', 'anchor', 'coalesced-full')
LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}


def read(path, cap=1024 * 1024):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute input required')
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or before.st_size == 0 or before.st_size > cap):
        raise ValueError('bounded owner-controlled regular input required')
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode,
                             info.st_uid, info.st_nlink, info.st_size,
                             info.st_mtime_ns, info.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise ValueError('input changed at open')
        raw = stream.read(cap + 1)
        after_handle = os.fstat(stream.fileno())
    if (len(raw) != before.st_size or len(raw) > cap
            or identity(after_handle) != identity(before)
            or identity(path.lstat()) != identity(before)):
        raise ValueError('input changed while reading')
    return raw, hashlib.sha256(raw).hexdigest()


def document(path, cap=1024 * 1024):
    raw, digest = read(path, cap)
    return json.loads(raw), digest


def fresh(path):
    path = Path(path)
    if (not path.is_absolute() or path.exists() or path.is_symlink()
            or path.parent.resolve(strict=True) != path.parent):
        raise ValueError('fresh canonical output required')
    return path


def create(args):
    if args.mode not in MODES or args.target_count not in COUNTS:
        raise ValueError('registered campaign effect mode/count required')
    count = args.target_count
    if count:
        if any(getattr(args, name) is None for name in (
                'transition_config', 'transition_report', 'transition_status',
                'transition_monitor', 'transition_monitor_owner')):
            raise ValueError('Rk transition evidence required')
        source, source_sha = document(args.transition_config)
        changed, changed_sha = document(args.transition_report)
        status, status_sha = document(args.transition_status)
        monitor, monitor_sha = document(args.transition_monitor)
        stage_config_path = source['stage_config']
        stage_status_path = source['stage_status']
        stage_monitor_path = source['stage_monitor']
        stage_monitor_owner = source['stage_monitor_owner']
        cohort_root = source['cohort_root']
        context_path = source['context']
        expected_genesis = source['expected_genesis']
        stage_root = source['stage_root']
    else:
        if any(getattr(args, name) is None for name in (
                'stage_config', 'stage_status', 'stage_monitor',
                'stage_monitor_owner', 'cohort_root')):
            raise ValueError('R0 stage evidence required')
        source = changed = status = monitor = None
        source_sha = changed_sha = status_sha = monitor_sha = None
        stage_config_path = args.stage_config
        stage_status_path = args.stage_status
        stage_monitor_path = args.stage_monitor
        stage_monitor_owner = args.stage_monitor_owner
        cohort_root = args.cohort_root
        stage_config, _ = document(stage_config_path)
        context_path = stage_config['context']
        expected_genesis = stage_config['expected_genesis']
        stage_root = stage_config['stage_output']
    clone, clone_sha = document(args.clone_report)
    packet, packet_sha = document(args.proof_packet)
    proof, proof_sha = document(args.proof_report)
    mode = f'campaign-{args.mode}-k{count}'
    expected_packet_schema = ('credential-v3-cumulative-coalesced-request-v1'
                              if args.mode == 'coalesced-full'
                              else 'credential-v3-cumulative-request-v1')
    stage_config, stage_config_sha = document(stage_config_path)
    stage_status, stage_status_sha = document(stage_status_path)
    stage_monitor, stage_monitor_sha = document(stage_monitor_path)
    context, context_sha = document(context_path, 8192)
    if (stage_config.get('scope') != 'part5-v3-campaign-stage'
            or stage_config.get('stage_output') != stage_root
            or stage_config.get('context_sha256') != context_sha
            or stage_status.get('stage_verified') is not True
            or stage_status.get('stage_report_sha256') != read(args.stage_report, 65536)[1]
            or stage_monitor.get('owner') != stage_monitor_owner
            or stage_monitor.get('stop_reason') is not None
            or stage_monitor.get('cleanup_remaining_owned_processes') != 0
            or context.get('schema') != 'part5-v3-campaign-context-v1'
            or clone.get('copy_identical') is not True
            or Path(clone['destination']).name != 'ledger'
            or Path(clone['destination']).parent / 'clone-report.json' != Path(args.clone_report)
            or packet.get('schema') != expected_packet_schema
            or packet.get('update_count') != count
            or proof.get('schema') != 'credential-v3-cumulative-proof-v1'
            or proof.get('passed') is not True
            or proof.get('mode') != mode
            or proof.get('update_count') != count
            or proof.get('packet_sha256') != packet_sha
            or proof.get('application_stage_pins') != packet.get('application_stage')):
        raise ValueError('signed stage, clone, packet and proof roles differ')
    if count:
        if (source.get('schema') != 1 or source.get('scope') != 'part5-v3-campaign-transition'
                or source.get('target_count') != count
                or source.get('transition_output') != str(Path(args.transition_report).parent)
                or source.get('stage_config_sha256') != stage_config_sha
                or source.get('stage_status_sha256') != stage_status_sha
                or source.get('stage_monitor_sha256') != stage_monitor_sha
                or source.get('context_sha256') != context_sha
                or changed.get('schema') != 'part5-v3-campaign-transition-v1'
                or changed.get('passed') is not True or changed.get('target_count') != count
                or changed.get('stage_report_sha256') != source['stage_report_sha256']
                or changed.get('stage_plan_sha256') != source['stage_plan_sha256']
                or changed.get('context_sha256') != source['context_sha256']
                or changed.get('current_root') != context['root_sequence'][count]
                or status.get('scope') != 'part5-v3-campaign-transition'
                or status.get('transition_verified') is not True
                or status.get('config_sha256') != source_sha
                or status.get('transition_report_sha256') != changed_sha
                or status.get('transition_output') != source['transition_output']
                or monitor.get('owner') != args.transition_monitor_owner
                or monitor.get('stop_reason') is not None
                or monitor.get('cleanup_remaining_owned_processes') != 0
                or clone.get('schema') != 'part5-v3-campaign-final-ledger-clone-v1'
                or clone.get('source') != source['ledger']
                or clone.get('transition_config_sha256') != source_sha
                or clone.get('transition_report_sha256') != changed_sha
                or clone.get('transition_status_sha256') != status_sha
                or clone.get('transition_monitor_sha256') != monitor_sha
                or clone.get('target_count') != count
                or clone.get('current_root') != changed['current_root']):
            raise ValueError('signed Rk transition and final clone roles differ')
    elif (clone.get('schema') != 'part5-v3-campaign-r0-ledger-clone-v1'
          or clone.get('source') != stage_config['ledger']
          or clone.get('stage_report_sha256') != read(args.stage_report, 65536)[1]
          or clone.get('stage_status_sha256') != stage_status_sha
          or clone.get('stage_monitor_sha256') != stage_monitor_sha):
        raise ValueError('signed R0 stage clone roles differ')
    if (Path(stage_root) / 'stage-report.json' != Path(args.stage_report)
            or Path(stage_root) / 'plan.json' != Path(args.stage_plan)):
        raise ValueError('stage and transition artifact paths differ')
    _, stage_sha = read(args.stage_report, 65536)
    _, plan_sha = read(args.stage_plan, 8192)
    if args.mode == 'coalesced-full':
        if args.base_wire is not None:
            raise ValueError('coalesced final-only control has no R0 proof wire')
        base_wire_sha = None
    else:
        if args.base_wire is None:
            raise ValueError('cumulative Full/Anchor R0 proof wire required')
        _, base_wire_sha = read(args.base_wire, 448)
    _, current_wire_sha = read(args.current_wire, 448)
    if (stage_sha != stage_status['stage_report_sha256']
            or (count and (stage_sha != source['stage_report_sha256']
                           or plan_sha != source['stage_plan_sha256']))
            or (count and args.base_wire is not None
                and Path(args.base_wire) == Path(args.current_wire))):
        raise ValueError('stage or distinct proof wire pins differ')
    effect_output, control_output, output = map(fresh, (
        args.effect_output, args.control_output, args.output))
    if len({effect_output, control_output, output}) != 3:
        raise ValueError('effect, control and config outputs must differ')
    config = {'schema': 1, 'scope': 'part5-v3-campaign-effect',
              'mode': args.mode, 'target_count': count,
              'transition_config': args.transition_config,
              'transition_config_sha256': source_sha,
              'transition_report_sha256': changed_sha,
              'transition_status': args.transition_status,
              'transition_status_sha256': status_sha,
              'transition_monitor': args.transition_monitor,
              'transition_monitor_sha256': monitor_sha,
              'transition_monitor_owner': args.transition_monitor_owner,
              'stage_config': stage_config_path,
              'stage_config_sha256': stage_config_sha,
              'stage_status': stage_status_path,
              'stage_status_sha256': stage_status_sha,
              'stage_monitor': stage_monitor_path,
              'stage_monitor_sha256': stage_monitor_sha,
              'stage_monitor_owner': stage_monitor_owner,
              'stage_root': stage_root,
              'stage_report_sha256': stage_sha,
              'stage_plan_sha256': plan_sha,
              'transition_root': source['transition_output'] if count else None,
              'context': context_path,
              'context_sha256': context_sha,
              'cohort_root': cohort_root,
              'expected_genesis': expected_genesis,
              'clone_report': args.clone_report,
              'clone_report_sha256': clone_sha,
              'ledger': clone['destination'],
              'proof_packet': args.proof_packet,
              'proof_packet_sha256': packet_sha,
              'proof_report': args.proof_report,
              'proof_report_sha256': proof_sha,
              'base_wire': args.base_wire,
              'base_wire_sha256': base_wire_sha,
              'current_wire': args.current_wire,
              'current_wire_sha256': current_wire_sha,
              'runner': args.runner,
              'runner_sha256': read(args.runner, 128 * 1024 * 1024)[1],
              'effect_output': str(effect_output),
              'control_output': str(control_output),
              'outer_limits_required': LIMITS}
    raw = (json.dumps(config, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--target-count', type=int, choices=COUNTS, required=True)
    for name in ('transition_config', 'transition_report', 'transition_status',
                 'transition_monitor', 'transition_monitor_owner', 'stage_config',
                 'stage_status', 'stage_monitor', 'stage_monitor_owner', 'cohort_root'):
        parser.add_argument('--' + name.replace('_', '-'))
    parser.add_argument('--base-wire')
    for name in ('clone_report', 'proof_packet', 'proof_report', 'stage_report', 'stage_plan',
                 'current_wire', 'runner', 'effect_output',
                 'control_output', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    args = parser.parse_args()
    print(json.dumps({'config_sha256': create(args), 'path': args.output}))


if __name__ == '__main__':
    main()
