#!/usr/bin/env python3
"""Run the registered v3 campaign matrix sequentially from a pinned manifest.

Example (from the repository root)::

    python3 -B -m tools.part5.run_v3_campaign_matrix /absolute/path/matrix.json --plan
    python3 -B -m tools.part5.run_v3_campaign_matrix /absolute/path/matrix.json
    python3 -B -m tools.part5.run_v3_campaign_matrix /absolute/path/matrix.json --resume

The JSON manifest uses schema ``part5-v3-campaign-matrix-input-v1`` and has:

* ``campaign_id``, ``output_root`` and ``campaign_runtime_seconds`` (129600)
* ``limits`` keyed by each registered count, then mode, with explicit
  ``runtime_seconds``, ``rss_bytes`` and ``storage_bytes``
* ``evidence`` pins for freeze, cohort receipt/root, context, stage root,
  stage config/report/plan/status/monitor and stage monitor owner; plus
  ``transitions`` keyed by k=1,2,5,10 with root, config/report/status/monitor
  pins and a monitor owner
* ``tools`` pins for python, proof_binary, adapter_binary, exporter, node, old_packet,
  effect_runner, session_script, bounded_runner, effect_config,
  effect_supervisor, clone_r0 and clone_final

Every file pin is ``{"path": "/absolute/canonical/path", "sha256": "..."}``.
The script only executes after all manifest pins and registered evidence roles
validate. ``--plan`` emits argv and paths without creating or running anything.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO / 'artifacts/dynark/part5'
SCHEMA = 'part5-v3-campaign-matrix-input-v1'
SLOT_RECEIPT_SCHEMA = 'part5-v3-campaign-matrix-slot-v1'
SEQUENCE_SCHEMA = 'part5-v3-campaign-matrix-sequence-v1'
ECONOMICS_INPUT_SCHEMA = 'part5-v3-campaign-economics-input-v1'
CAMPAIGN_SECONDS = 36 * 60 * 60
MAX_RSS_BYTES = 4 * 1024 * 1024 * 1024
MAX_STORAGE_BYTES = 256 * 1024 * 1024

from tools.part5 import run_v3_campaign_session as session


def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def write_new(path, value, mode=0o600):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical_json(value))
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return sha256(path)


def sha256(path, cap=2 * 1024 * 1024 * 1024):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute file required')
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_size <= 0 or info.st_size > cap
            or info.st_mode & 0o022):
        raise ValueError('bounded owner-controlled regular file required')
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            value.update(chunk)
    return value.hexdigest()


def read_json(path, cap=4 * 1024 * 1024):
    sha256(path, cap)
    return json.loads(Path(path).read_bytes())


def checked_dir(value, private=False):
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute directory required')
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('owner-controlled directory required')
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('owner0700 directory required')
    return path


def verify_pin(pin, name, cap=2 * 1024 * 1024 * 1024):
    if not isinstance(pin, dict) or set(pin) != {'path', 'sha256'}:
        raise ValueError(f'explicit path and SHA-256 pin required for {name}')
    path = Path(pin['path'])
    expected = pin['sha256']
    if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError(f'valid SHA-256 required for {name}')
    actual = sha256(path, cap)
    if actual != expected:
        raise ValueError(f'{name} differs from manifest SHA-256')
    return path


def slot_specs():
    slots = []
    sequence = 0
    for repetition in range(1, len(session.ORDERS) + 1):
        order = list(session.ORDERS[repetition - 1])
        for count in session.COUNTS:
            for position, mode in enumerate(order, 1):
                sequence += 1
                slots.append({'sequence': sequence, 'repetition': repetition,
                              'target_count': count, 'mode': mode,
                              'registered_order': order,
                              'registered_order_position': position})
    return slots


def slot_owner(repetition, count, mode):
    """Return the bounded-runner owner accepted by the economics analyzer."""
    return f'v3-campaign-{mode}-k{count}-r{repetition}-matrix'


def economics_input_manifest(planned_slots):
    """Return analyzer-compatible paths for the complete registered matrix."""
    if len(planned_slots) != 60:
        raise ValueError('complete 60-slot campaign plan required')
    sessions = []
    for slot in planned_slots:
        paths = slot['paths']
        sessions.append({
            'mode': slot['mode'],
            'target_count': slot['target_count'],
            'repetition': slot['repetition'],
            'session_report': paths['session_report'],
            'outer_report': paths['outer_report'],
        })
    return {'schema': ECONOMICS_INPUT_SCHEMA, 'sessions': sessions}


def validate_caps(raw, campaign_seconds):
    counts = {str(count) for count in session.COUNTS}
    if not isinstance(raw, dict) or set(raw) != counts:
        raise ValueError('explicit limits for each registered target count required')
    normalized = {}
    for count in session.COUNTS:
        by_mode = raw[str(count)]
        if not isinstance(by_mode, dict) or set(by_mode) != set(session.MODES):
            raise ValueError(f'explicit limits for every mode at k={count} required')
        normalized[str(count)] = {}
        for mode in session.MODES:
            limit = by_mode[mode]
            if (not isinstance(limit, dict)
                    or set(limit) != {'runtime_seconds', 'rss_bytes', 'storage_bytes'}):
                raise ValueError(f'explicit runtime, RSS and storage caps required for {mode} k={count}')
            runtime, rss, storage = (limit['runtime_seconds'], limit['rss_bytes'],
                                     limit['storage_bytes'])
            if (type(runtime) is not int or runtime < 1 or runtime > campaign_seconds
                    or type(rss) is not int or not 1 <= rss <= MAX_RSS_BYTES
                    or type(storage) is not int or not 1 <= storage <= MAX_STORAGE_BYTES):
                raise ValueError(f'bounded positive limits required for {mode} k={count}')
            if count == 1 and mode == 'anchor' and runtime < 2400:
                raise ValueError('Anchor k=1 requires an explicit runtime cap of at least 2400 seconds')
            normalized[str(count)][mode] = {
                'runtime_seconds': runtime, 'rss_bytes': rss,
                'storage_bytes': storage}
    return normalized


def validate_manifest(manifest_path):
    manifest_path = Path(manifest_path).absolute()
    if manifest_path.resolve(strict=True) != manifest_path:
        raise ValueError('canonical matrix manifest path required')
    sha256(manifest_path, 4 * 1024 * 1024)
    manifest_raw = manifest_path.read_bytes()
    if len(manifest_raw) > 4 * 1024 * 1024:
        raise ValueError('matrix manifest exceeds size cap')
    manifest = json.loads(manifest_raw)
    if manifest.get('schema') != SCHEMA:
        raise ValueError(f'{SCHEMA} manifest required')
    campaign_id = manifest.get('campaign_id')
    if not isinstance(campaign_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', campaign_id):
        raise ValueError('safe explicit campaign_id required')
    if manifest.get('campaign_runtime_seconds') != CAMPAIGN_SECONDS:
        raise ValueError('registered 36-hour campaign runtime envelope required')
    limits = validate_caps(manifest.get('limits'), CAMPAIGN_SECONDS)
    output_root = Path(manifest.get('output_root', ''))
    if (not output_root.is_absolute() or output_root.parent != ARTIFACTS
            or output_root.name != f'v3-matrix-{campaign_id}'
            or output_root.parent.resolve(strict=True) != output_root.parent):
        raise ValueError('matrix output root must be its fresh named artifacts directory')

    evidence = manifest.get('evidence')
    if not isinstance(evidence, dict):
        raise ValueError('explicit frozen evidence manifest required')
    evidence_names = ('freeze', 'cohort_receipt', 'context', 'stage_config',
                      'stage_report', 'stage_plan', 'stage_status', 'stage_monitor')
    evidence_paths = {name: verify_pin(evidence.get(name), name) for name in evidence_names}
    cohort_root = checked_dir(evidence.get('cohort_root'))
    stage_root = checked_dir(evidence.get('stage_root'))
    if evidence_paths['cohort_receipt'] != cohort_root / 'cohort-receipt.json':
        raise ValueError('cohort receipt must be the pinned receipt in cohort_root')
    if (evidence_paths['stage_report'] != stage_root / 'stage-report.json'
            or evidence_paths['stage_plan'] != stage_root / 'plan.json'):
        raise ValueError('stage report and plan must belong to the pinned stage_root')
    stage_owner = evidence.get('stage_monitor_owner')
    if not isinstance(stage_owner, str) or not stage_owner:
        raise ValueError('explicit stopped-stage monitor owner required')
    transitions = evidence.get('transitions')
    expected_transition_keys = {'1', '2', '5', '10'}
    if not isinstance(transitions, dict) or set(transitions) != expected_transition_keys:
        raise ValueError('signed transition evidence required for k=1,2,5,10')
    transition_paths = {}
    for count in (1, 2, 5, 10):
        row = transitions[str(count)]
        if not isinstance(row, dict):
            raise ValueError(f'explicit transition evidence required for k={count}')
        paths = {key: verify_pin(row.get(key), f'transition {count} {key}')
                 for key in ('config', 'report', 'status', 'monitor')}
        root = checked_dir(row.get('root'))
        if paths['report'] != root / 'transition-report.json':
            raise ValueError(f'transition k={count} report must belong to transition root')
        owner = row.get('monitor_owner')
        if not isinstance(owner, str) or not owner:
            raise ValueError(f'explicit transition monitor owner required for k={count}')
        transition_paths[str(count)] = {'root': root, **paths, 'monitor_owner': owner}

    tool_names = ('python', 'proof_binary', 'adapter_binary', 'exporter', 'node', 'old_packet',
                  'effect_runner', 'session_script', 'bounded_runner', 'effect_config',
                  'effect_supervisor', 'clone_r0', 'clone_final')
    tools_manifest = manifest.get('tools')
    if not isinstance(tools_manifest, dict):
        raise ValueError('pinned tools manifest required')
    tool_paths = {name: verify_pin(tools_manifest.get(name), name)
                  for name in tool_names}
    expected_tool_paths = {
        'python': sys.executable,
        'session_script': session.__file__,
        'bounded_runner': REPO / 'results/dynark/part5/session_runner.py',
        'effect_config': session.EFFECT_CONFIG,
        'effect_supervisor': session.EFFECT_SUPERVISOR,
        'clone_r0': REPO / 'harness/tests/queue_v3_clone_campaign_r0.py',
        'clone_final': REPO / 'harness/tests/queue_v3_clone_campaign_final.py',
    }
    for name, expected in expected_tool_paths.items():
        if tool_paths[name] != Path(expected).resolve(strict=True):
            raise ValueError(f'{name} must point to the registered repository tool')

    return {'manifest': manifest, 'manifest_path': manifest_path,
            'manifest_sha256': digest_bytes(canonical_json(manifest)), 'campaign_id': campaign_id,
            'driver_sha256': sha256(Path(__file__).resolve()),
            'output_root': output_root, 'limits': limits,
            'evidence': evidence, 'evidence_paths': evidence_paths,
            'cohort_root': cohort_root, 'stage_root': stage_root,
            'stage_monitor_owner': stage_owner, 'transitions': transition_paths,
            'tools_manifest': tools_manifest, 'tools': tool_paths,
            'tool_pins': {name: tools_manifest[name]['sha256'] for name in tool_names}}


def output_paths(validated, slot):
    root = validated['output_root']
    label = f"r{slot['repetition']}-k{slot['target_count']}-{slot['mode']}"
    slot_root = root / ('slot-' + label)
    effect_name = f"application-v3-matrix-{validated['campaign_id']}-{label}-effect"
    control_name = f"application-v3-matrix-{validated['campaign_id']}-{label}-control"
    return {'slot_root': slot_root,
            'clone_dir': slot_root / 'clone',
            'clone_ledger': slot_root / 'clone' / 'ledger',
            'clone_report': slot_root / 'clone' / 'clone-report.json',
            'work_root': slot_root / 'work',
            'outer_private': slot_root / 'outer-private',
            'outer_report': slot_root / 'outer-report.json',
            'session_report': slot_root / 'work' / 'session-report.json',
            'slot_receipt': slot_root / 'slot-receipt.json',
            'effect_output': ARTIFACTS / effect_name,
            'control_output': ARTIFACTS / control_name}


def slot_identity(validated, slot, paths):
    value = {'campaign_id': validated['campaign_id'],
             'manifest_sha256': validated['manifest_sha256'],
             'driver_sha256': validated['driver_sha256'],
             'tool_pins': validated['tool_pins'],
             'sequence': slot['sequence'], 'repetition': slot['repetition'],
             'target_count': slot['target_count'], 'mode': slot['mode'],
             'registered_order': slot['registered_order'],
             'registered_order_position': slot['registered_order_position'],
             'limits': validated['limits'][str(slot['target_count'])][slot['mode']],
             'paths': {key: str(value) for key, value in paths.items()}}
    return digest_bytes(canonical_json(value))


def clone_argv(validated, slot, paths):
    evidence = validated['evidence']
    if slot['target_count'] == 0:
        command = [str(validated['tools']['python']), '-B', str(validated['tools']['clone_r0']),
                   '--stage-config', str(validated['evidence_paths']['stage_config']),
                   '--config-sha', evidence['stage_config']['sha256'],
                   '--stage-report', str(validated['evidence_paths']['stage_report']),
                   '--report-sha', evidence['stage_report']['sha256'],
                   '--stage-status', str(validated['evidence_paths']['stage_status']),
                   '--status-sha', evidence['stage_status']['sha256'],
                   '--stage-monitor', str(validated['evidence_paths']['stage_monitor']),
                   '--monitor-sha', evidence['stage_monitor']['sha256'],
                   '--monitor-owner', validated['stage_monitor_owner'],
                   '--destination', str(paths['clone_ledger'])]
        return command
    row = validated['transitions'][str(slot['target_count'])]
    pins = evidence['transitions'][str(slot['target_count'])]
    return [str(validated['tools']['python']), '-B', str(validated['tools']['clone_final']),
            '--transition-config', str(row['config']),
            '--config-sha', pins['config']['sha256'],
            '--transition-report', str(row['report']),
            '--report-sha', pins['report']['sha256'],
            '--transition-status', str(row['status']),
            '--status-sha', pins['status']['sha256'],
            '--transition-monitor', str(row['monitor']),
            '--monitor-sha', pins['monitor']['sha256'],
            '--monitor-owner', row['monitor_owner'],
            '--target-count', str(slot['target_count']),
            '--destination', str(paths['clone_ledger'])]


def session_argv(validated, slot, paths):
    evidence = validated['evidence']
    tools = validated['tools']
    values = [str(tools['python']), '-B', str(tools['session_script']),
              '--mode', slot['mode'], '--target-count', str(slot['target_count']),
              '--repetition', str(slot['repetition']),
              '--freeze', str(validated['evidence_paths']['freeze']),
              '--cohort-root', str(validated['cohort_root']),
              '--context', str(validated['evidence_paths']['context']),
              '--stage-root', str(validated['stage_root']),
              '--clone-report', str(paths['clone_report']),
              '--work-root', str(paths['work_root']),
              '--effect-output', str(paths['effect_output']),
              '--control-output', str(paths['control_output']),
              '--proof-binary', str(tools['proof_binary']),
              '--adapter-binary', str(tools['adapter_binary']),
              '--exporter', str(tools['exporter']),
              '--node', str(tools['node']),
              '--old-packet', str(tools['old_packet']),
              '--effect-runner', str(tools['effect_runner']),
              '--exporter-sha256', validated['tools_manifest']['exporter']['sha256'],
              '--node-sha256', validated['tools_manifest']['node']['sha256'],
              '--old-packet-sha256', validated['tools_manifest']['old_packet']['sha256'],
              '--effect-config-sha256', validated['tools_manifest']['effect_config']['sha256'],
              '--effect-supervisor-sha256', validated['tools_manifest']['effect_supervisor']['sha256'],
              '--bounded-runner-sha256', validated['tools_manifest']['bounded_runner']['sha256']]
    if slot['target_count'] == 0:
        values.extend(['--stage-config', str(validated['evidence_paths']['stage_config']),
                       '--stage-status', str(validated['evidence_paths']['stage_status']),
                       '--stage-monitor', str(validated['evidence_paths']['stage_monitor']),
                       '--stage-monitor-owner', validated['stage_monitor_owner']])
    else:
        row = validated['transitions'][str(slot['target_count'])]
        values.extend(['--transition-root', str(row['root']),
                       '--transition-config', str(row['config']),
                       '--transition-report', str(row['report']),
                       '--transition-status', str(row['status']),
                       '--transition-monitor', str(row['monitor']),
                       '--transition-monitor-owner', row['monitor_owner']])
    return values


def plan_slots(validated):
    rows = []
    for slot in slot_specs():
        paths = output_paths(validated, slot)
        slot = dict(slot)
        slot['owner'] = slot_owner(slot['repetition'], slot['target_count'], slot['mode'])
        slot['limits'] = validated['limits'][str(slot['target_count'])][slot['mode']]
        slot['identity_sha256'] = slot_identity(validated, slot, paths)
        clone = clone_argv(validated, slot, paths)
        run = [str(validated['tools']['python']), '-B', str(validated['tools']['bounded_runner']),
               '--owner', slot['owner'], '--cwd', str(REPO),
               '--private-output', str(paths['outer_private']),
               '--report', str(paths['outer_report']),
               '--runtime-seconds', str(slot['limits']['runtime_seconds']),
               '--rss-bytes', str(slot['limits']['rss_bytes']),
               '--storage-bytes', str(slot['limits']['storage_bytes']),
               '--storage-path', str(paths['effect_output']),
               '--storage-path', str(paths['control_output']),
               '--storage-path', str(paths['work_root']),
               '--storage-path', str(paths['clone_dir']), '--',
               *session_argv(validated, slot, paths)]
        rows.append({**slot, 'paths': {key: str(value) for key, value in paths.items()},
                     'clone_argv': clone, 'outer_argv': run,
                     'environment': {'P5_V3_CAMPAIGN_SESSION_SUPERVISOR':
                                     'bounded-complete-session'}})
    return rows


def publish_economics_manifest(root, planned_slots):
    """Publish the analyzer input only after every slot has passed verification."""
    path = Path(root) / 'economics-input-manifest.json'
    expected = economics_input_manifest(planned_slots)
    if path.exists() or path.is_symlink():
        if read_json(path, 1024 * 1024) != expected:
            raise ValueError('existing economics input manifest differs from verified plan')
        return path
    write_new(path, expected)
    return path


def validate_slot_documents(slot, receipt, outer, session_report, *,
                            outer_sha256, session_sha256,
                            expected_previous_receipt_sha256,
                            expected_previous_end_utc=None):
    if (receipt.get('schema') != SLOT_RECEIPT_SCHEMA
            or receipt.get('slot_identity_sha256') != slot['identity_sha256']
            or receipt.get('sequence') != slot['sequence']
            or receipt.get('repetition') != slot['repetition']
            or receipt.get('target_count') != slot['target_count']
            or receipt.get('mode') != slot['mode']
            or receipt.get('registered_order') != slot['registered_order']
            or receipt.get('registered_order_position') != slot['registered_order_position']
            or receipt.get('previous_slot_receipt_sha256') != expected_previous_receipt_sha256
            or receipt.get('outer_report_sha256') != outer_sha256
            or receipt.get('session_report_sha256') != session_sha256):
        raise ValueError('slot receipt identity or report hash mismatch')
    limits = slot['limits']
    if (outer.get('schema') != 1
            or outer.get('measurement') != 'bounded_complete_session'
            or outer.get('passed') is not True
            or outer.get('censored') is not False
            or outer.get('owner') != slot['owner']
            or outer.get('stop_reason') is not None
            or outer.get('exit_code') != 0
            or outer.get('runner_error_type') is not None
            or outer.get('cleanup_remaining_owned_processes') != 0
            or outer.get('cleanup_status_unknown') is not False
            or outer.get('limits', {}).get('runtime_seconds') != limits['runtime_seconds']
            or outer['limits'].get('owned_tree_rss_bytes') != limits['rss_bytes']
            or outer['limits'].get('storage_growth_bytes') != limits['storage_bytes']):
        raise ValueError('passed uncensored bounded outer session report required')
    try:
        outer_started = datetime.datetime.fromisoformat(outer['started_at_utc'])
        outer_ended = datetime.datetime.fromisoformat(outer['ended_at_utc'])
        duration = outer.get('duration_seconds')
        if (outer_started.tzinfo is None or outer_ended.tzinfo is None
                or outer_ended < outer_started or isinstance(duration, bool)
                or not isinstance(duration, (int, float))
                or not math.isfinite(duration) or duration <= 0):
            raise ValueError
        if expected_previous_end_utc is not None:
            previous_end = datetime.datetime.fromisoformat(expected_previous_end_utc)
            if previous_end.tzinfo is None or outer_started < previous_end:
                raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ValueError('outer reports must show non-overlapping UTC session times') from None
    if (session_report.get('schema') != 'part5-v3-campaign-session-v1'
            or session_report.get('passed') is not True
            or session_report.get('effect_verified') is not True
            or session_report.get('mode') != slot['mode']
            or session_report.get('target_count') != slot['target_count']
            or session_report.get('repetition') != slot['repetition']
            or session_report.get('registered_order') != slot['registered_order']
            or session_report.get('registered_order_position') != slot['registered_order_position']
            or session_report.get('session_source_sha256') != slot['session_source_sha256']
            or session_report.get('clone_report_sha256') != receipt.get('clone_report_sha256')):
        raise ValueError('passed matching campaign session report required')
    clone_seconds = receipt.get('clone_preparation_wall_seconds')
    if (clone_seconds is not None
            and (isinstance(clone_seconds, bool)
                 or not isinstance(clone_seconds, (int, float))
                 or not math.isfinite(clone_seconds) or clone_seconds < 0)):
        raise ValueError('clone preparation duration must be a nonnegative measured value')
    return True


def verify_clone_receipt(validated, slot, paths):
    clone = read_json(paths['clone_report'], 65536)
    row = validated['transitions'].get(str(slot['target_count']))
    if slot['target_count'] == 0:
        expected = {'schema': 'part5-v3-campaign-r0-ledger-clone-v1',
                    'stage_report_sha256': validated['evidence']['stage_report']['sha256'],
                    'stage_status_sha256': validated['evidence']['stage_status']['sha256'],
                    'stage_monitor_sha256': validated['evidence']['stage_monitor']['sha256']}
        if clone.get('source') != json.loads(validated['evidence_paths']['stage_config'].read_bytes()).get('ledger'):
            raise ValueError('R0 clone must come from the registered stage ledger')
    else:
        pins = validated['evidence']['transitions'][str(slot['target_count'])]
        expected = {'schema': 'part5-v3-campaign-final-ledger-clone-v1',
                    'target_count': slot['target_count'],
                    'transition_config_sha256': pins['config']['sha256'],
                    'transition_report_sha256': pins['report']['sha256'],
                    'transition_status_sha256': pins['status']['sha256'],
                    'transition_monitor_sha256': pins['monitor']['sha256']}
        if clone.get('source') != json.loads(row['config'].read_bytes()).get('ledger'):
            raise ValueError('Rk clone must come from the registered transition ledger')
    if (any(clone.get(key) != value for key, value in expected.items())
            or clone.get('copy_identical') is not True
            or clone.get('application_effect') is not False
            or clone.get('destination') != str(paths['clone_ledger'])):
        raise ValueError('fresh byte-identical stopped campaign clone required')
    checked_dir(paths['clone_ledger'], private=True)
    return sha256(paths['clone_report'], 65536)


def execute_clone(validated, slot, paths, deadline):
    clone_tool = 'clone_r0' if slot['target_count'] == 0 else 'clone_final'
    verify_launch_pins(validated, ('python', clone_tool))
    paths['slot_root'].mkdir(mode=0o700)
    paths['clone_dir'].mkdir(mode=0o700)
    paths['work_root'].mkdir(mode=0o700)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('36-hour campaign envelope exhausted before clone')
    completed = subprocess.run(clone_argv(validated, slot, paths), cwd=REPO,
                               stdin=subprocess.DEVNULL, check=False,
                               timeout=remaining)
    if completed.returncode != 0:
        raise RuntimeError(f"clone helper exited {completed.returncode}")
    return verify_clone_receipt(validated, slot, paths)


def verify_launch_pins(validated, names):
    for name in names:
        pin = validated['tools_manifest'][name]
        if sha256(validated['tools'][name]) != pin['sha256']:
            raise ValueError(f'{name} changed after manifest validation')


def verify_existing_slot(plan_slot, validated, paths, expected_previous,
                         expected_previous_end_utc):
    if not paths['slot_root'].exists() or paths['slot_root'].is_symlink():
        return None
    checked_dir(paths['slot_root'], private=True)
    private_outer_report = paths['outer_private'] / 'report.json'
    required = (paths['clone_report'], paths['outer_report'], private_outer_report,
                paths['session_report'])
    if any(not path.is_file() or path.is_symlink() for path in required):
        raise ValueError('partial matrix slot exists; refusing retry or reuse')
    clone_sha = verify_clone_receipt(validated, plan_slot, paths)
    outer_sha, session_sha = sha256(paths['outer_report']), sha256(paths['session_report'])
    if sha256(private_outer_report) != outer_sha:
        raise ValueError('private and public outer report copies differ')
    receipt_path = paths['slot_receipt']
    receipt = read_json(receipt_path, 65536) if receipt_path.exists() else None
    slot = dict(plan_slot)
    slot['session_source_sha256'] = validated['tool_pins']['session_script']
    outer, session_report = read_json(paths['outer_report']), read_json(paths['session_report'])
    if receipt is None:
        provisional = {'schema': SLOT_RECEIPT_SCHEMA,
                       'slot_identity_sha256': plan_slot['identity_sha256'],
                       'sequence': plan_slot['sequence'],
                       'repetition': plan_slot['repetition'],
                       'target_count': plan_slot['target_count'], 'mode': plan_slot['mode'],
                       'registered_order': plan_slot['registered_order'],
                       'registered_order_position': plan_slot['registered_order_position'],
                       'previous_slot_receipt_sha256': expected_previous,
                       'clone_report_sha256': clone_sha,
                       'clone_preparation_wall_seconds': None,
                       'outer_report_sha256': outer_sha,
                       'session_report_sha256': session_sha}
        validate_slot_documents(slot, provisional, outer, session_report,
                                outer_sha256=outer_sha, session_sha256=session_sha,
                                expected_previous_receipt_sha256=expected_previous,
                                expected_previous_end_utc=expected_previous_end_utc)
        receipt_sha = write_new(receipt_path, provisional)
        return receipt_sha, provisional
    validate_slot_documents(slot, receipt, outer, session_report,
                            outer_sha256=outer_sha, session_sha256=session_sha,
                            expected_previous_receipt_sha256=expected_previous,
                            expected_previous_end_utc=expected_previous_end_utc)
    if receipt.get('clone_report_sha256') != clone_sha:
        raise ValueError('slot clone receipt hash mismatch')
    return sha256(receipt_path, 65536), receipt


def create_slot_receipt(plan_slot, validated, paths, previous_sha, clone_sha,
                        clone_seconds, previous_end_utc):
    slot = dict(plan_slot)
    slot['session_source_sha256'] = validated['tool_pins']['session_script']
    outer_sha = sha256(paths['outer_report'])
    session_sha = sha256(paths['session_report'])
    if sha256(paths['outer_private'] / 'report.json') != outer_sha:
        raise ValueError('private and public outer report copies differ')
    outer, session_report = read_json(paths['outer_report']), read_json(paths['session_report'])
    receipt = {'schema': SLOT_RECEIPT_SCHEMA,
               'slot_identity_sha256': plan_slot['identity_sha256'],
               'sequence': plan_slot['sequence'],
               'repetition': plan_slot['repetition'],
               'target_count': plan_slot['target_count'],
               'mode': plan_slot['mode'],
               'registered_order': plan_slot['registered_order'],
               'registered_order_position': plan_slot['registered_order_position'],
               'previous_slot_receipt_sha256': previous_sha,
               'clone_report_sha256': clone_sha,
               'clone_preparation_wall_seconds': clone_seconds,
               'outer_report_sha256': outer_sha,
               'session_report_sha256': session_sha}
    validate_slot_documents(slot, receipt, outer, session_report,
                            outer_sha256=outer_sha, session_sha256=session_sha,
                            expected_previous_receipt_sha256=previous_sha,
                            expected_previous_end_utc=previous_end_utc)
    return write_new(paths['slot_receipt'], receipt), receipt


def verify_actual_sequence(sequence, planned_slots):
    if len(sequence) != len(planned_slots) or len(planned_slots) != 60:
        raise ValueError('complete 60-slot campaign sequence required')
    previous_receipt = None
    previous_end = None
    for index, (actual, planned) in enumerate(zip(sequence, planned_slots), 1):
        if (actual.get('sequence') != index
                or actual.get('slot_identity_sha256') != planned['identity_sha256']
                or actual.get('repetition') != planned['repetition']
                or actual.get('target_count') != planned['target_count']
                or actual.get('mode') != planned['mode']
                or actual.get('registered_order') != planned['registered_order']
                or actual.get('registered_order_position') != planned['registered_order_position']
                or actual.get('previous_slot_receipt_sha256') != previous_receipt
                or not isinstance(actual.get('slot_receipt_sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', actual['slot_receipt_sha256'])):
            raise ValueError('actual campaign order differs from registered plan')
        try:
            started = datetime.datetime.fromisoformat(actual['outer_started_at_utc'])
            ended = datetime.datetime.fromisoformat(actual['outer_ended_at_utc'])
            if (started.tzinfo is None or ended.tzinfo is None or ended < started
                    or (previous_end is not None and started < previous_end)):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise ValueError('actual session timestamps overlap or are invalid') from None
        previous_receipt = actual['slot_receipt_sha256']
        previous_end = ended
    return True


def run_matrix(validated, *, resume=False):
    root = validated['output_root']
    state_path = root / 'campaign-state.json'
    if resume:
        checked_dir(root, private=True)
        manifest_copy = root / 'input-manifest.json'
        plan_path = root / 'matrix-plan.json'
        if (sha256(manifest_copy, 4 * 1024 * 1024) != validated['manifest_sha256']
                or read_json(plan_path, 8 * 1024 * 1024).get('manifest_sha256')
                   != validated['manifest_sha256']):
            raise ValueError('resume manifest or plan identity differs')
        state = read_json(state_path, 65536)
        if (state.get('schema') != 'part5-v3-campaign-matrix-state-v1'
                or state.get('campaign_id') != validated['campaign_id']
                or state.get('manifest_sha256') != validated['manifest_sha256']
                or state.get('campaign_runtime_seconds') != CAMPAIGN_SECONDS):
            raise ValueError('resume campaign deadline state mismatch')
    else:
        if root.exists() or root.is_symlink():
            raise FileExistsError('fresh output_root required; pass --resume to inspect existing slots')
        root.mkdir(mode=0o700)
        write_new(root / 'input-manifest.json', validated['manifest'])
        started_utc = datetime.datetime.now(datetime.timezone.utc)
        state = {'schema': 'part5-v3-campaign-matrix-state-v1',
                 'campaign_id': validated['campaign_id'],
                 'manifest_sha256': validated['manifest_sha256'],
                 'campaign_runtime_seconds': CAMPAIGN_SECONDS,
                 'started_at_utc': started_utc.isoformat(),
                 'deadline_utc': (started_utc + datetime.timedelta(seconds=CAMPAIGN_SECONDS)).isoformat()}
        write_new(state_path, state)
    rows = plan_slots(validated)
    plan_document = {'schema': 'part5-v3-campaign-matrix-plan-v1',
                     'manifest_sha256': validated['manifest_sha256'],
                     'driver_sha256': validated['driver_sha256'],
                     'campaign_id': validated['campaign_id'],
                     'campaign_runtime_seconds': CAMPAIGN_SECONDS,
                     'slot_count': len(rows), 'slots': rows}
    plan_path = root / 'matrix-plan.json'
    if resume:
        if read_json(plan_path, 8 * 1024 * 1024) != plan_document:
            raise ValueError('existing plan does not match current exact argv and identities')
    else:
        write_new(plan_path, plan_document)

    existing = []
    for row in rows:
        paths = output_paths(validated, row)
        existing.append(paths['slot_root'].exists() or paths['slot_root'].is_symlink())
    first_missing = next((index for index, present in enumerate(existing) if not present), len(existing))
    if any(existing[first_missing:]):
        raise ValueError('existing slots must be one contiguous passed prefix')
    if first_missing and not resume:
        raise ValueError('existing slot state requires explicit --resume')

    try:
        deadline_utc = datetime.datetime.fromisoformat(state['deadline_utc'])
        if deadline_utc.tzinfo is None:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ValueError('valid persisted UTC campaign deadline required') from None
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if now_utc >= deadline_utc:
        raise TimeoutError('persisted 36-hour campaign envelope expired')
    deadline = time.monotonic() + (deadline_utc - now_utc).total_seconds()
    sequence = []
    previous_sha = None
    previous_end_utc = None
    for index, row in enumerate(rows):
        paths = output_paths(validated, row)
        if index < first_missing:
            receipt_sha, receipt = verify_existing_slot(row, validated, paths, previous_sha,
                                                        previous_end_utc)
            outer = read_json(paths['outer_report'])
            sequence.append({'sequence': row['sequence'],
                             'slot_identity_sha256': row['identity_sha256'],
                             'slot_receipt_sha256': receipt_sha,
                             'previous_slot_receipt_sha256': receipt.get('previous_slot_receipt_sha256'),
                             'mode': row['mode'], 'target_count': row['target_count'],
                             'repetition': row['repetition'],
                             'registered_order': row['registered_order'],
                             'registered_order_position': row['registered_order_position'],
                             'clone_preparation_wall_seconds': receipt.get('clone_preparation_wall_seconds'),
                             'outer_started_at_utc': outer['started_at_utc'],
                             'outer_ended_at_utc': outer['ended_at_utc']})
            previous_sha = receipt_sha
            previous_end_utc = outer['ended_at_utc']
            continue
        limits = row['limits']
        if any(path.exists() or path.is_symlink()
               for path in (paths['effect_output'], paths['control_output'])):
            raise FileExistsError('fresh effect and control outputs required for every slot')
        remaining = deadline - time.monotonic()
        if limits['runtime_seconds'] > remaining:
            raise TimeoutError('remaining campaign envelope is below the next explicit session cap')
        clone_started = time.monotonic()
        clone_sha = execute_clone(validated, row, paths, deadline)
        clone_seconds = time.monotonic() - clone_started
        if limits['runtime_seconds'] > deadline - time.monotonic():
            raise TimeoutError('36-hour campaign envelope exhausted after clone')
        env = os.environ.copy()
        verify_launch_pins(validated, ('python', 'session_script', 'bounded_runner'))
        env['P5_V3_CAMPAIGN_SESSION_SUPERVISOR'] = 'bounded-complete-session'
        command = [str(validated['tools']['python']), '-B', str(validated['tools']['bounded_runner']),
                   '--owner', row['owner'], '--cwd', str(REPO),
                   '--private-output', str(paths['outer_private']),
                   '--report', str(paths['outer_report']),
                   '--runtime-seconds', str(limits['runtime_seconds']),
                   '--rss-bytes', str(limits['rss_bytes']),
                   '--storage-bytes', str(limits['storage_bytes']),
                   '--storage-path', str(paths['effect_output']),
                   '--storage-path', str(paths['control_output']),
                   '--storage-path', str(paths['work_root']),
                   '--storage-path', str(paths['clone_dir']), '--',
                   *session_argv(validated, row, paths)]
        result = subprocess.run(command, cwd=REPO, env=env,
                                stdin=subprocess.DEVNULL, check=False,
                                timeout=max(1, deadline - time.monotonic() + 10))
        if result.returncode != 0:
            raise RuntimeError(f"bounded campaign slot exited {result.returncode}")
        if time.monotonic() >= deadline:
            raise TimeoutError('36-hour campaign envelope exhausted during slot cleanup')
        receipt_sha, receipt = create_slot_receipt(row, validated, paths,
                                                  previous_sha, clone_sha,
                                                  clone_seconds, previous_end_utc)
        outer = read_json(paths['outer_report'])
        if time.monotonic() >= deadline:
            raise TimeoutError('36-hour campaign envelope expired during bounded cleanup')
        sequence.append({'sequence': row['sequence'],
                         'slot_identity_sha256': row['identity_sha256'],
                         'slot_receipt_sha256': receipt_sha,
                         'previous_slot_receipt_sha256': receipt.get('previous_slot_receipt_sha256'),
                         'mode': row['mode'], 'target_count': row['target_count'],
                         'repetition': row['repetition'],
                         'registered_order': row['registered_order'],
                         'registered_order_position': row['registered_order_position'],
                         'clone_preparation_wall_seconds': clone_seconds,
                         'outer_started_at_utc': outer['started_at_utc'],
                         'outer_ended_at_utc': outer['ended_at_utc']})
        previous_sha = receipt_sha
        previous_end_utc = outer['ended_at_utc']

    order_passed = verify_actual_sequence(sequence, rows)
    final = {'schema': SEQUENCE_SCHEMA, 'campaign_id': validated['campaign_id'],
             'manifest_sha256': validated['manifest_sha256'],
             'campaign_runtime_seconds': CAMPAIGN_SECONDS,
             'sequence_count': len(sequence), 'passed': True,
             'campaign_started_at_utc': state['started_at_utc'],
             'campaign_completed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'cross_session_order_verified': order_passed,
             'sequence': sequence, 'final_slot_receipt_sha256': previous_sha,
             'registered_orders': [list(order) for order in session.ORDERS]}
    if datetime.datetime.now(datetime.timezone.utc) >= deadline_utc:
        raise TimeoutError('36-hour campaign envelope expired before sequence receipt')
    sequence_path = root / 'sequence-receipt.json'
    if sequence_path.exists():
        existing_final = read_json(sequence_path, 1024 * 1024)
        comparable = dict(final)
        comparable.pop('campaign_completed_at_utc')
        existing_comparable = dict(existing_final)
        completed_at_value = existing_comparable.pop('campaign_completed_at_utc', None)
        try:
            completed_at = datetime.datetime.fromisoformat(completed_at_value)
            if (completed_at.tzinfo is None or completed_at > deadline_utc
                    or (previous_end_utc is not None
                        and completed_at < datetime.datetime.fromisoformat(previous_end_utc))):
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError('existing campaign completion timestamp is invalid') from None
        if existing_comparable != comparable:
            raise ValueError('existing sequence receipt differs from verified slot chain')
        final = existing_final
    else:
        write_new(sequence_path, final)
    publish_economics_manifest(root, rows)
    return final


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--plan', action='store_true',
                        help='validate pins and print exact argv without creating outputs')
    parser.add_argument('--resume', action='store_true',
                        help='skip only a contiguous prefix of verified passed slots')
    args = parser.parse_args()
    if args.plan and args.resume:
        parser.error('--plan and --resume are separate operations')
    validated = validate_manifest(args.manifest)
    rows = plan_slots(validated)
    if args.plan:
        plan = {'schema': 'part5-v3-campaign-matrix-plan-v1',
                'manifest_sha256': validated['manifest_sha256'],
                'driver_sha256': validated['driver_sha256'],
                'campaign_id': validated['campaign_id'],
                'campaign_runtime_seconds': CAMPAIGN_SECONDS,
                'slot_count': len(rows), 'slots': rows}
        print(json.dumps(plan, sort_keys=True, indent=2))
        return 0
    os.umask(0o077)
    result = run_matrix(validated, resume=args.resume)
    print(json.dumps({'passed': result['passed'],
                      'sequence_count': result['sequence_count'],
                      'sequence_receipt': str(validated['output_root'] / 'sequence-receipt.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
