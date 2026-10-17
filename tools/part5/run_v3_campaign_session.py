#!/usr/bin/env python3
"""Run one bounded v3 campaign session on a fresh stopped Rk ledger clone.

Invoke under results/dynark/part5/session_runner.py with a fresh private work
root. The outer measurement owns this entire command, from source import through
effect reconciliation. A cloned ledger and signed R0..Rk history are supplied
before timing; their preparation is common external work. The coalesced control
does not generate complete witnesses for preliminary checkpoints.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.part5 import freeze_v3_campaign_cohort as freeze_tool
from tools.part5 import prepare_v3_campaign_cohort as cohort_tool
from harness.tests import queue_v3_build_prep

COUNTS = (0, 1, 2, 5, 10)
MODES = ('full', 'anchor', 'coalesced-full')
ORDERS = (
    ('full', 'anchor', 'coalesced-full'),
    ('anchor', 'coalesced-full', 'full'),
    ('full', 'coalesced-full', 'anchor'),
    ('coalesced-full', 'anchor', 'full'),
)
CLIENT = REPO / 'crates/dynark-native-client/tests/support'
SOURCE = REPO / 'tools/part5/prepare_v3_campaign_training_source.py'
BASE = CLIENT / 'prepare_v3_request_bound_training.py'
TARGET = REPO / 'tools/part5/prepare_v3_campaign_target.py'
PACKET = REPO / 'tools/part5/build_v3_campaign_packet.py'
WITNESS = CLIENT / 'v3_relation_witness.cjs'
RELATION = CLIENT / 'prepare_v3_relation.py'
EFFECT_CONFIG = REPO / 'tools/part5/create_v3_campaign_effect_config.py'
EFFECT_SUPERVISOR = REPO / 'harness/tests/queue_v3_local_campaign_effect.py'
BOUNDED = REPO / 'results/dynark/part5/session_runner.py'


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            value.update(chunk)
    return value.hexdigest()


def checked_file(path, cap=256 * 1024 * 1024):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_size <= 0 or before.st_size > cap
            or before.st_mode & 0o022):
        raise ValueError('bounded canonical owner-controlled file required')
    return path


def private_dir(path, empty=False):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o700
            or (empty and any(path.iterdir()))):
        raise ValueError('canonical empty owner0700 directory required')
    return path


def fresh_output(path):
    path = Path(path)
    root = REPO / 'artifacts/dynark/part5'
    if (not path.is_absolute() or path.parent != root
            or path.exists() or path.is_symlink()):
        raise ValueError('fresh direct private application output required')
    return path


def checked_digest(path, expected):
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError('explicit SHA-256 pin required')
    checked_file(path)
    actual = digest(path)
    if actual != expected:
        raise ValueError('file identity differs from supplied pin')
    return actual


def document(path, cap=1024 * 1024):
    return json.loads(checked_file(path, cap).read_bytes())


def planned_checkpoints(mode, count):
    if mode not in MODES or type(count) is not int or count not in COUNTS:
        raise ValueError('registered campaign mode/count required')
    input_generations = tuple(range(1, count + 1)) if mode != 'coalesced-full' else ((count,) if count else ())
    witness_generations = tuple(range(count + 1)) if mode != 'coalesced-full' else (count,)
    return input_generations, witness_generations


def child_cpu():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def run_stage(stages, work, name, command, environment=None, accepted=(0,)):
    start, cpu = time.monotonic(), child_cpu()
    with (work / (name + '.stdout.log')).open('xb') as stdout, \
            (work / (name + '.stderr.log')).open('xb') as stderr:
        completed = subprocess.run([str(part) for part in command], cwd=REPO,
            env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            check=False)
    row = {'stage': name, 'wall_seconds': time.monotonic() - start,
           'waited_child_cpu_seconds': child_cpu() - cpu,
           'exit_code': completed.returncode}
    stages.append(row)
    if completed.returncode not in accepted:
        raise RuntimeError(f'{name} exited {completed.returncode}')


def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def verify_boundary(args):
    freeze = document(args.freeze, 65536)
    cohort = document(Path(args.cohort_root) / 'cohort-receipt.json', 65536)
    identities = freeze.get('identities')
    if (freeze.get('schema') != cohort_tool.FREEZE_SCHEMA
            or set(identities or {}) != cohort_tool.keys.IDENTITY_ROLES
            or freeze.get('source_sha256') != cohort_tool.source_hashes()
            or cohort.get('freeze_receipt_sha256') != digest(args.freeze)
            or cohort.get('identities') != identities
            or cohort.get('training_only') is not True):
        raise ValueError('exact preregistered campaign cohort freeze required')
    if (freeze_tool.bundle(freeze_tool.CLIENT_FILES)[0] != identities['client']
            or freeze_tool.bundle(freeze_tool.REGISTRY_FILES)[0] != identities['registry']
            or freeze_tool.file_digest(Path(args.proof_binary)) != identities['proof_runner']
            or freeze_tool.file_digest(Path(args.adapter_binary)) != identities['ordinary_adapter']
            or freeze_tool.file_digest(REPO / 'tools/part5/prepare_v3_request_fixture.py')
               != identities['signer_interface']):
        raise ValueError('frozen campaign code or binary identity changed')
    manifest = queue_v3_build_prep.source_manifest(REPO)
    manifest_sha = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    if manifest_sha != identities['application_source']:
        raise ValueError('frozen application source manifest changed')
    for path, expected in ((args.exporter, args.exporter_sha256),
                           (args.node, args.node_sha256),
                           (args.old_packet, args.old_packet_sha256),
                           (EFFECT_CONFIG, args.effect_config_sha256),
                           (EFFECT_SUPERVISOR, args.effect_supervisor_sha256),
                           (BOUNDED, args.bounded_runner_sha256)):
        checked_digest(path, expected)
    stage = document(Path(args.stage_root) / 'stage-report.json', 65536)
    context = document(args.context, 8192)
    plan = document(Path(args.stage_root) / 'plan.json', 8192)
    roots = context.get('root_sequence')
    if (stage.get('schema') != 'part5-v3-campaign-stage-v1'
            or stage.get('passed') is not True
            or context.get('schema') != 'part5-v3-campaign-context-v1'
            or not isinstance(roots, list) or len(roots) != 11
            or roots[0] != bytes(plan['root']).hex()
            or stage.get('plan_sha256') != digest(Path(args.stage_root) / 'plan.json')
            or stage.get('loaded_program', {}).get('elf_sha256') != identities['loaded_elf']):
        raise ValueError('signed R0 stage and campaign root schedule required')
    clone = document(args.clone_report, 65536)
    if (clone.get('copy_identical') is not True
            or clone.get('application_effect') is not False
            or Path(clone.get('destination', '')).parent / 'clone-report.json' != args.clone_report):
        raise ValueError('fresh reviewed clone required')
    private_dir(clone['destination'])
    if args.target_count == 0:
        if (args.stage_config is None or args.stage_status is None
                or args.stage_monitor is None or not args.stage_monitor_owner
                or clone.get('schema') != 'part5-v3-campaign-r0-ledger-clone-v1'
                or clone.get('stage_report_sha256') != digest(Path(args.stage_root) / 'stage-report.json')
                or clone.get('stage_status_sha256') != digest(args.stage_status)
                or clone.get('stage_monitor_sha256') != digest(args.stage_monitor)):
            raise ValueError('pinned stopped R0 clone required')
        current_root = args.stage_root
        current_report = Path(args.stage_root) / 'stage-report.json'
        current_report_sha = digest(current_report)
        runner_pin = document(args.stage_config, 65536)['runner_sha256']
    else:
        if any(getattr(args, key) is None for key in
               ('transition_config', 'transition_report', 'transition_status',
                'transition_monitor', 'transition_monitor_owner', 'transition_root')):
            raise ValueError('signed stopped Rk transition evidence required')
        changed = document(args.transition_report, 65536)
        transition = document(args.transition_config, 65536)
        if (clone.get('schema') != 'part5-v3-campaign-final-ledger-clone-v1'
                or clone.get('target_count') != args.target_count
                or clone.get('current_root') != context['root_sequence'][args.target_count]
                or clone.get('transition_config_sha256') != digest(args.transition_config)
                or clone.get('transition_report_sha256') != digest(args.transition_report)
                or clone.get('transition_status_sha256') != digest(args.transition_status)
                or clone.get('transition_monitor_sha256') != digest(args.transition_monitor)
                or changed.get('schema') != 'part5-v3-campaign-transition-v1'
                or changed.get('passed') is not True
                or changed.get('target_count') != args.target_count
                or changed.get('current_root') != clone['current_root']
                or Path(args.transition_root) != Path(args.transition_report).parent
                or Path(transition.get('transition_output', '')) != args.transition_root):
            raise ValueError('pinned stopped signed Rk clone required')
        current_root = args.transition_root
        current_report = args.transition_report
        current_report_sha = digest(current_report)
        runner_pin = transition['runner_sha256']
    checked_digest(args.effect_runner, runner_pin)
    return {'freeze_sha256': digest(args.freeze),
            'cohort_receipt_sha256': digest(Path(args.cohort_root) / 'cohort-receipt.json'),
            'clone_report_sha256': digest(args.clone_report),
            'current_root': str(current_root), 'current_report_sha256': current_report_sha,
            'source_identities': identities}


def verified_proof(packet_path, report_path, mode, count):
    packet = document(packet_path, 262144)
    report = document(report_path, 65536)
    proofs = 1 if mode == 'coalesced-full' else count + 1
    cross_root = 0 if mode == 'coalesced-full' else 2 * count
    if (report.get('schema') != 'credential-v3-cumulative-proof-v1'
            or report.get('passed') is not True
            or report.get('mode') != f'campaign-{mode}-k{count}'
            or report.get('update_count') != count
            or report.get('packet_sha256') != digest(packet_path)
            or report.get('application_stage_pins') != packet.get('application_stage')
            or report.get('counts', {}).get('proofs') != proofs
            or report['counts'].get('ordinary_checks') != 7 * proofs + cross_root):
        raise ValueError('complete cumulative proof/check report required')
    return digest(report_path)


def verified_effect(status_path, report_path, mode, count):
    status = document(status_path, 65536)
    effect = document(report_path, 65536)
    report_sha = digest(report_path)
    cleanup = status.get('validator_cleanup', {})
    clean_shutdown = (status.get('status') == 'passed'
                      and status.get('ledger_reuse_requires_review') is False
                      and cleanup.get('graceful') is True
                      and cleanup.get('exit_code') == 0)
    reviewed_shutdown = (status.get('status') == 'failed'
                         and status.get('ledger_reuse_requires_review') is True
                         and cleanup.get('exit_code') == -2)
    identity_fields = ('program', 'programdata', 'elf_sha256',
                       'program_account_sha256', 'programdata_account_sha256', 'genesis',
                       'loader', 'elf_bytes')
    status_loaded = status.get('loaded_program', {})
    effect_loaded = effect.get('loaded_program', {})
    if (status.get('scope') != 'part5-v3-campaign-effect'
            or status.get('mode') != mode
            or status.get('target_count') != count
            or status.get('effect_verified') is not True
            or status.get('application_effect') is not True
            or status.get('effect_outcome') != 'verified'
            or status.get('effect_count') != 1
            or status.get('effect_report_sha256') != report_sha
            or status.get('effect_output') != str(Path(report_path).parent)
            or status.get('error_type') is not None
            or not (clean_shutdown or reviewed_shutdown)
            or cleanup.get('reaped') is not True
            or status.get('runner_cleanup', {}).get('exit_code') != 0
            or status['runner_cleanup'].get('reaped') is not True
            or effect.get('schema') != 'part5-v3-campaign-effect-v1'
            or effect.get('passed') is not True
            or effect.get('mode') != mode
            or effect.get('target_count') != count
            or effect.get('application_effect') is not True
            or effect.get('effect_count') != 1
            or effect.get('request_consumed') is not True
            or effect.get('stale_r0_rejected') is not (count > 0 and mode != 'coalesced-full')
            or status_loaded.get('elf_match') is not True
            or effect_loaded.get('elf_match') is not True
            or any(key not in status_loaded for key in identity_fields)
            or effect_loaded.get('elf_sha256') != status_loaded.get('elf_sha256')
            or not isinstance(status_loaded.get('loader'), str)
            or not status_loaded['loader']
            or effect_loaded.get('loader') != status_loaded.get('loader')
            or type(status_loaded.get('elf_bytes')) is not int
            or status_loaded['elf_bytes'] <= 0
            or type(effect_loaded.get('local_bytes')) is not int
            or type(effect_loaded.get('remote_bytes')) is not int
            or effect_loaded.get('local_bytes') != status_loaded.get('elf_bytes')
            or effect_loaded.get('remote_bytes') != status_loaded.get('elf_bytes')
            or type(status.get('finalized_slot')) is not int
            or type(effect.get('finalized_slot')) is not int
            or status['finalized_slot'] < effect['finalized_slot']):
        raise ValueError('finalized campaign effect and cleanup required')
    return report_sha


def run(args):
    os.umask(0o077)
    started = time.monotonic()
    if os.environ.get('P5_V3_CAMPAIGN_SESSION_SUPERVISOR') != 'bounded-complete-session':
        raise ValueError('outer bounded complete-session supervisor required')
    input_generations, witnesses = planned_checkpoints(args.mode, args.target_count)
    if type(args.repetition) is not int or not 1 <= args.repetition <= 4:
        raise ValueError('registered four-repetition campaign required')
    work = private_dir(args.work_root, empty=True)
    fresh_output(args.effect_output)
    fresh_output(args.control_output)
    if args.effect_output == args.control_output:
        raise ValueError('distinct effect and control outputs required')
    stages = []
    result = {'schema': 'part5-v3-campaign-session-v1', 'mode': args.mode,
              'target_count': args.target_count, 'training_only': True,
              'passed': False, 'effect_verified': False,
              'complete_tree_cpu_qualified': False,
              'preexisting_signed_history_preparation_charged': False,
              'preexisting_ledger_clone_charged': False,
              'preexisting_state_wait_charged': False,
              'coalesced_state_wait_seconds_observed': None,
              'repetition': args.repetition,
              'registered_order': list(ORDERS[args.repetition - 1]),
              'registered_order_position': ORDERS[args.repetition - 1].index(args.mode) + 1,
              'cross_session_order_verified': False,
              'stages': stages, 'session_source_sha256': digest(__file__)}
    try:
        boundary = verify_boundary(args)
        result.update(boundary)
        source, base = work / 'source', work / 'r0'
        source.mkdir(mode=0o700)
        base.mkdir(mode=0o700)
        run_stage(stages, work, 'source_import', [sys.executable, '-B', SOURCE,
            '--stage-root', args.stage_root, '--cohort-root', args.cohort_root,
            '--context-path', args.context, '--output', source,
            '--exporter', args.exporter])
        source_receipt_sha = digest(source / 'source-receipt.json')
        run_stage(stages, work, 'r0_input', [sys.executable, '-B', BASE,
            source, base, args.exporter])
        base_receipt_sha = digest(base / 'training-receipt.json')
        fixtures = {0: base}
        for generation in input_generations:
            output = work / f'r{generation}'
            output.mkdir(mode=0o700)
            command = [sys.executable, '-B', TARGET,
                '--source', source, '--base', base, '--stage-root', args.stage_root,
                '--transition-root', args.transition_root,
                '--cohort-root', args.cohort_root, '--context-path', args.context,
                '--generation', generation, '--output', output,
                '--source-receipt-sha256', source_receipt_sha,
                '--base-receipt-sha256', base_receipt_sha,
                '--transition-report-sha256', boundary['current_report_sha256']]
            run_stage(stages, work, f'r{generation}_input', command)
            fixtures[generation] = output
        for generation in witnesses:
            directory = fixtures[generation]
            run_stage(stages, work, f'r{generation}_witness',
                      [args.node, WITNESS, directory])
            run_stage(stages, work, f'r{generation}_relation',
                      [sys.executable, '-B', RELATION, 'check', directory])
        packet_path = work / 'packet.json'
        packet_fixtures = ([fixtures[args.target_count]] if args.mode == 'coalesced-full'
                           else [fixtures[i] for i in range(args.target_count + 1)])
        packet_command = [sys.executable, '-B', PACKET,
            '--stage-root', args.stage_root, '--transition-root', boundary['current_root'],
            '--cohort-root', args.cohort_root, '--context', args.context,
            '--old-packet', args.old_packet, '--output', packet_path,
            '--count', args.target_count]
        if args.mode == 'coalesced-full':
            packet_command.append('--coalesced')
        for fixture in packet_fixtures:
            packet_command.extend(('--fixture', fixture))
        run_stage(stages, work, 'packet', packet_command)
        packet_sha = digest(packet_path)
        result['packet_sha256'] = packet_sha
        proof_dir = work / 'proof'
        proof_mode = f'campaign-{args.mode}-k{args.target_count}'
        run_stage(stages, work, 'proof',
            [args.proof_binary, proof_mode, packet_path, packet_sha, proof_dir],
            {**os.environ, 'RAYON_NUM_THREADS': '4'})
        proof_report = proof_dir / 'proof-report.json'
        result['proof_report_sha256'] = verified_proof(packet_path, proof_report,
            args.mode, args.target_count)
        final_fixture = fixtures[args.target_count]
        final_receipt_sha = digest(final_fixture / 'training-receipt.json')
        adapter_env = {**os.environ,
            'M2_V3_CAMPAIGN_MODE': proof_mode,
            'M2_V3_CAMPAIGN_FINAL_FIXTURE': str(final_fixture),
            'M2_V3_CAMPAIGN_FINAL_RECEIPT_SHA256': final_receipt_sha,
            'M2_V3_CAMPAIGN_PACKET': str(packet_path),
            'M2_V3_CAMPAIGN_PACKET_SHA256': packet_sha,
            'M2_V3_CAMPAIGN_PROOFS': str(proof_dir),
            'M2_V3_CAMPAIGN_REPORT_SHA256': result['proof_report_sha256']}
        if args.mode != 'coalesced-full':
            adapter_env['M2_V3_CAMPAIGN_BASE_FIXTURE'] = str(base)
            adapter_env['M2_V3_CAMPAIGN_BASE_RECEIPT_SHA256'] = base_receipt_sha
        run_stage(stages, work, 'adapter', [args.adapter_binary,
            'private_campaign_final_wire_passes_adapter_and_program_host',
            '--exact', '--ignored', '--test-threads=1'], adapter_env)
        current_wire = final_fixture / f'{proof_mode}-solana-wire.bin'
        checked_file(current_wire, 448)
        result['current_wire_sha256'] = digest(current_wire)
        base_wire = base / 'campaign-full-k0-solana-wire.bin'
        if args.mode != 'coalesced-full' and args.target_count > 0:
            checked_file(base_wire, 448)
            result['base_wire_sha256'] = digest(base_wire)
        elif args.mode != 'coalesced-full' and args.target_count == 0:
            base_wire = current_wire
            result['base_wire_sha256'] = result['current_wire_sha256']
        config_path = work / 'effect-config.json'
        config_command = [sys.executable, '-B', EFFECT_CONFIG,
            '--mode', args.mode, '--target-count', args.target_count,
            '--clone-report', args.clone_report, '--proof-packet', packet_path,
            '--proof-report', proof_report,
            '--stage-report', Path(args.stage_root) / 'stage-report.json',
            '--stage-plan', Path(args.stage_root) / 'plan.json',
            '--current-wire', current_wire, '--runner', args.effect_runner,
            '--effect-output', args.effect_output,
            '--control-output', args.control_output, '--output', config_path]
        if args.mode != 'coalesced-full':
            config_command.extend(('--base-wire', base_wire))
        if args.target_count == 0:
            for option in ('stage_config', 'stage_status', 'stage_monitor',
                           'stage_monitor_owner', 'cohort_root'):
                config_command.extend(('--' + option.replace('_', '-'), getattr(args, option)))
        else:
            for option in ('transition_config', 'transition_report', 'transition_status',
                           'transition_monitor', 'transition_monitor_owner'):
                config_command.extend(('--' + option.replace('_', '-'), getattr(args, option)))
        run_stage(stages, work, 'effect_config', config_command)
        config_sha = digest(config_path)
        result['effect_config_sha256'] = config_sha
        application_env = {**os.environ,
            'P5_V3_CAMPAIGN_EFFECT_SUPERVISOR': 'reviewed-campaign-clone'}
        monitor_output = work / 'effect-monitor-private'
        monitor_report = work / 'effect-monitor.json'
        monitor_owner = f'v3-campaign-{args.mode}-k{args.target_count}'
        run_stage(stages, work, 'application', [sys.executable, '-B',
            BOUNDED,
            '--owner', monitor_owner, '--cwd', REPO,
            '--private-output', monitor_output, '--report', monitor_report,
            '--runtime-seconds', '180', '--rss-bytes', '4294967296',
            '--storage-bytes', '268435456',
            '--storage-path', args.effect_output,
            '--storage-path', args.control_output,
            '--', sys.executable, '-B', EFFECT_SUPERVISOR,
            '--config', config_path, '--config-sha256', config_sha],
            application_env, accepted=(0, 1))
        monitor = document(monitor_report, 4 * 1024 * 1024)
        if (monitor.get('owner') != monitor_owner
                or monitor.get('stop_reason') is not None
                or monitor.get('runner_error_type') is not None
                or monitor.get('cleanup_remaining_owned_processes') != 0
                or monitor.get('cleanup_status_unknown') is not False
                or monitor.get('exit_code') not in (0, 1)
                or monitor.get('limits', {}).get('runtime_seconds') != 180
                or monitor['limits'].get('owned_tree_rss_bytes') != 4294967296
                or monitor['limits'].get('storage_growth_bytes') != 268435456):
            raise ValueError('bounded application process or cleanup failed')
        result['effect_monitor_sha256'] = digest(monitor_report)
        result['effect_monitor_peak_rss_bytes'] = monitor.get('sampled_peak_owned_tree_rss_bytes')
        result['effect_monitor_peak_storage_growth_bytes'] = monitor.get('sampled_peak_storage_growth_bytes')
        result['effect_report_sha256'] = verified_effect(
            Path(args.control_output) / 'status.json',
            Path(args.effect_output) / 'effect-report.json', args.mode, args.target_count)
        effect_status = document(Path(args.control_output) / 'status.json', 65536)
        if monitor['exit_code'] != (0 if effect_status['status'] == 'passed' else 1):
            raise ValueError('effect supervisor and bounded monitor exits differ')
        result['effect_supervisor_status'] = effect_status['status']
        result['validator_cleanup'] = effect_status['validator_cleanup']
        result['ledger_reuse_requires_review'] = effect_status['ledger_reuse_requires_review']
        result['effect_verified'] = True
        result['passed'] = True
    except Exception as error:
        result['error_type'] = type(error).__name__
        result['error_message'] = str(error)[:160]
    finally:
        result['total_command_wall_seconds'] = time.monotonic() - started
        result['waited_child_cpu_seconds_sum'] = sum(row['waited_child_cpu_seconds'] for row in stages)
        result['stage_wall_seconds_sum'] = sum(row['wall_seconds'] for row in stages)
        write_json(work / 'session-report.json', result)
    return 0 if result['passed'] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=MODES)
    parser.add_argument('--target-count', required=True, type=int, choices=COUNTS)
    parser.add_argument('--repetition', required=True, type=int, choices=(1, 2, 3, 4))
    for name in ('freeze', 'cohort_root', 'context', 'stage_root', 'clone_report',
                 'work_root', 'effect_output', 'control_output', 'proof_binary',
                 'adapter_binary', 'exporter', 'node', 'old_packet', 'effect_runner'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    for name in ('exporter_sha256', 'node_sha256', 'old_packet_sha256',
                 'effect_config_sha256', 'effect_supervisor_sha256',
                 'bounded_runner_sha256'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    for name in ('transition_root', 'transition_config', 'transition_report',
                 'transition_status', 'transition_monitor', 'stage_config',
                 'stage_status', 'stage_monitor'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path)
    for name in ('transition_monitor_owner', 'stage_monitor_owner'):
        parser.add_argument('--' + name.replace('_', '-'))
    return run(parser.parse_args())


if __name__ == '__main__':
    sys.exit(main())
