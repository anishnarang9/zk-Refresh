#!/usr/bin/env python3
"""Supervise signed R0-to-Rk campaign revocations on a stopped R0 clone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from harness.tests import queue_v3_clone_ledger as ledgers
from harness.tests import queue_v3_local_execute as execute
from harness.tests import queue_v3_local_stage as stage
from tools.part5.prepare_v3_campaign_context import derive, encoded

base = stage.base
LIMITS = {'runtime_seconds': 420, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}
COUNTS = (1, 2, 5, 10)
RUNNER_CLEANUP_RESERVE_SECONDS = 60


def runner_deadline(started):
    return started + LIMITS['runtime_seconds'] - RUNNER_CLEANUP_RESERVE_SECONDS


def pinned(path, digest, cap=65536):
    return base.decode_json(base.checked(path, digest, cap))


def checked_history(history, context, plan, report, staged):
    if (history.get('schema') != 'part5-v3-eleven-leaf-signed-history-v1'
            or not isinstance(history.get('checkpoints'), list)
            or len(history['checkpoints']) != report['target_count'] + 1):
        raise ValueError('complete signed R0-to-Rk history required')
    source_key = bytes(plan['source'])
    publisher_key = bytes(plan['publisher'])
    digests = [bytes.fromhex(word) for word in context['initial_allocations']['tbs_digests']]
    prior_source = bytes(32)
    prior_publisher = bytes(32)
    commitments = []
    for index, checkpoint in enumerate(history['checkpoints']):
        signed, binding = checkpoint['source'], checkpoint['publisher']
        observation = signed['observation']
        changes = ([{'Issue': {'tbs_digest': list(digest),
                               'slot': 0 if j == 0 else j + 15,
                               'allocation_epoch': 1}}
                    for j, digest in enumerate(digests)] if index == 0
                   else [{'Revoke': {'tbs_digest': list(digests[index])}}])
        if (observation['changes'] != changes
                or observation['sequence'] != index + 1
                or bytes(observation['previous_digest']) != prior_source
                or observation['issuer_status_active'] is not True
                or binding['publication_sequence'] != index + 1
                or bytes(binding['previous_publication_digest']) != prior_publisher
                or binding['root_version'] != index
                or bytes(binding['root']).hex() != context['root_sequence'][index]
                or binding['scope'] != observation['scope']
                or binding['issuer'] != observation['issuer']
                or binding['source_head']['sequence'] != index + 1
                or bytes(observation['issuer']['source_key']) != source_key
                or bytes(binding['publisher_key']) != publisher_key):
            raise ValueError('signed campaign chain, change or root mismatch')
        source_message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
            observation, separators=(',', ':'), ensure_ascii=False).encode()
        Ed25519PublicKey.from_public_bytes(source_key).verify(
            bytes(signed['signature']), source_message)
        source_wire = b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
            signed, separators=(',', ':'), ensure_ascii=False).encode()
        source_digest = hashlib.sha256(source_wire).digest()
        if bytes(binding['source_head']['digest']) != source_digest:
            raise ValueError('publisher committed another source observation')
        body = {name: binding[name] for name in (
            'scope', 'issuer', 'source_head', 'root', 'root_version',
            'publisher_key', 'publication_sequence', 'previous_publication_digest')}
        publisher_message = b'DYNARK-V3-PUBLISHER-BINDING-v1\0' + json.dumps(
            body, separators=(',', ':'), ensure_ascii=False).encode()
        Ed25519PublicKey.from_public_bytes(publisher_key).verify(
            bytes(binding['signature']), publisher_message)
        publisher_wire = b'DYNARK-V3-PUBLISHER-WIRE-v1\0' + json.dumps(
            binding, separators=(',', ':'), ensure_ascii=False).encode()
        publisher_digest = hashlib.sha256(publisher_wire).digest()
        if index == 0:
            if (source_digest.hex() != staged['source_head_digest']
                    or publisher_digest.hex() != staged['publisher_envelope_digest']):
                raise ValueError('campaign history differs from signed R0 stage')
        else:
            row = report['checkpoints'][index - 1]
            if (row['root_version'] != index
                    or row['root'] != context['root_sequence'][index]
                    or row['source_sequence'] != index + 1
                    or row['source_head_digest'] != source_digest.hex()
                    or row['publication_sequence'] != index + 1
                    or row['publisher_envelope_digest'] != publisher_digest.hex()):
                raise ValueError('campaign report differs from signed checkpoint')
        commitments.append((source_digest, publisher_digest))
        prior_source, prior_publisher = source_digest, publisher_digest
    return commitments


def check_finalized_chain(before, after, plan, context, history, commitments):
    if (len(before) != 5 or len(after) != 5
            or len(commitments) != len(history['checkpoints'])):
        raise ValueError('complete campaign account and signed history required')
    for index, accounts in ((0, before), (len(commitments) - 1, after)):
        issuer, head = accounts[1], accounts[2]
        observation = history['checkpoints'][index]['source']['observation']
        source_digest, publisher_digest = commitments[index]
        root = bytes.fromhex(context['root_sequence'][index])
        sequence = (index + 1).to_bytes(8, 'big')
        version = index.to_bytes(8, 'big')
        previous_publisher = commitments[index - 1][1] if index else bytes(32)
        if (len(issuer) != 374 or len(head) != 280
                or issuer[:8] != b'DYNISS03' or head[:8] != b'DYNHEAD3'
                or issuer[140:172] != bytes(plan['source'])
                or issuer[172] != 1 or issuer[357] != 1
                or issuer[173:181] != sequence
                or issuer[181:213] != source_digest
                or issuer[213:221] != observation['observed_at'].to_bytes(8, 'big', signed=True)
                or issuer[221:229] != observation['valid_until'].to_bytes(8, 'big', signed=True)
                or issuer[229:261] != root or issuer[261:269] != version
                or issuer[269:277] != sequence or issuer[277:309] != source_digest
                or head[72:104] != bytes(plan['publisher'])
                or head[104:112] != sequence
                or head[112:144] != publisher_digest
                or head[144:176] != previous_publisher
                or head[176:208] != root or head[208:216] != version
                or head[216:224] != sequence or head[224:256] != source_digest):
            raise ValueError('finalized campaign account differs from signed chain')
    if (after[1][:173] != before[1][:173]
            or after[1][309:] != before[1][309:]
            or after[2][:104] != before[2][:104]
            or after[2][256:272] != before[2][256:272]):
        raise ValueError('campaign changed enrolled issuer or publisher identity')


def admit(config):
    if (config.get('schema') != 1
            or config.get('scope') != 'part5-v3-campaign-transition'
            or config.get('target_count') not in COUNTS
            or config.get('outer_limits_required') != LIMITS):
        raise ValueError('explicit bounded campaign transition required')
    stage_config = pinned(config['stage_config'], config['stage_config_sha256'])
    status = pinned(config['stage_status'], config['stage_status_sha256'])
    monitor = pinned(config['stage_monitor'], config['stage_monitor_sha256'])
    staged = pinned(config['stage_root'] + '/stage-report.json',
                    config['stage_report_sha256'])
    plan = pinned(config['stage_root'] + '/plan.json', config['stage_plan_sha256'], 8192)
    if (stage_config.get('scope') != 'part5-v3-campaign-stage'
            or stage_config.get('stage_output') != config['stage_root']
            or stage_config.get('context') != config['context']
            or stage_config.get('context_sha256') != config['context_sha256']
            or status.get('scope') != 'part5-v3-campaign-stage'
            or status.get('config_sha256') != config['stage_config_sha256']
            or status.get('stage_report_sha256') != config['stage_report_sha256']
            or status.get('stage_verified') is not True
            or status.get('ledger_reuse_requires_review') is not True
            or status.get('validator_cleanup', {}).get('exit_code') != -signal.SIGINT
            or status.get('runner_cleanup', {}).get('exit_code') != 0
            or monitor.get('owner') != config['stage_monitor_owner']
            or monitor.get('stop_reason') is not None
            or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False):
        raise ValueError('reviewed signed campaign R0 stage required')
    original = pinned(stage_config['prior_config'], stage_config['prior_config_sha256'])
    build = pinned(original['build_plan'], original['build_plan_sha256'])
    base.prep.check_manifest(REPO, build['source_manifest'])
    if base.prep.external_config_pins(REPO) != build['external_cargo_config_pins']:
        raise ValueError('reviewed Cargo configuration changed')
    base.checked(build['argv'][0], build['builder_sha256'], 128 * 1024 * 1024)
    elf = base.checked(original['elf'], original['elf_sha256'], 4 * 1024 * 1024)
    base.prep.compare_elf_payload(elf, elf, original['elf_sha256'])
    base.checked(original['validator'], original['validator_sha256'], 128 * 1024 * 1024)
    base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
    context_raw = base.checked(config['context'], config['context_sha256'], 8192)
    context = base.decode_json(context_raw)
    if (context.get('schema') != 'part5-v3-campaign-context-v1'
            or encoded(derive(Path(config['cohort_root']),
                              context['initial_allocations']['cohort_receipt_sha256'],
                              context['initial_allocations']['membership_sha256'])) != context_raw):
        raise ValueError('admitted signed campaign cohort required')
    if (staged.get('schema') != 'part5-v3-campaign-stage-v1'
            or staged.get('passed') is not True
            or staged.get('registry_history_authenticated') is not True
            or staged.get('allocation_history_authenticated') is not True
            or staged.get('application_effect') is not False
            or staged.get('proof_created') is not False
            or staged.get('program') != original['program']
            or staged.get('genesis') != config['expected_genesis']
            or staged.get('plan_sha256') != config['stage_plan_sha256']
            or bytes(plan['root']).hex() != context['root_sequence'][0]
            or not isinstance(staged.get('account_sha256'), list)
            or len(staged['account_sha256']) != 5):
        raise ValueError('exact R0 campaign account report required')
    execute.report_loaded(staged, original)
    clone = pinned(config['clone_report'], config['clone_report_sha256'])
    ledger = execute.private_directory(config['ledger'])
    if (clone.get('schema') != 'part5-v3-campaign-r0-ledger-clone-v1'
            or clone.get('copy_identical') is not True
            or clone.get('stage_report_sha256') != config['stage_report_sha256']
            or clone.get('source') != stage_config['ledger']
            or clone.get('destination') != str(ledger)
            or Path(config['clone_report']).parent != ledger.parent):
        raise ValueError('byte-identical stopped R0 clone required')
    rows = ledgers.inventory(ledger)
    tree_sha = hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()
    if tree_sha != clone['tree_sha256']:
        raise ValueError('R0 clone changed before campaign transition')
    sizes = []
    for name, expected in zip(execute.ACCOUNT_NAMES, staged['account_sha256']):
        raw, digest = stage.snapshot_generated(Path(config['stage_root']) / (name + '.bin'), 4096)
        if not raw or digest != expected:
            raise ValueError('R0 account artifact changed')
        sizes.append(len(raw))
    output = base.fresh_child(config['transition_output'], REPO / 'artifacts/dynark/part5')
    control = base.fresh_child(config['control_output'], REPO / 'artifacts/dynark/part5')
    stage.validate_stage_paths(output, control, REPO / 'artifacts/dynark/part5')
    return original, status, staged, plan, context, elf, sizes, output, control


def run(config, config_sha256):
    started = time.monotonic()
    if os.environ.get('P5_V3_CAMPAIGN_TRANSITION_SUPERVISOR') != 'reviewed-r0-campaign-clone':
        raise ValueError('explicit external bounded campaign supervisor required')
    original, prior, staged, plan, context, elf, sizes, output, control = admit(config)
    validator = runner = None; logs = []; handlers = {}
    previous_umask = os.umask(0o077)
    result = {'schema': 1, 'scope': 'part5-v3-campaign-transition',
              'status': 'failed', 'transition_verified': False,
              'target_count': config['target_count'],
              'application_effect': False, 'ledger_reuse_requires_review': True,
              'config_sha256': config_sha256, 'training_only': True, 'devnet': False,
              'outer_limits_required': LIMITS,
              'whole_tree_cleanup_authority': 'external bounded_runner'}
    def interrupted(signum, frame):
        raise InterruptedError('campaign transition supervisor interrupted')
    try:
        control.mkdir(mode=0o700); output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        base.ports_free()
        argv = stage.resume_argv(original['validator'], config['ledger'])
        base.write_new(control / 'invocation.json', {'validator_argv': argv,
            'runner': config['runner'], 'runner_sha256': config['runner_sha256'],
            'stage_report_sha256': config['stage_report_sha256'],
            'context_sha256': config['context_sha256'],
            'target_count': config['target_count'], 'outer_limits_required': LIMITS})
        for name in ('validator.stdout.log', 'validator.stderr.log',
                     'runner.stdout.log', 'runner.stderr.log'):
            fd = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            logs.append(os.fdopen(fd, 'wb'))
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        validator = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                     stdout=logs[0], stderr=logs[1], start_new_session=False)
        rpc = base.LocalRpc()
        loaded = execute.wait_loaded_after_start(rpc, validator,
                                                  original['program'], elf, original['elf_sha256'])
        execute.same_loaded(prior['loaded_program'], loaded)
        pre_slot, before = execute.wait_staged_finality(rpc, staged,
            original['program'], staged['account_sha256'], sizes)
        env.update({'P5_V3_CAMPAIGN_TRANSITION_SCOPE': 'part5-v3-campaign-transition',
                    'P5_V3_CAMPAIGN_COUNT': str(config['target_count']),
                    'P5_V3_STAGE_ROOT': config['stage_root'],
                    'P5_V3_STAGE_REPORT_SHA256': config['stage_report_sha256'],
                    'P5_V3_STAGE_PLAN_SHA256': config['stage_plan_sha256'],
                    'P5_V3_CONTEXT': config['context'],
                    'P5_V3_CONTEXT_SHA256': config['context_sha256'],
                    'P5_QUEUE_RPC': base.RPC.rstrip('/'),
                    'P5_QUEUE_PROGRAM': original['program'],
                    'P5_QUEUE_GENESIS': loaded['genesis'],
                    'P5_QUEUE_ELF': original['elf'],
                    'P5_QUEUE_ELF_SHA256': original['elf_sha256'],
                    'P5_QUEUE_OUTPUT': str(output)})
        runner_argv = [config['runner'], 'root_pinned_queue_v3_campaign_transition',
                       '--exact', '--ignored', '--test-threads=1']
        runner = subprocess.Popen(runner_argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                  stdout=logs[2], stderr=logs[3], start_new_session=False)
        deadline = runner_deadline(started)
        while runner.poll() is None:
            if validator.poll() is not None:
                raise RuntimeError('validator exited during campaign transition')
            if time.monotonic() >= deadline:
                raise TimeoutError('campaign transition deadline')
            time.sleep(0.1)
        if runner.wait() != 0:
            raise RuntimeError('campaign transition runner rejected')
        report_raw, report_sha = stage.snapshot_generated(output / 'transition-report.json', 65536)
        report = base.decode_json(report_raw)
        count = config['target_count']
        if (report.get('schema') != 'part5-v3-campaign-transition-v1'
                or report.get('passed') is not True
                or report.get('target_count') != count
                or report.get('registry_history_authenticated') is not True
                or report.get('allocation_history_authenticated') is not True
                or report.get('request_unconsumed') is not True
                or report.get('application_effect') is not False
                or report.get('stage_report_sha256') != config['stage_report_sha256']
                or report.get('stage_plan_sha256') != config['stage_plan_sha256']
                or report.get('context_sha256') != config['context_sha256']
                or report.get('program') != original['program']
                or report.get('genesis') != config['expected_genesis']
                or report.get('base_root') != context['root_sequence'][0]
                or report.get('current_root') != context['root_sequence'][count]
                or report.get('root_sequence_sha256')
                   != context['initial_allocations']['root_sequence_sha256']
                or not isinstance(report.get('checkpoints'), list)
                or len(report['checkpoints']) != count
                or not isinstance(report.get('transactions'), list)
                or len(report['transactions']) != 3 * count
                or any(row.get('err') is not None for row in report['transactions'])
                or not isinstance(report.get('account_sha256'), list)
                or len(report['account_sha256']) != 5):
            raise ValueError('exact signed campaign transition report required')
        execute.report_loaded(report, original)
        history_raw, history_sha = stage.snapshot_generated(output / 'signed-history.json', 1024 * 1024)
        if history_sha != report['signed_history_sha256']:
            raise ValueError('signed campaign history artifact changed')
        history = base.decode_json(history_raw)
        commitments = checked_history(history, context, plan, report, staged)
        post_slot, after = execute.finalized_accounts(rpc, staged,
            max(pre_slot, report['finalized_slot']), original['program'],
            report['account_sha256'], sizes)
        expected_config = bytearray(before[0])
        expected_config[332:364] = bytes.fromhex(context['root_sequence'][count])
        expected_config[364:372] = count.to_bytes(8, 'big')
        if (after[0] != expected_config or after[3] != before[3]
                or after[4] != before[4]):
            raise ValueError('campaign changed request/queue or wrong finalized root')
        check_finalized_chain(before, after, plan, context, history, commitments)
        for name, data in zip(execute.ACCOUNT_NAMES, after):
            artifact, _ = stage.snapshot_generated(output / (name + '.bin'), 4096)
            if artifact != data:
                raise ValueError('campaign artifact differs from finalized account')
        latest = base.wait_loaded(rpc, validator, original['program'], elf, original['elf_sha256'])
        execute.same_loaded(loaded, latest)
        result.update({'transition_verified': True, 'finalized_slot': post_slot,
                       'transition_report_sha256': report_sha,
                       'loaded_program': latest, 'transition_output': str(output)})
    except Exception as error:
        result['error_type'] = type(error).__name__
        result['error_message'] = str(error)[:256]
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        for name, proc in (('runner', runner), ('validator', validator)):
            try:
                result[name + '_cleanup'] = base.cleanup(proc)
            except Exception as error:
                result[name + '_cleanup'] = {'reaped': False, 'graceful': False,
                                             'error_type': type(error).__name__}
        if (result['transition_verified'] and result['validator_cleanup'].get('graceful') is True
                and result['validator_cleanup'].get('reaped') is True
                and result['validator_cleanup'].get('exit_code') == 0
                and result['runner_cleanup'].get('exit_code') == 0):
            result['status'] = 'passed'
            result['ledger_reuse_requires_review'] = False
        result['elapsed_seconds'] = time.monotonic() - started
        for stream in logs:
            stream.close()
        try:
            if control.is_dir():
                base.write_new(control / 'status.json', result)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            os.umask(previous_umask)
    print(json.dumps({'status': result['status'],
                      'transition_verified': result['transition_verified'],
                      'report': str(control / 'status.json')}))
    return 0 if result['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    config = pinned(args.config, args.config_sha256)
    return run(config, args.config_sha256)


if __name__ == '__main__':
    sys.exit(main())
