#!/usr/bin/env python3
"""Supervise one signed unrelated-root transition on an unconsumed v3 request.

The external bounded runner owns whole-tree limits. Source-signature and
finalized-account evidence are separate from graceful ledger shutdown.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location('v3_execute', Path(__file__).with_name('queue_v3_local_execute.py'))
execute = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(execute)
base, stage = execute.base, execute.stage
REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
LIMITS = execute.LIMITS


def check_cohort(config, context):
    from tools.part5.credential_profile import admit_certificate, public_bindings
    from tools.part5.registry_v3_vectors import rebuild, siblings
    root = execute.private_directory(config['cohort_root'])
    receipt_raw, receipt_sha = stage.snapshot_generated(root / 'cohort-receipt.json', 8192)
    if receipt_sha != context['cohort_receipt_sha256']:
        raise ValueError('signed cohort receipt pin mismatch')
    receipt = base.decode_json(receipt_raw)
    if (receipt.get('schema') != 'v3-two-signed-training-credentials-v1'
            or receipt.get('training_only') is not True
            or receipt.get('registry_history_authenticated') is not False):
        raise ValueError('training cohort boundary required')
    own, own_sha = stage.snapshot_generated(root / 'credential.der', 952)
    other, other_sha = stage.snapshot_generated(root / 'unrelated.der', 952)
    modulus_bytes, _ = stage.snapshot_generated(root / 'issuer-modulus.bin', 256)
    member_raw, member_sha = stage.snapshot_generated(root / 'membership.json', 16384)
    if (len(own) != 952 or len(other) != 952 or len(modulus_bytes) != 256
            or own_sha != receipt['credential_sha256']
            or other_sha != receipt['unrelated_credential_sha256']
            or member_sha != receipt['membership_sha256']
            or member_sha != context['membership_sha256']):
        raise ValueError('exact signed pair and membership required')
    member = base.decode_json(member_raw)
    modulus = int.from_bytes(modulus_bytes, 'big')
    parsed = admit_certificate(own, modulus)
    other_parsed = admit_certificate(other, modulus)
    issuer, policy = public_bindings(parsed, modulus)
    other_issuer, _ = public_bindings(other_parsed, modulus)
    own_digest = hashlib.sha256(parsed['tbs']).digest()
    other_digest = hashlib.sha256(other_parsed['tbs']).digest()
    slot, other_slot = member['slot'], member['unrelated_slot']
    if (issuer != other_issuer or parsed['aki'] != other_parsed['aki']
            or member['issuer_hash'] != issuer or member['policy_hash'] != policy
            or type(slot) is not int or not 0 <= slot < 1024
            or other_slot != (slot ^ 1)
            or member['own_tbs_digest'] != own_digest.hex()
            or member['unrelated_tbs_digest'] != other_digest.hex()
            or context['own_tbs_digest'] != own_digest.hex()
            or context['unrelated_tbs_digest'] != other_digest.hex()
            or context['slot'] != slot or context['unrelated_slot'] != other_slot):
        raise ValueError('two distinct signed allocated leaves required')
    for name, active in (('active', True), ('unrelated', False)):
        tree = rebuild([(slot, own_digest, True), (other_slot, other_digest, active)])
        expected_path = [int(word, 16) for word in siblings(tree, slot)]
        if (tree[-1][0] != member[name + '_root']
                or expected_path != member[name + '_siblings']
                or context['base_root' if name == 'active' else 'near_root']
                   != tree[-1][0].to_bytes(32, 'big').hex()):
            raise ValueError('independently rebuilt revocation root/path mismatch')
    if sum(a != b for a, b in zip(member['active_siblings'], member['unrelated_siblings'])) != 1:
        raise ValueError('one sibling change required')
    return receipt_sha, member_sha


def check_signed_source(output, plan, report):
    signed_raw, _ = stage.snapshot_generated(output / 'signed-source.json', 65536)
    enrolled_raw, _ = stage.snapshot_generated(output / 'enrolled-source.json', 65536)
    signed, enrolled = base.decode_json(signed_raw), base.decode_json(enrolled_raw)
    observation = signed['observation']
    signature = bytes(signed['signature'])
    source_key = bytes(plan['source'])
    if (len(signature) != 64 or bytes(enrolled['issuer']['source_key']) != source_key
            or bytes(observation['issuer']['source_key']) != source_key
            or observation['changes'] != [{'Revoke': {
                'tbs_digest': list(bytes.fromhex(report['unrelated_tbs_digest']))}}]):
        raise ValueError('exact source-signed unrelated revocation required')
    message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
        observation, separators=(',', ':'), ensure_ascii=False).encode()
    Ed25519PublicKey.from_public_bytes(source_key).verify(signature, message)
    wire = b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
        signed, separators=(',', ':'), ensure_ascii=False).encode()
    if hashlib.sha256(wire).hexdigest() != report['source_head_digest']:
        raise ValueError('source commitment digest differs from signed wire')


def admit(config):
    if (config.get('schema') != 1 or config.get('scope') != 'part5-v3-local-unrelated-transition'
            or config.get('outer_limits_required') != LIMITS):
        raise ValueError('explicit bounded transition contract required')
    prior_config = execute.pinned_json(config['prior_stage_config'], config['prior_stage_config_sha256'])
    prior = execute.pinned_json(config['prior_stage_status'], config['prior_stage_status_sha256'])
    monitor = execute.pinned_json(config['prior_stage_monitor'], config['prior_stage_monitor_sha256'])
    execute.review_stage(prior, monitor, config)
    original = execute.pinned_json(prior_config['prior_config'], prior_config['prior_config_sha256'])
    build = execute.pinned_json(original['build_plan'], original['build_plan_sha256'])
    base.prep.check_manifest(REPO, build['source_manifest'])
    if base.prep.external_config_pins(REPO) != build['external_cargo_config_pins']:
        raise ValueError('reviewed Cargo configuration changed')
    base.checked(build['argv'][0], build['builder_sha256'], 128 * 1024 * 1024)
    elf = base.checked(original['elf'], original['elf_sha256'], 4 * 1024 * 1024)
    base.prep.compare_elf_payload(elf, elf, original['elf_sha256'])
    base.checked(original['validator'], original['validator_sha256'], 128 * 1024 * 1024)
    base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
    context_raw = base.checked(config['transition_context'], config['transition_context_sha256'], 8192)
    context = base.decode_json(context_raw)
    if (context.get('schema') != 'part5-v3-unrelated-training-transition-v1'
            or context.get('training_only') is not True
            or context.get('stage_report_sha256') != config['stage_report_sha256']):
        raise ValueError('exact transition context required')
    check_cohort(config, context)
    root = execute.private_directory(config['stage_root'])
    if str(root) != prior_config['stage_output']:
        raise ValueError('original staged request required')
    raw, digest = stage.snapshot_generated(root / 'stage-report.json', 65536)
    if digest != config['stage_report_sha256']:
        raise ValueError('stage report changed')
    staged = base.decode_json(raw)
    raw, digest = stage.snapshot_generated(root / 'plan.json', 8192)
    if digest != config['stage_plan_sha256']:
        raise ValueError('stage plan changed')
    plan = base.decode_json(raw)
    execute.check_stage_report(staged, plan, config, original)
    execute.report_loaded(staged, original)
    if bytes(plan['root']).hex() != context['base_root']:
        raise ValueError('finalized base root differs from signed leaves')
    sizes = []
    for name, expected in zip(execute.ACCOUNT_NAMES, staged['account_sha256']):
        data, digest = stage.snapshot_generated(root / (name + '.bin'), 4096)
        if not data or digest != expected:
            raise ValueError('staged account artifact changed')
        sizes.append(len(data))
    ledger = execute.private_directory(config['ledger'])
    if str(ledger) != prior_config['ledger'] or ledger != Path(original['runtime_output']) / 'ledger':
        raise ValueError('original persistent ledger required')
    stage.snapshot_generated(ledger / 'genesis.bin', 16 * 1024 * 1024)
    output = base.fresh_child(config['transition_output'], REPO / 'artifacts/dynark/part5')
    control = base.fresh_child(config['control_output'], REPO / 'artifacts/dynark/part5')
    stage.validate_stage_paths(output, control, REPO / 'artifacts/dynark/part5')
    return original, prior, staged, plan, context, elf, sizes, output, control


def run(config, config_sha256):
    if os.environ.get('P5_V3_TRANSITION_SUPERVISOR') != 'local-ledger-review-and-transition':
        raise ValueError('explicit external bounded transition scope required')
    original, prior, staged, plan, context, elf, sizes, output, control = admit(config)
    started = time.monotonic(); validator = runner = None; logs = []; handlers = {}
    old_umask = os.umask(0o077)
    status = {'schema': 1, 'scope': 'part5-v3-local-unrelated-transition',
              'status': 'failed', 'transition_verified': False,
              'application_effect': False, 'ledger_reuse_requires_review': True,
              'config_sha256': config_sha256, 'training_only': True, 'devnet': False,
              'outer_limits_required': LIMITS, 'whole_tree_cleanup_authority': 'external bounded_runner'}
    def interrupted(signum, frame):
        raise InterruptedError('transition supervisor interrupted')
    try:
        control.mkdir(mode=0o700); output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        base.ports_free(timeout_seconds=base.PORT_WAIT_SECONDS)
        argv = stage.resume_argv(original['validator'], config['ledger'])
        base.write_new(control / 'invocation.json', {'validator_argv': argv,
            'runner': config['runner'], 'runner_sha256': config['runner_sha256'],
            'transition_context_sha256': config['transition_context_sha256'],
            'stage_report_sha256': config['stage_report_sha256'],
            'outer_limits_required': LIMITS})
        for name in ('validator.stdout.log', 'validator.stderr.log', 'runner.stdout.log', 'runner.stderr.log'):
            fd = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            logs.append(os.fdopen(fd, 'wb'))
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        validator = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                     stdout=logs[0], stderr=logs[1], start_new_session=False)
        rpc = base.LocalRpc()
        loaded = execute.wait_loaded_after_start(rpc, validator, original['program'], elf, original['elf_sha256'])
        execute.same_loaded(prior['loaded_program'], loaded)
        pre_slot, before = execute.wait_staged_finality(
            rpc, staged, original['program'], staged['account_sha256'], sizes)
        env.update({'P5_V3_TRANSITION_SCOPE': 'part5-v3-unrelated-transition',
                    'P5_V3_STAGE_ROOT': config['stage_root'],
                    'P5_V3_STAGE_REPORT_SHA256': config['stage_report_sha256'],
                    'P5_V3_STAGE_PLAN_SHA256': config['stage_plan_sha256'],
                    'P5_V3_TRANSITION_CONTEXT': config['transition_context'],
                    'P5_V3_TRANSITION_CONTEXT_SHA256': config['transition_context_sha256'],
                    'P5_QUEUE_RPC': base.RPC.rstrip('/'), 'P5_QUEUE_PROGRAM': original['program'],
                    'P5_QUEUE_GENESIS': loaded['genesis'], 'P5_QUEUE_ELF': original['elf'],
                    'P5_QUEUE_ELF_SHA256': original['elf_sha256'], 'P5_QUEUE_OUTPUT': str(output)})
        runner_argv = [config['runner'], 'root_pinned_queue_v3_unrelated_transition',
                       '--exact', '--ignored', '--test-threads=1']
        runner = subprocess.Popen(runner_argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                  stdout=logs[2], stderr=logs[3], start_new_session=False)
        deadline = time.monotonic() + 110
        while runner.poll() is None:
            if validator.poll() is not None:
                raise RuntimeError('validator exited during unrelated transition')
            if time.monotonic() >= deadline:
                raise TimeoutError('transition runner deadline')
            time.sleep(0.1)
        if runner.wait() != 0:
            raise RuntimeError('transition runner rejected; ledger requires reconciliation')
        raw, report_sha = stage.snapshot_generated(output / 'transition-report.json', 65536)
        report = base.decode_json(raw)
        if (report.get('schema') != 'part5-v3-unrelated-local-transition-v1'
                or report.get('passed') is not True or report.get('application_effect') is not False
                or report.get('request_unconsumed') is not True
                or report.get('upstream_source_authentication') is not True
                or report.get('stage_report_sha256') != config['stage_report_sha256']
                or report.get('stage_plan_sha256') != config['stage_plan_sha256']
                or report.get('transition_context_sha256') != config['transition_context_sha256']
                or report.get('program') != original['program']
                or report.get('genesis') != config['expected_genesis']
                or report.get('base_root') != context['base_root']
                or report.get('near_root') != context['near_root']
                or not isinstance(report.get('account_sha256'), list)
                or len(report['account_sha256']) != 5):
            raise ValueError('exact unrelated transition report required')
        execute.report_loaded(report, original)
        report['unrelated_tbs_digest'] = context['unrelated_tbs_digest']
        check_signed_source(output, plan, report)
        post_slot, after = execute.finalized_accounts(rpc, staged,
            max(pre_slot, report['finalized_slot']), original['program'],
            report['account_sha256'], sizes)
        expected_config = bytearray(before[0])
        expected_config[332:364] = bytes.fromhex(context['near_root'])
        expected_config[364:372] = (1).to_bytes(8, 'big')
        if after[0] != expected_config or after[3] != before[3] or after[4] != before[4]:
            raise ValueError('transition changed request/queue or wrong finalized root')
        for name, data in zip(execute.ACCOUNT_NAMES, after):
            artifact, _ = stage.snapshot_generated(output / (name + '.bin'), 4096)
            if artifact != data:
                raise ValueError('transition artifact differs from finalized account')
        latest = base.wait_loaded(rpc, validator, original['program'], elf, original['elf_sha256'])
        execute.same_loaded(loaded, latest)
        status.update({'transition_verified': True, 'finalized_slot': post_slot,
                       'transition_report_sha256': report_sha, 'loaded_program': latest,
                       'transition_output': str(output)})
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
                status[name + '_cleanup'] = {'reaped': False, 'graceful': False,
                                             'error_type': type(error).__name__}
        if (status['transition_verified'] and status['validator_cleanup'].get('graceful') is True
                and status['validator_cleanup'].get('reaped') is True
                and status['validator_cleanup'].get('exit_code') == 0
                and status['runner_cleanup'].get('exit_code') == 0):
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
            os.umask(old_umask)
    print(json.dumps({'status': status['status'], 'transition_verified': status['transition_verified'],
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
