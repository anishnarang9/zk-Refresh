#!/usr/bin/env python3
"""Bound one R1 ledger clone to Anchor effect or the holder's own revocation."""
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

_spec = importlib.util.spec_from_file_location('v3_transition', Path(__file__).with_name('queue_v3_local_transition.py'))
transition = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(transition)
execute, stage, base = transition.execute, transition.stage, transition.base
REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def signed_successor(output, plan, branch, prior_digest, own_digest):
    signed_raw, _ = stage.snapshot_generated(output / 'signed-source.json', 65536)
    enrolled_raw, _ = stage.snapshot_generated(output / 'enrolled-source.json', 65536)
    signed, enrolled = base.decode_json(signed_raw), base.decode_json(enrolled_raw)
    obs = signed['observation']
    source_key = bytes(plan['source'])
    changes = [] if branch == 'anchor' else [{'Revoke': {'tbs_digest': list(bytes.fromhex(own_digest))}}]
    if (bytes(enrolled['issuer']['source_key']) != source_key
            or bytes(obs['issuer']['source_key']) != source_key
            or obs['scope'] != enrolled['scope']
            or obs['issuer'] != enrolled['issuer']
            or obs['sequence'] != 3
            or type(obs['observed_at']) is not int
            or type(obs['valid_until']) is not int
            or not 0 <= obs['valid_until'] - obs['observed_at'] <= 180
            or obs['changes'] != changes
            or bytes(obs['previous_digest']).hex() != prior_digest):
        raise ValueError('exact signed branch successor required')
    signature = bytes(signed['signature'])
    if len(signature) != 64:
        raise ValueError('Ed25519 source signature length')
    message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
        obs, separators=(',', ':'), ensure_ascii=False).encode()
    Ed25519PublicKey.from_public_bytes(source_key).verify(signature, message)
    wire = b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
        signed, separators=(',', ':'), ensure_ascii=False).encode()
    return hashlib.sha256(wire).hexdigest()


def admit(config):
    if (config.get('schema') != 1 or config.get('scope') != 'part5-v3-r1-branch'
            or config.get('mode') not in ('anchor', 'own-revocation')
            or config.get('outer_limits_required') != execute.LIMITS):
        raise ValueError('explicit bounded R1 branch contract required')
    stage_config = execute.pinned_json(config['prior_stage_config'], config['prior_stage_config_sha256'])
    prior = execute.pinned_json(config['prior_stage_status'], config['prior_stage_status_sha256'])
    monitor = execute.pinned_json(config['prior_stage_monitor'], config['prior_stage_monitor_sha256'])
    execute.review_stage(prior, monitor, config)
    original = execute.pinned_json(stage_config['prior_config'], stage_config['prior_config_sha256'])
    build = execute.pinned_json(original['build_plan'], original['build_plan_sha256'])
    base.prep.check_manifest(REPO, build['source_manifest'])
    if base.prep.external_config_pins(REPO) != build['external_cargo_config_pins']:
        raise ValueError('build Cargo configuration changed')
    base.checked(build['argv'][0], build['builder_sha256'], 128 * 1024 * 1024)
    elf = base.checked(original['elf'], original['elf_sha256'], 4 * 1024 * 1024)
    base.prep.compare_elf_payload(elf, elf, original['elf_sha256'])
    base.checked(original['validator'], original['validator_sha256'], 128 * 1024 * 1024)
    base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
    stage_root = execute.private_directory(config['stage_root'])
    transition_root = execute.private_directory(config['transition_root'])
    staged = execute.pinned_json(stage_root / 'stage-report.json', config['stage_report_sha256'])
    raw, digest = stage.snapshot_generated(stage_root / 'plan.json', 8192)
    if digest != config['stage_plan_sha256']:
        raise ValueError('stage plan pin')
    plan = base.decode_json(raw)
    execute.check_stage_report(staged, plan, config, original)
    execute.report_loaded(staged, original)
    changed = execute.pinned_json(transition_root / 'transition-report.json', config['transition_report_sha256'])
    if (changed.get('schema') != 'part5-v3-unrelated-local-transition-v1'
            or changed.get('passed') is not True or changed.get('request_unconsumed') is not True
            or changed.get('upstream_source_authentication') is not True
            or changed.get('stage_report_sha256') != config['stage_report_sha256']
            or changed.get('stage_plan_sha256') != config['stage_plan_sha256']
            or changed.get('program') != original['program']
            or changed.get('genesis') != config['expected_genesis']):
        raise ValueError('exact signed unrelated R1 transition required')
    execute.report_loaded(changed, original)
    context_raw = base.checked(config['transition_context'], config['transition_context_sha256'], 8192)
    context = base.decode_json(context_raw)
    if (context.get('schema') != 'part5-v3-unrelated-training-transition-v1'
            or context.get('stage_report_sha256') != config['stage_report_sha256']
            or context.get('base_root') != changed['base_root']
            or context.get('near_root') != changed['near_root']):
        raise ValueError('exact R0/R1 signed-leaf context required')
    transition.check_cohort(config, context)
    signed_r1 = dict(changed)
    signed_r1['unrelated_tbs_digest'] = context['unrelated_tbs_digest']
    transition.check_signed_source(transition_root, plan, signed_r1)
    status = execute.pinned_json(config['transition_status'], config['transition_status_sha256'])
    prior_monitor = execute.pinned_json(config['transition_monitor'], config['transition_monitor_sha256'])
    if (status.get('transition_verified') is not True
            or status.get('transition_report_sha256') != config['transition_report_sha256']
            or status.get('validator_cleanup', {}).get('exit_code') != -signal.SIGINT
            or prior_monitor.get('stop_reason') is not None
            or prior_monitor.get('cleanup_remaining_owned_processes') != 0):
        raise ValueError('reviewed R1 stop and cleanup required')
    clone = execute.pinned_json(config['clone_report'], config['clone_report_sha256'])
    ledger = execute.private_directory(config['ledger'])
    if (clone.get('schema') != 'part5-v3-r1-ledger-clone-v1'
            or clone.get('copy_identical') is not True
            or clone.get('transition_report_sha256') != config['transition_report_sha256']
            or clone.get('transition_status_sha256') != config['transition_status_sha256']
            or clone.get('transition_monitor_sha256') != config['transition_monitor_sha256']
            or clone.get('destination') != str(ledger)
            or clone.get('source') != stage_config['ledger']):
        raise ValueError('pinned stopped R1 ledger clone required')
    from harness.tests.queue_v3_clone_ledger import inventory
    copied = json.dumps(inventory(ledger), separators=(',', ':')).encode()
    if hashlib.sha256(copied).hexdigest() != clone['tree_sha256']:
        raise ValueError('R1 ledger clone changed before restart')
    base.checked(config['context'], config['context_sha256'], 8192)
    for role in ('full', 'anchor'):
        path = Path(config[role + '_wire'])
        execute.private_directory(path.parent)
        base.checked(path, config[role + '_wire_sha256'], 448)
    sizes = []
    for name, digest in zip(execute.ACCOUNT_NAMES, changed['account_sha256']):
        data, actual = stage.snapshot_generated(transition_root / (name + '.bin'), 4096)
        if actual != digest:
            raise ValueError('saved R1 account changed')
        sizes.append(len(data))
    output = base.fresh_child(config['branch_output'], REPO / 'artifacts/dynark/part5')
    control = base.fresh_child(config['control_output'], REPO / 'artifacts/dynark/part5')
    stage.validate_stage_paths(output, control, REPO / 'artifacts/dynark/part5')
    return original, staged, plan, changed, status, context, elf, sizes, ledger, output, control


def run(config, config_sha256):
    if os.environ.get('P5_V3_BRANCH_SUPERVISOR') != 'reviewed-r1-clone':
        raise ValueError('explicit external bounded R1 branch scope required')
    original, staged, plan, changed, transition_status, context, elf, sizes, ledger, output, control = admit(config)
    started = time.monotonic(); validator = runner = None; logs = []; handlers = {}
    old_umask = os.umask(0o077)
    result = {'schema': 1, 'scope': 'part5-v3-r1-branch', 'mode': config['mode'],
              'status': 'failed', 'branch_verified': False,
              'application_effect': None, 'ledger_reuse_requires_review': True,
              'config_sha256': config_sha256, 'training_only': True, 'devnet': False,
              'outer_limits_required': execute.LIMITS,
              'whole_tree_cleanup_authority': 'external bounded_runner'}
    def interrupted(signum, frame):
        raise InterruptedError('R1 branch supervisor interrupted')
    try:
        control.mkdir(mode=0o700); output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        base.ports_free()
        argv = stage.resume_argv(original['validator'], str(ledger))
        base.write_new(control / 'invocation.json', {'validator_argv': argv,
            'runner': config['runner'], 'runner_sha256': config['runner_sha256'],
            'transition_report_sha256': config['transition_report_sha256'],
            'full_wire_sha256': config['full_wire_sha256'],
            'anchor_wire_sha256': config['anchor_wire_sha256'],
            'outer_limits_required': execute.LIMITS})
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
        execute.same_loaded(transition_status['loaded_program'], loaded)
        prior_slot, before = execute.wait_staged_finality(
            rpc, staged, original['program'], changed['account_sha256'], sizes)
        env.update({'P5_V3_BRANCH_MODE': config['mode'],
                    'P5_V3_STAGE_ROOT': config['stage_root'],
                    'P5_V3_STAGE_REPORT_SHA256': config['stage_report_sha256'],
                    'P5_V3_STAGE_PLAN_SHA256': config['stage_plan_sha256'],
                    'P5_V3_TRANSITION_ROOT': config['transition_root'],
                    'P5_V3_TRANSITION_REPORT_SHA256': config['transition_report_sha256'],
                    'P5_V3_TRANSITION_CONTEXT': config['transition_context'],
                    'P5_V3_TRANSITION_CONTEXT_SHA256': config['transition_context_sha256'],
                    'P5_V3_CONTEXT': config['context'], 'P5_V3_CONTEXT_SHA256': config['context_sha256'],
                    'P5_V3_FULL_WIRE': config['full_wire'],
                    'P5_V3_FULL_WIRE_SHA256': config['full_wire_sha256'],
                    'P5_V3_ANCHOR_WIRE': config['anchor_wire'],
                    'P5_V3_ANCHOR_WIRE_SHA256': config['anchor_wire_sha256'],
                    'P5_QUEUE_RPC': base.RPC.rstrip('/'), 'P5_QUEUE_PROGRAM': original['program'],
                    'P5_QUEUE_GENESIS': loaded['genesis'], 'P5_QUEUE_ELF': original['elf'],
                    'P5_QUEUE_ELF_SHA256': original['elf_sha256'], 'P5_QUEUE_OUTPUT': str(output)})
        runner_argv = [config['runner'], 'root_pinned_queue_v3_branch',
                       '--exact', '--ignored', '--test-threads=1']
        runner = subprocess.Popen(runner_argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                  stdout=logs[2], stderr=logs[3], start_new_session=False)
        deadline = time.monotonic() + 110
        while runner.poll() is None:
            if validator.poll() is not None:
                raise RuntimeError('validator exited during R1 branch')
            if time.monotonic() >= deadline:
                raise TimeoutError('R1 branch runner deadline')
            time.sleep(0.1)
        if runner.wait() != 0:
            raise RuntimeError('R1 branch runner rejected; ledger needs reconciliation')
        raw, report_sha = stage.snapshot_generated(output / 'branch-report.json', 65536)
        report = base.decode_json(raw)
        effect = config['mode'] == 'anchor'
        if (report.get('schema') != 'part5-v3-r1-branch-v1'
                or report.get('passed') is not True or report.get('mode') != config['mode']
                or report.get('application_effect') is not effect
                or report.get('effect_count') != int(effect)
                or report.get('request_consumed') is not effect
                or report.get('transition_report_sha256') != config['transition_report_sha256']
                or report.get('stage_report_sha256') != config['stage_report_sha256']
                or report.get('stage_plan_sha256') != config['stage_plan_sha256']
                or report.get('program') != original['program']
                or report.get('genesis') != config['expected_genesis']
                or report.get('base_root') != context['base_root']
                or report.get('near_root') != context['near_root']
                or type(report.get('finalized_slot')) is not int
                or report['finalized_slot'] <= changed['finalized_slot']
                or not isinstance(report.get('account_sha256'), list)
                or len(report['account_sha256']) != 5):
            raise ValueError('exact R1 branch report required')
        expected_transactions = ([
            ('v3-observe-signed-current-status', None),
            ('v3-bind-current-branch-head', None),
            ('v3-stale-R0-full', 713),
            ('v3-anchor-wrong-action', 712),
            ('v3-anchor-invalid-proof', 714),
            ('v3-valid-anchor-R1', None),
            ('v3-anchor-replay', 707),
        ] if effect else [
            ('v3-publish-own-revocation', None),
            ('v3-observe-signed-own-revocation', None),
            ('v3-bind-current-branch-head', None),
            ('v3-stale-R0-full', 713),
            ('v3-own-revoked-R1-anchor', 713),
        ])
        transactions = report.get('transactions')
        if (not isinstance(transactions, list)
                or len(transactions) != len(expected_transactions)
                or any(tx.get('scenario') != name or tx.get('customError') != code
                       or (tx.get('err') is None) != (code is None)
                       for tx, (name, code) in zip(transactions, expected_transactions))):
            raise ValueError('exact branch transaction outcomes required')
        execute.report_loaded(report, original)
        source_digest = signed_successor(output, plan, config['mode'],
                                         changed['source_head_digest'], context['own_tbs_digest'])
        if report['source_head_digest'] != source_digest:
            raise ValueError('signed branch source digest mismatch')
        if effect:
            if report['current_root'] != context['near_root']:
                raise ValueError('Anchor current root must be R1')
        else:
            from tools.part5.registry_v3_vectors import rebuild, siblings, leaf, h
            own = bytes.fromhex(context['own_tbs_digest'])
            other = bytes.fromhex(context['unrelated_tbs_digest'])
            tree = rebuild([(context['slot'], own, False), (context['unrelated_slot'], other, False)])
            member_raw, member_sha = stage.snapshot_generated(
                Path(config['cohort_root']) / 'membership.json', 16384)
            member = base.decode_json(member_raw)
            if (member_sha != context['membership_sha256']
                    or member['own_revoked_root'] != tree[-1][0]
                    or member['own_revoked_siblings'] != [int(s, 16) for s in siblings(tree, context['slot'])]
                    or report['current_root'] != tree[-1][0].to_bytes(32, 'big').hex()):
                raise ValueError('own-revoked R2 root mismatch')
            active_candidate = leaf(own, context['slot'], True)
            for level, sibling in enumerate(siblings(tree, context['slot'])):
                neighbor = int(sibling, 16)
                active_candidate = h((neighbor, active_candidate)) if (context['slot'] >> level) & 1 else h((active_candidate, neighbor))
            if active_candidate == tree[-1][0]:
                raise ValueError('revoked holder retains active membership')
        post_slot, after = execute.finalized_accounts(rpc, staged,
            max(prior_slot, report['finalized_slot']), original['program'],
            report['account_sha256'], sizes)
        if effect:
            execute.check_effect_bytes(before, after, staged)
        else:
            expected = bytearray(before[0])
            expected[332:364] = bytes.fromhex(report['current_root'])
            expected[364:372] = (2).to_bytes(8, 'big')
            if after[0] != expected or after[3] != before[3] or after[4] != before[4]:
                raise ValueError('own revocation changed request/queue or wrong root')
        for name, data in zip(execute.ACCOUNT_NAMES, after):
            artifact, _ = stage.snapshot_generated(output / (name + '.bin'), 4096)
            if artifact != data:
                raise ValueError('branch artifact differs from finalized account')
        latest = base.wait_loaded(rpc, validator, original['program'], elf, original['elf_sha256'])
        execute.same_loaded(loaded, latest)
        result.update({'branch_verified': True, 'application_effect': effect,
                       'effect_count': int(effect), 'finalized_slot': post_slot,
                       'branch_report_sha256': report_sha, 'loaded_program': latest,
                       'branch_output': str(output)})
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
        if (result['branch_verified'] and result['validator_cleanup'].get('graceful') is True
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
            os.umask(old_umask)
    print(json.dumps({'status': result['status'], 'branch_verified': result['branch_verified'],
                      'report': str(control / 'status.json')}))
    return 0 if result['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    config = base.decode_json(base.checked(args.config, args.config_sha256, 65536))
    return run(config, args.config_sha256)


if __name__ == '__main__':
    sys.exit(main())
