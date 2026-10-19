#!/usr/bin/env python3
"""Directly time a matched heldout Full-B / Anchor-B loaded application pair.

Each arm is a fresh B-only run from the pinned case manifest and is wrapped by
the existing complete-session supervisor. The case runner and all frozen inputs
remain unchanged. This command performs real heldout work when invoked; tests
must use only the pure validation helpers below.
"""
import argparse
import fcntl
import hashlib
import hmac
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ARTIFACTS = ROOT / 'artifacts/dynark/part5'
RESULTS = ROOT / 'results/dynark/part5'
HEAVY_LOCK = ARTIFACTS / '.v3-heldout-heavy.lock'
ARM_SCHEMA = 'credential-v3-heldout-direct-arm-v1'
PAIR_SCHEMA = 'credential-v3-heldout-direct-pair-v1'
WORKER_TICKET_SCHEMA = 'credential-v3-heldout-worker-ticket-v1'
WORKER_TICKET_NAME = 'worker-launch.json'
WORKER_CLAIM_NAME = 'worker-claim.json'
LOCK_OWNER_SCHEMA = 'credential-v3-heldout-heavy-lock-owner-v1'
OUTER_LIMITS = {
    'full': {'runtime_seconds': 6000, 'rss_bytes': 4294967296,
             'storage_bytes': 2147483648},
    'anchor': {'runtime_seconds': 8000, 'rss_bytes': 4294967296,
               'storage_bytes': 2147483648},
}
HEX = frozenset('0123456789abcdef')


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _hash(value):
    return (type(value) is str and len(value) == 64
            and all(character in HEX for character in value))


def _write_new(path, value):
    path = Path(path)
    if path.exists() or path.is_symlink() or path.parent.resolve(strict=True) != path.parent:
        raise ValueError('fresh canonical report path required')
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return _digest(raw)


def _write_pair_report(path, report):
    path = Path(path)
    report_sha256 = _write_new(path, report)
    _write_new(Path(str(path) + '.sha256.json'), {
        'schema': 'credential-v3-heldout-direct-pair-hash-v1',
        'report_file': path.name,
        'report_sha256': report_sha256,
    })
    return report_sha256


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError('required local runner could not be loaded')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def arm_order(variant):
    if type(variant) is not int or not 0 <= variant < 8:
        raise ValueError('heldout variant must be in 0..7')
    return ('full', 'anchor') if variant % 2 == 0 else ('anchor', 'full')


def _outer_seconds(report):
    if (type(report) is not dict or report.get('schema') != 1
            or report.get('measurement') != 'bounded_complete_session'
            or report.get('passed') is not True or report.get('exit_code') != 0
            or report.get('censored') is not False or report.get('stop_reason') is not None
            or report.get('runner_error_type') is not None):
        raise ValueError('outer direct-session report failed or was censored')
    if (report.get('cleanup_remaining_owned_processes') != 0
            or report.get('cleanup_status_unknown') is not False):
        raise ValueError('outer direct-session cleanup is incomplete or unknown')
    duration = report.get('duration_seconds')
    if (type(duration) not in (int, float)
            or not math.isfinite(duration) or duration <= 0):
        raise ValueError('positive outer direct-session duration required')
    if type(report.get('sample_count')) is not int or report['sample_count'] < 1:
        raise ValueError('outer direct-session samples required')
    return float(duration)


def _arm_identity(arm, mode, variant):
    if (type(arm) is not dict or arm.get('schema') != ARM_SCHEMA
            or type(arm.get('variant')) is not int or arm.get('variant') != variant
            or arm.get('mode') != mode
            or arm.get('status') != 'passed' or not _hash(arm.get('run_manifest_sha256'))):
        raise ValueError('completed B-arm evidence is malformed')
    identity = arm.get('identity')
    fields = {'credential_sha256', 'finalized_request_sha256',
              'finalized_action_transport_sha256', 'action_hash', 'roots',
              'setup_sha256', 'vk_sha256', 'elf_sha256'}
    if type(identity) is not dict or set(identity) != fields:
        raise ValueError('B-arm identity fields are incomplete')
    for field in fields - {'roots'}:
        if not _hash(identity.get(field)):
            raise ValueError('B-arm identity hash is malformed')
    roots = identity['roots']
    if (type(roots) is not dict or set(roots) != {'R0', 'R1'}
            or not all(_hash(value) for value in roots.values())
            or roots['R0'] == roots['R1']):
        raise ValueError('distinct pinned B-arm R0 and R1 roots required')
    proof = arm.get('proof')
    if (type(proof) is not dict or proof.get('mode') != mode
            or proof.get('proof_created') is not True
            or proof.get('ordinary_verified') is not True):
        raise ValueError('proof creation and ordinary verification required')
    clone = arm.get('clone')
    if (type(clone) is not dict or not _hash(clone.get('receipt_sha256'))
            or not _hash(clone.get('tree_sha256'))
            or clone.get('copy_identical') is not True
            or type(clone.get('destination')) is not str
            or not Path(clone['destination']).is_absolute()):
        raise ValueError('reviewed private R1 clone required')
    effect = arm.get('effect')
    if (type(effect) is not dict or not _hash(effect.get('report_sha256'))
            or effect.get('mode') != mode or effect.get('passed') is not True
            or effect.get('effect_count') != 1
            or effect.get('request_consumed') is not True):
        raise ValueError('one verified loaded application effect required')
    return identity, clone


def validate_direct_pair(full, anchor, full_outer, anchor_outer, *, variant, order):
    """Validate direct B-arm evidence; do not infer any unmeasured k > 1 result."""
    expected_order = arm_order(variant)
    if tuple(order) != expected_order:
        raise ValueError('counterbalanced arm order does not match the heldout variant')
    full_identity, full_clone = _arm_identity(full, 'full', variant)
    anchor_identity, anchor_clone = _arm_identity(anchor, 'anchor', variant)
    if full.get('run_manifest_sha256') != anchor.get('run_manifest_sha256'):
        raise ValueError('matched case manifest identity required')
    for field in ('credential_sha256', 'finalized_request_sha256',
                  'finalized_action_transport_sha256', 'action_hash'):
        if full_identity[field] != anchor_identity[field]:
            raise ValueError('Full and Anchor B finalized action mismatch')
    if full_identity['roots'] != anchor_identity['roots']:
        raise ValueError('Full and Anchor B authenticated root sequence mismatch')
    for field in ('setup_sha256', 'vk_sha256', 'elf_sha256'):
        if full_identity[field] != anchor_identity[field]:
            raise ValueError('Full and Anchor B frozen product identity mismatch')
    if full_clone['destination'] == anchor_clone['destination']:
        raise ValueError('Full and Anchor R1 clone destinations must be independent')
    if full_clone['tree_sha256'] != anchor_clone['tree_sha256']:
        raise ValueError('Full and Anchor R1 ledger clones are not byte-identical')
    full_seconds = _outer_seconds(full_outer)
    anchor_seconds = _outer_seconds(anchor_outer)
    savings = (full_seconds - anchor_seconds) / full_seconds
    return {
        'matched': True,
        'basis': 'separate directly timed bounded request-B pipeline outer wall',
        'variant': variant,
        'arm_order': list(order),
        'update_count': 1,
        'full_direct_wall_seconds': full_seconds,
        'anchor_direct_wall_seconds': anchor_seconds,
        'anchor_wall_savings_seconds': full_seconds - anchor_seconds,
        'anchor_wall_savings_fraction': savings,
        'k_gt_1_measured': False,
        'complete_tree_cpu_qualified': False,
        'outer_cleanup_verified': True,
        'independent_byte_identical_r1_clones': True,
        'same_finalized_action_and_root_sequence': True,
    }


def _private_dir(path, *, fresh=False, ignored=False):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute private output path required')
    if fresh:
        if path.exists() or path.is_symlink():
            raise ValueError('fresh private output directory required')
        _canonical_directory(path.parent)
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('canonical owner-only output directory required')
    if ignored:
        from tools.part5 import generate_v3_heldout_keys as keygen
        if not keygen._ignored(path):
            raise ValueError('direct-arm output must be Git-ignored')
    return path


def _canonical_directory(path):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError('canonical existing output parent required') from error
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode)):
        raise ValueError('canonical existing output parent required')
    return path


def _worker_output_paths(case_output_root):
    case_output_root = Path(case_output_root)
    if (not case_output_root.is_absolute()
            or case_output_root.name in ('', '.', '..')):
        raise ValueError('absolute case output root required')
    return case_output_root.parent, case_output_root


def _locked_parent_pid(lock_path):
    lock_path = Path(lock_path)
    if (not lock_path.is_absolute() or lock_path.resolve(strict=True) != lock_path
            or lock_path.is_symlink()):
        raise ValueError('canonical locked-parent file required')
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('owner-only regular lock file required')
        raw = os.read(fd, 4096)
        try:
            owner = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError('locked-parent identity required') from error
        if (type(owner) is not dict or owner.get('schema') != LOCK_OWNER_SCHEMA
                or type(owner.get('pid')) is not int or owner['pid'] <= 0):
            raise ValueError('locked-parent identity required')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return owner['pid']
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            raise ValueError('worker parent does not hold the heavyweight lock')
    finally:
        os.close(fd)


def _authorize_worker(ticket_path, case_output_root, mode, manifest_sha256, token,
                      *, child_parent_pid=None, lock_path=HEAVY_LOCK):
    mode_root, case_output_root = _worker_output_paths(case_output_root)
    _canonical_directory(mode_root)
    ticket_path = Path(ticket_path)
    expected_ticket = mode_root / WORKER_TICKET_NAME
    if ticket_path != expected_ticket:
        raise ValueError('canonical worker ticket path required')
    try:
        if ticket_path.resolve(strict=True) != ticket_path:
            raise ValueError('owner-only worker ticket required')
        ticket_fd = os.open(ticket_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(ticket_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('owner-only worker ticket required')
            raw = os.read(ticket_fd, 65537)
        finally:
            os.close(ticket_fd)
        if len(raw) > 65536:
            raise ValueError('worker ticket exceeds size limit')
        ticket = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError('one-time locked-parent worker ticket required') from error
    parent_pid = os.getppid() if child_parent_pid is None else child_parent_pid
    env_token = os.environ.get('P5_V3_DIRECT_ARM_WORKER_TOKEN')
    if (type(ticket) is not dict
            or set(ticket) != {'schema', 'mode', 'case_output_root',
                               'manifest_sha256', 'supervisor_pid', 'token'}
            or ticket.get('schema') != WORKER_TICKET_SCHEMA
            or ticket.get('mode') != mode
            or ticket.get('case_output_root') != str(case_output_root)
            or ticket.get('manifest_sha256') != manifest_sha256
            or type(ticket.get('supervisor_pid')) is not int
            or ticket['supervisor_pid'] != parent_pid
            or type(token) is not str or type(env_token) is not str
            or not hmac.compare_digest(ticket.get('token', ''), token)
            or not hmac.compare_digest(token, env_token)):
        raise ValueError('locked-parent worker ticket identity mismatch')
    if _locked_parent_pid(lock_path) != parent_pid:
        raise ValueError('worker ticket parent does not own the heavyweight lock')
    claim_path = mode_root / WORKER_CLAIM_NAME
    _write_new(claim_path, {
        'schema': 'credential-v3-heldout-worker-claim-v1',
        'mode': mode,
        'manifest_sha256': manifest_sha256,
        'supervisor_pid': parent_pid,
        'ticket_sha256': _digest(raw),
    })
    ticket_path.unlink()
    return mode_root


def _read_manifest(case_runner, manifest_path):
    raw = case_runner._read(manifest_path, cap=1024 * 1024)
    manifest = json.loads(raw)
    run_ref, manifest_sha = case_runner.run_manifest_identity(
        manifest_path, raw, manifest)
    case_runner.validate_manifest(manifest)
    return raw, manifest, run_ref, manifest_sha


def _write_arm_report(path, report):
    _write_new(path, report)


def _run_arm_worker(manifest_path, mode, case_output_root, token):
    if mode not in ('full', 'anchor'):
        raise ValueError('Full or Anchor B arm required')
    case_runner = _load_module('direct_arm_case_runner',
                               ROOT / 'tools/part5/run_v3_heldout_case.py')
    _, manifest, run_ref, manifest_sha = _read_manifest(case_runner, Path(manifest_path))
    variant = manifest['variant']
    mode_root, output_root = _worker_output_paths(case_output_root)
    _private_dir(mode_root, ignored=True)
    _authorize_worker(mode_root / WORKER_TICKET_NAME, output_root, mode,
                      manifest_sha, token)
    _private_dir(output_root, fresh=True, ignored=True)
    runner = case_runner.HeldoutCaseRunner(
        manifest, output_root, run_manifest_ref=run_ref,
        manifest_sha256=manifest_sha)
    case_root = runner.output_root / 'pair-view'
    context_builder = _load_module('direct_arm_context_builder',
                                   ROOT / 'tools/part5/prepare_v3_heldout_context.py')

    def pair_view():
        if case_root.exists() or case_root.is_symlink():
            raise ValueError('fresh B-arm pair view required')
        case_root.mkdir(mode=0o700)
        context_builder.prepare(Path(manifest['cohort_root']),
            manifest['cohort_sha256'], variant, case_root)
        pair_doc = case_runner._json(case_root / 'cohort-receipt.json')
        case_doc = case_runner._json(case_root / 'case-context.json')
        if (case_doc.get('target', {}).get('variant') != variant
                or pair_doc.get('heldout_acceptance') is not False):
            raise ValueError('B-arm pair view does not match the frozen case manifest')
        return {'status': 'passed',
                'case_context_sha256': case_runner.digest(
                    case_runner._read(case_root / 'case-context.json')),
                'pair_receipt_sha256': case_runner.digest(
                    case_runner._read(case_root / 'cohort-receipt.json'))}

    spec = case_runner.request_matrix()[1]
    req = spec['name']
    root = runner._layout(req)
    request_inputs = {
        'case_context_sha256': None,
        'prepare_template_sha256': manifest['base_prepare_config_sha256'],
        'request_slot': spec['request_slot'],
    }

    with runner.journal:
        pair = runner.journal.run_step('pair-view',
            inputs={'cohort': manifest['cohort_sha256'], 'variant': variant},
            job=pair_view,
            reuse=lambda saved: saved.get('status') == 'passed'
                and saved.get('case_context_sha256') == case_runner.digest(
                    case_runner._read(case_root / 'case-context.json'))
                and saved.get('pair_receipt_sha256') == case_runner.digest(
                    case_runner._read(case_root / 'cohort-receipt.json')))
        request_inputs['case_context_sha256'] = pair['case_context_sha256']
        prepared = runner.journal.run_step(req + ':prepare', inputs=request_inputs,
            job=lambda: {'status': 'passed', **runner._prepare(
                req, root, case_root, case_root / 'stage-context.json')},
            reuse=lambda saved: runner._verify_record(
                saved, ('config', 'status_path', 'monitor')))
        stage, transition, _ = runner._stage_transition(
            req, root, case_root, request_inputs, prepared)

        def source_call(source_variant, out, r0_source=None):
            out = Path(out)
            if out.exists() or out.is_symlink():
                raise ValueError('fresh B-arm source directory required')
            out.mkdir(mode=0o700)
            receipt_path = out / 'source-receipt.json'
            command = [sys.executable,
                str(ROOT / 'tools/part5/prepare_v3_heldout_source.py'),
                '--case-root', str(case_root), '--cohort-root', manifest['cohort_root'],
                '--freeze-receipt', manifest['freeze_receipt'],
                '--freeze-sha256', manifest['freeze_sha256'],
                '--stage-root', stage['root'],
                '--exporter', manifest['proof_inputs']['exporter']['path'],
                '--variant', source_variant, '--output', str(out)]
            if source_variant == 'R1':
                command.extend(['--transition-root', transition['root'],
                    '--transition-context', transition['context'],
                    '--transition-context-sha256', transition['context_sha256'],
                    '--r0-source-receipt', r0_source['receipt'],
                    '--r0-source-receipt-sha256', r0_source['receipt_sha256']])
            monitor_dir = root / ('source-' + source_variant + '-monitor')
            monitor_path = root / ('source-' + source_variant + '-monitor.json')
            owner = f'direct-v{variant:02d}-B-source-{source_variant}'
            outer = runner.bounded_run(owner, command, monitor_dir, monitor_path,
                runtime=case_runner.LIMITS['runtime_seconds'], storage_paths=(out,))
            if (outer.get('passed') is not True or outer.get('stop_reason') is not None
                    or outer.get('cleanup_remaining_owned_processes') != 0
                    or outer.get('cleanup_status_unknown') is not False):
                raise ValueError('bounded B-arm source preparation failed')
            receipt = case_runner._json(receipt_path)
            if receipt.get('schema') != 'credential-v3-heldout-request-source-v1':
                raise ValueError('pinned B-arm request source receipt required')
            return {'status': 'passed', 'root': str(out),
                'receipt': str(receipt_path),
                'receipt_sha256': case_runner.digest(case_runner._read(receipt_path)),
                'monitor': str(monitor_path),
                'monitor_sha256': case_runner.digest(case_runner._read(monitor_path)),
                'monitor_owner': owner}

        source_inputs = {'stage_report_sha256': stage['report_sha256'],
                         'freeze_sha256': manifest['freeze_sha256']}
        r0 = runner.journal.run_step(req + ':source-R0', inputs=source_inputs,
            job=lambda: source_call('R0', root / 'source-R0'),
            reuse=lambda saved: runner._verify_record(saved,
                ('receipt', 'monitor'), ('receipt_sha256', 'monitor_sha256')))
        r1 = runner.journal.run_step(req + ':source-R1',
            inputs={**source_inputs,
                    'transition_report_sha256': transition['report_sha256'],
                    'r0_receipt_sha256': r0['receipt_sha256']},
            job=lambda: source_call('R1', root / 'source-R1', r0),
            reuse=lambda saved: runner._verify_record(saved,
                ('receipt', 'monitor'), ('receipt_sha256', 'monitor_sha256')))
        proof = runner._request_proof(req, mode, root, case_root, stage,
                                      transition, r0, r1)
        clone_label = 'r1-full' if mode == 'full' else 'r1-anchor'
        clone = runner.journal.run_step(
            f'unrelated_compare:{"unrelated_full" if mode == "full" else "anchor"}:clone',
            inputs={'transition_report_sha256': transition['report_sha256'],
                    'label': clone_label},
            job=lambda: {'status': 'passed', **runner._clone_r1(
                req, clone_label, root, transition)},
            reuse=lambda saved: runner._verify_record(
                saved, ('receipt',), ('receipt_sha256',)))
        wires = {'full': proof['wires']['r0_full_wire'],
                 'anchor': proof['wires']['r1_wire']}
        if mode == 'full':
            wires['full_near'] = proof['wires']['r1_wire']
        branch_label = 'unrelated_full' if mode == 'full' else 'anchor'
        effect = runner.journal.run_step(
            f'unrelated_compare:{branch_label}:effect',
            inputs={'transition_report_sha256': transition['report_sha256'],
                    'source_r0_sha256': r0['receipt_sha256'],
                    'source_r1_sha256': r1['receipt_sha256'],
                    'proof_mode': mode,
                    'clone_receipt_sha256': clone['receipt_sha256']},
            job=lambda: {'status': 'passed', **runner._run_branch(
                req, branch_label, mode, root, stage, transition, clone,
                {mode: proof}, wires)},
            reuse=lambda saved: runner._verify_record(
                saved, ('report', 'status_path', 'config', 'outer', 'signed_history'),
                ('report_sha256', 'status_sha256')))

    r0_doc = case_runner._json(r0['receipt'], r0['receipt_sha256'])
    r1_doc = case_runner._json(r1['receipt'], r1['receipt_sha256'])
    proof_doc = case_runner._json(proof['receipt'], proof['receipt_sha256'])
    proof_report_ref = proof_doc.get('proof_report')
    proof_report = case_runner._json(proof_report_ref['path'], proof_report_ref['sha256'])
    clone_doc = case_runner._json(clone['receipt'], clone['receipt_sha256'])
    branch_doc = case_runner._json(effect['report'], effect['report_sha256'])
    setup = manifest['frozen_files']['setup_manifest']['sha256']
    vk = manifest['frozen_files']['ordinary_vk']['sha256']
    elf = manifest['frozen_files']['loaded_elf']['sha256']
    if (proof_doc.get('mode') != mode
            or proof_doc.get('proof_created') is not True
            or proof_doc.get('application_verified') is not False
            or proof_report.get('mode') != ('matched-full-k1' if mode == 'full'
                                             else 'matched-anchor-k1')
            or proof_report.get('passed') is not True
            or proof_doc.get('ordinary_verification', {}).get('passed') is not True
            or branch_doc.get('passed') is not True
            or branch_doc.get('mode') != mode
            or branch_doc.get('effect_count') != 1
            or branch_doc.get('request_consumed') is not True
            or clone_doc.get('copy_identical') is not True):
        raise ValueError('complete matched proof and loaded effect evidence required')
    roots = r0_doc.get('membership_roots')
    if (type(roots) is not dict or set(roots) != {'R0', 'R1'}
            or r0_doc.get('selected_root') != roots['R0']
            or r1_doc.get('selected_root') != roots['R1']
            or r0_doc.get('target_der_sha256') != r1_doc.get('target_der_sha256')
            or r0_doc.get('finalized_request_sha256')
                != r1_doc.get('finalized_request_sha256')
            or r0_doc.get('action_hash') != r1_doc.get('action_hash')):
        raise ValueError('B-arm finalized request and R0/R1 continuity required')
    identity = {
        'credential_sha256': r0_doc['target_der_sha256'],
        'finalized_request_sha256': r0_doc['finalized_request_sha256'],
        'finalized_action_transport_sha256': r0_doc['finalized_action_transport_sha256'],
        'action_hash': r0_doc['action_hash'],
        'roots': roots,
        'setup_sha256': setup,
        'vk_sha256': vk,
        'elf_sha256': elf,
    }
    arm = {
        'schema': ARM_SCHEMA, 'variant': variant, 'mode': mode, 'status': 'passed',
        'run_manifest_sha256': manifest_sha,
        'identity': identity,
        'proof': {'mode': mode, 'proof_created': True,
                  'ordinary_verified': True,
                  'receipt_sha256': proof['receipt_sha256'],
                  'proof_report_sha256': proof_report_ref['sha256']},
        'clone': {'receipt_sha256': clone['receipt_sha256'],
                  'tree_sha256': clone_doc['tree_sha256'],
                  'copy_identical': clone_doc['copy_identical'],
                  'destination': clone_doc['destination']},
        'effect': {'report_sha256': effect['report_sha256'], 'mode': mode,
                   'passed': True, 'effect_count': 1, 'request_consumed': True},
        'evidence': {
            'pair_context_sha256': pair['case_context_sha256'],
            'stage_report_sha256': stage['report_sha256'],
            'transition_report_sha256': transition['report_sha256'],
            'source_r0_receipt_sha256': r0['receipt_sha256'],
            'source_r1_receipt_sha256': r1['receipt_sha256'],
            'clone_receipt_sha256': clone['receipt_sha256'],
            'proof_receipt_sha256': proof['receipt_sha256'],
            'branch_report_sha256': effect['report_sha256'],
        },
        'limitations': {
            'private_proof_state_serialization_reload': 'not implemented by current heldout path',
            'loaded_expired_status_negative': 'not part of B arm',
            'loaded_full_queue_negative': 'not part of B arm',
        },
    }
    arm_path = mode_root / 'arm-report.json'
    _write_new(arm_path, arm)
    return arm


def _load_json(path):
    path = Path(path)
    raw = path.read_bytes()
    return json.loads(raw)


def _acquire_heavy_lock():
    _canonical_directory(ARTIFACTS)
    if HEAVY_LOCK.parent != ARTIFACTS:
        raise ValueError('canonical heavyweight lock path required')
    fd = os.open(HEAVY_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise ValueError('another heldout heavyweight job owns the runbook lock') from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('owner-only regular heavyweight lock required')
        owner = json.dumps({'schema': LOCK_OWNER_SCHEMA, 'pid': os.getpid()},
                           sort_keys=True, separators=(',', ':')).encode()
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, owner)
        os.fsync(fd)
    except Exception:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        raise
    return fd


def run_pair(manifest_path, output_root):
    case_runner = _load_module('direct_pair_case_runner',
                               ROOT / 'tools/part5/run_v3_heldout_case.py')
    manifest_path, output_root = Path(manifest_path), Path(output_root)
    _, manifest, _, manifest_sha = _read_manifest(case_runner, manifest_path)
    variant = manifest['variant']
    order = arm_order(variant)
    if (not output_root.is_absolute() or output_root.parent != ARTIFACTS
            or output_root.name in ('', '.', '..')):
        raise ValueError('fresh direct pair root must be one Part 5 artifact child')
    supervision_root = ARTIFACTS / ('.v3-direct-arm-supervisor-' + uuid.uuid4().hex)
    lock_fd = _acquire_heavy_lock()
    try:
        _private_dir(output_root, fresh=True, ignored=True)
        _private_dir(supervision_root, fresh=True, ignored=True)
        rows = {}
        mode_roots = {}
        outer_reports = {}
        session_runner = _load_module('direct_arm_session_runner',
                                      ROOT / 'results/dynark/part5/session_runner.py')
        for mode in order:
            mode_root = output_root / ('arm-' + mode)
            _private_dir(mode_root, fresh=True, ignored=True)
            arm_output_root = mode_root / 'case-run'
            worker_token = uuid.uuid4().hex
            _write_new(mode_root / WORKER_TICKET_NAME, {
                'schema': WORKER_TICKET_SCHEMA,
                'mode': mode,
                'case_output_root': str(arm_output_root),
                'manifest_sha256': manifest_sha,
                'supervisor_pid': os.getpid(),
                'token': worker_token,
            })
            private_monitor = supervision_root / (mode + '-monitor')
            outer_path = supervision_root / (mode + '-outer.json')
            command = [sys.executable, str(Path(__file__).resolve()),
                '--manifest', str(manifest_path), '--output-root', str(arm_output_root),
                '--_arm-mode', mode]
            limits = OUTER_LIMITS[mode]
            outer = session_runner.run(owner=f'heldout-v{variant:02d}-direct-{mode}',
                command=command, cwd=str(ROOT), private_output=str(private_monitor),
                report=str(outer_path), runtime_seconds=limits['runtime_seconds'],
                rss_bytes=limits['rss_bytes'], storage_bytes=limits['storage_bytes'],
                storage_paths=(str(mode_root),),
                environment={'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1',
                             'TZ': 'UTC',
                             'P5_V3_DIRECT_ARM_WORKER_TOKEN': worker_token})
            outer_reports[mode] = outer
            if outer.get('passed') is not True:
                raise ValueError(f'{mode} complete-session outer monitor failed')
            arm_report = mode_root / 'arm-report.json'
            arm = _load_json(arm_report)
            arm_report_sha256 = _digest(arm_report.read_bytes())
            if arm.get('run_manifest_sha256') != manifest_sha:
                raise ValueError(f'{mode} B-arm report digest or manifest pin mismatch')
            rows[mode] = arm
            mode_roots[mode] = {'root': str(mode_root),
                'arm_report': str(arm_report), 'arm_report_sha256': arm_report_sha256,
                'outer_report': str(outer_path), 'outer_report_sha256': _digest(outer_path.read_bytes()),
                'supervisor_private_output': str(private_monitor)}
        comparison = validate_direct_pair(rows['full'], rows['anchor'],
            outer_reports['full'], outer_reports['anchor'], variant=variant, order=order)
        report = {
            'schema': PAIR_SCHEMA,
            'variant': variant,
            'run_manifest': {'path': str(manifest_path), 'sha256': manifest_sha},
            'comparison': comparison,
            'arms': {mode: mode_roots[mode] for mode in ('full', 'anchor')},
            'timing_notes': [
                'outer wall starts immediately before the arm worker launch and ends after owned-process cleanup',
                'session-runner metadata setup and final outer report writing are outside the timed interval',
                'nested child monitor durations are attribution only and are not summed into the direct arm wall',
                'outer CPU fields are incomplete and are not a qualified complete-tree CPU comparison',
                'outer storage sampling covers the arm private output root; child limits cover other output locations',
            ],
            'workload_limits': {
                'one_finalized_B_action_per_credential': True,
                'one_unrelated_root_transition': True,
                'k_gt_1_measured': False,
                'expired_status_negative_included': False,
                'full_queue_negative_included': False,
                'proof_state_serialization_reload': 'not implemented by current heldout path',
            },
        }
        report_sha256 = _write_pair_report(output_root / 'direct-pair-report.json', report)
        return {'report': report, 'report_sha256': report_sha256}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output-root', required=True, type=Path)
    parser.add_argument('--_arm-mode', choices=('full', 'anchor'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args._arm_mode:
            token = os.environ.get('P5_V3_DIRECT_ARM_WORKER_TOKEN')
            if not token:
                raise ValueError('locked-parent worker invocation required')
            report = _run_arm_worker(args.manifest, args._arm_mode, args.output_root, token)
            print(json.dumps({'schema': ARM_SCHEMA, 'variant': report['variant'],
                              'mode': report['mode'], 'status': report['status']}))
        else:
            result = run_pair(args.manifest, args.output_root)
            report = result['report']
            print(json.dumps({'schema': PAIR_SCHEMA, 'variant': report['variant'],
                              'report': str(args.output_root / 'direct-pair-report.json'),
                              'report_sha256': result['report_sha256']}))
    except Exception as error:
        raise SystemExit(f'direct heldout B-arm measurement rejected: {type(error).__name__}: {str(error)[:180]}') from None


if __name__ == '__main__':
    main()
