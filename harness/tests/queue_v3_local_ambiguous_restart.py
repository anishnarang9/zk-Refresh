#!/usr/bin/env python3
"""Bounded one-shot ambiguous Full Execute and same-ledger restart supervisor."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from harness.tests import queue_v3_local_execute as execute
from harness.tests import queue_v3_ambiguous_rpc_proxy as proxy

SCOPE = 'part5-v3-local-ambiguous-restart'
SCHEMA = 'part5-v3-local-ambiguous-restart-supervisor-v1'
LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}
SUPERVISOR_BUDGET_SECONDS = 150
RUNNER_BUDGET_SECONDS = 110
ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')
TRANSPORT_FAILURE = b'RPC sendTransaction transport failed'
PROXY_RECEIPT_SCHEMA = 'queue-v3-ambiguous-rpc-proxy-receipt-v1'
PREPOSITIVE_SCHEMA = 'part5-v3-ambiguous-pre-submit-v1'


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError('ambiguous-restart supervisor deadline')


def _receipt_digest(value: object, field: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(character not in '0123456789abcdef' for character in value)):
        raise ValueError(field + ' must be lowercase SHA-256')
    return value


def validate_proxy_receipt(receipt: object, expected_wire_sha256: str) -> dict:
    if type(receipt) is not dict:
        raise ValueError('private proxy receipt object required')
    expected_fields = {
        'schema', 'status', 'target_wire_sha256', 'transaction_sha256', 'signature',
        'matching_submissions', 'duplicate_matching_submissions', 'duplicate_rejected',
        'forward_attempted', 'forwarded', 'response_dropped'}
    if set(receipt) != expected_fields:
        raise ValueError('proxy receipt fields differ from the pinned schema')
    if (receipt.get('schema') != PROXY_RECEIPT_SCHEMA
            or receipt.get('status') != 'response_dropped'
            or receipt.get('target_wire_sha256') != expected_wire_sha256
            or type(receipt.get('matching_submissions')) is not int
            or receipt['matching_submissions'] != 1
            or receipt.get('duplicate_matching_submissions') != 0
            or receipt.get('duplicate_rejected') is not False
            or receipt.get('forward_attempted') != 1
            or receipt.get('forwarded') != 1
            or receipt.get('response_dropped') is not True):
        raise ValueError('one accepted matching submission with dropped response required')
    _receipt_digest(receipt.get('transaction_sha256'), 'transaction_sha256')
    signature = receipt.get('signature')
    proxy.decode_base58_signature(signature)
    return receipt


def expected_transport_failure(return_code: int, stdout: bytes, stderr: bytes,
                               receipt: dict, expected_wire_sha256: str) -> bool:
    if type(return_code) is not int or return_code == 0:
        raise ValueError('Rust runner must fail after the ambiguous submission')
    if (not isinstance(stdout, bytes) or not isinstance(stderr, bytes)
            or (TRANSPORT_FAILURE not in stdout and TRANSPORT_FAILURE not in stderr)):
        raise ValueError('Rust runner did not report the expected sendTransaction transport failure')
    validate_proxy_receipt(receipt, expected_wire_sha256)
    return True


def expected_reconciled_accounts(before: list[bytes], context: dict) -> list[bytes]:
    if len(before) != 5 or any(not isinstance(item, bytes) for item in before):
        raise ValueError('five staged account byte arrays required')
    config, issuer, head, request, queue = before
    if (len(config) != 381 or config[:8] != b'DYNCONF3'
            or len(issuer) != 374 or issuer[:8] != b'DYNISS03'
            or len(head) != 280 or head[:8] != b'DYNHEAD3'
            or len(request) != 2249 or request[:8] != b'DYNREQ03'
            or len(queue) != 2090 or queue[:8] != b'DYNQUE03'):
        raise ValueError('pinned v3 account layouts required')
    root = context.get('root')
    request_key = context.get('request')
    observed = context.get('observed_at')
    committed = context.get('head_committed_at')
    if (type(root) is not bytes or len(root) != 32 or root != config[332:364]
            or type(request_key) is not bytes or len(request_key) != 32
            or type(observed) is not int or type(committed) is not int):
        raise ValueError('pinned training context and bounded observed times required')
    if request[183] != 1 or int.from_bytes(queue[40:42], 'big') != 0 or any(queue[42:]):
        raise ValueError('initial finalized request and empty queue required')
    if observed <= int.from_bytes(issuer[213:221], 'big', signed=True):
        raise ValueError('source observation must advance')
    expires = observed + 240
    if (committed < observed or committed > expires
            or committed < int.from_bytes(head[272:280], 'big', signed=True)):
        raise ValueError('publisher binding time outside the source status interval')

    next_sequence = int.from_bytes(issuer[173:181], 'big') + 1
    issuer_hash = issuer[40:72]
    old_digest = issuer[181:213]
    evidence_digest = issuer[317:349]
    source_digest = hashlib.sha256(
        b'part5-v3-local-execute-source-training-v1' + root + issuer_hash
        + evidence_digest + old_digest + next_sequence.to_bytes(8, 'big')
        + observed.to_bytes(8, 'big', signed=True)).digest()
    next_publication = int.from_bytes(head[104:112], 'big') + 1
    if next_sequence >= (1 << 64) or next_publication >= (1 << 64):
        raise ValueError('source or publication sequence overflow')
    envelope_digest = hashlib.sha256(
        b'part5-v3-local-execute-head-training-v1' + root + head[112:144]
        + source_digest + observed.to_bytes(8, 'big', signed=True)).digest()

    expected_issuer = bytearray(issuer)
    expected_issuer[173:181] = next_sequence.to_bytes(8, 'big')
    expected_issuer[181:213] = source_digest
    expected_issuer[213:221] = observed.to_bytes(8, 'big', signed=True)
    expected_issuer[221:229] = expires.to_bytes(8, 'big', signed=True)
    expected_issuer[229:261] = root
    expected_issuer[261:269] = config[364:372]
    expected_issuer[269:277] = next_sequence.to_bytes(8, 'big')
    expected_issuer[277:309] = source_digest
    expected_issuer[349:357] = config[372:380]
    expected_issuer[366:374] = issuer[358:366]

    expected_head = bytearray(head)
    expected_head[104:112] = next_publication.to_bytes(8, 'big')
    expected_head[112:144] = envelope_digest
    expected_head[144:176] = head[112:144]
    expected_head[176:208] = root
    expected_head[208:216] = config[364:372]
    expected_head[216:224] = next_sequence.to_bytes(8, 'big')
    expected_head[224:256] = source_digest
    expected_head[256:264] = config[372:380]
    expected_head[264:272] = issuer[358:366]
    expected_head[272:280] = committed.to_bytes(8, 'big', signed=True)

    consumed = bytearray(request)
    consumed[183] = 2
    appended = bytearray(queue)
    appended[40:42] = (1).to_bytes(2, 'big')
    appended[42:74] = request_key
    return [config, bytes(expected_issuer), bytes(expected_head), bytes(consumed), bytes(appended)]


def _pre_submit_matches_stage_transition(before: list[bytes], pre_submit: list[bytes],
                                        context: dict) -> bool:
    if len(pre_submit) != 5:
        raise ValueError('five direct pre-submit account byte arrays required')
    issuer, head = pre_submit[1], pre_submit[2]
    if len(issuer) != 374 or len(head) != 280:
        raise ValueError('pre-submit issuer/head account lengths changed')
    derived_context = dict(context)
    derived_context['observed_at'] = int.from_bytes(issuer[213:221], 'big', signed=True)
    derived_context['head_committed_at'] = int.from_bytes(head[272:280], 'big', signed=True)
    after_execute = expected_reconciled_accounts(before, derived_context)
    expected_pre_submit = after_execute[:3] + [before[3], before[4]]
    if pre_submit != expected_pre_submit:
        raise ValueError('direct pre-submit accounts differ from the one source/head refresh')
    return True


def reconcile_final_accounts(before: list[bytes], after: list[bytes], context: dict,
                             pre_submit: list[bytes] | None = None) -> list[str]:
    if len(after) != 5 or any(not isinstance(item, bytes) for item in after):
        raise ValueError('five finalized account byte arrays required')
    issuer, head = after[1], after[2]
    if len(issuer) != 374 or len(head) != 280:
        raise ValueError('finalized issuer/head account lengths changed')
    derived_context = dict(context)
    if pre_submit is not None:
        _pre_submit_matches_stage_transition(before, pre_submit, context)
        if after[:3] != pre_submit[:3]:
            raise ValueError('Full Execute changed config, issuer, or head after pre-submit snapshot')
        derived_context['observed_at'] = int.from_bytes(
            pre_submit[1][213:221], 'big', signed=True)
        derived_context['head_committed_at'] = int.from_bytes(
            pre_submit[2][272:280], 'big', signed=True)
        execute.check_effect_bytes(pre_submit, after, {
            'config': execute.base.b58(pre_submit[0][8:40]),
            'request': execute.base.b58(context['request'])})
    else:
        derived_context['observed_at'] = int.from_bytes(issuer[213:221], 'big', signed=True)
        derived_context['head_committed_at'] = int.from_bytes(head[272:280], 'big', signed=True)
    expected = expected_reconciled_accounts(before, derived_context)
    if after != expected:
        raise ValueError('five finalized accounts differ from the one-execute transition')
    return [_sha(raw) for raw in after]


def final_status(evidence: dict) -> dict:
    required = (
        'proxy_receipt_verified', 'expected_transport_failure',
        'restart_identity_verified', 'signature_finalized_success',
        'five_account_reconciliation_verified', 'prepositive_snapshot_saved_by_runner',
        'cleanup_verified')
    if any(evidence.get(name) is not True for name in required):
        return {'status': 'failed', 'heldout_acceptance': False}
    return {'status': 'passed', 'heldout_acceptance': True}


def reviewed_validator_stop(cleanup: object) -> str:
    if type(cleanup) is not dict or cleanup.get('spawned') is not True \
            or cleanup.get('reaped') is not True:
        raise ValueError('validator was not fully reaped')
    if cleanup.get('graceful') is True and cleanup.get('exit_code') == 0:
        return 'clean_zero'
    if cleanup.get('graceful') is False and cleanup.get('exit_code') == -signal.SIGINT:
        return 'interrupted_sigint'
    raise ValueError('validator stop is not a reviewed exit mode')


def _read_private_json(path: Path, cap: int = 65536) -> tuple[dict, str]:
    raw, digest = execute.stage.snapshot_generated(path, cap)
    value = execute.base.decode_json(raw)
    if type(value) is not dict:
        raise ValueError('private JSON object required')
    return value, digest


def _write_log(path: Path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, 'wb')


def _write_new_bytes(path: Path, raw: bytes) -> None:
    if not isinstance(raw, bytes) or not raw:
        raise ValueError('nonempty finalized account bytes required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o600:
            raise ValueError('owner-only finalized account output required')
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise OSError('short finalized account write')
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_saved_final_account_bytes(output: Path, expected: list[bytes]) -> tuple[list[str], list[str]]:
    if len(expected) != 5 or any(not isinstance(raw, bytes) or not raw for raw in expected):
        raise ValueError('five nonempty finalized account byte arrays required')
    hashes, paths = [], []
    for name, raw in zip(ACCOUNT_NAMES, expected):
        path = output / f'final-{name}.bin'
        info = path.lstat()
        if info.st_nlink != 1:
            raise ValueError('finalized account output must have one link')
        saved, digest = execute.stage.snapshot_generated(path, 4096)
        if saved != raw or digest != _sha(raw):
            raise ValueError('saved finalized account bytes differ from reconciled RPC bytes')
        hashes.append(digest)
        paths.append(str(path))
    return hashes, paths


def _persist_final_account_bytes(output: Path, accounts: list[bytes]) -> tuple[list[str], list[str]]:
    if len(accounts) != 5 or any(not isinstance(raw, bytes) or not raw for raw in accounts):
        raise ValueError('five nonempty finalized account byte arrays required')
    for name, raw in zip(ACCOUNT_NAMES, accounts):
        _write_new_bytes(output / f'final-{name}.bin', raw)
    directory_fd = os.open(output, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return _verify_saved_final_account_bytes(output, accounts)


def _wait_loaded(rpc, proc, original, elf, deadline):
    local_deadline = min(deadline, time.monotonic() + 30)
    while True:
        _check_deadline(local_deadline)
        if proc.poll() is not None:
            raise RuntimeError('validator exited before finalized program identity')
        try:
            return execute.base.wait_loaded(
                rpc, proc, original['program'], elf, original['elf_sha256'],
                timeout=max(0.1, local_deadline - time.monotonic()))
        except ValueError as error:
            if str(error) != 'invalid RPC envelope' or time.monotonic() >= local_deadline:
                raise
            time.sleep(min(0.1, local_deadline - time.monotonic()))


def _wait_staged(rpc, report, program, sizes, deadline):
    local_deadline = min(deadline, time.monotonic() + 30)
    minimum = report['finalized_slot']
    while True:
        _check_deadline(local_deadline)
        try:
            return execute.finalized_accounts(
                rpc, report, minimum, program, report['account_sha256'], sizes)
        except execute.base.NotReady:
            pass
        except ValueError as error:
            if str(error) != 'invalid RPC envelope':
                raise
        time.sleep(min(0.1, max(0.0, local_deadline - time.monotonic())))


def _wait_proxy(proc, host: str, port: int, deadline: float) -> None:
    while True:
        _check_deadline(deadline)
        if proc.poll() is not None:
            raise RuntimeError('ambiguous RPC proxy exited before listening')
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)


def _wait_child(proc, validator, deadline: float) -> int:
    child_deadline = min(deadline, time.monotonic() + RUNNER_BUDGET_SECONDS)
    while proc.poll() is None:
        _check_deadline(child_deadline)
        if validator.poll() is not None:
            raise RuntimeError('validator exited during ambiguous Execute')
        time.sleep(0.1)
    return proc.wait()


def _stop_proxy(proc) -> dict:
    result = execute.base.cleanup(proc)
    if (result.get('reaped') is not True or result.get('graceful') is not True
            or result.get('exit_code') != 0):
        raise RuntimeError('ambiguous proxy did not shut down cleanly')
    return result


def _wait_finalized_signature(rpc, signature: str, deadline: float) -> dict:
    while True:
        _check_deadline(deadline)
        status_result = rpc('getSignatureStatuses', [[signature], {'searchTransactionHistory': True}])
        values = status_result.get('value') if isinstance(status_result, dict) else None
        if not isinstance(values, list) or len(values) != 1:
            raise ValueError('signature status response width mismatch')
        current = values[0]
        if isinstance(current, dict) and current.get('confirmationStatus') == 'finalized':
            if current.get('err') is not None:
                raise ValueError('ambiguous Full signature finalized with an error')
            slot = execute.base.integer(current.get('slot'), 1)
            transaction = rpc('getTransaction', [signature, {
                'commitment': 'finalized', 'maxSupportedTransactionVersion': 0,
                'encoding': 'json'}])
            if (not isinstance(transaction, dict)
                    or type(transaction.get('slot')) is not int
                    or transaction.get('slot') != slot
                    or not isinstance(transaction.get('meta'), dict)
                    or transaction['meta'].get('err') is not None):
                raise ValueError('finalized transaction record does not confirm success')
            transaction_body = transaction.get('transaction')
            signatures = (transaction_body.get('signatures')
                          if isinstance(transaction_body, dict) else None)
            if not isinstance(signatures, list) or not signatures or signatures[0] != signature:
                raise ValueError('finalized transaction signature differs from proxy receipt')
            return {
                'schema': 'part5-v3-ambiguous-finality-receipt-v1',
                'signature': signature,
                'signature_status': {
                    'slot': slot,
                    'confirmationStatus': 'finalized',
                    'err': None,
                },
                'transaction': {
                    'slot': slot,
                    'meta': {'err': None},
                    'signatures': [signature],
                },
            }
        time.sleep(0.1)


def _persist_finality_receipt(control: Path, receipt: dict) -> tuple[str, str]:
    if (type(receipt) is not dict
            or set(receipt) != {'schema', 'signature', 'signature_status', 'transaction'}
            or receipt.get('schema') != 'part5-v3-ambiguous-finality-receipt-v1'):
        raise ValueError('scrubbed finalized signature receipt required')
    signature_status = receipt.get('signature_status')
    transaction = receipt.get('transaction')
    if (type(signature_status) is not dict
            or set(signature_status) != {'slot', 'confirmationStatus', 'err'}
            or signature_status.get('confirmationStatus') != 'finalized'
            or signature_status.get('err') is not None
            or type(transaction) is not dict
            or set(transaction) != {'slot', 'meta', 'signatures'}
            or type(transaction.get('meta')) is not dict
            or set(transaction['meta']) != {'err'}
            or transaction['meta'].get('err') is not None
            or transaction.get('signatures') != [receipt.get('signature')]):
        raise ValueError('scrubbed finalized signature receipt required')
    slot = execute.base.integer(signature_status.get('slot'), 1)
    if type(transaction.get('slot')) is not int or transaction['slot'] != slot:
        raise ValueError('finality receipt transaction slot mismatch')
    signature = receipt.get('signature')
    proxy.decode_base58_signature(signature)
    expected = {
        'schema': 'part5-v3-ambiguous-finality-receipt-v1',
        'signature': signature,
        'signature_status': {'slot': slot, 'confirmationStatus': 'finalized', 'err': None},
        'transaction': {'slot': slot, 'meta': {'err': None},
                        'signatures': [signature]},
    }
    path = control / 'finality-receipt.json'
    raw = (json.dumps(expected, sort_keys=True, separators=(',', ':'),
                      allow_nan=False) + '\n').encode()
    _write_new_bytes(path, raw)
    directory_fd = os.open(control, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    info = path.lstat()
    if info.st_nlink != 1:
        raise ValueError('finality receipt must have one link')
    return str(path), _sha(raw)


def _finalized_accounts(rpc, report, minimum_slot, program, sizes, deadline):
    keys = [report[name] for name in ACCOUNT_NAMES]
    while True:
        _check_deadline(deadline)
        result = rpc('getMultipleAccounts', [keys, {
            'encoding': 'base64', 'commitment': 'finalized',
            'minContextSlot': minimum_slot}])
        try:
            slot, accounts = execute.base.batch_result(result, 5, minimum_slot)
        except execute.base.NotReady:
            time.sleep(0.1)
            continue
        raw_accounts = []
        for index, account in enumerate(accounts):
            if (not isinstance(account, dict) or account.get('owner') != program
                    or account.get('executable') is not False):
                raise ValueError('finalized application account owner/executable mismatch')
            raw = execute.base.account_bytes(account)
            if len(raw) != sizes[index]:
                raise ValueError('finalized account size differs from the staged role')
            raw_accounts.append(raw)
        return slot, raw_accounts


def _load_pre_submit_snapshot(output: Path, expected_sizes: list[int], minimum_slot: int,
                              config: dict, staged: dict) -> tuple[dict, list[bytes], str]:
    report_path = output / 'pre-submit-report.json'
    if not report_path.exists() or report_path.is_symlink():
        raise ValueError('pinned direct pre-submit finalized snapshot required')
    report, report_sha = _read_private_json(report_path)
    if (report.get('schema') != PREPOSITIVE_SCHEMA
            or type(report.get('finalized_slot')) is not int
            or isinstance(report.get('finalized_slot'), bool)
            or report['finalized_slot'] < minimum_slot
            or report.get('training_only') is not True
            or report.get('application_effect') is not False
            or report.get('request_consumed') is not False
            or report.get('stage_report_sha256') != config['stage_report_sha256']
            or report.get('stage_plan_sha256') != config['stage_plan_sha256']
            or report.get('wire_sha256') != config['full_wire_sha256']
            or report.get('program') != config['expected_program']
            or report.get('genesis') != config['expected_genesis']
            or report.get('addresses') != {name: staged[name] for name in ACCOUNT_NAMES}
            or report.get('loaded_program', {}).get('elf_match') is not True
            or report.get('loaded_program', {}).get('elf_sha256') != config['expected_elf_sha256']
            or type(report.get('account_sha256')) is not list
            or len(report['account_sha256']) != 5):
        raise ValueError('Rust pre-submit finalized snapshot report is malformed or unpinned')
    snapshots = []
    if len(expected_sizes) != 5:
        raise ValueError('five staged account sizes required')
    snapshots = []
    for name, expected_size, expected_hash in zip(
            ACCOUNT_NAMES, expected_sizes, report['account_sha256']):
        saved, digest = execute.stage.snapshot_generated(output / f'pre-submit-{name}.bin', 4096)
        if len(saved) != expected_size or digest != expected_hash:
            raise ValueError('Rust pre-submit account bytes differ from its pinned report')
        snapshots.append(saved)
    return report, snapshots, report_sha


def _config_for_execute(config: dict) -> dict:
    execute_config = dict(config)
    execute_config['schema'] = 1
    execute_config['scope'] = 'part5-v3-local-execute'
    return execute_config


def _validate_config(config: dict) -> None:
    required = {
        'schema', 'scope', 'outer_limits_required', 'proxy_script',
        'proxy_script_sha256', 'proxy_port', 'expected_program', 'expected_genesis',
        'expected_elf_sha256', 'prior_monitor_owner', 'execute_output', 'control_output',
        'prior_stage_config', 'prior_stage_config_sha256', 'prior_stage_status',
        'prior_stage_status_sha256', 'prior_stage_monitor', 'prior_stage_monitor_sha256',
        'stage_root', 'stage_report_sha256', 'stage_plan_sha256', 'ledger',
        'heldout_r0_clone_report', 'heldout_r0_clone_report_sha256', 'runner',
        'runner_sha256', 'context', 'context_sha256', 'full_wire', 'full_wire_sha256',
        'replay_full_wire', 'replay_full_wire_sha256'}
    if (type(config) is not dict or config.get('schema') != SCHEMA
            or config.get('scope') != SCOPE or config.get('outer_limits_required') != LIMITS
            or not required.issubset(config)):
        raise ValueError('explicit pinned ambiguous-restart contract required')
    if type(config.get('proxy_port')) is not int or not 1024 <= config['proxy_port'] <= 65535:
        raise ValueError('bounded loopback proxy port required')
    for field in ('proxy_script_sha256', 'expected_elf_sha256'):
        _receipt_digest(config.get(field), field)
    execute.base.key(config['expected_program'])
    execute.base.key(config['expected_genesis'])
    if config['proxy_port'] in {18999, 19000, 19001, 18901, *range(19002, 19029)}:
        raise ValueError('proxy port overlaps the validator port range')


def run(config: dict, config_sha256: str, config_path: str) -> int:
    started = time.monotonic()
    deadline = started + SUPERVISOR_BUDGET_SECONDS
    if os.environ.get('P5_V3_AMBIGUOUS_RESTART_SUPERVISOR') != SCOPE:
        raise ValueError('explicit bounded ambiguous-restart scope required')
    _validate_config(config)
    config_path = Path(config_path)
    if not config_path.is_absolute() or config_path.resolve(strict=True) != config_path:
        raise ValueError('canonical absolute supervisor config path required')
    encoded = (json.dumps(config, sort_keys=True, separators=(',', ':'),
                          allow_nan=False) + '\n').encode()
    if _sha(encoded) != config_sha256:
        raise ValueError('ambiguous-restart config hash mismatch')
    _check_deadline(deadline)

    execution = _config_for_execute(config)
    original, prior, staged, elf, sizes, output, control = execute.admit(execution)
    _check_deadline(deadline)
    if (original.get('program') != config['expected_program']
            or original.get('elf_sha256') != config['expected_elf_sha256']
            or staged.get('genesis') != config['expected_genesis']):
        raise ValueError('ambiguous-restart expected loader identity differs from reviewed stage')
    execute.base.checked(config['proxy_script'], config['proxy_script_sha256'], 128 * 1024 * 1024)
    context_raw = execute.stage.snapshot_generated(config['context'], 8192)[0]
    context = execute.base.decode_json(context_raw)
    if context.get('schema') != 'part5-v3-local-training-context-v1' or context.get('training_only') is not True:
        raise ValueError('pinned local training context required')
    wire, wire_sha = execute.stage.snapshot_generated(config['full_wire'], 448)
    if len(wire) != 448 or wire_sha != config['full_wire_sha256']:
        raise ValueError('pinned Full wire required')

    output, control = Path(output), Path(control)
    ledger = Path(config['ledger'])
    validator = runner = proxy_proc = None
    streams = []
    handlers = {}
    status = {
        'schema': 1, 'scope': SCOPE, 'status': 'failed',
        'heldout_acceptance': False, 'config_sha256': config_sha256,
        'outer_limits_required': LIMITS, 'effect_outcome': 'requires_reconciliation',
        'proof_mode': 'Full', 'full_wire_sha256': wire_sha,
        'ledger_path_sha256': _sha(str(ledger).encode()),
        'expected_program': config['expected_program'],
        'expected_genesis': config['expected_genesis'],
        'expected_elf_sha256': config['expected_elf_sha256'],
        'stage_report_sha256': config['stage_report_sha256'],
        'stage_plan_sha256': config['stage_plan_sha256'],
        'heldout_r0_clone_report_sha256': config['heldout_r0_clone_report_sha256'],
        'runner_sha256': config['runner_sha256'],
        'proxy_script_sha256': config['proxy_script_sha256'],
        'context_sha256': config['context_sha256'],
        'replay_full_wire_sha256': config['replay_full_wire_sha256'],
        'finality_receipt_path': str(control / 'finality-receipt.json'),
        'finality_receipt_sha256': None,
        'proxy_receipt_verified': False, 'expected_transport_failure': False,
        'restart_identity_verified': False, 'signature_finalized_success': False,
        'five_account_reconciliation_verified': False,
        'prepositive_snapshot_saved_by_runner': False,
        'whole_tree_cleanup_authority': 'external bounded_runner',
    }

    def interrupted(signum, frame):
        raise InterruptedError('ambiguous-restart supervisor interrupted')

    try:
        _check_deadline(deadline)
        control.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        execute.base.ports_free(timeout_seconds=execute.base.PORT_WAIT_SECONDS)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', config['proxy_port']))
        argv = execute.stage.resume_argv(original['validator'], ledger)
        if '--reset' in argv:
            raise ValueError('same-ledger validator restart must not reset state')
        execute.base.write_new(control / 'invocation.json', {
            'validator_argv': argv, 'runner': config['runner'],
            'runner_sha256': config['runner_sha256'], 'proxy_script_sha256': config['proxy_script_sha256'],
            'stage_report_sha256': config['stage_report_sha256'],
            'stage_plan_sha256': config['stage_plan_sha256'], 'full_wire_sha256': wire_sha,
            'proxy_port': config['proxy_port'], 'outer_limits_required': LIMITS})
        for name in ('validator.stdout.log', 'validator.stderr.log', 'proxy.stdout.log',
                     'proxy.stderr.log', 'runner.stdout.log', 'runner.stderr.log'):
            streams.append(_write_log(control / name))
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        validator = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                     stdout=streams[0], stderr=streams[1], start_new_session=False)
        rpc = execute.base.LocalRpc()
        loaded = _wait_loaded(rpc, validator, original, elf, deadline)
        execute.same_loaded(prior['loaded_program'], loaded)
        if (loaded.get('program') != config['expected_program']
                or loaded.get('genesis') != config['expected_genesis']):
            raise ValueError('loaded heldout clone identity mismatch')
        pre_slot, before = _wait_staged(
            rpc, staged, original['program'], sizes, deadline)
        staged_bytes = [execute.stage.snapshot_generated(
            Path(config['stage_root']) / (name + '.bin'), 4096)[0] for name in ACCOUNT_NAMES]
        if before != staged_bytes:
            raise ValueError('heldout clone does not start from the exact staged accounts')
        context_for_effect = {
            'root': bytes.fromhex(context['root']),
            'request': execute.base.key(staged['request'])}
        status.update({'initial_finalized_slot': pre_slot,
                       'initial_account_sha256': [_sha(raw) for raw in before],
                       'loaded_program_before': loaded})
        genesis_before, genesis_before_sha = execute.stage.snapshot_generated(
            ledger / 'genesis.bin', 16 * 1024 * 1024)
        if not genesis_before:
            raise ValueError('persistent heldout ledger genesis missing before stop')
        status['ledger_genesis_sha256_before_stop'] = genesis_before_sha

        receipt_path = control / 'proxy-receipt.json'
        proxy_argv = [sys.executable, config['proxy_script'], '--upstream-url',
            execute.base.RPC.rstrip('/'), '--bind-host', '127.0.0.1',
            '--port', str(config['proxy_port']), '--wire-path', config['full_wire'],
            '--wire-sha256', wire_sha, '--receipt-path', str(receipt_path)]
        proxy_proc = subprocess.Popen(proxy_argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
            stdout=streams[2], stderr=streams[3], start_new_session=False)
        _wait_proxy(proxy_proc, '127.0.0.1', config['proxy_port'], deadline)
        env.update({
            'P5_V3_EXEC_SCOPE': 'part5-v3-local-execute',
            'P5_V3_AMBIGUOUS_SNAPSHOT': '1',
            'P5_V3_STAGE_ROOT': config['stage_root'],
            'P5_V3_STAGE_REPORT_SHA256': config['stage_report_sha256'],
            'P5_V3_STAGE_PLAN_SHA256': config['stage_plan_sha256'],
            'P5_V3_FULL_WIRE': config['full_wire'],
            'P5_V3_FULL_WIRE_SHA256': wire_sha,
            'P5_V3_REPLAY_FULL_WIRE': config['replay_full_wire'],
            'P5_V3_REPLAY_FULL_WIRE_SHA256': config['replay_full_wire_sha256'],
            'P5_V3_CONTEXT': config['context'],
            'P5_V3_CONTEXT_SHA256': config['context_sha256'],
            'P5_QUEUE_RPC': f'http://127.0.0.1:{config["proxy_port"]}/',
            'P5_QUEUE_PROGRAM': original['program'], 'P5_QUEUE_GENESIS': loaded['genesis'],
            'P5_QUEUE_ELF': original['elf'], 'P5_QUEUE_ELF_SHA256': original['elf_sha256'],
            'P5_QUEUE_OUTPUT': str(output)})
        runner_argv = [config['runner'], 'root_pinned_queue_v3_execute', '--exact',
                       '--ignored', '--test-threads=1']
        runner = subprocess.Popen(runner_argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
            stdout=streams[4], stderr=streams[5], start_new_session=False)
        return_code = _wait_child(runner, validator, deadline)
        stdout, _ = execute.stage.snapshot_generated(control / 'runner.stdout.log', 65536)
        stderr, _ = execute.stage.snapshot_generated(control / 'runner.stderr.log', 65536)
        receipt, receipt_sha = _read_private_json(receipt_path, 4096)
        receipt = validate_proxy_receipt(receipt, wire_sha)
        expected_transport_failure(return_code, stdout, stderr, receipt, wire_sha)
        status.update({
            'proxy_receipt_verified': True,
            'proxy_receipt_sha256': receipt_sha,
            'transaction_sha256': receipt['transaction_sha256'],
            'signature_sha256': _sha(receipt['signature'].encode()),
            'proxy_status': receipt['status'],
            'matching_submissions': receipt['matching_submissions'],
            'retry_count': receipt['duplicate_matching_submissions'],
            'runner_exit_code': return_code,
            'expected_transport_failure': True,
        })
        pre_submit_report, pre_submit, pre_submit_report_sha = _load_pre_submit_snapshot(
            output, sizes, pre_slot, config, staged)
        _pre_submit_matches_stage_transition(before, pre_submit, context_for_effect)
        status.update({
            'prepositive_snapshot_saved_by_runner': True,
            'pre_submit_report_sha256': pre_submit_report_sha,
            'pre_submit_finalized_slot': pre_submit_report['finalized_slot'],
            'pre_submit_account_sha256': pre_submit_report['account_sha256'],
        })

        proxy_cleanup = _stop_proxy(proxy_proc)
        proxy_proc = None
        first_stop = execute.base.cleanup(validator)
        validator = None
        status.update({'proxy_cleanup': proxy_cleanup, 'first_validator_cleanup': first_stop,
                       'first_validator_stop_mode': reviewed_validator_stop(first_stop)})
        genesis_raw, genesis_sha = execute.stage.snapshot_generated(ledger / 'genesis.bin', 16 * 1024 * 1024)
        if not genesis_raw or genesis_sha != genesis_before_sha:
            raise ValueError('persistent heldout ledger genesis changed after stop')
        status['ledger_genesis_sha256_after_stop'] = genesis_sha
        _check_deadline(deadline)

        restart_argv = execute.stage.resume_argv(original['validator'], ledger)
        if '--reset' in restart_argv:
            raise ValueError('same-ledger restart unexpectedly requests reset')
        validator = subprocess.Popen(restart_argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                     stdout=streams[0], stderr=streams[1], start_new_session=False)
        reloaded = _wait_loaded(rpc, validator, original, elf, deadline)
        execute.same_loaded(loaded, reloaded)
        if reloaded.get('genesis') != config['expected_genesis']:
            raise ValueError('same-ledger restart genesis mismatch')
        status.update({'restart_identity_verified': True, 'loaded_program_after': reloaded})

        finality_receipt = _wait_finalized_signature(rpc, receipt['signature'], deadline)
        finality_receipt_path, finality_receipt_sha256 = _persist_finality_receipt(
            control, finality_receipt)
        signature_slot = finality_receipt['signature_status']['slot']
        if pre_submit_report['finalized_slot'] > signature_slot:
            raise ValueError('pre-submit snapshot slot is later than the submitted transaction')
        status.update({'signature_finalized_success': True,
                       'signature_sha256': _sha(receipt['signature'].encode()),
                       'signature_finalized_slot': signature_slot,
                       'finality_receipt_path': finality_receipt_path,
                       'finality_receipt_sha256': finality_receipt_sha256})
        minimum_slot, after = _finalized_accounts(
            rpc, staged, signature_slot, original['program'], sizes, deadline)
        account_hashes = reconcile_final_accounts(
            before, after, context_for_effect, pre_submit)
        saved_hashes, saved_paths = _persist_final_account_bytes(output, after)
        if saved_hashes != account_hashes:
            raise ValueError('saved finalized account hashes differ from reconciled hashes')
        status.update({'five_account_reconciliation_verified': True,
                       'finalized_accounts_slot': minimum_slot,
                       'final_account_sha256': saved_hashes,
                       'final_account_paths': saved_paths,
                       'effect_count': 1, 'request_consumed': True,
                       'queue_appends': 1, 'application_effect': True,
                       'effect_outcome': 'reconciled_by_deterministic_transition'})
    except Exception as error:
        status['error_type'] = type(error).__name__
        status['error_message'] = str(error)[:256]
        if (status.get('proxy_receipt_verified') is True
                and status.get('prepositive_snapshot_saved_by_runner') is not True):
            status['limitation'] = (
                'Required direct pre-submit snapshot was absent or failed pin checks; '
                'validator restart and reconciliation were skipped.')
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        if proxy_proc is not None:
            try:
                status['proxy_cleanup'] = execute.base.cleanup(proxy_proc)
            except Exception as error:
                status['proxy_cleanup'] = {'reaped': False, 'error_type': type(error).__name__}
        if runner is not None and runner.poll() is None:
            try:
                status['runner_cleanup'] = execute.base.cleanup(runner)
            except Exception as error:
                status['runner_cleanup'] = {'reaped': False, 'error_type': type(error).__name__}
        if validator is not None:
            try:
                status['final_validator_cleanup'] = execute.base.cleanup(validator)
            except Exception as error:
                status['final_validator_cleanup'] = {'reaped': False, 'error_type': type(error).__name__}
        for key in ('first', 'final'):
            try:
                status[key + '_validator_stop_mode'] = reviewed_validator_stop(
                    status.get(key + '_validator_cleanup'))
            except ValueError:
                pass
        status['elapsed_seconds'] = time.monotonic() - started
        status['cleanup_verified'] = (
            status.get('proxy_cleanup', {}).get('reaped') is True
            and status.get('proxy_cleanup', {}).get('graceful') is True
            and status.get('proxy_cleanup', {}).get('exit_code') == 0
            and status.get('first_validator_stop_mode') in
                ('clean_zero', 'interrupted_sigint')
            and status.get('final_validator_stop_mode') in
                ('clean_zero', 'interrupted_sigint'))
        if status.get('error_type') is None:
            status.update(final_status({key: status.get(key) for key in (
                'proxy_receipt_verified', 'expected_transport_failure',
                'restart_identity_verified', 'signature_finalized_success',
                'five_account_reconciliation_verified',
                'prepositive_snapshot_saved_by_runner')
                } | {'cleanup_verified': status['cleanup_verified']}))
        for stream in streams:
            stream.close()
        try:
            if control.is_dir() and not (control / 'status.json').exists():
                execute.base.write_new(control / 'status.json', status)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    print(json.dumps({'status': status['status'], 'heldout_acceptance': status['heldout_acceptance'],
                      'status_report': str(control / 'status.json')}))
    return 0 if status['status'] == 'passed' else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    config = execute.pinned_json(args.config, args.config_sha256, 65536)
    return run(config, args.config_sha256, str(args.config))


if __name__ == '__main__':
    sys.exit(main())
