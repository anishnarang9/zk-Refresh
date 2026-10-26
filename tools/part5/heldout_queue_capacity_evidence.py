#!/usr/bin/env python3
"""Validate supplied capacity evidence, without RPC, execution, or acceptance.

Exact v1 schema (all objects reject extra/missing fields):
root: schema='part5-v3-heldout-queue-capacity-evidence-v1', identities,
 fill_history, before_queue_addresses, after_queue_addresses, rejected_request,
 preconditions, snapshots, owner.
identities: freeze_sha256, genesis_sha256, elf_sha256, stage_sha256,
 proof_sha256, wire_sha256, clone_sha256 (64 lowercase hex; equal external pins).
fill_history: exactly 64 rows with request_address, signature, slot, finalized,
 consumed, queue_after_addresses, request_before_sha256, request_after_sha256,
 queue_before_sha256, queue_after_sha256; shared loaded-negative helper semantics.
rejected_request: request_address, signature, slot (positive int), finalized=true,
 consumed=false, rpc_error={'InstructionError':[1,{'Custom':708}]}.
preconditions: status_active, issuer_active, head_bound, request_live,
 full_wire_valid (all true), observed_at, expires_at, now, request_deadline
 (nonnegative integer clocks; fresh lifetime <=300, now before both deadlines).
snapshots: five ordered rows name=config/issuer/head/request/queue, before, after.
 Each reference: path (relative to supplied evidence directory, no symlinks or
 traversal), sha256; file size 1..1048576 bytes; paired bytes must be identical.
owner: wall_limit_seconds, rss_limit_bytes, storage_limit_bytes (positive finite
 numbers, booleans excluded), wall_seconds, peak_owned_rss_bytes,
 storage_growth_bytes (finite nonnegative, within limits), ownership_known=true,
 cleanup_complete=true, remaining_owned_processes=0.
Addresses/signatures are opaque bounded strings; their on-chain authenticity,
report truth, ownership and actual execution remain outside this pure check.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

from harness.tests import queue_v3_loaded_negative_checks as checks
from tools.part5 import verify_v3_campaign_public_projection as public

SCHEMA = 'part5-v3-heldout-queue-capacity-evidence-v1'
IDENTITIES = {name + '_sha256' for name in ('freeze', 'genesis', 'elf', 'stage', 'proof', 'wire', 'clone')}
MAX_REPORT_BYTES = 1024 * 1024
MAX_ACCOUNT_BYTES = 1024 * 1024
SCOPE = ('supplied report consistency and snapshot bytes only; no loaded execution, '
         'on-chain authenticity, report truth, or heldout acceptance established')


def _fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError('unknown or missing evidence fields')


def _true(value):
    if value is not True:
        raise ValueError('required evidence precondition is not true')


def _hash(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('invalid evidence SHA-256')


def _integer(value, positive=False):
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError('invalid evidence integer')


def _number(value, positive=False):
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        valid = False
    if not valid or (positive and value == 0):
        raise ValueError('invalid finite owner bound or measurement')


def _opaque(value):
    if type(value) is not str or not 1 <= len(value) <= 128 or any(c.isspace() for c in value):
        raise ValueError('invalid bounded address or signature')


def _read_bounded_regular(path, cap):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
                raise ValueError('evidence file must be a bounded nonempty regular file')
            raw = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
        stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(raw) != before.st_size or len(raw) > cap
                or any(getattr(before, key) != getattr(after, key) for key in stable)):
            raise ValueError('evidence file changed during read')
    except OSError as error:
        raise ValueError('evidence file unavailable') from error
    return raw


def _snapshot(reference, root):
    _fields(reference, {'path', 'sha256'})
    _hash(reference['sha256'])
    name = reference['path']
    if type(name) is not str or not name or len(name) > 1024:
        raise ValueError('invalid snapshot reference')
    relative = Path(name)
    if relative.is_absolute() or any(part in ('.', '..') for part in name.split('/')):
        raise ValueError('snapshot reference must be bounded relative path')
    path = root / relative
    try:
        if path.resolve(strict=True) != path or not path.is_relative_to(root):
            raise ValueError('snapshot must be an in-directory regular file')
    except OSError as error:
        raise ValueError('snapshot unavailable') from error
    raw = _read_bounded_regular(path, MAX_ACCOUNT_BYTES)
    if hashlib.sha256(raw).hexdigest() != reference['sha256']:
        raise ValueError('snapshot digest mismatch')
    return raw


def validate_report(report, evidence_dir, expected_identities):
    """Check supplied evidence against independently selected identity pins."""
    root = Path(evidence_dir).absolute()
    if root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError('evidence directory must be real and have no symlink parents')
    _fields(report, {'schema', 'identities', 'fill_history', 'before_queue_addresses',
                     'after_queue_addresses', 'rejected_request', 'preconditions', 'snapshots', 'owner'})
    if report['schema'] != SCHEMA:
        raise ValueError('unsupported capacity evidence schema')
    for identities in (report['identities'], expected_identities):
        _fields(identities, IDENTITIES)
        for digest in identities.values():
            _hash(digest)
    if report['identities'] != expected_identities:
        raise ValueError('capacity evidence identity drift')
    rejected = report['rejected_request']
    _fields(rejected, {'request_address', 'signature', 'slot', 'finalized', 'consumed', 'rpc_error'})
    _opaque(rejected['request_address'])
    _opaque(rejected['signature'])
    _integer(rejected['slot'], True)
    _true(rejected['finalized'])
    if rejected['consumed'] is not False:
        raise ValueError('rejected request must remain unconsumed')
    # The shared helper uses Python equality; enforce exact JSON integer types too.
    _fields(rejected['rpc_error'], {'InstructionError'})
    error = rejected['rpc_error']['InstructionError']
    if type(error) is not list or len(error) != 2 or type(error[0]) is not int:
        raise ValueError('invalid Execute error shape')
    _fields(error[1], {'Custom'})
    if type(error[1]['Custom']) is not int:
        raise ValueError('invalid custom error type')
    checks.check_execute_error(rejected['rpc_error'], 708)
    checks.check_full_queue(report['before_queue_addresses'], report['after_queue_addresses'], rejected['request_address'])
    signatures = set()
    previous_slot = 0
    for row in report['fill_history']:
        _opaque(row['request_address'])
        _opaque(row['signature'])
        if row['signature'] in signatures or row['signature'] == rejected['signature'] or row['slot'] < previous_slot:
            raise ValueError('fill transaction identities/order invalid')
        signatures.add(row['signature'])
        previous_slot = row['slot']
    if rejected['slot'] < previous_slot:
        raise ValueError('rejection predates fill history')
    if report['before_queue_addresses'] != report['after_queue_addresses']:
        raise ValueError('capacity rejection changed queue order')
    preconditions = report['preconditions']
    flags = {'status_active', 'issuer_active', 'head_bound', 'request_live', 'full_wire_valid'}
    _fields(preconditions, flags | {'observed_at', 'expires_at', 'now', 'request_deadline'})
    for name in flags:
        _true(preconditions[name])
    for name in ('observed_at', 'expires_at', 'now', 'request_deadline'):
        _integer(preconditions[name])
    observed, expiry, now = (preconditions[name] for name in ('observed_at', 'expires_at', 'now'))
    if not (observed <= now < expiry <= observed + checks.STATUS_MAX_AGE
            and now < preconditions['request_deadline']):
        raise ValueError('status or request is not fresh at rejection')
    snapshots = report['snapshots']
    if type(snapshots) is not list or len(snapshots) != 5:
        raise ValueError('exactly five ordered snapshots required')
    before, after = {}, {}
    for row, name in zip(snapshots, checks.ACCOUNT_NAMES):
        _fields(row, {'name', 'before', 'after'})
        if row['name'] != name:
            raise ValueError('application account snapshot order mismatch')
        before[name], after[name] = _snapshot(row['before'], root), _snapshot(row['after'], root)
    checks.check_application_accounts_unchanged(before, after)
    checks.check_finalized_fill_history(
        report['fill_history'], report['before_queue_addresses'], rejected['request_address'],
        snapshots[checks.ACCOUNT_NAMES.index('queue')]['before']['sha256'])
    owner = report['owner']
    _fields(owner, {'wall_limit_seconds', 'rss_limit_bytes', 'storage_limit_bytes', 'wall_seconds',
                    'peak_owned_rss_bytes', 'storage_growth_bytes', 'ownership_known',
                    'cleanup_complete', 'remaining_owned_processes'})
    _true(owner['ownership_known'])
    _true(owner['cleanup_complete'])
    _integer(owner['remaining_owned_processes'])
    if owner['remaining_owned_processes'] != 0:
        raise ValueError('owned processes remain')
    for measured, limit in (('wall_seconds', 'wall_limit_seconds'), ('peak_owned_rss_bytes', 'rss_limit_bytes'),
                            ('storage_growth_bytes', 'storage_limit_bytes')):
        _number(owner[measured])
        _number(owner[limit], True)
        if owner[measured] > owner[limit]:
            raise ValueError('owner limit exceeded')
    # Reopen all ten refs after the remaining checks, including shared-inode refs.
    for row in snapshots:
        for phase in ('before', 'after'):
            if _snapshot(row[phase], root) != before[row['name']]:
                raise ValueError('snapshot changed during evidence validation')
    return {'schema': SCHEMA, 'report_consistent': True, 'scope': SCOPE,
            'successful_fill_count': 64, 'queue_capacity': 64,
            'rejected_request_unconsumed': True, 'execute_instruction_index': 1,
            'custom_error': 708, 'unchanged_application_account_count': 5,
            'cleanup_known': True, 'loaded_run_established': False, 'heldout_acceptance_established': False}


def verify_file(report_path, evidence_dir, expected_identities):
    """Decode bounded strict JSON then check supplied report evidence."""
    report_path = Path(report_path)
    if not report_path.is_absolute() or report_path.resolve(strict=True) != report_path:
        raise ValueError('canonical nonsymlink capacity report required')
    raw = _read_bounded_regular(report_path, MAX_REPORT_BYTES)
    report = public._json_object(raw, 'capacity report')
    return validate_report(report, evidence_dir, expected_identities)
