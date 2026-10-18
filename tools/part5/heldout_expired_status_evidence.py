"""Strict, read-only contract for prospective loaded expired-status evidence.

This new standalone v1 contract is deliberately unintegrated with heldout
acceptance. A report has exactly: schema, identities, clock, preconditions,
transaction, source_refs, snapshots, limits, measured, cleanup, application_effect.
source_refs has exactly full_proof and full_wire path/sha256 references. The
full_proof identity is the raw SHA-256 of the Full proof RECEIPT JSON bytes;
full_wire is the raw SHA-256 of its separate complete wire artifact bytes.
Receipt contents and wire semantics are outside this consistency check.
Identity roles include genesis and must equal separately supplied expected
pins exactly. They are opaque SHA-256 pins, not authenticated preimages. Snapshots
are five ordered account rows, each with name and before/after {path, sha256}
references. Times are seconds; byte limits are positive integers. Measured
owner wall, clock wait, peak owned RSS and storage growth must fit those limits.
A finalized
RPC clock and transaction, valid Full wire, active issuer/status, bound head,
and live request are explicit publisher assertions. This checker validates
those assertions and reopened snapshot bytes; it does not contact RPC, verify
a proof or wire, authenticate issuer signatures, or establish acceptance.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

from harness.tests import queue_v3_loaded_negative_checks as checks

SCHEMA = 'part5-v3-heldout-expired-status-evidence-v1'
FACTS_SCHEMA = 'part5-v3-heldout-expired-status-validated-facts-v1'
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
IDENTITY_ROLES = ('freeze', 'genesis', 'loaded_elf', 'stage', 'clone', 'full_proof', 'full_wire')
REPORT_FIELDS = {'schema', 'identities', 'clock', 'preconditions', 'transaction',
                 'source_refs', 'snapshots', 'limits', 'measured', 'cleanup', 'application_effect'}


def _fields(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError('unknown or missing evidence field')


def _hash(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('lowercase SHA-256 required')
    return value


def _number(value, positive=False, integer=False):
    try:
        valid = (type(value) in ((int,) if integer else (int, float))
                 and math.isfinite(value) and value >= 0
                 and (not positive or value > 0))
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError('finite bounded measurement required')
    return value


def _true(value):
    if value is not True:
        raise ValueError('true evidence assertion required')


def _snapshot(ref, cap=None):
    if cap is None:
        cap = MAX_SNAPSHOT_BYTES
    _fields(ref, ('path', 'sha256'))
    digest = _hash(ref['sha256'])
    if type(ref['path']) is not str:
        raise ValueError('canonical snapshot path required')
    path = Path(ref['path'])
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('canonical nonsymlink snapshot required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
                raise ValueError('bounded nonempty regular snapshot required')
            raw = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
        stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(raw) > cap
                or any(getattr(before, key) != getattr(after, key) for key in stable)
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('snapshot changed or hash mismatch')
        return raw
    except (OSError, RuntimeError):
        raise ValueError('snapshot unavailable') from None


def validate_report(report, expected_identities):
    """Validate an already decoded report; return path-free facts, never acceptance."""
    _fields(report, REPORT_FIELDS)
    if report['schema'] != SCHEMA or report['application_effect'] is not False:
        raise ValueError('expired-status evidence without application effect required')
    identities = report['identities']
    _fields(identities, IDENTITY_ROLES)
    _fields(expected_identities, IDENTITY_ROLES)
    for mapping in (identities, expected_identities):
        for value in mapping.values():
            _hash(value)
    if identities != expected_identities:
        raise ValueError('expired-status evidence identity drift')
    source_refs = report['source_refs']
    _fields(source_refs, ('full_proof', 'full_wire'))
    for role, ref in source_refs.items():
        _fields(ref, ('path', 'sha256'))
        if ref['sha256'] != expected_identities[role]:
            raise ValueError('Full source reference differs from expected identity')
        _snapshot(ref, MAX_SOURCE_BYTES)
    clock = report['clock']
    _fields(clock, ('observed_at', 'expires_at', 'now', 'rpc_finalized'))
    _true(clock['rpc_finalized'])
    preconditions = report['preconditions']
    _fields(preconditions, ('status_active', 'issuer_active', 'head_bound',
                            'request_live', 'full_wire_valid'))
    checks.check_expired_status(**{key: clock[key] for key in ('observed_at', 'expires_at', 'now')},
                                **preconditions)
    transaction = report['transaction']
    _fields(transaction, ('signature', 'slot', 'finalized', 'error'))
    _true(transaction['finalized'])
    _number(transaction['slot'], positive=True, integer=True)
    if (type(transaction['signature']) is not str
            or re.fullmatch('[1-9A-HJ-NP-Za-km-z]{64,88}', transaction['signature']) is None):
        raise ValueError('transaction signature required')
    error = transaction['error']
    checks.check_execute_error(error, 705)
    # Python equality treats True/1 and 705.0/705 as equal; reject those explicitly.
    if (type(error['InstructionError']) is not list
            or type(error['InstructionError'][0]) is not int
            or type(error['InstructionError'][1]['Custom']) is not int):
        raise ValueError('integer instruction and custom error required')
    limits = report['limits']
    _fields(limits, ('owner_wall_seconds', 'rss_bytes', 'storage_growth_bytes', 'clock_wait_seconds'))
    for key, value in limits.items():
        _number(value, positive=True, integer=key.endswith('_bytes'))
    measured = report['measured']
    _fields(measured, ('owner_wall_seconds', 'clock_wait_seconds',
                       'peak_owned_rss_bytes', 'storage_growth_bytes'))
    for measured_key, limit_key in (('owner_wall_seconds', 'owner_wall_seconds'),
                                    ('clock_wait_seconds', 'clock_wait_seconds'),
                                    ('peak_owned_rss_bytes', 'rss_bytes'),
                                    ('storage_growth_bytes', 'storage_growth_bytes')):
        value = _number(measured[measured_key], integer=measured_key.endswith('_bytes'))
        if value > limits[limit_key]:
            raise ValueError('owner resource or clock wait limit exceeded')
    if (measured['clock_wait_seconds'] > measured['owner_wall_seconds']
            or limits['clock_wait_seconds'] > limits['owner_wall_seconds']):
        raise ValueError('clock wait must fit owner wall bound')
    cleanup = report['cleanup']
    _fields(cleanup, ('remaining_owned_processes', 'status_unknown', 'runner_reaped',
                      'validator_reaped', 'censored', 'stop_reason', 'runner_error_type'))
    if (type(cleanup['remaining_owned_processes']) is not int
            or cleanup['remaining_owned_processes'] != 0
            or cleanup['status_unknown'] is not False
            or cleanup['runner_reaped'] is not True or cleanup['validator_reaped'] is not True
            or cleanup['censored'] is not False or cleanup['stop_reason'] is not None
            or cleanup['runner_error_type'] is not None):
        raise ValueError('known complete bounded cleanup required')
    snapshots = report['snapshots']
    if type(snapshots) is not list or len(snapshots) != 5:
        raise ValueError('five ordered application snapshots required')
    before, after = {}, {}
    for name, row in zip(checks.ACCOUNT_NAMES, snapshots):
        _fields(row, ('name', 'before', 'after'))
        if row['name'] != name:
            raise ValueError('canonical five-account order required')
        before[name], after[name] = _snapshot(row['before']), _snapshot(row['after'])
    checks.check_application_accounts_unchanged(before, after)
    # Reopen every source after all checks, including refs that shared an inode.
    for row in snapshots:
        for phase in ('before', 'after'):
            if _snapshot(row[phase]) != before[row['name']]:
                raise ValueError('snapshot changed during evidence validation')
    for ref in source_refs.values():
        _snapshot(ref, MAX_SOURCE_BYTES)
    return {'schema': FACTS_SCHEMA, 'identities': dict(identities),
            'loaded_run_established': False, 'heldout_acceptance_established': False,
            'observed_at': clock['observed_at'], 'expires_at': clock['expires_at'], 'now': clock['now'],
            'custom_error': 705, 'instruction_index': 1, 'finalized_slot': transaction['slot'],
            'application_account_count': 5, 'application_accounts_unchanged': True,
            'application_effect': False, 'measured': dict(measured),
            'snapshot_sha256': {row['name']: row['before']['sha256'] for row in snapshots}}


def verify_file(report_path, expected_identities):
    """Read bounded strict JSON without blocking on FIFOs; return consistency facts."""
    path = Path(report_path)
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('canonical nonsymlink report required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_REPORT_BYTES:
                raise ValueError('bounded nonempty regular report required')
            raw = stream.read(MAX_REPORT_BYTES + 1)
            after = os.fstat(stream.fileno())
        stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(raw) != before.st_size or len(raw) > MAX_REPORT_BYTES
                or any(getattr(before, key) != getattr(after, key) for key in stable)):
            raise ValueError('report changed during read')
    except (OSError, RuntimeError):
        raise ValueError('report unavailable') from None

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate report key')
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError('nonfinite report number')

    def finite(value):
        if type(value) is float and not math.isfinite(value):
            raise ValueError('nonfinite report number')
        if type(value) is dict:
            for child in value.values():
                finite(child)
        elif type(value) is list:
            for child in value:
                finite(child)

    try:
        report = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
        finite(report)
    except (UnicodeDecodeError, RecursionError):
        raise ValueError('invalid report JSON') from None
    return validate_report(report, expected_identities)
