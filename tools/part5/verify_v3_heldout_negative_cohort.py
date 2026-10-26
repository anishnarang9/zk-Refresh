#!/usr/bin/env python3
"""Prospective report-consistency gate; no heldout acceptance integration.

Exact v1 manifest: schema='part5-v3-heldout-negative-cohort-v1',
 common_identities={freeze_sha256,genesis_sha256,elf_sha256},
 expired_status_reports=[8 entries ordered variant 0..7],
 queue_capacity_reports=[exactly 1 entry].
Expired entry: variant, path, sha256, expected_identities (expired checker roles).
Capacity entry: path, sha256, expected_identities (capacity checker roles), evidence_dir.
Paths/directories are canonical absolute nonsymlink paths. SHA values are lowercase
64-hex. Expected identity pins and variant associations are supplied by the manifest
publisher; they do not authenticate withheld evidence or actual execution.
Expired reports must have distinct raw digests and distinct
(stage, clone, full_proof, full_wire) identity tuples.
"""
import hashlib
from pathlib import Path

from tools.part5 import heldout_expired_status_evidence as expired
from tools.part5 import heldout_queue_capacity_evidence as capacity
from tools.part5 import verify_v3_campaign_public_projection as public

SCHEMA = 'part5-v3-heldout-negative-cohort-v1'
MAX_MANIFEST_BYTES = 256 * 1024
COMMON = {'freeze_sha256', 'genesis_sha256', 'elf_sha256'}
SCOPE = ('supplied report consistency and publisher-selected variant identity associations only; '
         'no loaded run, evidence authenticity, or heldout acceptance established')


def _fields(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError('unknown or missing cohort evidence fields')


def _path(value, directory=False):
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError('invalid canonical evidence path')
    path = Path(value)
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('canonical nonsymlink evidence path required')
        if directory and not path.is_dir():
            raise ValueError('evidence directory required')
    except (OSError, RuntimeError):
        raise ValueError('evidence unavailable') from None
    return path


def _pin(path, cap, digest):
    capacity._hash(digest)
    raw = capacity._read_bounded_regular(path, cap)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('cohort evidence byte digest mismatch')
    return raw


def validate_manifest(manifest):
    """Validate externally selected report references and their common identities."""
    _fields(manifest, {'schema', 'common_identities', 'expired_status_reports', 'queue_capacity_reports'})
    if manifest['schema'] != SCHEMA:
        raise ValueError('unsupported negative cohort schema')
    common = manifest['common_identities']
    _fields(common, COMMON)
    for digest in common.values():
        capacity._hash(digest)
    stale, queue = manifest['expired_status_reports'], manifest['queue_capacity_reports']
    if type(stale) is not list or len(stale) != 8 or type(queue) is not list or len(queue) != 1:
        raise ValueError('exactly eight expired-status and one capacity report required')
    pins, paths = [], set()
    expired_hashes, expired_case_identities = set(), set()
    for variant, entry in enumerate(stale + queue):
        is_capacity = variant == 8
        _fields(entry, {'path', 'sha256', 'expected_identities'} | ({'evidence_dir'} if is_capacity else {'variant'}))
        if not is_capacity and (type(entry['variant']) is not int or entry['variant'] != variant):
            raise ValueError('expired-status variants must be ordered 0 through 7')
        path = _path(entry['path'])
        if path in paths:
            raise ValueError('cohort reports must use distinct paths')
        paths.add(path)
        expected = entry['expected_identities']
        _fields(expected, capacity.IDENTITIES if is_capacity else expired.IDENTITY_ROLES)
        for digest in expected.values():
            capacity._hash(digest)
        common_roles = ({key: key for key in COMMON} if is_capacity else
                        {'freeze_sha256': 'freeze', 'genesis_sha256': 'genesis', 'elf_sha256': 'loaded_elf'})
        for common_key, child_key in common_roles.items():
            if expected[child_key] != common[common_key]:
                raise ValueError('common freeze/genesis/ELF identity mismatch')
        if not is_capacity:
            case_identity = tuple(expected[role] for role in ('stage', 'clone', 'full_proof', 'full_wire'))
            if entry['sha256'] in expired_hashes or case_identity in expired_case_identities:
                raise ValueError('expired reports require distinct bytes and per-case identity tuples')
            expired_hashes.add(entry['sha256'])
            expired_case_identities.add(case_identity)
        cap = capacity.MAX_REPORT_BYTES if is_capacity else expired.MAX_REPORT_BYTES
        raw = _pin(path, cap, entry['sha256'])
        report = public._json_object(raw, 'negative evidence report')
        pins.append((path, cap, entry['sha256']))
        evidence_dir = _path(entry['evidence_dir'], directory=True) if is_capacity else None
        if is_capacity:
            facts = capacity.validate_report(report, evidence_dir, expected)
            if facts.get('report_consistent') is not True:
                raise ValueError('capacity report is inconsistent')
        else:
            facts = expired.validate_report(report, expected)
        if (facts.get('loaded_run_established') is not False
                or facts.get('heldout_acceptance_established') is not False):
            raise ValueError('child report exceeded consistency scope')
        # Child validation establishes exact snapshot shape; retain those sources
        # for a cohort-wide recheck after later children have run.
        for row in report['snapshots']:
            for phase in ('before', 'after'):
                reference = row[phase]
                snapshot = (evidence_dir / reference['path']) if is_capacity else Path(reference['path'])
                snapshot = _path(str(snapshot))
                snapshot_cap = capacity.MAX_ACCOUNT_BYTES if is_capacity else expired.MAX_SNAPSHOT_BYTES
                _pin(snapshot, snapshot_cap, reference['sha256'])
                pins.append((snapshot, snapshot_cap, reference['sha256']))
        if not is_capacity:
            for reference in report['source_refs'].values():
                source = _path(reference['path'])
                _pin(source, expired.MAX_SOURCE_BYTES, reference['sha256'])
                pins.append((source, expired.MAX_SOURCE_BYTES, reference['sha256']))
    for path, cap, digest in pins:
        _path(str(path))
        _pin(path, cap, digest)
    return {'schema': SCHEMA, 'scope': SCOPE, 'report_consistent': True,
            'expired_status_report_count': 8, 'shared_queue_capacity_report_count': 1,
            'loaded_run_established': False, 'heldout_acceptance_established': False}


def verify_file(manifest_path, expected_sha256):
    """Read a manifest fixed by a separately trusted raw SHA-256."""
    path = _path(str(manifest_path))
    raw = _pin(path, MAX_MANIFEST_BYTES, expected_sha256)
    result = validate_manifest(public._json_object(raw, 'negative cohort manifest'))
    _path(str(path))
    _pin(path, MAX_MANIFEST_BYTES, expected_sha256)
    return result
