"""Verify source-level direct arm timing receipts against external byte and identity pins.

This checks one receipt's shape, arithmetic, and clock agreement. The receipt
is not linked to a loaded runner, journal, proof, or protected effect here.
"""
from datetime import datetime
import hashlib
import math
import os
from pathlib import Path
import re
import stat

from tools.part5 import verify_v3_campaign_public_projection as strict_json

SCHEMA = 'part5-v3-direct-arm-span-v1'
STEP_NAMES = ('prepare', 'stage', 'transition', 'source-r0', 'source-r1',
              'proof', 'clone', 'effect', 'cleanup')
IDENTITY_FIELDS = ('credential_sha256', 'action_sha256', 'root_sha256',
                   'setup_sha256', 'vk_sha256', 'elf_sha256')
MAX_RECEIPT_BYTES = 64 * 1024
CLOCK_TOLERANCE_SECONDS = 5.0
FIELDS = {'schema', 'arm_identity', 'directly_timed', 'start_utc', 'end_utc',
          'direct_duration_seconds', 'utc_monotonic_disagreement_seconds',
          'step_durations_seconds', 'step_durations_are_attribution_only',
          'integration_status', 'full_application_evidence_established'}


def _fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError('direct arm receipt fields mismatch')


def _hash(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('lowercase SHA-256 required')


def _number(value, positive=False):
    if type(value) not in (int, float):
        raise ValueError('finite direct arm duration required')
    try:
        number = float(value)
    except OverflowError:
        raise ValueError('finite direct arm duration required') from None
    if not math.isfinite(number) or number < 0 or (positive and number == 0):
        raise ValueError('finite direct arm duration required')
    return number


def _read(path):
    path = Path(path)
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('canonical nonsymlink receipt required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_RECEIPT_BYTES:
                raise ValueError('bounded regular receipt required')
            raw = source.read(MAX_RECEIPT_BYTES + 1)
            after = os.fstat(source.fileno())
        if (len(raw) != before.st_size or len(raw) > MAX_RECEIPT_BYTES
                or any(getattr(before, name) != getattr(after, name) for name in
                       ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            raise ValueError('receipt changed during read')
        return raw
    except (OSError, RuntimeError):
        raise ValueError('direct arm receipt unavailable') from None


def _identity(value):
    _fields(value, {'mode', *IDENTITY_FIELDS})
    if value['mode'] not in ('Full-B', 'Anchor-B'):
        raise ValueError('direct arm mode mismatch')
    for name in IDENTITY_FIELDS:
        _hash(value[name])
    return value


def _utc(value):
    try:
        if type(value) is not str or len(value) > 64:
            raise ValueError
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed
    except ValueError:
        raise ValueError('valid timezone-aware arm UTC required') from None


def verify_file(path, expected_raw_sha256, expected_identity):
    """Validate an external digest and identity; return only path-free facts."""
    _hash(expected_raw_sha256)
    _identity(expected_identity)
    raw = _read(path)
    if hashlib.sha256(raw).hexdigest() != expected_raw_sha256:
        raise ValueError('direct arm receipt byte digest mismatch')
    report = strict_json._json_object(raw, 'direct arm receipt')
    _fields(report, FIELDS)
    if report['schema'] != SCHEMA or report['arm_identity'] != expected_identity:
        raise ValueError('direct arm schema or identity mismatch')
    if (report['directly_timed'] is not True
            or report['step_durations_are_attribution_only'] is not True
            or report['integration_status'] != 'source-level-helper-only'
            or report['full_application_evidence_established'] is not False):
        raise ValueError('unsupported direct arm evidence scope')
    direct = _number(report['direct_duration_seconds'], positive=True)
    steps = report['step_durations_seconds']
    _fields(steps, STEP_NAMES)
    attributed = sum(_number(steps[name]) for name in STEP_NAMES)
    if attributed > direct + 1e-6:
        raise ValueError('step durations exceed direct arm span')
    utc_seconds = (_utc(report['end_utc']) - _utc(report['start_utc'])).total_seconds()
    disagreement = _number(report['utc_monotonic_disagreement_seconds'])
    if (utc_seconds < 0 or abs(utc_seconds - direct) > CLOCK_TOLERANCE_SECONDS
            or abs(abs(utc_seconds - direct) - disagreement) > 1e-6):
        raise ValueError('direct arm clock disagreement')
    if _read(path) != raw:
        raise ValueError('receipt changed during verification')
    return {'schema': SCHEMA, 'direct_span_consistent': True,
            'mode': report['arm_identity']['mode'],
            'direct_duration_seconds': direct,
            'attributed_step_seconds': attributed,
            'clock_disagreement_seconds': disagreement,
            'loaded_application_evidence_established': False,
            'whole_application_benefit_established': False}
