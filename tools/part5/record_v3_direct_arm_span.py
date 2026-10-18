"""Source-level direct arm-span recorder; not integrated with campaign runners.

This helper measures one serial Full-B or Anchor-B arm. It records only pinned
identity hashes and timing facts; successful source-level output is not loaded
application evidence until a real runner integrates and validates these steps.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

SCHEMA = 'part5-v3-direct-arm-span-v1'
STEP_NAMES = ('prepare', 'stage', 'transition', 'source-r0', 'source-r1',
              'proof', 'clone', 'effect', 'cleanup')
IDENTITY_FIELDS = ('credential_sha256', 'action_sha256', 'root_sha256',
                   'setup_sha256', 'vk_sha256', 'elf_sha256')
MAX_RECEIPT_BYTES = 64 * 1024
CLOCK_TOLERANCE_SECONDS = 5.0


class _SystemClock:
    @staticmethod
    def monotonic():
        return time.monotonic()

    @staticmethod
    def utc_now():
        return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _identity(value):
    if type(value) is not dict or set(value) != {'mode', *IDENTITY_FIELDS}:
        raise ValueError('arm identity is invalid')
    if value['mode'] not in ('Full-B', 'Anchor-B'):
        raise ValueError('arm identity mode is invalid')
    for field in IDENTITY_FIELDS:
        if type(value[field]) is not str or re.fullmatch('[0-9a-f]{64}', value[field]) is None:
            raise ValueError('arm identity pin is invalid')
    return dict(value)


def _steps(value):
    if type(value) not in (list, tuple) or len(value) != len(STEP_NAMES):
        raise ValueError('arm step order is invalid')
    result = []
    for item, expected in zip(value, STEP_NAMES):
        if (type(item) not in (list, tuple) or len(item) != 2
                or item[0] != expected or not callable(item[1])):
            raise ValueError('arm step order is invalid')
        result.append((expected, item[1]))
    return result


def _monotonic(clock):
    try:
        value = clock.monotonic()
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError
        return float(value)
    except Exception:
        raise ValueError('arm clock is invalid') from None


def _utc(clock):
    try:
        value = clock.utc_now()
        if type(value) is not str or len(value) > 64:
            raise ValueError
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return value
    except Exception:
        raise ValueError('arm clock is invalid') from None


def _output_path(output):
    try:
        path = Path(output)
    except (TypeError, ValueError):
        raise ValueError('fresh output path required') from None
    try:
        if not path.is_absolute() or path.name in ('', '.', '..'):
            raise ValueError
        parent = path.parent.resolve(strict=True)
        if not parent.is_dir():
            raise ValueError
        path = parent / path.name
    except (OSError, RuntimeError, ValueError):
        raise ValueError('fresh output path required') from None
    return path


def _reserve(path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    flags |= getattr(os, 'O_CLOEXEC', 0)
    fd = None
    created = None
    try:
        fd = os.open(path, flags, 0o600)
        created = os.fstat(fd)
        os.fchmod(fd, 0o600)
        return fd, created
    except OSError:
        if fd is not None:
            _remove_reserved(path, fd, created)
        raise ValueError('fresh output required') from None


def _remove_reserved(path, fd, created):
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        current = os.lstat(path)
        if (created is not None and stat.S_ISREG(current.st_mode) and current.st_dev == created.st_dev
                and current.st_ino == created.st_ino):
            os.unlink(path)
    except OSError:
        pass


def _write_receipt(path, fd, created, report):
    raw = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if not 0 < len(raw) <= MAX_RECEIPT_BYTES:
        raise ValueError('arm receipt exceeds output bound')
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(fd)
        os.close(fd)
    except OSError:
        _remove_reserved(path, fd, created)
        raise ValueError('arm receipt write failed') from None


def record_arm(arm_identity, ordered_steps, output, clock=None):
    """Run the exact serial arm and write a fresh 0600 timing receipt on success.

    Steps are ``(name, callable)`` pairs in ``STEP_NAMES`` order. Each callable
    must return a mapping with ``passed is True``. The effect step must also
    return ``effect_verified is True``; cleanup must return ``remaining_owned_processes == 0``
    and ``status_known is True``. Step result payloads are never copied to output.
    """
    identity = _identity(arm_identity)
    steps = _steps(ordered_steps)
    path = _output_path(output)
    clock = _SystemClock() if clock is None else clock
    fd, created = _reserve(path)
    completed = False
    try:
        started = _monotonic(clock)
        start_utc = _utc(clock)
        durations = {}
        for name, function in steps:
            step_start = _monotonic(clock)
            try:
                result = function()
            except Exception:
                raise ValueError('arm step failed') from None
            step_end = _monotonic(clock)
            if step_end < step_start:
                raise ValueError('arm clock moved backward')
            if type(result) is not dict or result.get('passed') is not True:
                raise ValueError('arm step failed')
            if name == 'effect' and result.get('effect_verified') is not True:
                raise ValueError('arm effect verification failed')
            if name == 'cleanup' and (
                    type(result.get('remaining_owned_processes')) is not int
                    or result['remaining_owned_processes'] != 0
                    or result.get('status_known') is not True):
                raise ValueError('arm cleanup is incomplete or unknown')
            durations[name] = step_end - step_start
        ended = _monotonic(clock)
        end_utc = _utc(clock)
        if ended < started:
            raise ValueError('arm clock moved backward')
        direct_duration = ended - started
        utc_duration = (datetime.fromisoformat(end_utc.replace('Z', '+00:00')) -
                        datetime.fromisoformat(start_utc.replace('Z', '+00:00'))).total_seconds()
        disagreement = abs(utc_duration - direct_duration)
        if utc_duration < 0 or disagreement > CLOCK_TOLERANCE_SECONDS:
            raise ValueError('arm clock disagreement')
        report = {
            'schema': SCHEMA,
            'arm_identity': identity,
            'directly_timed': True,
            'start_utc': start_utc,
            'end_utc': end_utc,
            'direct_duration_seconds': direct_duration,
            'utc_monotonic_disagreement_seconds': disagreement,
            'step_durations_seconds': durations,
            'step_durations_are_attribution_only': True,
            'integration_status': 'source-level-helper-only',
            'full_application_evidence_established': False,
        }
        _write_receipt(path, fd, created, report)
        completed = True
        return report
    finally:
        if not completed:
            _remove_reserved(path, fd, created)
