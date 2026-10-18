#!/usr/bin/env python3
"""Observe a post-freeze launch of the v3 held-out cohort builder.

The parent records its own launch times and independently checks the builder's
scrubbed receipt. This records local process chronology; it is not an external
timestamp, an observation of OpenSSL internals, or proof of application
acceptance.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
PART5_OUTPUT_ROOT = ROOT / 'artifacts' / 'dynark' / 'part5'

from tools.part5 import build_v3_heldout_cohort as builder
from tools.part5 import generate_v3_heldout_keys as keygen


FREEZE_SCHEMA = keygen.FREEZE_SCHEMA
COHORT_SCHEMA = builder.COHORT_SCHEMA
OBSERVER_SCHEMA = 'credential-v3-heldout-cohort-parent-observation-v1'
COHORT_RECEIPT = 'cohort-receipt.json'
CHILD_TIMEOUT_SECONDS = 900
_HEX_SHA256 = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class ObserverInputs:
    freeze: Path
    freeze_sha256: str
    prior_key_inventory: Path
    prior_key_inventory_sha256: str
    output: Path
    observation: Path


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_text(value):
    return type(value) is str and _HEX_SHA256.fullmatch(value) is not None


def _decode_json(raw):
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate JSON field')
            value[key] = item
        return value

    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs)


def _canonical_input(path):
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError('canonical absolute input required')
    resolved = path.resolve(strict=True)
    info = path.lstat()
    if path != resolved or not stat.S_ISREG(info.st_mode):
        raise ValueError('canonical regular input required')
    return path


def _read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('regular input required')
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        if len(raw) > limit:
            raise ValueError('input exceeds size bound')
        return raw
    finally:
        os.close(fd)


def _parent_directory(path):
    parent = path.parent
    resolved = parent.resolve(strict=True)
    info = parent.stat()
    part5_root = PART5_OUTPUT_ROOT.resolve(strict=True)
    if (parent != resolved or parent.parent != part5_root
            or not parent.name.startswith('v3-heldout-private-')
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('reserved owner0700 cohort parent required')
    if not keygen._ignored(parent):
        raise ValueError('ignored cohort parent required')
    if any(parent.iterdir()):
        raise ValueError('fresh cohort parent required')


def _validate_inputs(inputs):
    if not isinstance(inputs, ObserverInputs):
        raise ValueError('observer inputs required')
    freeze = _canonical_input(inputs.freeze)
    inventory = _canonical_input(inputs.prior_key_inventory)
    freeze_raw = _read_bounded(freeze, 64 * 1024)
    if (not _hash_text(inputs.freeze_sha256)
            or hashlib.sha256(freeze_raw).hexdigest() != inputs.freeze_sha256):
        raise ValueError('freeze digest mismatch')
    if (not _hash_text(inputs.prior_key_inventory_sha256)
            or _sha256(inventory) != inputs.prior_key_inventory_sha256):
        raise ValueError('inventory digest mismatch')
    freeze_value = _decode_json(freeze_raw)
    if (type(freeze_value) is not dict
            or freeze_value.get('schema') != FREEZE_SCHEMA
            or type(freeze_value.get('frozen_at_unix_ns')) is not int
            or freeze_value['frozen_at_unix_ns'] <= 0
            or type(freeze_value.get('identities')) is not dict):
        raise ValueError('valid freeze boundary required')

    output, observation = inputs.output, inputs.observation
    if (not isinstance(output, Path) or not isinstance(observation, Path)
            or not output.is_absolute() or not observation.is_absolute()
            or output.parent != observation.parent or output.name in ('', '.', '..')
            or observation.name in ('', '.', '..')):
        raise ValueError('canonical absolute sibling destinations required')
    _parent_directory(output)
    if (output.parent / output.name != output.resolve(strict=False)
            or observation.parent / observation.name != observation.resolve(strict=False)):
        raise ValueError('canonical destination required')
    if os.path.lexists(output) or os.path.lexists(observation):
        raise ValueError('fresh output and observation required')
    if not keygen._ignored(output) or not keygen._ignored(observation):
        raise ValueError('ignored destinations required')
    return freeze_value


def _read_receipt(output):
    parent_fd = os.open(output.parent,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        output_fd = os.open(output.name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        directory_info = os.fstat(output_fd)
        if (directory_info.st_uid != os.getuid()
                or stat.S_IMODE(directory_info.st_mode) != 0o700):
            raise ValueError('private cohort directory required')
        receipt_fd = os.open(COHORT_RECEIPT,
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=output_fd)
        try:
            info = os.fstat(receipt_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4 * 1024 * 1024):
                raise ValueError('private cohort receipt required')
            pieces = []
            remaining = 4 * 1024 * 1024 + 1
            while remaining:
                chunk = os.read(receipt_fd, min(65536, remaining))
                if not chunk:
                    break
                pieces.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(pieces)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('cohort receipt too large')
            return raw
        finally:
            os.close(receipt_fd)
    finally:
        os.close(output_fd)


def _validate_receipt(raw, freeze_sha256, inventory_sha256, boundary,
                      wall_started, wall_completed):
    receipt = _decode_json(raw)
    if (type(receipt) is not dict or receipt.get('schema') != COHORT_SCHEMA
            or receipt.get('status') != 'cohort_issued_pending_application_gate'
            or receipt.get('keys_generated_after_freeze') is not True
            or receipt.get('freeze_sha256') != freeze_sha256
            or receipt.get('prior_key_inventory_sha256') != inventory_sha256
            or receipt.get('frozen_at_unix_ns') != boundary['frozen_at_unix_ns']
            or receipt.get('identities') != boundary['identities']):
        raise ValueError('freeze-linked cohort receipt required')
    counts = receipt.get('counts')
    certificates = receipt.get('certificates')
    if (type(counts) is not dict
            or counts.get('issuers') != 4 or counts.get('holders') != 8
            or counts.get('certificates') != 8 or counts.get('openssl_issuances') != 4
            or type(certificates) is not list or len(certificates) != 8):
        raise ValueError('expected certificate cohort receipt required')
    variants, holders, issuers = [], [], []
    previous_completed = None
    for row in certificates:
        if type(row) is not dict:
            raise ValueError('certificate row required')
        variant = row.get('variant')
        holder_index = row.get('holder_index')
        issuer_index = row.get('issuer_index')
        expected_encoder = ('openssl' if type(variant) is int and variant < 4
                            else 'cryptography')
        started = row.get('issuance_started_unix_ns')
        completed = row.get('issuance_completed_unix_ns')
        if (type(variant) is not int or not 0 <= variant < 8
                or type(holder_index) is not int or not 0 <= holder_index < 8
                or type(issuer_index) is not int or issuer_index != variant % 4
                or row.get('encoder') != expected_encoder
                or type(started) is not int or type(completed) is not int
                or not wall_started <= started <= completed <= wall_completed
                or (previous_completed is not None and started < previous_completed)):
            raise ValueError('certificate row layout or chronology rejected')
        variants.append(variant)
        holders.append(holder_index)
        issuers.append(issuer_index)
        previous_completed = completed
    if (variants != list(range(8)) or sorted(set(holders)) != list(range(8))
            or sorted(set(issuers)) != list(range(4))):
        raise ValueError('certificate cohort layout incomplete')
    generation_started = receipt.get('generation_started_unix_ns')
    generation_completed = receipt.get('generation_completed_unix_ns')
    if (type(generation_started) is not int or type(generation_completed) is not int
            or not boundary['frozen_at_unix_ns'] < wall_started <= generation_started
            or generation_started > generation_completed
            or generation_completed > wall_completed):
        raise ValueError('cohort chronology outside parent observation interval')
    return receipt


def _builder_source_sha256():
    return _sha256(Path(builder.__file__).resolve(strict=True))


def _observer_source_sha256():
    return _sha256(Path(__file__).resolve(strict=True))


def _publish_observation(path, observation):
    raw = (json.dumps(observation, sort_keys=True, separators=(',', ':')) + '\n').encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    parent_fd = os.open(path.parent,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    parent_info = os.fstat(parent_fd)
    if (parent_info.st_uid != os.getuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o700):
        os.close(parent_fd)
        raise ValueError('owner0700 observation parent required')
    temporary_name = f'.{path.name}.observer-{secrets.token_hex(12)}'
    fd = None
    published = False
    try:
        fd = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('private observation file required')
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError('observation write failed')
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        # A hard link publishes the complete file atomically and fails if the
        # destination appeared after preflight, preserving O_EXCL semantics.
        os.link(temporary_name, path.name, src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd, follow_symlinks=False)
        published = True
        os.fsync(parent_fd)
        os.unlink(temporary_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except Exception:
        if fd is not None:
            os.close(fd)
        if published:
            try:
                linked = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                temporary = os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
                if (linked.st_dev, linked.st_ino) == (temporary.st_dev, temporary.st_ino):
                    os.unlink(path.name, dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except OSError:
            pass
        os.close(parent_fd)
        raise
    os.close(parent_fd)


def _observe(inputs):
    boundary = _validate_inputs(inputs)
    builder_source_sha256 = _builder_source_sha256()
    observer_source_sha256 = _observer_source_sha256()
    with tempfile.TemporaryDirectory(dir=inputs.output.parent) as temp_directory:
        os.chmod(temp_directory, 0o700)
        environment = os.environ.copy()
        environment['TMPDIR'] = temp_directory
        command = [sys.executable, '-B', '-m', 'tools.part5.build_v3_heldout_cohort',
                   '--freeze', str(inputs.freeze),
                   '--freeze-sha256', inputs.freeze_sha256,
                   '--prior-key-inventory', str(inputs.prior_key_inventory),
                   '--prior-key-inventory-sha256', inputs.prior_key_inventory_sha256,
                   '--output', str(inputs.output)]
        wall_started = time.time_ns()
        monotonic_started = time.monotonic_ns()
        if wall_started <= boundary['frozen_at_unix_ns']:
            raise ValueError('parent launch must follow freeze')
        completed = subprocess.run(command, cwd=ROOT, env=environment,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=False,
                                   timeout=CHILD_TIMEOUT_SECONDS)
        wall_completed = time.time_ns()
        monotonic_completed = time.monotonic_ns()
        if wall_completed < wall_started or monotonic_completed < monotonic_started:
            raise ValueError('observer clock moved backward')
        if _builder_source_sha256() != builder_source_sha256:
            raise ValueError('builder source changed during invocation')
        if completed.returncode != 0:
            raise ValueError('cohort builder failed')

    raw_receipt = _read_receipt(inputs.output)
    _validate_receipt(raw_receipt, inputs.freeze_sha256,
                      inputs.prior_key_inventory_sha256, boundary,
                      wall_started, wall_completed)
    observation = {
        'schema': OBSERVER_SCHEMA,
        'freeze_sha256': inputs.freeze_sha256,
        'prior_key_inventory_sha256': inputs.prior_key_inventory_sha256,
        'wall_started_unix_ns': wall_started,
        'wall_completed_unix_ns': wall_completed,
        'monotonic_started_ns': monotonic_started,
        'monotonic_completed_ns': monotonic_completed,
        'child_exit_code': 0,
        'builder_source_sha256': builder_source_sha256,
        'observer_source_sha256': observer_source_sha256,
        'output_path_sha256': hashlib.sha256(str(inputs.output).encode()).hexdigest(),
        'cohort_receipt_sha256': hashlib.sha256(raw_receipt).hexdigest(),
        'preexisting_output': False,
        'creation_time_basis': 'observer_parent_started_child_after_freeze',
        'openssl_invocation_observed': False,
    }
    _publish_observation(inputs.observation, observation)
    return observation


def observe(inputs):
    try:
        return _observe(inputs)
    except Exception:
        raise RuntimeError('heldout observation failed') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', required=True, type=Path)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--prior-key-inventory', required=True, type=Path)
    parser.add_argument('--prior-key-inventory-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--observation', required=True, type=Path)
    args = parser.parse_args(argv)
    inputs = ObserverInputs(
        freeze=args.freeze, freeze_sha256=args.freeze_sha256,
        prior_key_inventory=args.prior_key_inventory,
        prior_key_inventory_sha256=args.prior_key_inventory_sha256,
        output=args.output, observation=args.observation)
    try:
        observe(inputs)
    except Exception:
        raise SystemExit('frozen heldout cohort observation rejected') from None


if __name__ == '__main__':
    main()
