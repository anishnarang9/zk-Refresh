#!/usr/bin/env python3
"""Prepare private TRAINING inputs from a supplied credential and local request.

Usage: python this-file SOURCE_DIRECTORY FRESH_OUTPUT_DIRECTORY EXPORTER
Both directories must be absolute, canonical, owner0700 directories. SOURCE has
owner0600 single-link files credential.der (952 bytes), holder.pem (<=4096),
issuer-modulus.bin (BE256), config.bin (381), membership.json (<=16384), and
parameters.json (<=8192). Membership supplies slot, issuer_hash, policy_hash,
active_root, active_siblings. Parameters supplies program_id, genesis, creator,
nonce, recipient (lowercase hex32), payload (lowercase hex, <=1024 bytes),
request_type (u16), deadline and now (i64), exporter_sha256 (lowercase hex32).
No identity or request parameter is defaulted. Genesis must equal Config's
encoded genesis. Config, membership and parameters are LOCAL fixture inputs;
this helper authenticates no chain account, enrollment or current state.

The committed A2 bridge finalizes the plan and signs the resulting action. The
pinned input worker receives exactly that V3Q1. Outputs match the existing
v3_relation_witness.cjs / prepare_v3_relation.py check file contracts. No WTNS,
setup or proof runs here. This CLI is silent; failures carry no private detail.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.part5 import prepare_v3_request_fixture as bridge
from tools.part5.credential_profile import FR, admit_certificate, public_bindings

BRIDGE_SHA = '2b97cd1e02174ff67203f4b107923501a20b5d24bf11de03f204b77980f5691f'
WORKER_SHA = 'b1349652a0acc86b4d8a820020ea6c8cdbba1f021958c6a9770a200e3124762e'
RELATION_HELPER_SHA = 'ea5d1cf19cbe8840cea786dcda9738dccf9665b95480f9ab6c9a8ecad30e4d86'


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(path):
    if not isinstance(path, Path) or not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError()
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid()):
        raise ValueError()
    return info


def _read(path, cap, private=True, expected=None):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap
            or (private and (before.st_uid != os.getuid() or before.st_nlink != 1
                             or stat.S_IMODE(before.st_mode) != 0o600))):
        raise ValueError()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as handle:
        if _identity(os.fstat(handle.fileno())) != _identity(before):
            raise ValueError()
        data = handle.read(cap + 1)
        if (_identity(os.fstat(handle.fileno())) != _identity(before)
                or _identity(path.lstat()) != _identity(before)):
            raise ValueError()
    if len(data) != before.st_size or (expected and hashlib.sha256(data).hexdigest() != expected):
        raise ValueError()
    return data


def _module(path, digest):
    source = _read(path, 131072, private=False, expected=digest)
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def load_worker():
    return _module(ROOT / 'crates/dynark-native-client/workers/v3_input_worker.py', WORKER_SHA)


def _json(data):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def _hex(value, width=None):
    if (type(value) is not str or len(value) % 2 or not re.fullmatch('[0-9a-f]*', value)
            or (width is not None and len(value) != width * 2)):
        raise ValueError()
    return bytes.fromhex(value)


def _encoded(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')


def prepare(source, output, exporter):
    """Return scrubbed identities only; every written artifact remains private."""
    try:
        return _prepare(source, output, exporter)
    except Exception:
        raise ValueError('request-bound training preparation rejected') from None


def _prepare(source, output, exporter):
    source_info, output_info = _directory(source), _directory(output)
    if source == output or any(output.iterdir()):
        raise ValueError()
    _read(ROOT / 'tools/part5/prepare_v3_request_fixture.py', 131072,
          private=False, expected=BRIDGE_SHA)
    bounds = {'credential.der': 952, 'holder.pem': 4096, 'issuer-modulus.bin': 256,
              'config.bin': 381, 'membership.json': 16384, 'parameters.json': 8192}
    raw = {name: _read(source / name, cap) for name, cap in bounds.items()}
    if any(len(raw[name]) != size for name, size in
           [('credential.der', 952), ('issuer-modulus.bin', 256), ('config.bin', 381)]):
        raise ValueError()
    params, membership = _json(raw['parameters.json']), _json(raw['membership.json'])
    names = {'program_id', 'genesis', 'creator', 'nonce', 'recipient', 'payload',
             'request_type', 'deadline', 'now', 'exporter_sha256'}
    if type(params) is not dict or set(params) != names or type(membership) is not dict:
        raise ValueError()
    public_keys = {key: _hex(params[key], 32) for key in
                   ('program_id', 'genesis', 'creator', 'nonce', 'recipient', 'exporter_sha256')}
    payload = _hex(params['payload'])
    if len(payload) > 1024 or public_keys['genesis'] != raw['config.bin'][104:136]:
        raise ValueError()
    if (type(params['request_type']) is not int or not 0 <= params['request_type'] < 65536
            or any(type(params[key]) is not int or not -(1 << 63) <= params[key] < 1 << 63
                   for key in ('deadline', 'now'))):
        raise ValueError()
    if (not isinstance(exporter, Path) or not exporter.is_absolute()
            or exporter.resolve(strict=True) != exporter):
        raise ValueError()
    binary = exporter.lstat()
    if (not stat.S_ISREG(binary.st_mode) or binary.st_uid != os.getuid()
            or binary.st_nlink != 1 or binary.st_mode & 0o022 or not binary.st_mode & 0o111):
        raise ValueError()
    _read(exporter, 64 * 1024 * 1024, private=False, expected=params['exporter_sha256'])
    der, config = raw['credential.der'], raw['config.bin']
    modulus = int.from_bytes(raw['issuer-modulus.bin'], 'big')
    parsed = admit_certificate(der, modulus)
    issuer, policy = public_bindings(parsed, modulus)
    plan = bridge.build_v3p1(der, modulus, membership, config_bytes=config,
                           program_id=public_keys['program_id'], creator=public_keys['creator'],
                           nonce=public_keys['nonce'], recipient=public_keys['recipient'],
                           request_type=params['request_type'], deadline=params['deadline'],
                           payload=payload, now=params['now'])
    finalized = bridge.finalize_v3p1(plan, exporter)
    if finalized['exporter_sha256'] != params['exporter_sha256']:
        raise ValueError()
    q1 = bridge.build_request_bound_v3q1(der, modulus, source / 'holder.pem', membership,
                                       plan, finalized, exporter)
    expected = [membership['active_root'], issuer, parsed['not_before'], parsed['not_after'],
                int.from_bytes(finalized['v3f2'][164:196], 'big'), policy]
    if (finalized['v3f1'][52:244] != b''.join(x.to_bytes(32, 'big') for x in expected)
            or q1[1212:1244] != finalized['v3f2'][164:196]):
        raise ValueError()
    worker = load_worker()
    response = worker.build(q1)
    if type(response) is not bytes or len(response) != 24495 or response[:4] != b'V3I1':
        raise ValueError()
    expected_summary = (b'V3A1' + bytes([parsed['variant']]) + hashlib.sha256(parsed['tbs']).digest()
                        + parsed['holder_modulus'].to_bytes(256, 'big')
                        + issuer.to_bytes(32, 'little') + policy.to_bytes(32, 'little')
                        + parsed['not_before'].to_bytes(8, 'big') + parsed['not_after'].to_bytes(8, 'big')
                        + parsed['aki'] + parsed['organization'] + parsed['group']
                        + b''.join(parsed['offsets'][key].to_bytes(2, 'big')
                                   for key in worker.OFFSET_FIELDS))
    fields = [int.from_bytes(response[i:i + 32], 'little') for i in range(463, 24495, 32)]
    if response[4:463] != expected_summary or fields[:6] != expected or any(x >= FR for x in fields):
        raise ValueError()
    inputs, cursor = {}, 0
    for name, count in worker.INPUT_FIELDS:
        group = [str(value) for value in fields[cursor:cursor + count]]
        inputs[name] = group[0] if count == 1 else group
        cursor += count
    if cursor != 751:
        raise ValueError()
    relation = _module(Path(__file__).with_name('prepare_v3_relation.py'), RELATION_HELPER_SHA)
    coordinates, internal = relation.coordinates(types.SimpleNamespace(FIELDS=worker.INPUT_FIELDS))
    input_json, public_json = _encoded(inputs), _encoded([str(x) for x in expected])
    receipt = {'schema': 'v3-request-bound-training-input-v1', 'training_only': True,
               'live_state_authenticated': False, 'proof_created': False,
               'complete_relation_checked': False,
               'local_fixture_inputs': True, 'bridge_sha256': BRIDGE_SHA,
               'worker_sha256': WORKER_SHA, 'exporter_sha256': params['exporter_sha256'],
               'program_id_sha256': hashlib.sha256(public_keys['program_id']).hexdigest(),
               'genesis_sha256': hashlib.sha256(public_keys['genesis']).hexdigest(),
               'config_sha256': hashlib.sha256(config).hexdigest(),
               'membership_sha256': hashlib.sha256(raw['membership.json']).hexdigest(),
               'parameters_sha256': hashlib.sha256(raw['parameters.json']).hexdigest(),
               'plan_sha256': hashlib.sha256(plan).hexdigest(),
               'finalized_fixture_sha256': hashlib.sha256(finalized['v3f1']).hexdigest(),
               'finalized_action_transport_sha256': hashlib.sha256(finalized['v3f2']).hexdigest(),
               'public_fields': 6, 'input_scalars': 751,
               'artifact_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in
                                   [('request.bin', q1), ('input.json', input_json),
                                    ('public.json', public_json)]}}
    outputs = {'request.bin': q1, 'summary.bin': response[4:463], 'input.json': input_json,
               'public.json': public_json,
               'input-coordinates.bin': coordinates, 'internal-coordinate.bin': internal,
               'training-receipt.json': _encoded(receipt)}
    # Recheck immutable private sources and directory identities before publication.
    for name, cap in bounds.items():
        if _read(source / name, cap) != raw[name]:
            raise ValueError()
    if (_identity(_directory(source)) != _identity(source_info)
            or _identity(_directory(output)) != _identity(output_info)):
        raise ValueError()
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    created = []
    try:
        if _identity(os.fstat(fd)) != _identity(output_info) or os.listdir(fd):
            raise ValueError()
        for name, data in outputs.items():
            handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
            created.append(name)
            with os.fdopen(handle, 'wb') as destination:
                os.fchmod(destination.fileno(), 0o600)
                destination.write(data)
                destination.flush()
                info = os.fstat(destination.fileno())
                if (info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != len(data)):
                    raise ValueError()
                os.fsync(destination.fileno())
        os.fsync(fd)
        current = _directory(output)
        if (current.st_dev, current.st_ino) != (output_info.st_dev, output_info.st_ino):
            raise ValueError()
    except Exception:
        for name in created:
            os.unlink(name, dir_fd=fd)
        raise
    finally:
        os.close(fd)
    return receipt


if __name__ == '__main__':
    try:
        if len(sys.argv) != 4:
            raise ValueError()
        prepare(*(Path(value) for value in sys.argv[1:]))
    except Exception:
        raise SystemExit(2) from None
