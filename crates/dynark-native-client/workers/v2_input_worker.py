#!/usr/bin/env python3
"""Pinned synthetic v2 signer/admission worker. Private binary/file protocol only."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

REPO = Path(__file__).resolve().parents[3]
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def sources():
    modules = []
    for name, relative, expected in [
        ('profile', 'tools/pre_part5/credential_profile.py', '59ede81c415356efb90517d7dbf62fc75efd1b2fbcb5d41ba8ad74d88147c827'),
        ('witness', 'circuits/credential-v2-dev/qualification/profile_witness.py', 'f0102703c1957ba6c2a1e86460dd25fcab3d4d67f2026d2a554232f0a751bf8b'),
    ]:
        path = REPO / relative
        source = path.read_bytes()
        if len(source) > 128 * 1024 or hashlib.sha256(source).hexdigest() != expected:
            raise ValueError('source identity')
        module = types.ModuleType(name)
        module.__file__ = str(path)
        exec(compile(source, str(path), 'exec'), module.__dict__)
        modules.append(module)
    return modules


def sign(key_bytes, action):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    profile, _ = sources()
    profile.check_action_field(action)
    if len(key_bytes) > 8192:
        raise ValueError('key bound')
    key = serialization.load_pem_private_key(key_bytes, None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048 or key.public_key().public_numbers().e != 65537:
        raise ValueError('synthetic signer mechanism')
    return profile.SyntheticSigner(key).sign_action(action)


def build(request):
    if len(request) != 1866:
        raise ValueError('input protocol length')
    profile, witness = sources()
    certificate, issuer_bytes, action, signature = request[:936], request[936:1192], request[1192:1224], request[1224:1480]
    slot = int.from_bytes(request[1480:1482], 'big')
    siblings = [int.from_bytes(request[i:i+32], 'little') for i in range(1482, 1802, 32)]
    root = int.from_bytes(request[1802:1834], 'little')
    issuer_hash = int.from_bytes(request[1834:1866], 'little')
    if slot >= 1024 or any(value >= FR for value in siblings + [root, issuer_hash]):
        raise ValueError('canonical authenticated path')
    issuer = int.from_bytes(issuer_bytes, 'big')
    parsed = profile.admit_certificate(certificate, issuer)
    material = profile.credential_witness_material(parsed, issuer, action, signature)
    constants = REPO / 'node_modules/circomlib/circuits/poseidon_constants.circom'
    limbs = profile.rsa_limbs(issuer)
    actual_issuer = witness.poseidon([witness.poseidon(limbs[:8], constants), witness.poseidon(limbs[8:], constants)], constants)
    actual_root = witness.registry_root({'tbs': list(parsed['tbs']), 'slot': slot, 'siblings': siblings}, constants)
    if issuer_hash != actual_issuer or root != actual_root:
        raise ValueError('credential issuer or membership mismatch')
    material.update({'root': root, 'issuerHash': issuer_hash, 'slot': slot, 'siblings': siblings,
        'pathIndices': [(slot >> level) & 1 for level in range(10)]})
    encoded = json.dumps(witness._strings(material), separators=(',', ':')).encode()
    if not encoded or len(encoded) > 65536:
        raise ValueError('canonical input bound')
    publics = [root, issuer_hash, parsed['not_before'], parsed['not_after'], int.from_bytes(action, 'big')]
    return (b'V2I1' + b''.join(value.to_bytes(32, 'little') for value in publics)
        + hashlib.sha256(parsed['tbs']).digest() + len(encoded).to_bytes(4, 'big') + encoded)


def read_private(path, maximum):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_size > maximum:
        raise ValueError('private input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (meta.st_dev, meta.st_ino, meta.st_size):
            raise ValueError('input changed')
        data = handle.read(maximum + 1)
    if len(data) != meta.st_size:
        raise ValueError('input bound')
    return data


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('sign', 'build'):
        raise ValueError('invocation')
    directory = Path(sys.argv[2])
    meta = directory.lstat()
    if not directory.is_absolute() or directory.resolve() != directory or not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o700:
        raise ValueError('private directory')
    os.umask(0o077)
    if sys.argv[1] == 'sign':
        result = sign(read_private(directory / 'key.pem', 8192), read_private(directory / 'action.be', 32))
    else:
        result = build(read_private(directory / 'request.bin', 1866))
    fd = os.open(directory / 'output.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(result)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Native typed status, never key/input/exception details in logs.
        raise SystemExit(2)
