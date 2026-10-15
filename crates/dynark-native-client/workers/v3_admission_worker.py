#!/usr/bin/env python3
"""Pinned structural bounded-v3 certificate admission; no setup, witness or proving.

An eligible signature does not establish enrollment. Expected issuer/policy/root
come from a separately verified capability at the native caller boundary.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

REPO = Path(__file__).resolve().parents[3]
PROFILE_SHA = '2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918'
SCHEMA_SHA = 'eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4'
POSEIDON_CONSTANTS_SHA = '94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee'
POSEIDON_CONSTANTS_PATH = REPO / 'node_modules/circomlib/circuits/poseidon_constants.circom'
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
OFFSET_FIELDS = ['serial', 'not_before', 'not_after', 'issuer_cn', 'subject_cn',
    'modulus', 'aki', 'organization', 'group']


class AdmissionFailure(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__('bounded-v3 operation rejected')


def pinned(path, expected, maximum):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_size > maximum:
        raise AdmissionFailure(20)
    source = path.read_bytes()
    if len(source) > maximum or hashlib.sha256(source).hexdigest() != expected:
        raise AdmissionFailure(20)
    return source


def sources():
    profile = json.loads(pinned(REPO / 'circuits/credential-v3-bounded/profile.json', PROFILE_SHA, 65536))
    encoded = json.dumps(profile['schema'], sort_keys=True, separators=(',', ':')).encode()
    if hashlib.sha256(encoded).hexdigest() != SCHEMA_SHA:
        raise AdmissionFailure(20)
    modules = []
    for name, relative, expected in [
        ('profile', 'tools/part5/credential_profile.py', 'c960f3d2bb8e72c28c0d6a9164b6eaa17ec2ff4ef36a7e0af23811737470f2e6'),
        ('poseidon', 'tools/part5/poseidon.py', '82d6a93d2af03f17fe340eb7a2d0edbd47dd774ef205d7332b956c2e8c743d68'),
    ]:
        path = REPO / relative
        source = pinned(path, expected, 128 * 1024)
        module = types.ModuleType(name)
        module.__file__ = str(path)
        # Compile exact pinned source; attacker-replaceable pycache is not used.
        exec(compile(source, str(path), 'exec'), module.__dict__)
        modules.append(module)
    return modules


def bindings(parsed, modulus, profile, poseidon):
    constants = POSEIDON_CONSTANTS_PATH
    # Explicit importer closure check precedes all issuer/policy computations;
    # the pinned evaluator also validates constants when deriving parameters.
    pinned(constants, POSEIDON_CONSTANTS_SHA, 3 * 1024 * 1024)
    limbs = profile.rsa_limbs(modulus)
    key_hash = poseidon.poseidon([poseidon.poseidon(limbs[:8], constants),
        poseidon.poseidon(limbs[8:], constants)], constants)
    issuer_hash = poseidon.poseidon([2026101505, key_hash, int.from_bytes(parsed['aki'], 'big')], constants)
    policy_hash = poseidon.poseidon([2026101503, int.from_bytes(parsed['organization'], 'big'),
        int.from_bytes(parsed['group'][:16], 'big'), int.from_bytes(parsed['group'][16:], 'big')], constants)
    return issuer_hash, policy_hash


def admit(certificate, issuer_modulus_be):
    profile, poseidon = sources()
    if type(certificate) is not bytes or len(certificate) != 952 or len(issuer_modulus_be) != 256:
        raise AdmissionFailure(10)
    # Parse the outer certificate before signature verification to report
    # malformed/out-of-profile DER separately from a wrong issuer/signature.
    try:
        outer = profile.DER(certificate)
        body = outer.child(0x30)
        outer.finish()
        start, _, end = body.read(0x30)
        body.exact(profile.SHA256_RSA_ALGORITHM)
        signature, _ = body.value(3)
        body.finish()
        if len(signature) != 257 or signature[0] != 0:
            raise ValueError('signature encoding')
        parsed = profile.parse_tbs(certificate[start:end])
    except ValueError:
        raise AdmissionFailure(10) from None
    modulus = int.from_bytes(issuer_modulus_be, 'big')
    try:
        profile.verify_rsa(modulus, parsed['tbs'], signature[1:])
    except ValueError:
        raise AdmissionFailure(11) from None
    parsed['issuer_signature'] = signature[1:]
    issuer_hash, policy_hash = bindings(parsed, modulus, profile, poseidon)
    return {'parsed': parsed, 'issuer_hash': issuer_hash, 'policy_hash': policy_hash}


def admission_bytes(admitted):
    parsed = admitted['parsed']
    return (b'V3A1' + bytes([parsed['variant']]) + parsed['tbs_digest']
        + parsed['holder_modulus'].to_bytes(256, 'big')
        + admitted['issuer_hash'].to_bytes(32, 'little') + admitted['policy_hash'].to_bytes(32, 'little')
        + parsed['not_before'].to_bytes(8, 'big') + parsed['not_after'].to_bytes(8, 'big')
        + parsed['aki'] + parsed['organization'] + parsed['group']
        + b''.join(parsed['offsets'][field].to_bytes(2, 'big') for field in OFFSET_FIELDS))


def read_private(path, maximum):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_uid != os.getuid() or meta.st_nlink != 1 or meta.st_size > maximum:
        raise AdmissionFailure(20)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (meta.st_dev, meta.st_ino, meta.st_size):
            raise AdmissionFailure(20)
        data = handle.read(maximum + 1)
    if len(data) != meta.st_size:
        raise AdmissionFailure(20)
    return data


def main():
    if len(sys.argv) != 3 or sys.argv[1] != 'admit':
        raise AdmissionFailure(10)
    directory = Path(sys.argv[2])
    meta = directory.lstat()
    if not directory.is_absolute() or directory.resolve() != directory or not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o700 or meta.st_uid != os.getuid():
        raise AdmissionFailure(20)
    os.umask(0o077)
    request = read_private(directory / 'request.bin', 1208)
    if len(request) != 1208:
        raise AdmissionFailure(10)
    result = admission_bytes(admit(request[:952], request[952:]))
    fd = os.open(directory / 'output.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(result)


if __name__ == '__main__':
    try:
        main()
    except AdmissionFailure as failure:
        raise SystemExit(failure.code)
    except Exception:
        raise SystemExit(20)
