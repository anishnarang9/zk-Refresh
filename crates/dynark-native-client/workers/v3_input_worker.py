#!/usr/bin/env python3
"""Non-authorizing bounded-v3 input candidate with private CLI transport.

Invocation: pinned-python this-script build ABSOLUTE_PRIVATE_DIRECTORY.
Input/output files are request.bin/output.bin in a 0700 directory, each
0600, owner checked, regular, single-link, opened without following symlinks.
The CLI carries candidate bytes only. The pure build function loads pinned profile
and Poseidon source bytes and uses an authenticated in-memory constants snapshot.
It verifies the mathematical credential/action/path relation, without signing or
proving. Python standard-library imports rely on the trusted runtime boundary.

Fixed request (1,918 bytes), with half-open byte ranges:
    [0:4]       V3Q1
    [4:956]     admitted certificate DER, exactly 952 bytes
    [956:1212]  issuer modulus, unsigned BE256
    [1212:1244] reviewed canonical action field, BE32
    [1244:1500] holder signature, unsigned BE256
    [1500:1502] allocation slot, BE16, below 1024
    [1502:1822] ten canonical Fr siblings, LE32 each, leaf-first
    [1822:1854] expected root, canonical Fr LE32
    [1854:1886] expected issuerHash, canonical Fr LE32
    [1886:1918] expected policyHash, canonical Fr LE32

Fixed response (24,495 bytes): V3I1 || admission_summary[459] || fields[751][32].
The summary is the existing exact V3A1 admission wire format. Every field is a
canonical Fr LE32. Field order is INPUT_FIELDS below, arrays expanded index-first.
The six initial fields are the exact public order. RSA limbs use 17 little-endian
121-bit limbs, with only 112 significant bits in the seventeenth limb. TBS bytes
are byte-valued fields. Path bits derive solely from the allocation slot.

Rust will compare DER/TBS bytes, imported metadata, action/state bytes, integer
limbs, path bits, canonical encodings and all mapped coordinate values itself.
RSA validity and recomputed Poseidon issuer/policy/active-root claims rely on the
reviewed pinned worker; Rust has no independent implementation of those checks.
Candidate JSON must equal serialization independently built from those sources;
caller JSON is never a source of expected fields. Complete R1CS validation and a
concrete chain authority remain mandatory before any proof admission. This
candidate output and caller-implemented state traits authorize
no credential, signer, chain state, or operation. open_full must remain closed.
"""

import ast
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import types

REQUEST_BYTES = 1918
RESPONSE_BYTES = 24495
FIELD_COUNT = 751
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ROOT = Path(__file__).resolve().parents[3]
CONSTANTS_RELATIVE = 'node_modules/circomlib/circuits/poseidon_constants.circom'
OFFSET_FIELDS = ('serial', 'not_before', 'not_after', 'issuer_cn', 'subject_cn',
                 'modulus', 'aki', 'organization', 'group')
INPUT_FIELDS = (
    ('root', 1), ('issuerHash', 1), ('notBefore', 1), ('notAfter', 1),
    ('actionHash', 1), ('policyHash', 1), ('layout', 1), ('slot', 1),
    ('tbs', 672), ('issuerModulus', 17), ('issuerSignature', 17),
    ('holderSignature', 17), ('siblings', 10), ('pathIndices', 10),
)
# Fixed policy, never caller-supplied assertions. build uses the profile,
# Poseidon evaluator and constants only; the remaining pins reserve existing
# boundaries without importing or claiming to execute those modules.
SOURCE_PINS = {
    'tools/part5/credential_profile.py':
        'c960f3d2bb8e72c28c0d6a9164b6eaa17ec2ff4ef36a7e0af23811737470f2e6',
    'tools/part5/poseidon.py':
        '82d6a93d2af03f17fe340eb7a2d0edbd47dd774ef205d7332b956c2e8c743d68',
    'node_modules/circomlib/circuits/poseidon_constants.circom':
        '94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee',
    'crates/dynark-native-client/workers/v3_admission_worker.py':
        '4ebb5c0201c3b98955d8fa0bc0ce8ce5f76104302b5e70f2a7359919e6b29a28',
    'crates/dynark-native-client/workers/v3_action_worker.py':
        '46692db2692d35f8624fde87ba9aa87239a5f8fab829a15a515a5a88ea6e80a6',
    'circuits/credential-v3-bounded/profile.json':
        '2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918',
}


class InputFailure(ValueError):
    """Typed rejection; never include credential, path, or signature bytes."""


def _source_bytes(relative, maximum):
    """Authenticate a bounded regular-file snapshot from one open handle."""
    path = ROOT / relative
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise InputFailure('bounded-v3 source rejected')
    def identity(meta):
        return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mode,
                meta.st_uid, meta.st_mtime_ns, meta.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise InputFailure('bounded-v3 source rejected')
        source = handle.read(maximum + 1)
        if (identity(os.fstat(handle.fileno())) != identity(before)
                or len(source) != before.st_size
                or len(source) > maximum
                or hashlib.sha256(source).hexdigest() != SOURCE_PINS[relative]):
            raise InputFailure('bounded-v3 source rejected')
    return source


def _sources():
    snapshots = [
        (relative, _source_bytes(relative, 128 * 1024))
        for relative in ('tools/part5/credential_profile.py', 'tools/part5/poseidon.py')
    ]
    constants = _source_bytes(CONSTANTS_RELATIVE, 3 * 1024 * 1024).decode('ascii')
    modules = []
    for relative, source in snapshots:
        path = ROOT / relative
        module = types.ModuleType(path.stem)
        module.__file__ = str(path)
        exec(compile(source, str(path), 'exec'), module.__dict__)
        modules.append(module)
    profile, poseidon = modules
    parameters = {}

    def snapshot_parameters(_path, width):
        # Adapt only the pinned evaluator's parameter loader. Its permutation
        # remains the exact pinned source; no mutable pathname is reread for
        # constants. This is its existing C/S/M/P parser over our snapshot.
        if width not in parameters:
            arrays = []
            for name in ('C', 'S', 'M', 'P'):
                function = re.search(r'function POSEIDON_' + name + r'\(t\)\s*\{', constants)
                if function is None:
                    raise InputFailure('bounded-v3 constants rejected')
                rest = constants[function.end():]
                branch = re.search(r'if\s*\(t\s*==\s*' + str(width) + r'\)\s*\{\s*return\s*', rest)
                if branch is None:
                    raise InputFailure('bounded-v3 constants rejected')
                tail = rest[branch.end():]
                arrays.append(ast.literal_eval(tail[:tail.index(';')]))
            parameters[width] = arrays
        return parameters[width]

    poseidon._parameters = snapshot_parameters
    return profile, poseidon


def _build(request):
    if type(request) is not bytes or len(request) != REQUEST_BYTES or request[:4] != b'V3Q1':
        raise InputFailure('bounded-v3 request rejected')
    certificate = request[4:956]
    modulus = int.from_bytes(request[956:1212], 'big')
    action = request[1212:1244]
    signature = request[1244:1500]
    slot = int.from_bytes(request[1500:1502], 'big')
    siblings = [int.from_bytes(request[start:start + 32], 'little')
                for start in range(1502, 1822, 32)]
    root = int.from_bytes(request[1822:1854], 'little')
    issuer_hash = int.from_bytes(request[1854:1886], 'little')
    policy_hash = int.from_bytes(request[1886:1918], 'little')
    if (slot >= 1024 or int.from_bytes(action, 'big') >= FR
            or any(value >= FR for value in siblings + [root, issuer_hash, policy_hash])):
        raise InputFailure('bounded-v3 field rejected')
    profile, poseidon = _sources()
    parsed = profile.admit_certificate(certificate, modulus)
    # This verifies both exact RSA messages/signatures and re-parses signed TBS.
    material = profile.credential_witness_material(parsed, modulus, action, signature)
    constants_path = ROOT / CONSTANTS_RELATIVE
    def hash_fields(values):
        return poseidon.poseidon(values, constants_path)
    limbs = profile.rsa_limbs(modulus)
    key_hash = hash_fields([hash_fields(limbs[:8]), hash_fields(limbs[8:])])
    actual_issuer = hash_fields([2026101505, key_hash, int.from_bytes(parsed['aki'], 'big')])
    actual_policy = hash_fields([2026101503, int.from_bytes(parsed['organization'], 'big'),
                                 int.from_bytes(parsed['group'][:16], 'big'),
                                 int.from_bytes(parsed['group'][16:], 'big')])
    digest = hashlib.sha256(parsed['tbs']).digest()
    node = hash_fields([2026101504, int.from_bytes(digest[:16], 'big'),
                        int.from_bytes(digest[16:], 'big'), slot, 1])
    path_indices = [(slot >> level) & 1 for level in range(10)]
    for direction, sibling in zip(path_indices, siblings):
        node = hash_fields([sibling, node] if direction else [node, sibling])
    if issuer_hash != actual_issuer or policy_hash != actual_policy or root != node:
        raise InputFailure('bounded-v3 binding rejected')
    material.update(root=node, issuerHash=actual_issuer, policyHash=actual_policy,
                    slot=slot, siblings=siblings, pathIndices=path_indices)
    summary = (b'V3A1' + bytes([parsed['variant']]) + digest
               + parsed['holder_modulus'].to_bytes(256, 'big')
               + actual_issuer.to_bytes(32, 'little') + actual_policy.to_bytes(32, 'little')
               + parsed['not_before'].to_bytes(8, 'big')
               + parsed['not_after'].to_bytes(8, 'big')
               + parsed['aki'] + parsed['organization'] + parsed['group']
               + b''.join(parsed['offsets'][name].to_bytes(2, 'big') for name in OFFSET_FIELDS))
    scalars = []
    if set(material) != {name for name, _ in INPUT_FIELDS}:
        raise InputFailure('bounded-v3 output rejected')
    for name, count in INPUT_FIELDS:
        values = [material[name]] if count == 1 else material[name]
        if len(values) != count or any(type(value) is not int or not 0 <= value < FR
                                       for value in values):
            raise InputFailure('bounded-v3 output rejected')
        scalars.extend(values)
    if len(summary) != 459 or len(scalars) != FIELD_COUNT:
        raise InputFailure('bounded-v3 output rejected')
    result = b'V3I1' + summary + b''.join(value.to_bytes(32, 'little') for value in scalars)
    if len(result) != RESPONSE_BYTES:
        raise InputFailure('bounded-v3 output rejected')
    return result


def build(request):
    """Derive and verify the complete candidate; no caller output is admitted."""
    try:
        return _build(request)
    except Exception:
        # Do not expose nested exceptions, input bytes, source paths or values.
        raise InputFailure('bounded-v3 input rejected') from None


def _private_cli(directory_argument):
    directory = Path(directory_argument)
    owner = os.getuid()

    def identity(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
                metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def directory_identity(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid)

    before_directory = directory.lstat()
    if (not directory.is_absolute() or directory.resolve(strict=True) != directory
            or not stat.S_ISDIR(before_directory.st_mode)
            or stat.S_IMODE(before_directory.st_mode) != 0o700
            or before_directory.st_uid != owner):
        raise InputFailure('bounded-v3 private directory rejected')
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(directory_fd)) != identity(before_directory):
            raise InputFailure('bounded-v3 private directory rejected')
        request_path = directory / 'request.bin'
        before_request = request_path.lstat()
        if (not stat.S_ISREG(before_request.st_mode)
                or stat.S_IMODE(before_request.st_mode) != 0o600
                or before_request.st_uid != owner or before_request.st_nlink != 1
                or before_request.st_size != REQUEST_BYTES):
            raise InputFailure('bounded-v3 private request rejected')
        request_fd = os.open('request.bin', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_fd)
        with os.fdopen(request_fd, 'rb') as handle:
            if identity(os.fstat(handle.fileno())) != identity(before_request):
                raise InputFailure('bounded-v3 private request rejected')
            request = handle.read(REQUEST_BYTES + 1)
            if (len(request) != REQUEST_BYTES
                    or identity(os.fstat(handle.fileno())) != identity(before_request)):
                raise InputFailure('bounded-v3 private request rejected')
        result = build(request)
        if (directory.resolve(strict=True) != directory
                or directory_identity(directory.lstat()) != directory_identity(before_directory)
                or directory_identity(os.fstat(directory_fd)) != directory_identity(before_directory)):
            raise InputFailure('bounded-v3 private directory rejected')
        # The stable directory handle anchors both leaf opens. O_EXCL never
        # reuses a prior output, including a symlink or another hard link.
        output_fd = os.open('output.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=directory_fd)
        created = os.fstat(output_fd)
        try:
            with os.fdopen(output_fd, 'wb') as handle:
                os.fchmod(handle.fileno(), 0o600)
                opened = os.fstat(handle.fileno())
                if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner
                        or opened.st_nlink != 1 or opened.st_size != 0
                        or stat.S_IMODE(opened.st_mode) != 0o600):
                    raise InputFailure('bounded-v3 private output rejected')
                if handle.write(result) != RESPONSE_BYTES:
                    raise InputFailure('bounded-v3 private output rejected')
                handle.flush()
                finished = os.fstat(handle.fileno())
                named = os.stat('output.bin', dir_fd=directory_fd, follow_symlinks=False)
                if (finished.st_size != RESPONSE_BYTES or finished.st_nlink != 1
                        or finished.st_uid != owner or stat.S_IMODE(finished.st_mode) != 0o600
                        or identity(named) != identity(finished)
                        or directory.resolve(strict=True) != directory
                        or directory_identity(directory.lstat()) != directory_identity(before_directory)
                        or directory_identity(os.fstat(directory_fd)) != directory_identity(before_directory)):
                    raise InputFailure('bounded-v3 private output rejected')
        except Exception:
            # Remove only our own failed output, never a replacement pathname.
            try:
                named = os.stat('output.bin', dir_fd=directory_fd, follow_symlinks=False)
                if (named.st_dev, named.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink('output.bin', dir_fd=directory_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(directory_fd)
    return 0


def main():
    if len(sys.argv) != 3 or sys.argv[1] != 'build':
        return 2
    try:
        return _private_cli(sys.argv[2])
    except Exception:
        raise InputFailure('bounded-v3 private invocation rejected') from None


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except InputFailure:
        raise SystemExit(2) from None
