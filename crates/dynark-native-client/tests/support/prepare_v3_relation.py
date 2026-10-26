#!/usr/bin/env python3
"""Fresh private relation fixture and independent full-R1CS preflight only.

No existing corpus, key, credential, witness or cache is read. Fresh RSA keys
remain in memory. Existing shared public compiler/setup artifacts stay unchanged.
All generated credential, action, membership and WTNS data are private test data,
not evidence of current chain state or an application authorization capability.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

ROOT = Path(__file__).resolve().parents[4]
PINS = {
    'crates/dynark-native-client/tests/test_v3_input_worker.py':
        'd2985f3d6cec3a254f3c6bb5b548d0138503f25d0cbbb5697c6c3cd66f945729',
    'crates/dynark-native-client/workers/v3_input_worker.py':
        'b1349652a0acc86b4d8a820020ea6c8cdbba1f021958c6a9770a200e3124762e',
    'tools/part5/witness_check.py':
        '5c972a36497100cb63b4a24b966b6fc6cce56a8e86dd9896c3656f63af10f763',
    'artifacts/dynark/part5/v3-compile-001/credential.sym':
        'd2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0',
    'artifacts/dynark/part5/v3-compile-001/credential.r1cs':
        '976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888',
}


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def read_file(path, cap, expected=None, private=False):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap
            or (private and (stat.S_IMODE(before.st_mode) != 0o600
                             or before.st_uid != os.getuid() or before.st_nlink != 1))):
        raise ValueError('fixture file rejected')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError('fixture handle rejected')
        data = handle.read(cap + 1)
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError('fixture changed')
    if (len(data) != before.st_size or len(data) > cap
            or (expected is not None and hashlib.sha256(data).hexdigest() != expected)):
        raise ValueError('fixture bytes rejected')
    return data


def source_module(relative):
    path = ROOT / relative
    source = read_file(path, 131072, PINS[relative])
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        metadata = os.fstat(handle.fileno())
        if (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1 or metadata.st_size != len(data)):
            raise ValueError('fixture output rejected')


def coordinates(reference):
    names = []
    for name, count in reference.FIELDS:
        names.extend(['main.' + name] if count == 1 else
                     ['main.%s[%d]' % (name, index) for index in range(count)])
    wanted = set(names)
    found, used = {}, set()
    internal = None
    relative = 'artifacts/dynark/part5/v3-compile-001/credential.sym'
    path = ROOT / relative
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 256 * 1024 * 1024:
        raise ValueError('compiler symbols rejected')
    digest, count = hashlib.sha256(), 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError('compiler handle rejected')
        while True:
            line = handle.readline(65537)
            if not line:
                break
            count += len(line)
            if len(line) > 65536 or count > before.st_size:
                raise ValueError('compiler symbol bounds')
            digest.update(line)
            fields = line.rstrip(b'\n').decode('ascii').split(',')
            if len(fields) != 4:
                raise ValueError('compiler symbol row')
            name = fields[3]
            if name in wanted:
                index = int(fields[1])
                if name in found or index in used or not 0 < index < 784796:
                    raise ValueError('compiler input ambiguity')
                found[name], _ = index, used.add(index)
            if name == 'main.certificateHash.out[0]':
                if internal is not None:
                    raise ValueError('internal coordinate ambiguity')
                internal = int(fields[1])
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError('compiler symbols changed')
    if (count != before.st_size or digest.hexdigest() != PINS[relative]
            or set(found) != wanted or len(found) != 751
            or any(found['main.' + name] != index + 1 for index, name in enumerate(
                ['root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash']))
            or internal is None or internal in used or not 7 <= internal < 784796):
        raise ValueError('compiler map rejected')
    return b''.join(found[name].to_bytes(4, 'little') for name in names), internal.to_bytes(4, 'little')


def generate(directory):
    if any(directory.iterdir()):
        raise ValueError('fresh fixture directory required')
    read_file(ROOT / 'crates/dynark-native-client/workers/v3_input_worker.py', 131072,
              PINS['crates/dynark-native-client/workers/v3_input_worker.py'])
    reference = source_module('crates/dynark-native-client/tests/test_v3_input_worker.py')
    # Only one fresh independent certificate is needed. No original key or DER
    # bytes exist in this strategy/source; cryptography.x509 performs encoding.
    reference.V3InputWorkerTests.issuers = [reference.rsa.generate_private_key(
        public_exponent=65537, key_size=2048)]
    reference.V3InputWorkerTests.holders = [reference.rsa.generate_private_key(
        public_exponent=65537, key_size=2048)]
    request, response, _, material = reference.V3InputWorkerTests().fixture(0)
    inputs = {name: [str(value) for value in material[name]] if count > 1 else str(material[name])
              for name, count in reference.FIELDS}
    encoded = json.dumps(inputs, separators=(',', ':')).encode('ascii')
    publics = json.dumps([inputs[name] for name, _ in reference.FIELDS[:6]],
                         separators=(',', ':')).encode('ascii')
    if len(request) != 1918 or len(response) != 24495 or not 0 < len(encoded) <= 65536:
        raise ValueError('fixture protocol bounds')
    mapped, internal = coordinates(reference)
    for name, data in [
        ('request.bin', request), ('summary.bin', response[4:463]),
        ('input.json', encoded), ('public.json', publics),
        ('input-coordinates.bin', mapped), ('internal-coordinate.bin', internal),
    ]:
        write_private(directory / name, data)


def check(directory):
    checker = source_module('tools/part5/witness_check.py')
    public_bytes = read_file(directory / 'public.json', 1024, private=True)
    public = json.loads(public_bytes)
    if (type(public) is not list or len(public) != 6
            or any(type(value) is not str or not value.isascii() or not value.isdecimal()
                   or str(int(value)) != value or not 0 <= int(value) < checker.FR for value in public)):
        raise ValueError('public statement rejected')
    # Authenticate a bounded same-handle public relation snapshot, then run the
    # independently pinned streaming checker against private immutable files.
    relative = 'artifacts/dynark/part5/v3-compile-001/credential.r1cs'
    source_path = ROOT / relative
    before = source_path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 192 * 1024 * 1024:
        raise ValueError('relation bounds')
    snapshot = directory / 'preflight.r1cs'
    source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    destination_fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        digest, count = hashlib.sha256(), 0
        with os.fdopen(source_fd, 'rb') as source, os.fdopen(destination_fd, 'wb') as destination:
            if identity(os.fstat(source.fileno())) != identity(before):
                raise ValueError('relation handle changed')
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                count += len(chunk)
                if count > before.st_size:
                    raise ValueError('relation grew')
                digest.update(chunk)
                destination.write(chunk)
            if (count != before.st_size or digest.hexdigest() != PINS[relative]
                    or identity(os.fstat(source.fileno())) != identity(before)):
                raise ValueError('relation identity rejected')
        result = checker.check_witness(snapshot, directory / 'output.wtns', [int(value) for value in public])
        if (result['satisfied'] is not True or result['assignment_fields'] != 784796
                or result['constraints_checked'] != 793681 or result['matrix_entries'] != 4257583):
            raise ValueError('complete relation preflight rejected')
        write_private(directory / 'preflight.bin', b'V3R1' + b''.join(
            value.to_bytes(4, 'little') for value in [784796, 793681, 4257583]))
    finally:
        snapshot.unlink(missing_ok=True)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('generate', 'check'):
        raise ValueError('fixture invocation')
    directory = Path(sys.argv[2])
    metadata = directory.lstat()
    if (not directory.is_absolute() or directory.resolve() != directory
            or not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.getuid()):
        raise ValueError('private fixture directory rejected')
    (generate if sys.argv[1] == 'generate' else check)(directory)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(2) from None
