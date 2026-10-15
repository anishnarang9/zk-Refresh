#!/usr/bin/env python3
"""Generate only private synthetic native-input fixtures; never retain keys.

The frozen test fixture independently encodes DER with cryptography.x509 and
signs under fresh in-memory RSA keys. Two issuer/holder/layout/action/path sets
share the unchanged production worker. A third request has a revoked-leaf root
with the otherwise valid first certificate/action/signature. No setup, witness,
chain record, cache or proof is generated. Fixture output confers no authority.
"""
import hashlib
import os
from pathlib import Path
import stat
import sys
import types

ROOT = Path(__file__).resolve().parents[4]
REFERENCE_SHA = 'd2985f3d6cec3a254f3c6bb5b548d0138503f25d0cbbb5697c6c3cd66f945729'
WORKER_SHA = 'b1349652a0acc86b4d8a820020ea6c8cdbba1f021958c6a9770a200e3124762e'


def pinned(path, expected, maximum):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise ValueError('fixture source identity')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_size):
            raise ValueError('fixture source identity')
        source = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    if (len(source) != before.st_size or len(source) > maximum
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            or hashlib.sha256(source).hexdigest() != expected):
        raise ValueError('fixture source identity')
    return source


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        metadata = os.fstat(handle.fileno())
        if (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1 or metadata.st_size != len(data)):
            raise ValueError('private fixture output')


def main():
    if len(sys.argv) != 2:
        raise ValueError('fixture arguments')
    directory = Path(sys.argv[1])
    metadata = directory.lstat()
    if (not directory.is_absolute() or directory.resolve() != directory
            or not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.getuid() or any(directory.iterdir())):
        raise ValueError('private fixture directory')
    # This uses the previously frozen independent fixture strategy, not the
    # production worker's build method. The reference also pins its profile,
    # Poseidon evaluator and constants before computing expected fixture values.
    pinned(ROOT / 'crates/dynark-native-client/workers/v3_input_worker.py', WORKER_SHA, 131072)
    reference_path = ROOT / 'crates/dynark-native-client/tests/test_v3_input_worker.py'
    source = pinned(reference_path, REFERENCE_SHA, 131072)
    reference = types.ModuleType('frozen_v3_roundtrip_fixture')
    reference.__file__ = str(reference_path)
    exec(compile(source, str(reference_path), 'exec'), reference.__dict__)
    fixture = reference.V3InputWorkerTests()
    reference.V3InputWorkerTests.setUpClass()
    for index in range(2):
        request, response, parsed, material = fixture.fixture(index)
        if len(request) != 1918 or len(response) != 24495:
            raise ValueError('fixture protocol')
        write_private(directory / ('case-%d.request.bin' % index), request)
        write_private(directory / ('case-%d.summary.bin' % index), response[4:463])
        if index == 0:
            revoked_root = reference.membership_root(
                parsed, material['slot'], material['siblings'], active=0)
            if revoked_root == material['root']:
                raise ValueError('distinct revoked root required')
            revoked = reference.patch(request, 1822, 1854, reference.field(revoked_root))
            write_private(directory / 'own-revoked.request.bin', revoked)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(2) from None
