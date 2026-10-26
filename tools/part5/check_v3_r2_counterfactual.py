#!/usr/bin/env python3
"""Record a pinned first unsatisfied R1CS row for an R2 counterfactual WTNS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import witness_check

SCHEMA = 'part5-v3-r2-active-witness-r1cs-result-v1'
PUBLIC_FIELDS = ('root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash',
                 'policyHash')


def _hash(value):
    return (type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value))


def _checked(path, expected, cap, *, private=False):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or not 0 < before.st_size <= cap
            or before.st_mode & 0o022 or (private and stat.S_IMODE(before.st_mode) != 0o600)
            or not _hash(expected)):
        raise ValueError('canonical pinned input file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                 info.st_nlink, info.st_size, info.st_mtime_ns,
                                 info.st_ctime_ns)
        if identity(opened) != identity(before):
            raise ValueError('input changed at open')
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise ValueError('input changed during hash')
    if identity(path.lstat()) != identity(before) or actual != expected:
        raise ValueError('input hash or identity differs')
    return path


def check(candidate_input, candidate_input_sha256, witness, witness_sha256,
          base_r1_witness, base_r1_witness_sha256, r1cs, r1cs_sha256,
          relation_checker, relation_checker_sha256, output):
    candidate = _checked(candidate_input, candidate_input_sha256, 65536,
                         private=True)
    witness = _checked(witness, witness_sha256, 32 * 1024 * 1024,
                       private=True)
    _checked(base_r1_witness, base_r1_witness_sha256, 32 * 1024 * 1024,
             private=True)
    r1cs = _checked(r1cs, r1cs_sha256, 192 * 1024 * 1024)
    checker = _checked(relation_checker, relation_checker_sha256, 131072)
    expected_checker = ROOT / 'crates/dynark-native-client/tests/support/prepare_v3_relation.py'
    if checker != expected_checker:
        raise ValueError('frozen relation checker required')
    raw = candidate.read_bytes()
    if hashlib.sha256(raw).hexdigest() != candidate_input_sha256:
        raise ValueError('candidate input changed after pin check')
    inputs = json.loads(raw)
    if type(inputs) is not dict or not all(name in inputs for name in PUBLIC_FIELDS):
        raise ValueError('canonical candidate public input required')
    public = []
    for name in PUBLIC_FIELDS:
        value = inputs[name]
        if (type(value) is not str or not value.isascii() or not value.isdecimal()
                or str(int(value)) != value or not 0 <= int(value) < witness_check.FR):
            raise ValueError('canonical candidate public field required')
        public.append(value)
    try:
        witness_check.check_witness(r1cs, witness, [int(value) for value in public])
    except ValueError as error:
        matched = re.fullmatch(r'unsatisfied relation row ([0-9]+)', str(error))
        if matched is None:
            raise
        row = int(matched.group(1))
        if not 0 <= row < 793681:
            raise ValueError('unsatisfied row outside frozen relation') from error
    else:
        raise ValueError('counterfactual WTNS unexpectedly satisfied the relation')
    result = {
        'schema': SCHEMA, 'status': 'unsatisfied',
        'scan': 'first_unsatisfied_row', 'constraint_row': row,
        'expected_public': public,
        'candidate_input_sha256': candidate_input_sha256,
        'witness_sha256': witness_sha256,
        'base_r1_witness_sha256': base_r1_witness_sha256,
        'r1cs_sha256': r1cs_sha256,
        'relation_checker_sha256': relation_checker_sha256,
    }
    output = Path(output)
    parent = output.parent
    info = parent.lstat()
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or parent.resolve(strict=True) != parent
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('fresh private result path required')
    content = (json.dumps(result, sort_keys=True, separators=(',', ':'),
                          allow_nan=False) + '\n').encode('ascii')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate_input', 'candidate_input_sha256', 'witness',
                 'witness_sha256', 'base_r1_witness',
                 'base_r1_witness_sha256', 'r1cs', 'r1cs_sha256', 'relation_checker',
                 'relation_checker_sha256', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), required=True,
                            type=Path if name in ('candidate_input', 'witness',
                                                  'base_r1_witness', 'r1cs', 'relation_checker',
                                                  'output') else str)
    check(**vars(parser.parse_args()))


if __name__ == '__main__':
    main()
