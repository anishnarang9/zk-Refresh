#!/usr/bin/env python3
"""Pin a fresh successful v3 witness suite for the private setup CLI."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat


SUITE_SCHEMA = 'credential-v3-bounded-witness-qualification-v1'
ASSIGNMENTS_SCHEMA = 'credential-v3-bounded-private-assignments-v1'
R1CS_SHA256 = '976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888'
WASM_SHA256 = 'fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6'
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ROWS = 793_681
ENTRIES = 4_257_583
ASSIGNMENT_COUNT = 784_796
MAX_REPORT_BYTES = 65_536
MAX_WTNS_BYTES = 32 * 1024 * 1024
MAX_PUBLIC_BYTES = 65_536
WTNS_BYTES = 76 + ASSIGNMENT_COUNT * 32
EXPECTED_ACCEPTED = {
    name
    for index in range(9)
    for name in (f'credential_{index}', f'credential_{index}_unrelated_refresh')
}
REPORT_FIELDS = {
    'schema', 'passed', 'r1cs_sha256', 'wasm_sha256',
    'host_admission_bypassed', 'setup_or_proofs_executed',
    'outputs_private', 'cases', 'accepted_count', 'rejected_count',
}
ACCEPTED_CASE_FIELDS = {
    'name', 'expected', 'family', 'witness_elapsed_ms', 'validation',
    'passed', 'complete_relation_check_ms',
}
REJECTED_CASE_FIELDS = {
    'name', 'expected', 'family', 'witness_elapsed_ms', 'rejection', 'passed',
}
VALIDATION_FIELDS = {
    'satisfied', 'constraints_checked', 'assignment_fields',
    'matrix_entries', 'max_row_terms',
}
MANIFEST_FIELDS = {
    'schema', 'synthetic_only', 'accepted_suite_path',
    'accepted_suite_sha256', 'assignments',
}
ASSIGNMENT_RECORD_FIELDS = {
    'name', 'wtns_path', 'wtns_sha256', 'public_path', 'public_sha256',
}
_NAME = re.compile(r'[A-Za-z0-9_]{1,80}\Z', re.ASCII)
_SHA256 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
_DECIMAL = re.compile(r'(?:0|[1-9][0-9]*)\Z', re.ASCII)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError('non-finite JSON number')


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant)


def _private_directory(path):
    path = Path(path)
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or path.resolve(strict=True) != path):
        raise ValueError('suite root must be a canonical owner-only directory')
    return metadata.st_dev, metadata.st_ino


def _read_private(path, root, cap, *, exact_size=None, capture=0):
    path = Path(path)
    if (not path.is_absolute() or path.parent != root or path.resolve(strict=True) != path):
        raise ValueError('suite artifact must be a direct child of suite root')
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > cap
            or (exact_size is not None and before.st_size != exact_size)):
        raise ValueError('suite artifact type, owner, mode, or size')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    hasher = hashlib.sha256()
    prefix = bytearray()
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size != before.st_size):
            raise ValueError('suite artifact changed at open')
        consumed = 0
        while True:
            block = os.read(fd, 65_536)
            if not block:
                break
            consumed += len(block)
            if consumed > cap:
                raise ValueError('suite artifact grew beyond cap')
            hasher.update(block)
            if len(prefix) < capture:
                prefix.extend(block[:capture - len(prefix)])
        after = os.fstat(fd)
        current = path.lstat()
        if (consumed != opened.st_size or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
                or current.st_dev != opened.st_dev or current.st_ino != opened.st_ino
                or not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid()
                or stat.S_IMODE(current.st_mode) != 0o600
                or current.st_size != opened.st_size):
            raise ValueError('suite artifact changed while hashing')
        return hasher.hexdigest(), bytes(prefix), (opened.st_dev, opened.st_ino)
    finally:
        os.close(fd)


def _exact_fields(value, expected, label):
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f'{label} fields')


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('suite case timing')


def validate_suite(report, suite_sha256):
    if not isinstance(suite_sha256, str) or not _SHA256.fullmatch(suite_sha256):
        raise ValueError('canonical expected suite SHA-256 required')
    _exact_fields(report, REPORT_FIELDS, 'suite report')
    if (report.get('schema') != SUITE_SCHEMA or report.get('passed') is not True
            or report.get('host_admission_bypassed') is not True
            or report.get('setup_or_proofs_executed') is not False
            or report.get('outputs_private') is not True
            or report.get('r1cs_sha256') != R1CS_SHA256
            or report.get('wasm_sha256') != WASM_SHA256
            or type(report.get('accepted_count')) is not int
            or report['accepted_count'] != 18
            or type(report.get('rejected_count')) is not int
            or report['rejected_count'] != 34):
        raise ValueError('accepted witness suite identity/context')
    cases = report.get('cases')
    if not isinstance(cases, list) or len(cases) != 52:
        raise ValueError('exact 52-case suite required')
    seen = set()
    accepted = {}
    rejected = 0
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError('suite case object required')
        name = case.get('name')
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in seen:
            raise ValueError('unique safe suite case names required')
        seen.add(name)
        if type(case.get('passed')) is not bool or case['passed'] is not True:
            raise ValueError('all witness suite cases must pass')
        if not isinstance(case.get('family'), str) or not case['family']:
            raise ValueError('suite case family required')
        _time(case.get('witness_elapsed_ms'))
        if case.get('expected') == 'accept':
            _exact_fields(case, ACCEPTED_CASE_FIELDS, 'accepted case')
            validation = case.get('validation')
            _exact_fields(validation, VALIDATION_FIELDS, 'relation validation')
            if (validation.get('satisfied') is not True
                    or type(validation.get('constraints_checked')) is not int
                    or validation['constraints_checked'] != ROWS
                    or type(validation.get('assignment_fields')) is not int
                    or validation['assignment_fields'] != ASSIGNMENT_COUNT
                    or type(validation.get('matrix_entries')) is not int
                    or validation['matrix_entries'] != ENTRIES
                    or type(validation.get('max_row_terms')) is not int
                    or not 0 <= validation['max_row_terms'] <= 4096):
                raise ValueError('complete accepted relation census required')
            _time(case.get('complete_relation_check_ms'))
            accepted[name] = case
        elif case.get('expected') == 'reject':
            _exact_fields(case, REJECTED_CASE_FIELDS, 'rejected case')
            if case.get('rejection') != 'circuit_assertion':
                raise ValueError('negative case must reject at circuit assertion')
            rejected += 1
        else:
            raise ValueError('suite expectation')
    if set(accepted) != EXPECTED_ACCEPTED or rejected != 34:
        raise ValueError('all and only the registered 18 accepted cases required')
    return accepted


def _decode_public(raw):
    public = _json(raw)
    if type(public) is not list or len(public) != 6:
        raise ValueError('six-field public statement required')
    values = []
    for value in public:
        if (not isinstance(value, str) or not _DECIMAL.fullmatch(value)
                or len(value) > 77):
            raise ValueError('canonical public decimal required')
        integer = int(value)
        if integer >= FIELD_MODULUS:
            raise ValueError('public decimal outside BN254 field')
        values.append(integer)
    return values


def _check_wtns_public(prefix, public):
    count = ASSIGNMENT_COUNT
    header = (b'wtns' + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little')
              + (1).to_bytes(4, 'little') + (40).to_bytes(8, 'little')
              + (32).to_bytes(4, 'little')
              + FIELD_MODULUS.to_bytes(32, 'little')
              + count.to_bytes(4, 'little') + (2).to_bytes(4, 'little')
              + (count * 32).to_bytes(8, 'little'))
    if len(prefix) < 76 + 7 * 32 or prefix[:76] != header:
        raise ValueError('canonical complete WTNS header required')
    values = [int.from_bytes(prefix[offset:offset + 32], 'little')
              for offset in range(76, 76 + 7 * 32, 32)]
    if values[0] != 1 or values[1:] != public or any(x >= FIELD_MODULUS for x in values):
        raise ValueError('WTNS public coordinates differ from public statement')


def _suite_root(report_path):
    report_path = Path(report_path)
    if not report_path.is_absolute() or report_path.name != 'report.json':
        raise ValueError('absolute witness suite report.json path required')
    root = report_path.parent
    _private_directory(root)
    if report_path.resolve(strict=True) != report_path:
        raise ValueError('canonical witness suite report path required')
    return root


def create(args):
    report_path = Path(args.suite_report)
    root = _suite_root(report_path)
    root_identity = _private_directory(root)
    report_sha256, report_raw, report_file_identity = _read_private(
        report_path, root, MAX_REPORT_BYTES, capture=MAX_REPORT_BYTES)
    if report_sha256 != args.suite_sha256:
        raise ValueError('witness suite SHA-256 does not match reviewed pin')
    report = _json(report_raw)
    accepted = validate_suite(report, args.suite_sha256)

    output = Path(args.output)
    if (not output.is_absolute() or output.parent != root or output == report_path
            or output.name in ('', '.', '..') or output.resolve(strict=False) != output
            or output.exists() or output.is_symlink()):
        raise ValueError('fresh output must be a direct child of the suite root')

    assignments = []
    file_identities = {report_file_identity}
    public_by_name = {}
    for name in sorted(accepted):
        wtns_path = root / f'{name}.wtns'
        public_path = root / f'{name}-public.json'
        wtns_sha, wtns_prefix, wtns_identity = _read_private(
            wtns_path, root, MAX_WTNS_BYTES, exact_size=WTNS_BYTES, capture=76 + 7 * 32)
        public_sha, public_raw, public_identity = _read_private(
            public_path, root, MAX_PUBLIC_BYTES, capture=MAX_PUBLIC_BYTES)
        if (wtns_identity in file_identities or public_identity in file_identities
                or wtns_identity == public_identity):
            raise ValueError('suite outputs must be distinct regular files')
        file_identities.update((wtns_identity, public_identity))
        public = _decode_public(public_raw)
        _check_wtns_public(wtns_prefix, public)
        public_by_name[name] = public
        assignment = {
            'name': name,
            'wtns_path': str(wtns_path),
            'wtns_sha256': wtns_sha,
            'public_path': str(public_path),
            'public_sha256': public_sha,
        }
        _exact_fields(assignment, ASSIGNMENT_RECORD_FIELDS, 'assignment record')
        assignments.append(assignment)

    for index in range(9):
        base = public_by_name[f'credential_{index}']
        near = public_by_name[f'credential_{index}_unrelated_refresh']
        if base[1:] != near[1:] or base[0] == near[0]:
            raise ValueError('accepted assignments must be root-only refresh pairs')

    manifest = {
        'schema': ASSIGNMENTS_SCHEMA,
        'synthetic_only': True,
        'accepted_suite_path': str(report_path),
        'accepted_suite_sha256': report_sha256,
        'assignments': assignments,
    }
    _exact_fields(manifest, MANIFEST_FIELDS, 'assignments manifest')
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError('assignments manifest exceeds package-check input cap')
    if _private_directory(root) != root_identity:
        raise ValueError('suite root changed before output')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(output, flags, 0o600)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError('private fresh output file required')
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite-report', required=True, type=Path)
    parser.add_argument('--suite-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        output_sha256 = create(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f'accepted assignments manifest rejected: {error}') from None
    print(json.dumps({'path': str(args.output), 'sha256': output_sha256}))


if __name__ == '__main__':
    main()
