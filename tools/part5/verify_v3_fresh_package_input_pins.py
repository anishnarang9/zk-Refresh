#!/usr/bin/env python3
"""Strict public input-record consistency for a prospective fresh v2 package.

Exact schema: schema='part5-v3-fresh-package-input-pins-v2', source_commit
(40 lowercase hex), toolchain, semantic_hashes, census, ordered_public_inputs,
reviewed_suite, public_repo_files. No additional keys anywhere.

toolchain: circom_version, node_version, rustc_version, cargo_version (bounded
release identifiers such as 2.2.3, v22.14.0, 1.90.0-nightly), circom_binary_sha256.
semantic_hashes: exact unchanged accepted r1cs_sha256, wasm_sha256,
profile_sha256, semantic_schema_sha256, circuit_source_sha256, symbol_map_sha256.
The circuit-source/schema values are existing semantic IDs, not assertions that
one source file has that raw hash. census: assignment_fields=784796,
constraints=793681, matrix_entries=4257583, domain_size=1048576.
ordered_public_inputs: root, issuerHash, notBefore, notAfter, actionHash, policyHash.
reviewed_suite: report_sha256 (fresh externally reviewed report bytes),
total_count=52, accepted_count=18, rejected_count=34.
public_repo_files: sorted unique list (possibly empty) of {path,sha256}, limited
to relative source/config paths accepted by _public_source_path. Files are
reopened and hashed in the selected repository; no private artifact reference
is permitted. This checker does not open the witness suite or establish its
truth/review, toolchain installation, source commit checkout, setup, proofs,
clean-checkout reproduction, or application compatibility.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.part5 import verify_v3_campaign_public_projection as strict_json

SCHEMA = 'part5-v3-fresh-package-input-pins-v2'
MAX_RECORD_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
SEMANTIC_HASHES = {
    'r1cs_sha256': '976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888',
    'wasm_sha256': 'fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6',
    'profile_sha256': '2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918',
    'semantic_schema_sha256': 'eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4',
    'circuit_source_sha256': '48d051e16dd1773b1831d9960a4a7f5a1fb6afd153ec2d87493696deb145d901',
    'symbol_map_sha256': 'd2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0',
}
CENSUS = {'assignment_fields': 784796, 'constraints': 793681,
          'matrix_entries': 4257583, 'domain_size': 1048576}
PUBLIC_INPUTS = ['root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash']
TOOL_VERSIONS = {'circom_version', 'node_version', 'rustc_version', 'cargo_version'}
FIELDS = {'schema', 'source_commit', 'toolchain', 'semantic_hashes', 'census',
          'ordered_public_inputs', 'reviewed_suite', 'public_repo_files'}
SCOPE = ('public input-record consistency and listed current source bytes only; '
         'suite truth/review, installed toolchains, checkout identity, and reproduction not established')


def _fields(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError('unknown or missing input-pins fields')


def _hash(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('lowercase SHA-256 required')


def _canonical(path):
    path = Path(path)
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('canonical nonsymlink public input required')
    except (OSError, RuntimeError):
        raise ValueError('public input unavailable') from None
    return path


def _read(path, cap):
    path = _canonical(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
                raise ValueError('bounded nonempty regular public input required')
            raw = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or len(raw) > cap or any(
                getattr(before, field) != getattr(after, field)
                for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            raise ValueError('public input changed during read')
        return raw
    except OSError:
        raise ValueError('public input unavailable') from None


def _public_source_path(value):
    if type(value) is not str or not 1 <= len(value) <= 240:
        raise ValueError('invalid public source path')
    if re.fullmatch('[A-Za-z0-9_./-]+', value) is None or any(
            part in ('', '.', '..') or part.startswith('.') for part in value.split('/')):
        raise ValueError('invalid public source path')
    path = Path(value)
    if path.is_absolute():
        raise ValueError('public source path must be relative')
    root_configs = {'package.json', 'package-lock.json', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'}
    prefixes = ('circuits/credential-v3-bounded/', 'tools/part5/', 'harness/tests/', 'program/src/')
    source = path.suffix in ('.circom', '.rs', '.py', '.cjs') or path.name in ('Cargo.toml', 'Cargo.lock')
    if value not in root_configs and value != 'circuits/credential-v3-bounded/profile.json' and not (
            value.startswith(prefixes) and source):
        raise ValueError('only public source/config references are allowed')
    return path


def verify_file(path, expected_raw_sha256, *, repo_root=REPO):
    """Check a separately trusted byte digest; never infer expected pins from input."""
    _hash(expected_raw_sha256)
    path = Path(path).absolute()
    raw = _read(path, MAX_RECORD_BYTES)
    if hashlib.sha256(raw).hexdigest() != expected_raw_sha256:
        raise ValueError('input-pins byte digest mismatch')
    record = strict_json._json_object(raw, 'input pins')
    _fields(record, FIELDS)
    if record['schema'] != SCHEMA:
        raise ValueError('unsupported input-pins schema')
    if type(record['source_commit']) is not str or re.fullmatch('[0-9a-f]{40}', record['source_commit']) is None:
        raise ValueError('40-character source commit required')
    tools = record['toolchain']
    _fields(tools, TOOL_VERSIONS | {'circom_binary_sha256'})
    _hash(tools['circom_binary_sha256'])
    for name in TOOL_VERSIONS:
        version = tools[name]
        if type(version) is not str or len(version) > 64 or re.fullmatch(
                r'v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?', version) is None:
            raise ValueError('bounded toolchain release identifier required')
    semantic = record['semantic_hashes']
    _fields(semantic, SEMANTIC_HASHES)
    for name, digest in semantic.items():
        _hash(digest)
        if digest != SEMANTIC_HASHES[name]:
            raise ValueError('accepted semantic identity mismatch')
    _fields(record['census'], CENSUS)
    for name, expected in CENSUS.items():
        if type(record['census'][name]) is not int or record['census'][name] != expected:
            raise ValueError('exact relation census required')
    if type(record['ordered_public_inputs']) is not list or record['ordered_public_inputs'] != PUBLIC_INPUTS:
        raise ValueError('exact public input order required')
    suite = record['reviewed_suite']
    _fields(suite, {'report_sha256', 'total_count', 'accepted_count', 'rejected_count'})
    _hash(suite['report_sha256'])
    for name, expected in (('total_count', 52), ('accepted_count', 18), ('rejected_count', 34)):
        if type(suite[name]) is not int or suite[name] != expected:
            raise ValueError('exact 52-case suite census required')
    files = record['public_repo_files']
    if type(files) is not list or len(files) > 128:
        raise ValueError('bounded public file reference list required')
    root = _canonical(Path(repo_root).absolute())
    if not root.is_dir():
        raise ValueError('repository directory required')
    previous, pins = '', []
    for reference in files:
        _fields(reference, {'path', 'sha256'})
        relative = _public_source_path(reference['path'])
        if reference['path'] <= previous:
            raise ValueError('public references must be sorted and distinct')
        previous = reference['path']
        _hash(reference['sha256'])
        if (reference['path'] == 'circuits/credential-v3-bounded/profile.json'
                and reference['sha256'] != SEMANTIC_HASHES['profile_sha256']):
            raise ValueError('public profile reference differs from accepted semantic pin')
        source = root / relative
        source_raw = _read(source, MAX_SOURCE_BYTES)
        if hashlib.sha256(source_raw).hexdigest() != reference['sha256']:
            raise ValueError('current public source digest mismatch')
        pins.append((source, reference['sha256']))
    for source, digest in pins:
        if hashlib.sha256(_read(source, MAX_SOURCE_BYTES)).hexdigest() != digest:
            raise ValueError('public source changed during verification')
    if _read(path, MAX_RECORD_BYTES) != raw:
        raise ValueError('input-pins record changed during verification')
    return {'schema': SCHEMA, 'input_record_consistent': True, 'scope': SCOPE,
            'public_source_file_count': len(files), 'suite_case_count': 52,
            'accepted_count': 18, 'rejected_count': 34,
            'clean_checkout_reproduction_established': False, 'setup_or_proofs_executed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--expected-raw-sha256', required=True)
    args = parser.parse_args()
    try:
        result = verify_file(args.record, args.expected_raw_sha256)
    except Exception as error:
        raise SystemExit(f'public input pins rejected ({type(error).__name__})') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
