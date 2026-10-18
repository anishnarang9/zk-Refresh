#!/usr/bin/env python3
"""Check a reviewed v2 package-output record against its referenced bytes.

This prospective source-level verifier authenticates a package record with a
separately supplied raw SHA-256, reopens its public inputs and private setup
outputs, and checks the v2 setup/package-check context. Synthetic fixtures can
exercise the contract without setup, proof, or application jobs. It does not
establish clean-checkout reproduction, proof-runner compatibility, or
application/deployment readiness.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.part5 import verify_v3_campaign_public_projection as strict_json
from tools.part5 import verify_v3_fresh_package_input_pins as input_pins_tool

SCHEMA = 'part5-v3-fresh-package-output-pins-v2'
MAX_RECORD_BYTES = 64 * 1024
MAX_REPORT_BYTES = 64 * 1024
MAX_VK_BYTES = 4096
MAX_PK_BYTES = 512 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
INPUT_PINS_PATH = 'docs/dynark/part5/v3-fresh-package-v2-input-pins.json'
SETUP_CRATE = 'circuits/credential-v3-bounded/qualification/prover-v2'
SETUP_SOURCE_PATH = f'{SETUP_CRATE}/src/main.rs'
SETUP_MANIFEST_SOURCE_PATH = f'{SETUP_CRATE}/Cargo.toml'
SETUP_LOCK_PATH = f'{SETUP_CRATE}/Cargo.lock'
SETUP_BINARY_PATH = f'{SETUP_CRATE}/target/release/credential-v3-bounded-qualification-v2'
PUBLIC_SCHEMA_SHA256 = 'ebb3ce4b4eef3ad43c5e21ad76d1bf9f0883a8ebc9e1a37c55c9894f1c00444b'
PUBLIC_INPUTS = ['root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash']
SEMANTIC_HASHES = dict(input_pins_tool.SEMANTIC_HASHES)
CENSUS = dict(input_pins_tool.CENSUS)
FIELDS = {
    'schema', 'source_commit', 'input_pins', 'setup_manifest',
    'package_check_report', 'ordinary_vk', 'proving_key', 'package_identity',
    'setup_launcher', 'semantic_hashes', 'census', 'ordered_public_inputs',
}
IDENTITY_FIELDS = {'matrix', 'circuit', 'pk', 'engine_extended_vk', 'package'}
HASH_REF_FIELDS = {'path', 'sha256'}
LAUNCHER_FIELDS = {'binary', 'source', 'manifest', 'lock'}
SETUP_FIELDS = {
    'schema', 'development_only', 'admitted', 'curve', 'reduction',
    'circuit_source_identity', 'launcher_src_sha256', 'package_manifest_sha256',
    'package_lock_sha256', 'semantic_schema_sha256', 'public_schema_sha256',
    'ordered_public_inputs', 'r1cs_sha256', 'wasm_sha256', 'profile_sha256',
    'input_pins_sha256', 'accepted_suite_sha256', 'constraints',
    'matrix_entries', 'assignment_fields', 'instance_fields_including_one',
    'ordinary_vk_ic_count', 'domain', 'ordinary_vk_tagged_digest',
    'six_field_adapter_qualified', 'identity', 'pk_file_sha256',
    'ordinary_vk_file_sha256', 'binary_sha256', 'accepted_suite_path',
    'input_pins_path', 'provenance', 'secret_scalars_written', 'elapsed_ms',
}
REPORT_FIELDS = {
    'schema', 'passed', 'development_only', 'identity',
    'ordinary_vk_file_sha256', 'input_pins_sha256', 'accepted_suite_sha256',
    'semantic_schema_sha256', 'public_schema_sha256', 'constraints',
    'matrix_entries', 'assignment_fields', 'accepted_complete_assignments',
    'root_refresh_pairs', 'public_package_loads', 'ordinary_vk_ic_count',
    'single_shared_package', 'setup_or_proofs_executed',
    'six_field_adapter_qualified', 'elapsed_ms', 'admitted',
}
SCOPE = (
    'prospective v2 package-output record and referenced-byte consistency only; '
    'clean-checkout reproduction, proof-runner compatibility, and '
    'application/deployment readiness are not established'
)


def _fields(value, expected, description):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError(f'unknown or missing {description} fields')


def _sha(value, description='SHA-256'):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError(f'{description} must be a lowercase SHA-256')
    return value


def _relative_path(value, description):
    if type(value) is not str or not 1 <= len(value) <= 300:
        raise ValueError(f'invalid {description} path')
    if re.fullmatch('[A-Za-z0-9_./-]+', value) is None:
        raise ValueError(f'invalid {description} path')
    parts = value.split('/')
    if any(part in ('', '.', '..') or part.startswith('.') for part in parts):
        raise ValueError(f'invalid {description} path')
    path = Path(value)
    if path.is_absolute():
        raise ValueError(f'{description} path must be relative')
    return path


def _canonical_root(repo_root):
    root = Path(repo_root).absolute()
    try:
        if root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError('canonical repository directory required')
    except (OSError, RuntimeError):
        raise ValueError('repository directory unavailable') from None
    return root


def _repo_path(root, relative, description, allowed_prefixes):
    relative = _relative_path(relative, description)
    if not any(str(relative).startswith(prefix) for prefix in allowed_prefixes):
        raise ValueError(f'{description} path is outside its allowed repository area')
    path = root / relative
    try:
        if path.resolve(strict=True) != path:
            raise ValueError(f'{description} must be a canonical nonsymlink path')
    except (OSError, RuntimeError):
        raise ValueError(f'{description} unavailable') from None
    return path


def _stable_read(path, cap, *, owner_uid, modes, private=False):
    """Read one bounded file without following a final symlink or blocking on a FIFO."""
    path = Path(path)
    try:
        if path.resolve(strict=True) != path:
            raise ValueError('canonical nonsymlink artifact required')
        before_path = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before_path.st_mode) or before_path.st_size <= 0 or before_path.st_size > cap:
            raise ValueError('bounded nonempty regular artifact required')
        mode = stat.S_IMODE(before_path.st_mode)
        if before_path.st_uid != owner_uid or mode not in modes:
            if private:
                raise ValueError('private artifact permissions/owner')
            raise ValueError('public artifact permissions/owner')
        if private:
            parent = path.parent.stat(follow_symlinks=False)
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner_uid
                    or stat.S_IMODE(parent.st_mode) != 0o700):
                raise ValueError('private artifact directory permissions/owner')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_dev != before_path.st_dev
                    or before.st_ino != before_path.st_ino or before.st_size != before_path.st_size):
                raise ValueError('artifact changed at open')
            chunks = []
            remaining = cap + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(chunks)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        after_path = path.stat(follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(raw) != before.st_size or len(raw) > cap
                or any(getattr(before, field) != getattr(after, field) for field in fields)
                or any(getattr(before_path, field) != getattr(after_path, field) for field in fields)):
            raise ValueError('artifact changed during read')
        return raw
    except OSError:
        raise ValueError('artifact unavailable') from None


def _read_ref(root, reference, description, *, cap, owner_uid, private,
              allowed_prefixes, modes):
    _fields(reference, HASH_REF_FIELDS, description)
    expected = _sha(reference['sha256'], f'{description} SHA-256')
    path = _repo_path(root, reference['path'], description, allowed_prefixes)
    raw = _stable_read(path, cap, owner_uid=owner_uid, modes=modes, private=private)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f'{description} artifact digest mismatch')
    return path, raw, expected


def _json_object(raw, description):
    return strict_json._json_object(raw, description)


def _validate_identity(value, description):
    _fields(value, IDENTITY_FIELDS, f'{description} identity')
    for field in IDENTITY_FIELDS:
        _sha(value[field], f'{description} identity {field}')


def _same_json(left, right, description):
    if left != right:
        raise ValueError(f'{description} mismatch')


def _validate_record(record):
    _fields(record, FIELDS, 'package-output record')
    if record['schema'] != SCHEMA:
        raise ValueError('unsupported package-output record schema')
    if type(record['source_commit']) is not str or re.fullmatch('[0-9a-f]{40}', record['source_commit']) is None:
        raise ValueError('40-character source commit required')
    _validate_identity(record['package_identity'], 'package-output')
    _fields(record['semantic_hashes'], SEMANTIC_HASHES, 'semantic hashes')
    for field, expected in SEMANTIC_HASHES.items():
        _sha(record['semantic_hashes'][field], field)
        if record['semantic_hashes'][field] != expected:
            raise ValueError('accepted semantic identity mismatch')
    _fields(record['census'], CENSUS, 'census')
    for field, expected in CENSUS.items():
        if type(record['census'][field]) is not int or record['census'][field] != expected:
            raise ValueError('exact relation census required')
    if type(record['ordered_public_inputs']) is not list or record['ordered_public_inputs'] != PUBLIC_INPUTS:
        raise ValueError('exact public-input order required')
    _fields(record['setup_launcher'], LAUNCHER_FIELDS, 'setup launcher')
    for name in LAUNCHER_FIELDS:
        _fields(record['setup_launcher'][name], HASH_REF_FIELDS, f'setup launcher {name}')
        _sha(record['setup_launcher'][name]['sha256'], f'setup launcher {name} SHA-256')


def verify_file(record_path, expected_raw_sha256, *, repo_root=REPO, owner_uid=None):
    """Verify externally pinned v2 package output references and their context.

    The package-record digest is supplied by the caller. Digests in the record
    are used only as reviewed expectations for the separately reopened files;
    no expected digest is inferred from a received output.
    """
    _sha(expected_raw_sha256, 'external package-output record SHA-256')
    root = _canonical_root(repo_root)
    owner = os.geteuid() if owner_uid is None else owner_uid
    record_path = Path(record_path).absolute()
    try:
        if record_path.resolve(strict=True) != record_path or not record_path.is_relative_to(root):
            raise ValueError('package-output record must be canonical inside the repository')
    except (OSError, RuntimeError):
        raise ValueError('package-output record unavailable') from None
    record_raw = _stable_read(record_path, MAX_RECORD_BYTES, owner_uid=owner,
                              modes={0o600, 0o644})
    if hashlib.sha256(record_raw).hexdigest() != expected_raw_sha256:
        raise ValueError('package-output record byte digest mismatch')
    record = _json_object(record_raw, 'package-output record')
    _validate_record(record)

    pins_path, pins_raw, pins_sha = _read_ref(
        root, record['input_pins'], 'input pins', cap=MAX_RECORD_BYTES,
        owner_uid=owner, private=False, allowed_prefixes=('docs/dynark/part5/',),
        modes={0o600, 0o644})
    if str(Path(record['input_pins']['path'])) != INPUT_PINS_PATH:
        raise ValueError('v2 input-pins path required')
    pins = input_pins_tool.verify_file(
        pins_path, pins_sha, repo_root=root)
    pins_record = _json_object(pins_raw, 'input pins')
    _same_json(record['source_commit'], pins_record['source_commit'], 'source commit')
    _same_json(record['semantic_hashes'], pins_record['semantic_hashes'], 'input-pins semantic context')
    _same_json(record['census'], pins_record['census'], 'input-pins census context')
    _same_json(record['ordered_public_inputs'], pins_record['ordered_public_inputs'], 'input-pins public-input context')
    suite_sha = pins_record['reviewed_suite']['report_sha256']

    setup_launcher = record['setup_launcher']
    launcher_path_contract = {
        'binary': (SETUP_BINARY_PATH, MAX_BINARY_BYTES, {0o700, 0o755}),
        'source': (SETUP_SOURCE_PATH, MAX_SOURCE_BYTES, {0o600, 0o644}),
        'manifest': (SETUP_MANIFEST_SOURCE_PATH, MAX_SOURCE_BYTES, {0o600, 0o644}),
        'lock': (SETUP_LOCK_PATH, MAX_SOURCE_BYTES, {0o600, 0o644}),
    }
    launcher_digests = {}
    for name, (expected_path, cap, modes) in launcher_path_contract.items():
        ref = setup_launcher[name]
        if ref['path'] != expected_path:
            raise ValueError(f'v2 setup launcher {name} path required')
        _, _, digest = _read_ref(
            root, ref, f'setup launcher {name}', cap=cap, owner_uid=owner,
            private=False, allowed_prefixes=(f'{SETUP_CRATE}/',), modes=modes)
        launcher_digests[name] = digest

    setup_path, setup_raw, _ = _read_ref(
        root, record['setup_manifest'], 'setup manifest', cap=MAX_REPORT_BYTES,
        owner_uid=owner, private=True, allowed_prefixes=('artifacts/dynark/part5/',),
        modes={0o600})
    report_path, report_raw, _ = _read_ref(
        root, record['package_check_report'], 'package-check report', cap=MAX_REPORT_BYTES,
        owner_uid=owner, private=True, allowed_prefixes=('artifacts/dynark/part5/',),
        modes={0o600})
    vk_path, _, vk_sha = _read_ref(
        root, record['ordinary_vk'], 'ordinary VK', cap=MAX_VK_BYTES,
        owner_uid=owner, private=True, allowed_prefixes=('artifacts/dynark/part5/',),
        modes={0o600})
    pk_path, _, pk_sha = _read_ref(
        root, record['proving_key'], 'proving key', cap=MAX_PK_BYTES,
        owner_uid=owner, private=True, allowed_prefixes=('artifacts/dynark/part5/',),
        modes={0o600})
    if setup_path.parent != vk_path.parent or setup_path.parent != pk_path.parent:
        raise ValueError('setup manifest, VK, and proving key must share one private output directory')
    if setup_path == report_path:
        raise ValueError('setup manifest and package-check report paths must differ')

    setup = _json_object(setup_raw, 'setup manifest')
    _fields(setup, SETUP_FIELDS, 'setup manifest v2')
    if setup['schema'] != 'credential-v3-bounded-setup-v2':
        raise ValueError('unsupported setup manifest v2 schema')
    for field, expected in (
        ('development_only', True), ('admitted', False), ('curve', 'BN254'),
        ('reduction', 'Original'), ('circuit_source_identity', SEMANTIC_HASHES['circuit_source_sha256']),
        ('launcher_src_sha256', launcher_digests['source']),
        ('package_manifest_sha256', launcher_digests['manifest']),
        ('package_lock_sha256', launcher_digests['lock']),
        ('semantic_schema_sha256', SEMANTIC_HASHES['semantic_schema_sha256']),
        ('public_schema_sha256', PUBLIC_SCHEMA_SHA256),
        ('ordered_public_inputs', PUBLIC_INPUTS),
        ('r1cs_sha256', SEMANTIC_HASHES['r1cs_sha256']),
        ('wasm_sha256', SEMANTIC_HASHES['wasm_sha256']),
        ('profile_sha256', SEMANTIC_HASHES['profile_sha256']),
        ('input_pins_sha256', pins_sha), ('accepted_suite_sha256', suite_sha),
        ('constraints', CENSUS['constraints']), ('matrix_entries', CENSUS['matrix_entries']),
        ('assignment_fields', CENSUS['assignment_fields']),
        ('instance_fields_including_one', 7), ('ordinary_vk_ic_count', 7),
        ('domain', CENSUS['domain_size']), ('ordinary_vk_tagged_digest', None),
        ('six_field_adapter_qualified', False), ('pk_file_sha256', pk_sha),
        ('ordinary_vk_file_sha256', vk_sha), ('binary_sha256', launcher_digests['binary']),
        ('provenance', 'one-time OS-CSPRNG trusted development setup; no production ceremony or secure erasure claim'),
        ('secret_scalars_written', False),
    ):
        if setup.get(field) != expected:
            raise ValueError(f'setup manifest v2 context mismatch: {field}')
    if type(setup['elapsed_ms']) not in (int, float) or not math.isfinite(setup['elapsed_ms']) or setup['elapsed_ms'] < 0:
        raise ValueError('setup manifest elapsed time invalid')
    _validate_identity(setup['identity'], 'setup manifest')
    _same_json(setup['identity'], record['package_identity'], 'setup package identity')
    input_path_text = setup['input_pins_path']
    if type(input_path_text) is not str or not Path(input_path_text).is_absolute():
        raise ValueError('setup manifest input-pins path invalid')
    if Path(input_path_text).resolve(strict=True) != pins_path:
        raise ValueError('setup manifest input-pins path mismatch')
    if type(setup['accepted_suite_path']) is not str or not setup['accepted_suite_path']:
        raise ValueError('setup manifest suite reference invalid')

    report = _json_object(report_raw, 'package-check report')
    _fields(report, REPORT_FIELDS, 'package-check report v2')
    if report['schema'] != 'credential-v3-bounded-public-package-check-v2':
        raise ValueError('unsupported package-check v2 schema')
    for field, expected in (
        ('passed', True), ('development_only', True), ('identity', record['package_identity']),
        ('ordinary_vk_file_sha256', vk_sha), ('input_pins_sha256', pins_sha),
        ('accepted_suite_sha256', suite_sha),
        ('semantic_schema_sha256', SEMANTIC_HASHES['semantic_schema_sha256']),
        ('public_schema_sha256', PUBLIC_SCHEMA_SHA256),
        ('constraints', CENSUS['constraints']), ('matrix_entries', CENSUS['matrix_entries']),
        ('assignment_fields', CENSUS['assignment_fields']),
        ('accepted_complete_assignments', 18), ('root_refresh_pairs', 9),
        ('public_package_loads', 1), ('ordinary_vk_ic_count', 7),
        ('single_shared_package', True), ('setup_or_proofs_executed', False),
        ('six_field_adapter_qualified', False), ('admitted', False),
    ):
        if report.get(field) != expected:
            raise ValueError(f'package-check v2 context mismatch: {field}')
    if type(report['elapsed_ms']) not in (int, float) or not math.isfinite(report['elapsed_ms']) or report['elapsed_ms'] < 0:
        raise ValueError('package-check report elapsed time invalid')
    _validate_identity(report['identity'], 'package-check report')
    _same_json(report['identity'], setup['identity'], 'setup/package-check identity')

    if _stable_read(record_path, MAX_RECORD_BYTES, owner_uid=owner, modes={0o600, 0o644}) != record_raw:
        raise ValueError('package-output record changed during verification')
    return {
        'schema': SCHEMA,
        'package_output_record_consistent': True,
        'scope': SCOPE,
        'package_sha256': record['package_identity']['package'],
        'accepted_complete_assignments': 18,
        'root_refresh_pairs': 9,
        'clean_checkout_reproduction_established': False,
        'proof_runner_or_application_compatibility_established': False,
        'setup_or_proofs_executed_by_verifier': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--expected-raw-sha256', required=True)
    args = parser.parse_args()
    try:
        result = verify_file(args.record, args.expected_raw_sha256)
    except Exception as error:
        raise SystemExit(f'prospective v2 package-output pins rejected ({type(error).__name__})') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
