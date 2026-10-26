#!/usr/bin/env python3
"""Prepare a private v2 heldout proof template; never generate witnesses or proofs.

The caller supplies reviewed package and heldout-relation report digests. This
tool verifies the fresh package-output record, checks the unchanged v3
compile-time identities at their v2 paths, and links every private input scalar
to the complete WTNS assignment and its public statement. The template is
consumed by build_v3_heldout_packet_v2.py.
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

from tools.part5 import credential_profile as profile
from tools.part5 import verify_v3_fresh_package_output_pins as package_output_pins
from tools.part5.build_v3_heldout_packet_v2 import TEMPLATE_FIELDS

PACKAGE_PINS_PATH = 'docs/dynark/part5/v3-fresh-package-v2-package-pins.json'
INPUT_PINS_PATH = 'docs/dynark/part5/v3-fresh-package-v2-input-pins.json'
COMPILE_ROOT = 'artifacts/dynark/part5/v3-compile-002'
SETUP_MANIFEST_PATH = 'artifacts/dynark/part5/v3-development-setup-002/setup-manifest.json'
PACKAGE_CHECK_PATH = 'artifacts/dynark/part5/v3-package-check-002/package-check-report.json'
PROFILE_PATH = 'circuits/credential-v3-bounded/profile.json'
FREEZE_SCHEMA = 'credential-v3-frozen-holdout-boundary-v2'
SUITE_SCHEMA = 'credential-v3-bounded-witness-qualification-v1'
ASSIGNMENTS_SCHEMA = 'credential-v3-bounded-private-assignments-v1'
INPUT_MAP_SCHEMA = 'credential-v3-bounded-input-wire-map-v1'
FR = profile.FR
PUBLIC_NAMES = profile.PUBLIC_NAMES
ARRAYS = [
    ('tbs', 672), ('issuerModulus', 17), ('issuerSignature', 17),
    ('holderSignature', 17), ('siblings', 10), ('pathIndices', 10),
]
ASSIGNMENT_FIELDS = 784796
CONSTRAINTS = 793681
MATRIX_ENTRIES = 4257583
DOMAIN_SIZE = 1048576
PUBLIC_INPUTS = ['root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash']
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
ASSIGNMENT_MANIFEST_FIELDS = {
    'schema', 'synthetic_only', 'accepted_suite_path',
    'accepted_suite_sha256', 'assignments',
}
ASSIGNMENT_ROW_FIELDS = {
    'name', 'wtns_path', 'wtns_sha256', 'public_path', 'public_sha256',
}
FREEZE_SHA_FIELDS = {
    'client_sha256', 'adapter_sha256', 'application_source_sha256',
    'application_elf_sha256', 'proof_binary_sha256', 'proof_source_identity',
    'input_preparer_sha256',
}
MAX_JSON_BYTES = 65536
MAX_WTNS_BYTES = 32 * 1024 * 1024
MAX_SYMBOL_BYTES = 256 * 1024 * 1024
MAX_COMPILE_BYTES = 512 * 1024 * 1024


def _sha(value, label='SHA-256'):
    if type(value) is not str or re.fullmatch(r'[0-9a-f]{64}', value) is None:
        raise ValueError(f'{label} must be a lowercase SHA-256')
    return value


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError('non-finite JSON number')

    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def _exact_fields(value, expected, label):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError(f'{label} fields')


def _private_directory(path):
    path = Path(path)
    try:
        info = path.lstat()
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('canonical owner-only directory required')
        return info.st_dev, info.st_ino
    except OSError:
        raise ValueError('owner-only directory unavailable') from None


def received(path, cap, expected=None, *, private=True, exact_size=None, retain=True):
    """Hash one bounded canonical artifact while rejecting replacement and links."""
    path = Path(path)
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('canonical absolute artifact required')
        before_path = path.lstat()
        modes = {0o600} if private else {0o600, 0o644}
        if (not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1
                or before_path.st_uid != os.geteuid()
                or stat.S_IMODE(before_path.st_mode) not in modes
                or before_path.st_size <= 0 or before_path.st_size > cap
                or (exact_size is not None and before_path.st_size != exact_size)):
            raise ValueError('artifact type/owner/mode/link/size')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                             | getattr(os, 'O_NONBLOCK', 0))
        hasher = hashlib.sha256()
        chunks = []
        count = 0
        try:
            before = os.fstat(descriptor)
            if (before.st_dev != before_path.st_dev or before.st_ino != before_path.st_ino
                    or not stat.S_ISREG(before.st_mode)):
                raise ValueError('artifact changed at open')
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > cap:
                    raise ValueError('artifact grew beyond bound')
                hasher.update(block)
                if retain:
                    chunks.append(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
        stable_fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (count != before.st_size
                or any(getattr(before, field) != getattr(after, field) for field in stable_fields)
                or any(getattr(before_path, field) != getattr(after_path, field)
                       for field in stable_fields)):
            raise ValueError('artifact changed while reading')
        digest = hasher.hexdigest()
        if expected is not None and digest != _sha(expected, 'expected artifact SHA-256'):
            raise ValueError('pinned artifact digest mismatch')
        return digest, b''.join(chunks) if retain else b''
    except OSError:
        raise ValueError('artifact unavailable') from None


def _record_path(path, repo_root):
    root = Path(repo_root).absolute()
    if root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError('canonical repository root required')
    expected = root / PACKAGE_PINS_PATH
    path = Path(path).absolute()
    if path != expected or path.resolve(strict=True) != path:
        raise ValueError('exact external v2 package-pins path required')
    return root, path


def _ref_path(record, key, root, expected_relative):
    ref = record.get(key)
    _exact_fields(ref, {'path', 'sha256'}, f'{key} pin')
    digest = _sha(ref['sha256'], f'{key} pin SHA-256')
    if ref['path'] != expected_relative:
        raise ValueError(f'exact v2 {key} path required')
    path = root / expected_relative
    if path.resolve(strict=True) != path:
        raise ValueError(f'canonical v2 {key} path required')
    return path, digest


def load_package_record(record_path, expected_raw_sha256, *, repo_root=REPO):
    """Verify an externally hashed v2 package-output record and return its context."""
    expected_raw_sha256 = _sha(expected_raw_sha256, 'external package-pins SHA-256')
    root, record_path = _record_path(record_path, repo_root)
    verified = package_output_pins.verify_file(
        record_path, expected_raw_sha256, repo_root=root,
    )
    if (type(verified) is not dict
            or verified.get('schema') != package_output_pins.SCHEMA
            or verified.get('package_output_record_consistent') is not True):
        raise ValueError('v2 package-output verifier did not confirm record consistency')
    record_raw_sha, raw = received(record_path, MAX_JSON_BYTES, expected_raw_sha256,
                                   private=False)
    del record_raw_sha
    record = _json(raw)
    if (type(record) is not dict
            or record.get('schema') != package_output_pins.SCHEMA):
        raise ValueError('verified v2 package-output record required')
    _exact_fields(record['package_identity'], package_output_pins.IDENTITY_FIELDS,
                  'package identity')
    package_digest = _sha(record['package_identity']['package'], 'package digest')
    if (package_digest != record.get('package_identity', {}).get('package')
            or verified.get('package_sha256') != package_digest):
        raise ValueError('v2 package identity mismatch')
    semantic = record.get('semantic_hashes')
    _exact_fields(semantic, package_output_pins.SEMANTIC_HASHES, 'semantic hashes')
    expected_hashes = {
        'r1cs_sha256': package_output_pins.SEMANTIC_HASHES['r1cs_sha256'],
        'wasm_sha256': package_output_pins.SEMANTIC_HASHES['wasm_sha256'],
        'profile_sha256': package_output_pins.SEMANTIC_HASHES['profile_sha256'],
        'symbol_map_sha256': package_output_pins.SEMANTIC_HASHES['symbol_map_sha256'],
    }
    for key, expected in expected_hashes.items():
        if _sha(semantic.get(key), key) != expected:
            raise ValueError(f'accepted v2 compile identity mismatch: {key}')

    setup_path, setup_sha = _ref_path(record, 'setup_manifest', root, SETUP_MANIFEST_PATH)
    package_path, package_sha = _ref_path(
        record, 'package_check_report', root, PACKAGE_CHECK_PATH,
    )
    input_ref = record.get('input_pins')
    _exact_fields(input_ref, {'path', 'sha256'}, 'input-pins reference')
    if input_ref['path'] != INPUT_PINS_PATH:
        raise ValueError('exact v2 input-pins path required')
    _sha(input_ref['sha256'], 'input-pins digest')

    compile_root = root / COMPILE_ROOT
    r1cs_path = compile_root / 'credential.r1cs'
    wasm_path = compile_root / 'credential_js/credential.wasm'
    symbol_path = compile_root / 'credential.sym'
    profile_path = root / PROFILE_PATH
    _private_directory(compile_root)
    _private_directory(wasm_path.parent)
    for path in (r1cs_path, wasm_path, symbol_path, profile_path):
        if path.resolve(strict=True) != path:
            raise ValueError('canonical v2 compile/profile path required')
    received(r1cs_path, MAX_COMPILE_BYTES, expected_hashes['r1cs_sha256'], retain=False)
    received(wasm_path, MAX_COMPILE_BYTES, expected_hashes['wasm_sha256'], retain=False)
    received(symbol_path, MAX_SYMBOL_BYTES, expected_hashes['symbol_map_sha256'], retain=False)
    received(profile_path, 1024 * 1024, expected_hashes['profile_sha256'],
             private=False, retain=False)
    return {
        'package_digest': package_digest,
        'setup_manifest_path': str(setup_path),
        'setup_manifest_sha256': setup_sha,
        'package_check_path': str(package_path),
        'package_check_sha256': package_sha,
        'r1cs_path': str(r1cs_path),
        'wasm_path': str(wasm_path),
        'symbol_map_path': str(symbol_path),
        'profile_path': str(profile_path),
        'semantic_hashes': semantic,
        'package_pins_path': str(record_path),
        'package_pins_sha256': expected_raw_sha256,
        'input_pins_path': str(root / INPUT_PINS_PATH),
        'input_pins_sha256': input_ref['sha256'],
    }


def required_symbols():
    symbols = ['main.' + key for key in PUBLIC_NAMES + ['layout', 'slot']]
    for name, count in ARRAYS:
        symbols.extend(f'main.{name}[{index}]' for index in range(count))
    return symbols


def scalar(value):
    if (type(value) is not str or re.fullmatch(r'0|[1-9][0-9]*', value) is None
            or len(value) > 77 or int(value) >= FR):
        raise ValueError('noncanonical scalar input')
    return int(value)


def flatten_inputs(inputs):
    expected_keys = PUBLIC_NAMES + ['layout', 'slot'] + [name for name, _ in ARRAYS]
    if type(inputs) is not dict or set(inputs) != set(expected_keys):
        raise ValueError('exact input keys required')
    flat = {'main.' + key: scalar(inputs[key]) for key in PUBLIC_NAMES + ['layout', 'slot']}
    for name, count in ARRAYS:
        if type(inputs[name]) is not list or len(inputs[name]) != count:
            raise ValueError('input array shape')
        flat.update({f'main.{name}[{index}]': scalar(value)
                     for index, value in enumerate(inputs[name])})
    return flat


def map_from_lines(lines):
    wanted = set(required_symbols())
    mapping = {}
    seen = set()
    for line in lines:
        fields = line.rstrip('\n').split(',', 3)
        if len(fields) != 4:
            raise ValueError('compiler symbol line')
        name = fields[3]
        if name not in wanted:
            continue
        try:
            index = int(fields[1])
        except ValueError:
            raise ValueError('compiler input coordinate') from None
        if name in mapping or not 0 < index < ASSIGNMENT_FIELDS or index in seen:
            raise ValueError('ambiguous or eliminated input coordinate')
        mapping[name] = index
        seen.add(index)
    if (set(mapping) != wanted
            or any(mapping['main.' + name] != index
                   for index, name in enumerate(PUBLIC_NAMES, 1))):
        raise ValueError('complete input map and exact public order required')
    return mapping


def _pinned_symbol_map(path, expected_sha256):
    """Parse and hash the large compiler map through one stable descriptor."""
    path = Path(path)
    expected_sha256 = _sha(expected_sha256, 'symbol-map digest')
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('canonical symbol-map path required')
        before_path = path.lstat()
        if (not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1
                or before_path.st_uid != os.geteuid()
                or stat.S_IMODE(before_path.st_mode) != 0o600
                or not 0 < before_path.st_size <= MAX_SYMBOL_BYTES):
            raise ValueError('bounded owner-only symbol map required')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        flags |= getattr(os, 'O_NONBLOCK', 0)
        with os.fdopen(os.open(path, flags), 'rb') as source:
            before = os.fstat(source.fileno())
            if (before.st_dev != before_path.st_dev or before.st_ino != before_path.st_ino
                    or before.st_size != before_path.st_size
                    or not stat.S_ISREG(before.st_mode)):
                raise ValueError('symbol map changed at open')
            hasher = hashlib.sha256()
            consumed = 0

            def lines():
                nonlocal consumed
                while True:
                    raw = source.readline(4097)
                    if not raw:
                        break
                    if len(raw) > 4096:
                        raise ValueError('compiler symbol line too long')
                    consumed += len(raw)
                    if consumed > MAX_SYMBOL_BYTES:
                        raise ValueError('symbol map grew beyond bound')
                    hasher.update(raw)
                    yield raw.decode('utf-8')

            mapping = map_from_lines(lines())
            after = os.fstat(source.fileno())
        after_path = path.lstat()
        stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (consumed != before.st_size
                or any(getattr(before, field) != getattr(after, field) for field in stable)
                or any(getattr(before_path, field) != getattr(after_path, field)
                       for field in stable)):
            raise ValueError('symbol map changed during parse')
        if hasher.hexdigest() != expected_sha256:
            raise ValueError('symbol map digest mismatch')
        return mapping
    except OSError:
        raise ValueError('symbol map unavailable') from None


def verify_wtns_input_link(path, flat, mapping, expected_count=ASSIGNMENT_FIELDS):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute WTNS path required')
    before_path = path.lstat()
    if (not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1
            or before_path.st_uid != os.geteuid()
            or stat.S_IMODE(before_path.st_mode) != 0o600):
        raise ValueError('owner-only regular WTNS required')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                         | getattr(os, 'O_NONBLOCK', 0))
    try:
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            before = os.fstat(source.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_dev != before_path.st_dev
                    or before.st_ino != before_path.st_ino or before.st_size != before_path.st_size):
                raise ValueError('WTNS changed at open')
            header = source.read(76)
            expected = (
                b'wtns' + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little')
                + (1).to_bytes(4, 'little') + (40).to_bytes(8, 'little')
                + (32).to_bytes(4, 'little') + FR.to_bytes(32, 'little')
                + expected_count.to_bytes(4, 'little') + (2).to_bytes(4, 'little')
                + (32 * expected_count).to_bytes(8, 'little')
            )
            if header != expected or before.st_size != 76 + 32 * expected_count:
                raise ValueError('canonical WTNS header/size')
            if int.from_bytes(source.read(32), 'little') != 1:
                raise ValueError('WTNS constant one')
            if set(flat) != set(mapping):
                raise ValueError('input map completeness')
            for name, index in mapping.items():
                if not 0 < index < expected_count:
                    raise ValueError('input witness coordinate')
                source.seek(76 + 32 * index)
                if int.from_bytes(source.read(32), 'little') != flat[name]:
                    raise ValueError('input-to-WTNS coordinate mismatch')
            after = os.fstat(source.fileno())
        after_path = path.lstat()
        stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (any(getattr(before, key) != getattr(after, key) for key in stable)
                or any(getattr(before_path, key) != getattr(after_path, key) for key in stable)):
            raise ValueError('WTNS changed during coordinate checks')
    finally:
        os.close(descriptor)


def validate_heldout_report(report, external_sha256, r1cs_sha256, wasm_sha256):
    _sha(external_sha256, 'external heldout relation-report SHA-256')
    _exact_fields(report, REPORT_FIELDS, 'heldout relation report')
    if (report['schema'] != SUITE_SCHEMA or report['passed'] is not True
            or report['host_admission_bypassed'] is not True
            or report['setup_or_proofs_executed'] is not False
            or report['outputs_private'] is not True
            or report['r1cs_sha256'] != r1cs_sha256
            or report['wasm_sha256'] != wasm_sha256):
        raise ValueError('heldout relation-report identity/context')
    cases = report['cases']
    if (type(cases) is not list or type(report['accepted_count']) is not int
            or report['accepted_count'] != 16 or type(report['rejected_count']) is not int
            or report['rejected_count'] < 0 or len(cases) != 16 + report['rejected_count']):
        raise ValueError('exact sixteen heldout accepted assignments required')
    expected_names = {
        name for index in range(8)
        for name in (f'holdout_{index}', f'holdout_{index}_unrelated_refresh')
    }
    accepted = {}
    rejected = 0
    seen = set()
    for case in cases:
        if type(case) is not dict:
            raise ValueError('heldout relation case object required')
        name = case.get('name')
        if type(name) is not str or re.fullmatch(r'[A-Za-z0-9_]{1,80}', name) is None or name in seen:
            raise ValueError('unique safe heldout relation case names required')
        seen.add(name)
        if case.get('passed') is not True or type(case.get('family')) is not str or not case['family']:
            raise ValueError('all heldout relation cases must pass')
        elapsed = case.get('witness_elapsed_ms')
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError('heldout witness timing')
        if case.get('expected') == 'accept':
            _exact_fields(case, ACCEPTED_CASE_FIELDS, 'accepted heldout case')
            validation = case['validation']
            _exact_fields(validation, VALIDATION_FIELDS, 'heldout relation census')
            if (validation.get('satisfied') is not True
                    or type(validation.get('constraints_checked')) is not int
                    or validation['constraints_checked'] != CONSTRAINTS
                    or type(validation.get('assignment_fields')) is not int
                    or validation['assignment_fields'] != ASSIGNMENT_FIELDS
                    or type(validation.get('matrix_entries')) is not int
                    or validation['matrix_entries'] != MATRIX_ENTRIES
                    or type(validation.get('max_row_terms')) is not int
                    or not 0 <= validation['max_row_terms'] <= 4096):
                raise ValueError('complete heldout relation census required')
            relation_ms = case.get('complete_relation_check_ms')
            if (type(relation_ms) not in (int, float) or not math.isfinite(relation_ms)
                    or relation_ms < 0):
                raise ValueError('heldout complete-relation timing')
            accepted[name] = case
        elif case.get('expected') == 'reject':
            _exact_fields(case, REJECTED_CASE_FIELDS, 'rejected heldout case')
            if case.get('rejection') != 'circuit_assertion':
                raise ValueError('negative heldout case must reject at circuit assertion')
            rejected += 1
        else:
            raise ValueError('heldout relation expectation')
    if set(accepted) != expected_names or rejected != report['rejected_count']:
        raise ValueError('all and only eight heldout root-refresh pairs required')
    return accepted


def build_template(package_context, input_map_path, input_map_sha256):
    input_map_path = Path(input_map_path)
    if (not input_map_path.is_absolute() or input_map_path.resolve(strict=True) != input_map_path):
        raise ValueError('canonical absolute private input map required')
    result = {
        'package_digest': package_context['package_digest'],
        'setup_manifest_path': package_context['setup_manifest_path'],
        'setup_manifest_sha256': package_context['setup_manifest_sha256'],
        'package_check_path': package_context['package_check_path'],
        'package_check_sha256': package_context['package_check_sha256'],
        'r1cs_path': package_context['r1cs_path'],
        'wasm_path': package_context['wasm_path'],
        'profile_path': package_context['profile_path'],
        'input_map_path': str(input_map_path),
        'input_map_sha256': _sha(input_map_sha256, 'input-map SHA-256'),
    }
    _exact_fields(result, TEMPLATE_FIELDS, 'v2 packet template')
    for key in ('package_digest', 'setup_manifest_sha256', 'package_check_sha256'):
        _sha(result[key], key)
    for key in ('setup_manifest_path', 'package_check_path', 'r1cs_path',
                'wasm_path', 'profile_path', 'input_map_path'):
        path = Path(result[key])
        if not path.is_absolute() or str(path) != result[key]:
            raise ValueError(f'absolute {key} required')
    if ('v3-development-setup-002' not in result['setup_manifest_path']
            or 'v3-package-check-002' not in result['package_check_path']
            or COMPILE_ROOT not in result['r1cs_path']
            or COMPILE_ROOT not in result['wasm_path']):
        raise ValueError('v2 setup, package-check, and compile paths required')
    return result


def _freeze_context(path, expected_sha256, package_context, preparer_sha256):
    _sha(expected_sha256, 'heldout freeze SHA-256')
    _private_directory(Path(path).absolute().parent)
    raw_sha, raw = received(path, MAX_JSON_BYTES, expected_sha256)
    del raw_sha
    frozen = _json(raw)
    if type(frozen) is not dict:
        raise ValueError('heldout freeze object required')
    frozen_at = frozen.get('frozen_at_unix_ns')
    if (frozen.get('schema') != FREEZE_SCHEMA or type(frozen_at) is not int
            or not 0 < frozen_at < 2**64
            or frozen.get('setup_manifest_sha256') != package_context['setup_manifest_sha256']
            or frozen.get('package_digest') != package_context['package_digest']
            or frozen.get('package_pins_sha256') != package_context['package_pins_sha256']
            or frozen.get('input_preparer_sha256') != preparer_sha256):
        raise ValueError('v2 heldout freeze identity mismatch')
    for key in FREEZE_SHA_FIELDS:
        _sha(frozen.get(key), f'freeze {key}')
    return frozen


def _read_json(path, cap, expected_sha256=None, *, private=True):
    digest, raw = received(path, cap, expected_sha256, private=private)
    return digest, _json(raw)


def _input_path(path, root):
    path = Path(path).absolute()
    if path.parent != root or path.resolve(strict=True) != path:
        raise ValueError('heldout input must be a direct child of the private input root')
    return path


def _accepted_manifest(assignments, report_sha256,
                       report_path, report, input_root, frozen_at, mapping):
    _exact_fields(assignments, ASSIGNMENT_MANIFEST_FIELDS, 'private assignments manifest')
    if (assignments['schema'] != ASSIGNMENTS_SCHEMA or assignments['synthetic_only'] is not True
            or assignments['accepted_suite_sha256'] != report_sha256):
        raise ValueError('heldout assignments/report digest binding')
    path_text = assignments['accepted_suite_path']
    if type(path_text) is not str or Path(path_text) != report_path:
        raise ValueError('heldout assignments report path mismatch')
    rows = assignments['assignments']
    if type(rows) is not list or len(rows) != 16:
        raise ValueError('exact sixteen heldout assignment rows required')
    by_name = {}
    for row in rows:
        _exact_fields(row, ASSIGNMENT_ROW_FIELDS, 'heldout assignment row')
        name = row['name']
        if type(name) is not str or name in by_name:
            raise ValueError('unique heldout assignment names required')
        by_name[name] = row
    expected_names = {
        name for index in range(8)
        for name in (f'holdout_{index}', f'holdout_{index}_unrelated_refresh')
    }
    if set(by_name) != expected_names:
        raise ValueError('exact eight heldout root-refresh pairs required')
    if set(by_name) != set(report):
        raise ValueError('heldout relation report assignment names mismatch')

    pairs = []
    for index in range(8):
        pair = {'name': f'holdout_{index}'}
        flat_by_role = {}
        for role, suffix, version in (
                ('base', '', 1), ('near', '_unrelated_refresh', 2)):
            label = f'holdout_{index}{suffix}'
            row = by_name[label]
            wtns_path = Path(row['wtns_path']).absolute()
            public_path = Path(row['public_path']).absolute()
            if (wtns_path != report_path.parent / f'{label}.wtns'
                    or public_path != report_path.parent / f'{label}-public.json'):
                raise ValueError('exact protected heldout witness paths required')
            received(wtns_path, MAX_WTNS_BYTES, _sha(row['wtns_sha256'], 'WTNS digest'))
            if wtns_path.stat().st_ctime_ns <= frozen_at:
                raise ValueError('heldout WTNS must be created after freeze')
            _, public_raw = received(public_path, MAX_JSON_BYTES,
                                     _sha(row['public_sha256'], 'public digest'))
            if public_path.stat().st_ctime_ns <= frozen_at:
                raise ValueError('heldout public values must be created after freeze')
            expected_public = _json(public_raw)
            input_path = _input_path(input_root / f'{label}.input.json', input_root)
            input_sha, input_raw = received(input_path, MAX_JSON_BYTES)
            if input_path.stat().st_ctime_ns <= frozen_at:
                raise ValueError('heldout input must be created after freeze')
            inputs = _json(input_raw)
            flat = flatten_inputs(inputs)
            flat_by_role[role] = flat
            if expected_public != [inputs[key] for key in PUBLIC_NAMES]:
                raise ValueError('heldout public values differ from original inputs')
            verify_wtns_input_link(wtns_path, flat, mapping)
            profile.parse_tbs(bytes(int(value) for value in inputs['tbs']))
            pair[role] = {
                **row,
                'wtns_path': str(wtns_path),
                'public_path': str(public_path),
                'input_path': str(input_path),
                'input_sha256': input_sha,
                'root_version': version,
                'issuer_version': 1,
                'policy_version': 1,
                'allocation_epoch': 1,
            }
        base_flat = flat_by_role['base']
        near_flat = flat_by_role['near']
        if (base_flat['main.root'] == near_flat['main.root']
                or sum(base_flat[f'main.siblings[{i}]'] != near_flat[f'main.siblings[{i}]']
                       for i in range(10)) != 1
                or any(value != near_flat[key]
                       for key, value in base_flat.items()
                       if key != 'main.root' and not key.startswith('main.siblings['))):
            raise ValueError('root-only heldout refresh input mismatch')
        pairs.append(pair)
    return pairs


def input_map_document(symbols_sha256, mapping):
    if set(mapping) != set(required_symbols()):
        raise ValueError('complete v2 symbol input map required')
    return {
        'schema': INPUT_MAP_SCHEMA,
        'symbols_sha256': _sha(symbols_sha256, 'symbol-map SHA-256'),
        'assignment_fields': ASSIGNMENT_FIELDS,
        'coordinates': mapping,
    }


def _copy_private_artifact(source_path, destination_path, cap, expected_sha256):
    source_path = Path(source_path)
    destination_path = Path(destination_path)
    expected_sha256 = _sha(expected_sha256, 'source artifact SHA-256')
    if not source_path.is_absolute() or source_path.resolve(strict=True) != source_path:
        raise ValueError('canonical absolute copy source required')
    _private_directory(destination_path.parent)
    if (destination_path.exists() or destination_path.is_symlink()
            or destination_path.resolve(strict=False) != destination_path):
        raise FileExistsError('fresh private copy destination required')
    try:
        before_path = source_path.lstat()
        if (not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1
                or before_path.st_uid != os.geteuid()
                or stat.S_IMODE(before_path.st_mode) != 0o600
                or not 0 < before_path.st_size <= cap):
            raise ValueError('owner-only bounded copy source required')
        source_fd = os.open(source_path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                            | getattr(os, 'O_NONBLOCK', 0))
        try:
            target_fd = os.open(destination_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        except Exception:
            os.close(source_fd)
            raise
        source_hash = hashlib.sha256()
        total = 0
        try:
            before = os.fstat(source_fd)
            target_before = os.fstat(target_fd)
            if (before.st_dev != before_path.st_dev or before.st_ino != before_path.st_ino
                    or before.st_size != before_path.st_size or not stat.S_ISREG(before.st_mode)
                    or not stat.S_ISREG(target_before.st_mode)
                    or target_before.st_uid != os.geteuid()
                    or stat.S_IMODE(target_before.st_mode) != 0o600):
                raise ValueError('copy source or destination changed at open')
            while True:
                block = os.read(source_fd, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > cap:
                    raise ValueError('copy source grew beyond bound')
                source_hash.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(target_fd, view)
                    if written <= 0:
                        raise OSError('short private copy write')
                    view = view[written:]
            os.fsync(target_fd)
            after = os.fstat(source_fd)
            target_after = os.fstat(target_fd)
        finally:
            os.close(source_fd)
            os.close(target_fd)
        source_current = source_path.lstat()
        stable_fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (total != before.st_size
                or any(getattr(before, key) != getattr(after, key) for key in stable_fields)
                or any(getattr(before_path, key) != getattr(source_current, key)
                       for key in stable_fields)
                or target_after.st_size != total):
            raise ValueError('copy source changed during transfer')
        if source_hash.hexdigest() != expected_sha256:
            raise ValueError('copy source digest mismatch')
        copied_sha256, _ = received(destination_path, cap, expected_sha256)
        if copied_sha256 != source_hash.hexdigest():
            raise ValueError('copied artifact digest mismatch')
        directory_fd = os.open(destination_path.parent,
                               os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return copied_sha256
    except OSError:
        raise ValueError('private artifact copy failed') from None


def _copy_case(case, destination):
    destination = Path(destination)
    if (not destination.is_absolute() or destination.resolve(strict=False) != destination
            or destination.exists() or destination.is_symlink()):
        raise FileExistsError('fresh canonical private pair directory required')
    _private_directory(destination.parent)
    destination.mkdir(mode=0o700)
    _private_directory(destination)
    files = (
        ('wtns', 'wtns_path', 'wtns_sha256', 'output.wtns', MAX_WTNS_BYTES),
        ('public', 'public_path', 'public_sha256', 'public.json', MAX_JSON_BYTES),
        ('input', 'input_path', 'input_sha256', 'input.json', MAX_JSON_BYTES),
    )
    result = {'directory': str(destination)}
    for kind, source_key, sha_key, filename, cap in files:
        digest = _copy_private_artifact(
            case[source_key], destination / filename, cap, case[sha_key],
        )
        result[f'{kind}_path'] = str(destination / filename)
        result[f'{kind}_sha256'] = digest
    return result


def _bridge_pairs(pairs, private_out):
    if type(pairs) is not list or len(pairs) != 8:
        raise ValueError('exactly eight validated heldout pairs required for bridge')
    pairs_root = Path(private_out) / 'pairs'
    pairs_root.mkdir(mode=0o700)
    _private_directory(pairs_root)
    manifest_pairs = []
    for index, pair in enumerate(pairs):
        expected_name = f'holdout_{index}'
        if type(pair) is not dict or pair.get('name') != expected_name:
            raise ValueError('ordered heldout pair names required for bridge')
        pair_root = pairs_root / expected_name
        pair_root.mkdir(mode=0o700)
        _private_directory(pair_root)
        base = _copy_case(pair['base'], pair_root / 'base')
        near = _copy_case(pair['near'], pair_root / 'near')
        manifest_pairs.append({
            'name': expected_name,
            'base_directory': base['directory'],
            'near_directory': near['directory'],
            'base_files': {key: base[key] for key in (
                'wtns_path', 'wtns_sha256', 'public_path', 'public_sha256',
                'input_path', 'input_sha256')},
            'near_files': {key: near[key] for key in (
                'wtns_path', 'wtns_sha256', 'public_path', 'public_sha256',
                'input_path', 'input_sha256')},
        })
    return {
        'schema': 'credential-v3-bounded-heldout-pair-directories-v2',
        'cohort': 'heldout-v2',
        'pairs': manifest_pairs,
    }


def _recheck_external_inputs(assignments_path, assignments_sha256,
                             report_path, report_sha256,
                             freeze_path, freeze_sha256, frozen_at):
    for path, digest, label in (
            (assignments_path, assignments_sha256, 'heldout assignments'),
            (report_path, report_sha256, 'heldout relation report'),
            (freeze_path, freeze_sha256, 'heldout freeze')):
        _private_directory(Path(path).parent)
        received(path, MAX_JSON_BYTES, digest)
        if Path(path).stat().st_ctime_ns <= frozen_at and label != 'heldout freeze':
            raise ValueError(f'{label} changed before the frozen heldout boundary')


def prepare(args):
    package_context = load_package_record(
        args.package_pins, args.package_pins_sha256, repo_root=args.repo_root,
    )
    input_root = Path(args.input_root).absolute()
    _private_directory(input_root)
    _private_directory(Path(args.assignments).absolute().parent)
    private_out = Path(args.private_out).absolute()
    if (private_out.exists() or private_out.is_symlink()
            or private_out.resolve(strict=False) != private_out):
        raise FileExistsError('fresh private output required')
    _private_directory(private_out.parent)

    assignments_sha256 = _sha(args.assignments_sha256, 'assignments manifest SHA-256')
    _, assignments = _read_json(args.assignments, MAX_JSON_BYTES, assignments_sha256)
    if type(assignments) is not dict or type(assignments.get('accepted_suite_path')) is not str:
        raise ValueError('heldout assignments manifest/report path required')
    report_path = Path(assignments['accepted_suite_path']).absolute()
    if report_path.name != 'report.json':
        raise ValueError('heldout relation report.json required')
    _private_directory(report_path.parent)
    report_sha256 = _sha(args.relation_report_sha256,
                         'external heldout relation-report SHA-256')
    actual_report_sha, raw_report = received(report_path, MAX_JSON_BYTES, report_sha256)
    del actual_report_sha
    report = _json(raw_report)
    accepted = validate_heldout_report(
        report, report_sha256,
        package_output_pins.SEMANTIC_HASHES['r1cs_sha256'],
        package_output_pins.SEMANTIC_HASHES['wasm_sha256'],
    )
    frozen = _freeze_context(
        args.freeze_receipt, args.freeze_sha256, package_context,
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    )
    frozen_at = frozen['frozen_at_unix_ns']
    if (Path(args.assignments).stat().st_ctime_ns <= frozen_at
            or report_path.stat().st_ctime_ns <= frozen_at):
        raise ValueError('heldout relation report and assignments must follow freeze')
    # Validate report/assignment/input linkage only after authenticating both
    # external digests and the freeze boundary.
    symbols = Path(package_context['symbol_map_path'])
    mapping = _pinned_symbol_map(
        symbols, package_context['semantic_hashes']['symbol_map_sha256'],
    )
    pairs = _accepted_manifest(
        assignments, report_sha256, report_path,
        accepted, input_root, frozen_at, mapping,
    )

    private_out.mkdir(mode=0o700)
    _private_directory(private_out)
    _recheck_external_inputs(
        args.assignments, assignments_sha256, report_path, report_sha256,
        args.freeze_receipt, args.freeze_sha256, frozen_at,
    )
    pair_manifest = _bridge_pairs(pairs, private_out)

    # Reopen every externally pinned boundary after validation and copying,
    # immediately before publishing the template and pair manifest.
    _recheck_external_inputs(
        args.assignments, assignments_sha256, report_path, report_sha256,
        args.freeze_receipt, args.freeze_sha256, frozen_at,
    )

    symbol_map_path = private_out / 'symbol-input-map.json'
    symbol_map = input_map_document(
        package_context['semantic_hashes']['symbol_map_sha256'], mapping,
    )
    _write_json(symbol_map_path, symbol_map)
    input_map_sha256, _ = received(symbol_map_path, MAX_JSON_BYTES)
    template = build_template(package_context, symbol_map_path, input_map_sha256)
    template_path = private_out / 'packet-template.json'
    _write_json(template_path, template)
    template_sha256, _ = received(template_path, MAX_JSON_BYTES)
    pair_manifest_path = private_out / 'heldout-pairs.json'
    _write_json(pair_manifest_path, pair_manifest)
    pair_manifest_sha256, _ = received(pair_manifest_path, MAX_JSON_BYTES)
    print(json.dumps({
        'packet_template_path': str(template_path),
        'packet_template_sha256': template_sha256,
        'input_map_sha256': input_map_sha256,
        'pair_manifest_path': str(pair_manifest_path),
        'pair_manifest_sha256': pair_manifest_sha256,
        'heldout_pairs_linked': len(pairs),
        'cohort': 'heldout-v2',
        'proofs_executed': False,
    }, sort_keys=True))


def _write_json(path, value):
    encoded = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if len(encoded) > MAX_JSON_BYTES:
        raise ValueError('private JSON envelope bound')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as target:
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=REPO)
    parser.add_argument('--package-pins', type=Path, required=True)
    parser.add_argument('--package-pins-sha256', required=True)
    parser.add_argument('--assignments', type=Path, required=True)
    parser.add_argument('--assignments-sha256', required=True)
    parser.add_argument('--relation-report-sha256', required=True,
                        help='independently reviewed heldout report.json SHA-256')
    parser.add_argument('--input-root', type=Path, required=True)
    parser.add_argument('--freeze-receipt', type=Path, required=True)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--private-out', type=Path, required=True)
    parser.add_argument('--cohort', choices=['heldout-v2'], default='heldout-v2')
    args = parser.parse_args(argv)
    args.repo_root = args.repo_root.absolute()
    args.package_pins = args.package_pins.absolute()
    args.assignments = args.assignments.absolute()
    args.input_root = args.input_root.absolute()
    args.freeze_receipt = args.freeze_receipt.absolute()
    args.private_out = args.private_out.absolute()
    prepare(args)


if __name__ == '__main__':
    main()
