#!/usr/bin/env python3
"""Export a scrubbed, hash-linked proof-package qualification summary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re


SUMMARY_SCHEMA = 'credential-v3-bounded-proof-package-public-summary-v1'
WITNESS_SCHEMA = 'credential-v3-bounded-witness-qualification-v1'
SETUP_SCHEMA = 'credential-v3-bounded-setup-v1'
PACKAGE_SCHEMA = 'credential-v3-bounded-public-package-check-v1'
MAX_REPORT_BYTES = 1024 * 1024
HASH_PATTERN = re.compile(r'[0-9a-f]{64}')
IDENTITY_FIELDS = (
    'circuit', 'engine_extended_vk', 'matrix', 'package', 'pk')
STRUCTURE_FIELDS = (
    'assignment_fields', 'constraints', 'matrix_entries', 'ordinary_vk_ic_count')


def _read_report(path):
    path = Path(path)
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError('source report exceeds the size limit')
    raw = path.read_bytes()
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError('source report exceeds the size limit')
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('source report must be valid JSON') from error
    if type(document) is not dict:
        raise ValueError('source report must be a JSON object')
    return raw, document


def _hash(value, field):
    if type(value) is not str or HASH_PATTERN.fullmatch(value) is None:
        raise ValueError(f'{field} must be a lowercase SHA-256')
    return value


def _integer(document, field):
    value = document.get(field)
    if type(value) is not int or value < 0:
        raise ValueError(f'{field} must be a nonnegative integer')
    return value


def _label(document, field):
    value = document.get(field)
    if (type(value) is not str or not value or len(value) > 64
            or re.fullmatch(r'[A-Za-z0-9._+-]+', value) is None):
        raise ValueError(f'{field} must be a short public label')
    return value


def _status(document, field, expected):
    if type(document.get(field)) is not bool or document[field] is not expected:
        raise ValueError(f'{field} status is not the required conservative value')


def _identity(document, description):
    identity = document.get('identity')
    if type(identity) is not dict or set(identity) != set(IDENTITY_FIELDS):
        raise ValueError(f'{description} identity fields are invalid')
    return {field: _hash(identity[field], f'{description} identity.{field}')
            for field in IDENTITY_FIELDS}


def _require_schema(document, expected, description):
    if document.get('schema') != expected:
        raise ValueError(f'unsupported {description} schema')


def build_summary(witness_raw, witness, setup_raw, setup, package_raw, package):
    """Validate report links and return only the public allowlisted projection."""
    _require_schema(witness, WITNESS_SCHEMA, 'witness report')
    _require_schema(setup, SETUP_SCHEMA, 'setup manifest')
    _require_schema(package, PACKAGE_SCHEMA, 'package-check report')

    for document, description in ((witness, 'witness report'),
                                  (package, 'package-check report')):
        if type(document.get('passed')) is not bool:
            raise ValueError(f'{description} passed status is invalid')

    _status(witness, 'passed', True)
    _status(witness, 'host_admission_bypassed', True)
    _status(witness, 'setup_or_proofs_executed', False)
    _status(witness, 'outputs_private', True)
    _status(setup, 'development_only', True)
    _status(setup, 'admitted', False)
    _status(setup, 'six_field_adapter_qualified', False)
    _status(setup, 'secret_scalars_written', False)
    _status(package, 'passed', True)
    _status(package, 'development_only', True)
    _status(package, 'admitted', False)
    _status(package, 'six_field_adapter_qualified', False)
    _status(package, 'setup_or_proofs_executed', False)
    _status(package, 'single_shared_package', True)

    if _hash(setup.get('accepted_suite_sha256'), 'accepted_suite_sha256') != \
            hashlib.sha256(witness_raw).hexdigest():
        raise ValueError('accepted suite report SHA-256 mismatch')

    source_hashes = {}
    for field in ('r1cs_sha256', 'wasm_sha256'):
        witness_hash = _hash(witness.get(field), f'witness {field}')
        setup_hash = _hash(setup.get(field), f'setup {field}')
        if witness_hash != setup_hash:
            raise ValueError('witness and setup R1CS/WASM hashes differ')
        source_hashes[field] = setup_hash

    setup_identity = _identity(setup, 'setup manifest')
    package_identity = _identity(package, 'package-check report')
    if setup_identity != package_identity:
        raise ValueError('setup and package identity hashes differ')

    linked_hashes = {}
    for field in ('ordinary_vk_file_sha256', 'public_schema_sha256',
                  'semantic_schema_sha256'):
        setup_hash = _hash(setup.get(field), f'setup {field}')
        package_hash = _hash(package.get(field), f'package-check {field}')
        if setup_hash != package_hash:
            raise ValueError(f'setup and package {field} differ')
        linked_hashes[field] = setup_hash

    witness_cases = witness.get('cases')
    if type(witness_cases) is not list:
        raise ValueError('witness cases must be a list')
    accepted_count = _integer(witness, 'accepted_count')
    rejected_count = _integer(witness, 'rejected_count')
    if len(witness_cases) != accepted_count + rejected_count:
        raise ValueError('witness case count does not match accepted/rejected counts')
    if any(type(case) is not dict or type(case.get('passed')) is not bool
           or case['passed'] is not True for case in witness_cases):
        raise ValueError('witness qualification contains a failed case')

    structure = {field: _integer(setup, field) for field in STRUCTURE_FIELDS}
    if any(_integer(package, field) != value
           for field, value in structure.items()):
        raise ValueError('setup and package structure counts differ')

    source_identity = {
        'circuit_source_identity': _hash(
            setup.get('circuit_source_identity'), 'circuit_source_identity'),
        'identity': setup_identity,
        **source_hashes,
        'binary_sha256': _hash(setup.get('binary_sha256'), 'binary_sha256'),
        'launcher_src_sha256': _hash(
            setup.get('launcher_src_sha256'), 'launcher_src_sha256'),
        'package_lock_sha256': _hash(
            setup.get('package_lock_sha256'), 'package_lock_sha256'),
        'profile_sha256': _hash(setup.get('profile_sha256'), 'profile_sha256'),
        **linked_hashes,
        'pk_file_sha256': _hash(setup.get('pk_file_sha256'), 'pk_file_sha256'),
    }
    accepted_suite_sha256 = hashlib.sha256(witness_raw).hexdigest()
    source_identity['accepted_suite_sha256'] = accepted_suite_sha256

    return {
        'schema': SUMMARY_SCHEMA,
        'inputs': {
            'witness_report_sha256': accepted_suite_sha256,
            'setup_manifest_sha256': hashlib.sha256(setup_raw).hexdigest(),
            'package_check_report_sha256': hashlib.sha256(package_raw).hexdigest(),
        },
        'source_identity': source_identity,
        'qualification': {
            'passed': witness['passed'],
            'case_count': len(witness_cases),
            'accepted_count': accepted_count,
            'rejected_count': rejected_count,
            'host_admission_bypassed': witness['host_admission_bypassed'],
            'setup_or_proofs_executed': witness['setup_or_proofs_executed'],
            'outputs_private': witness['outputs_private'],
        },
        'setup': {
            'development_only': setup['development_only'],
            'admitted': setup['admitted'],
            'six_field_adapter_qualified': setup['six_field_adapter_qualified'],
            'secret_scalars_written': setup['secret_scalars_written'],
            'curve': _label(setup, 'curve'),
            'domain': _integer(setup, 'domain'),
            'reduction': _label(setup, 'reduction'),
            **structure,
            'instance_fields_including_one': _integer(
                setup, 'instance_fields_including_one'),
        },
        'package_check': {
            'passed': package['passed'],
            'admitted': package['admitted'],
            'development_only': package['development_only'],
            'six_field_adapter_qualified': package['six_field_adapter_qualified'],
            'setup_or_proofs_executed': package['setup_or_proofs_executed'],
            'single_shared_package': package['single_shared_package'],
            **structure,
            'public_package_loads': _integer(package, 'public_package_loads'),
            'accepted_complete_assignments': _integer(
                package, 'accepted_complete_assignments'),
            'root_refresh_pairs': _integer(package, 'root_refresh_pairs'),
        },
    }


def _write_new(path, data):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def export_summary(witness_path, setup_path, package_path, output_path):
    witness_raw, witness = _read_report(witness_path)
    setup_raw, setup = _read_report(setup_path)
    package_raw, package = _read_report(package_path)
    summary = build_summary(witness_raw, witness, setup_raw, setup,
                            package_raw, package)
    encoded = (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode()
    _write_new(output_path, encoded)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--witness-report', required=True, type=Path)
    parser.add_argument('--setup-manifest', required=True, type=Path)
    parser.add_argument('--package-check-report', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    summary = export_summary(args.witness_report, args.setup_manifest,
                             args.package_check_report, args.output)
    output_sha256 = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({'schema': SUMMARY_SCHEMA,
                      'output_sha256': output_sha256,
                      'case_count': summary['qualification']['case_count']}))


if __name__ == '__main__':
    main()
