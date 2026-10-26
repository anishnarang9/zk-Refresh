#!/usr/bin/env python3
"""Build the eight pinned application-run manifests from one frozen cohort."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.tests import queue_v3_build_prep as build_prep
from tools.part5 import freeze_v3_heldout_cohort as freeze_tool
from tools.part5 import generate_v3_heldout_keys as keygen
from tools.part5 import run_v3_heldout_case as case_runner

PART5 = ROOT / 'artifacts/dynark/part5'
ROLE_PATHS = {
    'profile': ROOT / 'circuits/credential-v3-bounded/profile.json',
    'r1cs': freeze_tool.COMPILE / 'credential.r1cs',
    'witness_executable': freeze_tool.COMPILE / 'credential_js/credential.wasm',
    'setup_manifest': freeze_tool.SETUP / 'setup-manifest.json',
    'ordinary_vk': freeze_tool.SETUP / 'ordinary.vk',
    'proof_runner': freeze_tool.PROOF / 'target/release/credential-v3-bounded-proof-qualification-v1',
    'signer_interface': ROOT / 'tools/part5/prepare_v3_request_fixture.py',
    'loaded_elf': freeze_tool.LOADED_ELF,
}
PROOF_SOURCE_PATHS = {
    'witness_js': ROOT / 'crates/dynark-native-client/tests/support/v3_relation_witness.cjs',
    'relation_checker': ROOT / 'crates/dynark-native-client/tests/support/prepare_v3_relation.py',
}
CAPS = {
    'full': {'runtime_seconds': 1800, 'rss_bytes': 4294967296,
             'storage_bytes': 536870912},
    'anchor': {'runtime_seconds': 3600, 'rss_bytes': 4294967296,
               'storage_bytes': 536870912},
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(path, cap=1024 * 1024 * 1024):
    path = Path(path)
    before = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or before.st_mode & 0o022
            or not 0 < before.st_size <= cap):
        raise ValueError('canonical owner-controlled input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                         s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if key(before) != key(opened):
            raise ValueError('input changed at open')
        raw = stream.read(cap + 1)
        if key(opened) != key(os.fstat(stream.fileno())):
            raise ValueError('input changed during read')
    if len(raw) != before.st_size or key(before) != key(path.lstat()):
        raise ValueError('input changed after read')
    return raw


def _ref(path, cap=1024 * 1024 * 1024):
    path = Path(path)
    return {'path': str(path), 'sha256': digest(_read(path, cap))}


def _validate_observation_location(path, cohort_root):
    path, cohort_root = Path(path), Path(cohort_root)
    parent = path.parent
    try:
        parent_info = parent.lstat()
        file_info = path.lstat()
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or parent != cohort_root.parent
                or parent.resolve(strict=True) != parent
                or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != os.getuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700
                or not stat.S_ISREG(file_info.st_mode)
                or file_info.st_uid != os.getuid()
                or stat.S_IMODE(file_info.st_mode) != 0o600
                or file_info.st_nlink != 1):
            raise ValueError('private sibling observation required')
    except OSError as error:
        raise ValueError('private sibling observation required') from error


def validate_cohort_observation(reference, freeze_sha256, cohort_sha256,
                                prior_key_inventory_sha256, cohort_root):
    if (type(reference) is not dict or set(reference) != {'path', 'sha256'}
            or not isinstance(reference.get('path'), str)
            or not keygen._hash(reference.get('sha256'))):
        raise ValueError('pinned cohort parent observation required')
    try:
        _validate_observation_location(reference['path'], cohort_root)
        raw = _read(reference['path'], 65536)
        if digest(raw) != reference['sha256']:
            raise ValueError('observation pin mismatch')
        document = json.loads(raw)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ValueError('cohort parent observation could not be read') from error
    required_fields = {
        'schema', 'freeze_sha256', 'prior_key_inventory_sha256',
        'wall_started_unix_ns', 'wall_completed_unix_ns',
        'monotonic_started_ns', 'monotonic_completed_ns', 'child_exit_code',
        'builder_source_sha256', 'observer_source_sha256', 'output_path_sha256',
        'cohort_receipt_sha256', 'preexisting_output', 'creation_time_basis',
        'openssl_invocation_observed',
    }
    if (type(document) is not dict or set(document) != required_fields
            or document.get('schema') != 'credential-v3-heldout-cohort-parent-observation-v1'
            or document.get('freeze_sha256') != freeze_sha256
            or document.get('cohort_receipt_sha256') != cohort_sha256
            or not keygen._hash(document.get('prior_key_inventory_sha256'))
            or document.get('prior_key_inventory_sha256') != prior_key_inventory_sha256
            or not keygen._hash(document.get('builder_source_sha256'))
            or not keygen._hash(document.get('observer_source_sha256'))
            or document.get('output_path_sha256') != digest(
                str(Path(cohort_root)).encode())
            or any(type(document.get(field)) is not int or document[field] <= 0
                   for field in ('wall_started_unix_ns', 'wall_completed_unix_ns',
                                 'monotonic_started_ns', 'monotonic_completed_ns'))
            or document['wall_started_unix_ns'] > document['wall_completed_unix_ns']
            or document['monotonic_started_ns'] > document['monotonic_completed_ns']
            or type(document.get('child_exit_code')) is not int
            or document.get('child_exit_code') != 0
            or document.get('preexisting_output') is not False
            or document.get('creation_time_basis') != 'observer_parent_started_child_after_freeze'
            or document.get('openssl_invocation_observed') is not False):
        raise ValueError('cohort parent observation does not pin successful cohort output')
    return {'path': reference['path'], 'sha256': reference['sha256']}


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return digest(raw)


def _bundle(paths):
    return [{'path': name, 'artifact': _ref(ROOT / name, 64 * 1024 * 1024)}
            for name in sorted(paths)]


def _frozen_identities(boundary):
    identities = boundary.get('identities') if type(boundary) is dict else None
    if (type(identities) is not dict or set(identities) != keygen.IDENTITY_ROLES
            or not all(keygen._hash(value) for value in identities.values())):
        raise ValueError('exact frozen identity map required')
    return identities


def _proof_runner_ref(path, identities):
    reference = _ref(path, 128 * 1024 * 1024)
    if reference['sha256'] != identities.get('proof_runner'):
        raise ValueError('proof binary differs from frozen proof runner identity')
    return reference


def build(freeze_receipt, cohort_root, base_prepare_config, packet_template,
          adapter_binary, bounded_supervisor, node, exporter, runner, output_dir,
          cohort_observation, proof_binary=None):
    if Path(runner) != ROOT / freeze_tool.RUNNER_BINARY:
        raise ValueError('frozen heldout queue runner binary path required')
    output_dir = Path(output_dir)
    if (not output_dir.is_absolute() or output_dir.parent != PART5
            or output_dir.exists() or output_dir.is_symlink()
            or output_dir.parent.resolve(strict=True) != output_dir.parent
            or not keygen._ignored(output_dir)):
        raise ValueError('fresh direct Part 5 artifact directory required')
    freeze = _ref(freeze_receipt, 65536)
    boundary = json.loads(_read(freeze_receipt, 65536))
    identities = _frozen_identities(boundary)
    selected_proof_binary = (Path(proof_binary) if proof_binary is not None
                             else ROLE_PATHS['proof_runner'])
    proof_runner = _proof_runner_ref(selected_proof_binary, identities)
    cohort_root = Path(cohort_root)
    cohort = _ref(cohort_root / 'cohort-receipt.json', 65536)
    issued = json.loads(_read(cohort['path'], 65536))
    if (boundary.get('schema') != 'credential-v3-frozen-holdout-boundary-v1'
            or issued.get('schema') != 'credential-v3-heldout-issuance-cohort-v1'
            or issued.get('freeze_sha256') != freeze['sha256']
            or issued.get('identities') != boundary.get('identities')):
        raise ValueError('frozen heldout cohort required')
    observation = _ref(cohort_observation, 65536)
    validate_cohort_observation(observation, freeze['sha256'], cohort['sha256'],
                                issued.get('prior_key_inventory_sha256'), cohort_root)
    roles = dict(ROLE_PATHS, ordinary_adapter=Path(adapter_binary),
                 proof_runner=Path(proof_runner['path']))
    frozen_files = {name: _ref(path) for name, path in roles.items()}
    if (set(frozen_files) != set(case_runner.ROLE_NAMES)
            or any(ref['sha256'] != identities.get(name)
                   for name, ref in frozen_files.items())):
        raise ValueError('direct product roles changed after freeze')
    bundles = {
        'registry': _bundle(freeze_tool.REGISTRY_FILES),
        'client': _bundle(freeze_tool.CLIENT_FILES),
    }
    for name, paths in (('registry', freeze_tool.REGISTRY_FILES),
                        ('client', freeze_tool.CLIENT_FILES)):
        actual, _ = freeze_tool.prior_freeze.bundle(paths)
        if actual != identities[name]:
            raise ValueError('frozen source bundle changed')
    proof_inputs = {
        'packet_template': _ref(packet_template, 262144),
        'witness_js': _ref(PROOF_SOURCE_PATHS['witness_js'], 131072),
        'relation_checker': _ref(PROOF_SOURCE_PATHS['relation_checker'], 131072),
        'node': _ref(node, 512 * 1024 * 1024),
        'proof_runner': frozen_files['proof_runner'],
        'adapter_binary': frozen_files['ordinary_adapter'],
        'bounded_supervisor': _ref(bounded_supervisor, 1024 * 1024),
        'exporter': _ref(exporter, 1024 * 1024 * 1024),
    }
    source_files = {
        'heldout_source_tool': _ref(ROOT / 'tools/part5/prepare_v3_heldout_source.py', 131072),
        'training_helper': _ref(ROOT / 'crates/dynark-native-client/tests/support/prepare_v3_request_bound_training.py', 131072),
        'request_fixture_bridge': frozen_files['signer_interface'],
        'exporter': proof_inputs['exporter'],
    }
    if source_files['exporter'] != _ref(ROOT / 'program/target/debug/examples/export_v3_request_fixture',
                                        64 * 1024 * 1024):
        raise ValueError('request exporter binary changed after freeze')
    current_source = build_prep.source_manifest(ROOT)
    if digest(json.dumps(current_source, sort_keys=True).encode()) != identities['application_source']:
        raise ValueError('application sources changed after freeze')
    application_source_files = {
        name: _ref(ROOT / name, 1024 * 1024)
        for name in current_source['source_pins']
    }
    if any(ref['sha256'] != current_source['source_pins'][name]
           for name, ref in application_source_files.items()):
        raise ValueError('application source file changed after inventory')
    template = _ref(base_prepare_config, 65536)
    runner_binary = _ref(runner, 128 * 1024 * 1024)
    output_dir.mkdir(mode=0o700)
    try:
        source_raw = (json.dumps(current_source, sort_keys=True, indent=2) + '\n').encode()
        source_path = output_dir / 'application-source-manifest.json'
        source_ref = {'path': str(source_path), 'sha256': _write(source_path, source_raw)}
        emitted = []
        for variant in range(8):
            manifest = {
                'schema': case_runner.RUN_SCHEMA,
                'variant': variant,
                'freeze_receipt': freeze['path'], 'freeze_sha256': freeze['sha256'],
                'cohort_root': str(cohort_root), 'cohort_sha256': cohort['sha256'],
                'cohort_observation': observation,
                'base_prepare_config': template['path'],
                'base_prepare_config_sha256': template['sha256'],
                'runner': runner_binary['path'], 'runner_sha256': runner_binary['sha256'],
                'frozen_files': frozen_files, 'frozen_bundles': bundles,
                'application_source_manifest': source_ref,
                'application_source_files': application_source_files,
                'source_files': source_files,
                'proof_inputs': proof_inputs, 'proof_caps': CAPS,
            }
            case_runner.validate_manifest(manifest)
            path = output_dir / f'case-{variant:02d}.json'
            raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
            emitted.append({'variant': variant, 'path': str(path),
                            'sha256': _write(path, raw)})
        return {'freeze_sha256': freeze['sha256'],
                'cohort_sha256': cohort['sha256'], 'manifests': emitted}
    except Exception:
        shutil.rmtree(output_dir)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('freeze_receipt', 'cohort_root', 'base_prepare_config',
                 'packet_template', 'adapter_binary', 'bounded_supervisor',
                 'node', 'exporter', 'runner', 'output_dir',
                 'cohort_observation'):
        parser.add_argument('--' + name.replace('_', '-'), required=True, type=Path)
    parser.add_argument('--proof-binary', type=Path)
    args = parser.parse_args()
    try:
        result = build(**vars(args))
    except Exception:
        raise SystemExit('heldout run-manifest build rejected') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
