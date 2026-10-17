#!/usr/bin/env python3
"""Freeze v3 training campaign identities and earlier RSA key fingerprints.

Run once before generating the eleven training certificates. The resulting
freeze is an input boundary, not a claim that a certificate or app passed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.part5 import prepare_v3_campaign_cohort as cohort

PART5 = ROOT / 'artifacts/dynark/part5'
RESULTS = ROOT / 'results/dynark/part5'
SETUP = PART5 / 'v3-development-setup-001'
COMPILE = PART5 / 'v3-compile-001'
PROOF = ROOT / 'circuits/credential-v3-bounded/qualification/proof-runner-v1'
REGISTRY_FILES = [
    'crates/credential-registry/src/lib.rs',
    *[str(path.relative_to(ROOT)) for path in sorted((ROOT / 'crates/credential-registry/src/v3').glob('*.rs'))],
    'harness/src/solana/queue_v3/campaign.rs',
    'harness/tests/queue_v3_local_campaign_transition.py',
    'tools/part5/prepare_v3_campaign_context.py',
]
CLIENT_FILES = [
    'crates/dynark-native-client/src/v3_binding.rs',
    'crates/dynark-native-client/workers/v3_input_worker.py',
    'crates/dynark-native-client/tests/support/prepare_v3_request_bound_training.py',
    'crates/dynark-native-client/tests/support/v3_relation_witness.cjs',
    'crates/dynark-native-client/tests/support/prepare_v3_relation.py',
    'tools/part5/prepare_v3_campaign_training_source.py',
    'tools/part5/prepare_v3_campaign_target.py',
    'tools/part5/build_v3_campaign_packet.py',
]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_input(path, cap=256 * 1024 * 1024):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute identity input required')
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_mode & 0o022 or before.st_size > cap):
        raise ValueError('bounded owner-controlled regular identity input required')
    identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid,
                          st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError('identity input changed at open')
        raw = stream.read(cap + 1)
        if (len(raw) != before.st_size
                or identity(before) != identity(os.fstat(stream.fileno()))
                or identity(before) != identity(path.lstat())):
            raise ValueError('identity input changed during read')
    return raw


def file_digest(path):
    return digest(read_input(path))


def bundle(paths):
    hashing = hashlib.sha256(b'part5-v3-campaign-identity-bundle-v1\0')
    members = []
    for name in sorted(paths):
        raw = read_input(ROOT / name)
        members.append({'path': name, 'sha256': digest(raw)})
        hashing.update(len(name.encode()).to_bytes(4, 'big'))
        hashing.update(name.encode())
        hashing.update(len(raw).to_bytes(8, 'big'))
        hashing.update(raw)
    return hashing.hexdigest(), members


def prior_keys():
    fingerprints, sources = set(), []
    for directory, dirs, files in os.walk(PART5, followlinks=False):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError('symlink in earlier credential inventory')
        for name in sorted(files):
            path = Path(directory) / name
            if path.suffix not in ('.pem', '.der'):
                continue
            raw = read_input(path, 65536)
            if path.suffix == '.pem' and raw.count(b'-----BEGIN ') != 1:
                raise ValueError('single-object PEM inventory input required')
            loaders = ((serialization.load_pem_private_key, {'password': None}),
                       (serialization.load_pem_public_key, {}),
                       (x509.load_pem_x509_certificate, {})) if path.suffix == '.pem' else (
                       (serialization.load_der_private_key, {'password': None}),
                       (serialization.load_der_public_key, {}),
                       (x509.load_der_x509_certificate, {}))
            key = None
            for loader, kwargs in loaders:
                try:
                    value = loader(raw, **kwargs)
                    key = value.public_key() if hasattr(value, 'public_key') else value
                    break
                except (TypeError, ValueError):
                    continue
            if key is None:
                raise ValueError('unparsed earlier credential input requires inventory review')
            if not isinstance(key, rsa.RSAPublicKey):
                continue
            fingerprint = digest(key.public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
            fingerprints.add(fingerprint)
            sources.append({'path': str(path.relative_to(ROOT)), 'sha256': digest(raw),
                            'public_key_sha256': fingerprint})
    if not fingerprints:
        raise ValueError('earlier RSA key inventory required')
    return sorted(fingerprints), sorted(sources, key=lambda value: value['path'])


def fresh(path):
    path = Path(path)
    if (not path.is_absolute() or (path.parent != RESULTS and path.parent.parent != RESULTS)
            or path.parent.resolve(strict=True) != path.parent
            or path.exists() or path.is_symlink()):
        raise ValueError('fresh direct canonical campaign result required')
    meta = path.parent.stat()
    if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o700:
        raise ValueError('owner0700 results directory required')
    return path


def write_pair(path, boundary, manifest_path, report):
    # Publish the manifest first and the consumable freeze last. Exclusive links
    # prevent clobbering; ordinary failures roll back both outputs.
    pending, published = [], []
    try:
        for target, value in ((manifest_path, report), (path, boundary)):
            raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
            fd, name = tempfile.mkstemp(prefix='.campaign-freeze-', dir=target.parent)
            pending.append(Path(name))
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(name, target, follow_symlinks=False)
            published.append(target)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        for target in published:
            target.unlink()
        raise
    finally:
        for temporary in pending:
            temporary.unlink()


def freeze(path, manifest_path, prepare_status, adapter_binary):
    path, manifest_path = fresh(path), fresh(manifest_path)
    if path == manifest_path or path.parent != manifest_path.parent:
        raise ValueError('distinct freeze and identity manifest in one private directory required')
    prepared_raw = read_input(prepare_status, 65536)
    prepared = cohort.issuance.decode_parameters(prepared_raw)
    setup_raw = read_input(SETUP / 'setup-manifest.json', 65536)
    setup = cohort.issuance.decode_parameters(setup_raw)
    if (prepared.get('schema') != 1
            or prepared.get('status') not in ('passed', 'failed')
            or prepared.get('application_effect') is not False
            or prepared.get('devnet') is not False
            or (prepared.get('status') == 'failed' and (
                prepared.get('cleanup', {}).get('exit_code') != -2
                or prepared.get('ledger_reuse_requires_review') is not True))
            or prepared.get('error_type') is not None
            or prepared.get('cleanup', {}).get('reaped') is not True
            or not prepared.get('loaded_program', {}).get('genesis')
            or prepared.get('scope') != 'part5-v3-local-prepare'
            or prepared.get('loaded_program', {}).get('elf_match') is not True
            or prepared.get('prepared_application_accounts') is not False
            or prepared.get('source_manifest_sha256') is None):
        raise ValueError('fresh loaded-v3 prepare identity required')
    from harness.tests import queue_v3_build_prep as build_prep
    application_manifest = build_prep.source_manifest(ROOT)
    if digest(json.dumps(application_manifest, sort_keys=True).encode()) != prepared['source_manifest_sha256']:
        raise ValueError('prepared application source inventory changed')
    if (prepared.get('v3_vk', {}).get('setup_manifest_sha256') != digest(setup_raw)
            or prepared.get('v3_vk', {}).get('circuit_id') != setup['identity']['circuit']):
        raise ValueError('prepare/setup provenance mismatch')
    r1cs = COMPILE / 'credential.r1cs'
    wasm = COMPILE / 'credential_js/credential.wasm'
    profile = ROOT / 'circuits/credential-v3-bounded/profile.json'
    vk = SETUP / 'ordinary.vk'
    elf = PART5 / 'application-v3-sbf-build-002/elf/zk_fresh_program.so'
    single = {'profile': profile, 'r1cs': r1cs,
              'witness_executable': wasm, 'setup_manifest': SETUP / 'setup-manifest.json',
              'ordinary_vk': vk, 'proof_runner': PROOF / 'target/release/credential-v3-bounded-proof-qualification-v1',
              'signer_interface': ROOT / 'tools/part5/prepare_v3_request_fixture.py',
              'ordinary_adapter': Path(adapter_binary), 'loaded_elf': elf}
    identities = {role: file_digest(target) for role, target in single.items()}
    registry_sha, registry_members = bundle(REGISTRY_FILES)
    client_sha, client_members = bundle(CLIENT_FILES)
    identities.update(circuit=setup['identity']['circuit'], registry=registry_sha,
                      client=client_sha,
                      application_source=prepared['source_manifest_sha256'])
    if (set(identities) != cohort.keys.IDENTITY_ROLES
            or not all(cohort.keys._hash(value) for value in identities.values())
            or setup.get('schema') != 'credential-v3-bounded-setup-v1'
            or setup.get('development_only') is not True
            or identities['profile'] != setup['profile_sha256']
            or identities['r1cs'] != setup['r1cs_sha256']
            or identities['witness_executable'] != setup['wasm_sha256']
            or identities['ordinary_vk'] != setup['ordinary_vk_file_sha256']
            or identities['loaded_elf'] != prepared['loaded_program']['elf_sha256']):
        raise ValueError('accepted v3 package/ELF identity changed')
    forbidden, prior_sources = prior_keys()
    boundary = {'schema': cohort.FREEZE_SCHEMA,
                'frozen_at_unix_ns': time.time_ns(),
                'identities': identities,
                'source_sha256': cohort.source_hashes(),
                'forbidden_public_key_sha256': forbidden}
    report = {'schema': 'part5-v3-training-campaign-identity-manifest-v1',
              'freeze_sha256': None, 'training_only': True,
              'freeze_tool_sha256': file_digest(Path(__file__).resolve()),
              'prior_key_inventory_scope': 'all .pem/.der files under artifacts/dynark/part5',
              'identities': identities,
              'identity_inputs': {role: {'path': str(target.relative_to(ROOT))
                                            if target.is_relative_to(ROOT) else str(target),
                                            'sha256': identities[role]}
                                  for role, target in single.items()},
              'circuit_identity_source': 'accepted setup-manifest identity.circuit',
              'application_source_identity_source': str(Path(prepare_status)),
              'registry_members': registry_members, 'client_members': client_members,
              'prior_public_key_sources': prior_sources,
              'prior_public_key_count': len(forbidden)}
    freeze_sha = digest((json.dumps(boundary, sort_keys=True, indent=2) + '\n').encode())
    report['freeze_sha256'] = freeze_sha
    report['prepare_status_sha256'] = digest(prepared_raw)
    report['application_manifest'] = application_manifest
    # Recheck the complete snapshot immediately before publishing.
    if (read_input(prepare_status, 65536) != prepared_raw
            or any(file_digest(target) != identities[role] for role, target in single.items())
            or bundle(REGISTRY_FILES)[0] != registry_sha
            or bundle(CLIENT_FILES)[0] != client_sha
            or build_prep.source_manifest(ROOT) != application_manifest
            or prior_keys() != (forbidden, prior_sources)
            or cohort.source_hashes() != boundary['source_sha256']):
        raise ValueError('campaign inputs changed before publication')
    write_pair(path, boundary, manifest_path, report)
    return {'freeze_sha256': freeze_sha, 'prior_public_key_count': len(forbidden)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'identity_manifest', 'prepare_status', 'adapter_binary'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(freeze(args.output, args.identity_manifest,
                            args.prepare_status, args.adapter_binary)))


if __name__ == '__main__':
    main()
