#!/usr/bin/env python3
"""Fail-closed source preflight for a future v2 heldout freeze.

This versioned preflight validates fresh setup/package pins and loaded
application preparation evidence without publishing a freeze or inventory.
The current checkout has no fresh v2 setup/package record or v2-compatible
application ELF, so an actual freeze remains gated on those reviewed outputs.
"""
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

from tools.part5 import build_v3_heldout_packet_v2 as packet_v2
from tools.part5 import verify_v3_fresh_package_output_pins as package_pins_v2
from harness.tests import queue_v3_build_prep as build_prep

PREFLIGHT_SCHEMA = 'credential-v3-heldout-freeze-preflight-v2'
PACKAGE_PINS_PATH = ROOT / packet_v2.PACKAGE_PINS_RELATIVE
OUTPUT_PINS_SCHEMA = 'part5-v3-fresh-package-output-pins-v2'
SETUP_SCHEMA = 'credential-v3-bounded-setup-v2'
PREPARE_SCOPE = 'part5-v3-local-prepare-v2'
IDENTITY_ROLES = (
    'setup_manifest', 'package', 'package_pins', 'proof_binary',
    'proof_source', 'input_preparer', 'client', 'adapter',
    'application_source', 'application_elf',
)
DIRECT_IDENTITY_ROLES = {
    'setup_manifest_sha256': 'setup_manifest',
    'package_digest': 'package',
    'package_pins_sha256': 'package_pins',
    'proof_binary_sha256': 'proof_binary',
    'proof_source_identity': 'proof_source',
    'input_preparer_sha256': 'input_preparer',
    'client_sha256': 'client',
    'adapter_sha256': 'adapter',
    'application_source_sha256': 'application_source',
    'application_elf_sha256': 'application_elf',
}
PACKAGE_IDENTITY_FIELDS = {
    'matrix', 'circuit', 'pk', 'engine_extended_vk', 'package',
}
MAX_JSON_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024


def _sha(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _stable_read(path, maximum, *, modes=(0o600, 0o644)):
    path = Path(path)
    try:
        before = path.lstat()
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) not in modes
                or not 0 < before.st_size <= maximum):
            raise ValueError('canonical bounded owner-controlled file required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('file changed at open')
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        final = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(raw) != before.st_size or len(raw) > maximum
                or any(getattr(before, f) != getattr(after, f) for f in fields)
                or any(getattr(before, f) != getattr(final, f) for f in fields)):
            raise ValueError('file changed during read')
        return raw
    except OSError:
        raise ValueError('required input unavailable') from None


def _json(raw, description):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'duplicate {description} field')
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError(f'{description} object required')
    return value


def validate_setup_pin(setup, pin_record, setup_manifest_sha256):
    """Bind a v2 setup manifest to its externally pinned package identity."""
    reference = pin_record.get('setup_manifest')
    identity = pin_record.get('package_identity')
    if (pin_record.get('schema') != OUTPUT_PINS_SCHEMA
            or type(reference) is not dict
            or set(reference) != {'path', 'sha256'}
            or reference.get('sha256') != setup_manifest_sha256
            or not _sha(setup_manifest_sha256)
            or type(identity) is not dict
            or set(identity) != PACKAGE_IDENTITY_FIELDS
            or not all(_sha(value) for value in identity.values())):
        raise ValueError('external v2 setup/package pin required')
    if (setup.get('schema') != SETUP_SCHEMA
            or setup.get('admitted') is not False
            or setup.get('development_only') is not True
            or setup.get('identity') != identity):
        raise ValueError('setup/package identity mismatch')
    return identity['package']


def validate_application_vk(source_vk, pin_record, setup_manifest_sha256,
                            package_digest):
    """Bind the application VK source to the externally pinned v2 package."""
    identity = pin_record.get('package_identity')
    ordinary_vk = pin_record.get('ordinary_vk')
    if (type(source_vk) is not dict or type(identity) is not dict
            or type(ordinary_vk) is not dict
            or source_vk.get('setup_manifest_sha256') != setup_manifest_sha256
            or source_vk.get('package_id') != package_digest
            or source_vk.get('circuit_id') != identity.get('circuit')
            or source_vk.get('engine_extended_vk_digest') != identity.get('engine_extended_vk')
            or source_vk.get('ordinary_vk_file_sha256') != ordinary_vk.get('sha256')
            or not all(_sha(value) for value in (
                setup_manifest_sha256, package_digest,
                identity.get('circuit'), identity.get('engine_extended_vk'),
                ordinary_vk.get('sha256')))):
        raise ValueError('current application VK differs from fresh v2 package')


def validate_prepare_binding(prepare, *, setup_manifest_sha256, package_digest,
                             application_source_sha256, application_elf_sha256,
                             source_vk):
    """Require prepare evidence for this package, source manifest, and loaded ELF."""
    loaded = prepare.get('loaded_program') if type(prepare) is dict else None
    setup_identity = prepare.get('v3_vk') if type(prepare) is dict else None
    cleanup = prepare.get('cleanup') if type(prepare) is dict else None
    status = prepare.get('status') if type(prepare) is dict else None
    if (type(prepare) is not dict or prepare.get('schema') != 1
            or status not in ('passed', 'failed')
            or prepare.get('scope') != PREPARE_SCOPE
            or prepare.get('application_effect') is not False
            or prepare.get('devnet') is not False
            or prepare.get('prepared_application_accounts') is not False
            or prepare.get('error_type') is not None
            or prepare.get('source_manifest_sha256') != application_source_sha256
            or not _sha(application_source_sha256)
            or type(setup_identity) is not dict
            or setup_identity != source_vk
            or setup_identity.get('setup_manifest_sha256') != setup_manifest_sha256
            or setup_identity.get('package_id') != package_digest
            or type(cleanup) is not dict
            or cleanup.get('spawned') is not True
            or cleanup.get('reaped') is not True
            or (status == 'passed' and (
                cleanup.get('graceful') is not True
                or cleanup.get('exit_code') != 0
                or prepare.get('ledger_reuse_requires_review') is not False))
            or (status == 'failed' and (
                cleanup.get('graceful') is not False
                or cleanup.get('exit_code') != -2
                or prepare.get('ledger_reuse_requires_review') is not True))):
        raise ValueError('fresh v2 prepare identity required')
    if (type(loaded) is not dict or loaded.get('elf_match') is not True
            or loaded.get('elf_sha256') != application_elf_sha256
            or not _sha(application_elf_sha256)
            or loaded.get('commitment') != 'finalized'
            or loaded.get('application_effect') is not False
            or any(type(loaded.get(field)) is not str or not loaded[field]
                   for field in ('genesis', 'program', 'programdata'))
            or any(not _sha(loaded.get(field)) for field in
                   ('program_account_sha256', 'programdata_account_sha256'))):
        raise ValueError('loaded ELF does not match fresh prepare evidence')


def boundary_identity_fields(identities, *, external_pins=None):
    """Create direct convenience fields only from the nested role map."""
    if (type(identities) is not dict or set(identities) != set(IDENTITY_ROLES)
            or not all(_sha(value) for value in identities.values())):
        raise ValueError('complete v2 nested identity roles required')
    direct = {field: identities[role]
              for field, role in DIRECT_IDENTITY_ROLES.items()}
    if external_pins is not None:
        for field, role in (
                ('setup_manifest_sha256', 'setup_manifest'),
                ('package_digest', 'package'),
                ('package_pins_sha256', 'package_pins')):
            if external_pins.get(field) != direct[field]:
                raise ValueError(f'external pin mismatch: {field}')
    return {'identities': dict(identities), **direct}


def _file_digest(path, *, expected=None, maximum=MAX_SOURCE_BYTES,
                 modes=(0o600, 0o644)):
    raw = _stable_read(path, maximum, modes=modes)
    observed = hashlib.sha256(raw).hexdigest()
    if expected is not None and observed != expected:
        raise ValueError('explicit source/binary SHA-256 mismatch')
    return observed, raw


def preflight(*, package_pins_path, package_pins_sha256, prepare_status,
              application_source_manifest, application_elf, proof_binary,
              proof_binary_sha256, input_preparer, input_preparer_sha256,
              client_source, adapter_binary):
    """Validate current source/evidence inputs; never publishes output files."""
    pins_path = Path(package_pins_path)
    if pins_path != PACKAGE_PINS_PATH:
        raise ValueError('exact external v2 package-pins record required')
    package_pins_v2.verify_file(pins_path, package_pins_sha256, repo_root=ROOT)
    pin_raw = _stable_read(pins_path, package_pins_v2.MAX_RECORD_BYTES)
    if hashlib.sha256(pin_raw).hexdigest() != package_pins_sha256:
        raise ValueError('external v2 package-pins digest mismatch')
    pin_record = _json(pin_raw, 'external package-pins')
    setup_ref = pin_record.get('setup_manifest')
    setup_path = ROOT / setup_ref['path'] if type(setup_ref) is dict else None
    if setup_path is None or not setup_path.is_absolute():
        raise ValueError('externally pinned v2 setup manifest required')
    setup_raw = _stable_read(setup_path, package_pins_v2.MAX_REPORT_BYTES)
    setup_sha = hashlib.sha256(setup_raw).hexdigest()
    if setup_sha != setup_ref.get('sha256'):
        raise ValueError('externally pinned setup manifest changed')
    setup = _json(setup_raw, 'setup manifest')
    package_digest = validate_setup_pin(setup, pin_record, setup_sha)

    source_raw = _stable_read(application_source_manifest, MAX_JSON_BYTES)
    source_manifest = _json(source_raw, 'application source manifest')
    if source_manifest != build_prep.source_manifest(ROOT):
        raise ValueError('current application source manifest required')
    application_source_sha = hashlib.sha256(
        json.dumps(source_manifest, sort_keys=True).encode()).hexdigest()
    source_vk = source_manifest.get('v3_vk')
    validate_application_vk(source_vk, pin_record, setup_sha, package_digest)
    elf_sha, _ = _file_digest(application_elf, maximum=MAX_BINARY_BYTES)
    prepare_raw = _stable_read(prepare_status, MAX_JSON_BYTES)
    prepare = _json(prepare_raw, 'application prepare evidence')
    validate_prepare_binding(
        prepare,
        setup_manifest_sha256=setup_sha,
        package_digest=package_digest,
        application_source_sha256=application_source_sha,
        application_elf_sha256=elf_sha,
        source_vk=source_vk,
    )

    proof_sha, _ = _file_digest(
        proof_binary, expected=proof_binary_sha256, maximum=MAX_BINARY_BYTES,
        modes=(0o700, 0o755))
    preparer_sha, _ = _file_digest(input_preparer, expected=input_preparer_sha256)
    client_sha, _ = _file_digest(client_source)
    adapter_sha, _ = _file_digest(adapter_binary, maximum=MAX_BINARY_BYTES,
                                  modes=(0o700, 0o755))
    source_identity = packet_v2.proof_source_identity(ROOT)
    identities = {
        'setup_manifest': setup_sha,
        'package': package_digest,
        'package_pins': package_pins_sha256,
        'proof_binary': proof_sha,
        'proof_source': source_identity,
        'input_preparer': preparer_sha,
        'client': client_sha,
        'adapter': adapter_sha,
        'application_source': application_source_sha,
        'application_elf': elf_sha,
    }
    envelope = boundary_identity_fields(identities, external_pins={
        'setup_manifest_sha256': setup_ref['sha256'],
        'package_digest': pin_record['package_identity']['package'],
        'package_pins_sha256': package_pins_sha256,
    })
    package_pins_v2.verify_file(pins_path, package_pins_sha256, repo_root=ROOT)
    checked_files = (
        (pins_path, package_pins_sha256, package_pins_v2.MAX_RECORD_BYTES,
         (0o600, 0o644)),
        (setup_path, setup_sha, package_pins_v2.MAX_REPORT_BYTES,
         (0o600, 0o644)),
        (Path(application_source_manifest), hashlib.sha256(source_raw).hexdigest(),
         MAX_JSON_BYTES, (0o600, 0o644)),
        (Path(prepare_status), hashlib.sha256(prepare_raw).hexdigest(),
         MAX_JSON_BYTES, (0o600, 0o644)),
        (Path(application_elf), elf_sha, MAX_BINARY_BYTES, (0o600, 0o644)),
        (Path(proof_binary), proof_sha, MAX_BINARY_BYTES, (0o700, 0o755)),
        (Path(input_preparer), preparer_sha, MAX_SOURCE_BYTES, (0o600, 0o644)),
        (Path(client_source), client_sha, MAX_SOURCE_BYTES, (0o600, 0o644)),
        (Path(adapter_binary), adapter_sha, MAX_BINARY_BYTES, (0o700, 0o755)),
    )
    for path, expected, maximum, modes in checked_files:
        if hashlib.sha256(_stable_read(path, maximum, modes=modes)).hexdigest() != expected:
            raise ValueError('preflight input changed before return')
    if (source_manifest != build_prep.source_manifest(ROOT)
            or source_identity != packet_v2.proof_source_identity(ROOT)):
        raise ValueError('source closure changed before return')
    return {
        'schema': PREFLIGHT_SCHEMA,
        'preflight_passed': True,
        'freeze_published': False,
        **envelope,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-pins', type=Path, required=True)
    parser.add_argument('--package-pins-sha256', required=True)
    parser.add_argument('--prepare-status', type=Path, required=True)
    parser.add_argument('--application-source-manifest', type=Path, required=True)
    parser.add_argument('--application-elf', type=Path, required=True)
    parser.add_argument('--proof-binary', type=Path, required=True)
    parser.add_argument('--proof-binary-sha256', required=True)
    parser.add_argument('--input-preparer', type=Path, required=True)
    parser.add_argument('--input-preparer-sha256', required=True)
    parser.add_argument('--client-source', type=Path, required=True)
    parser.add_argument('--adapter-binary', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = preflight(
            package_pins_path=args.package_pins,
            package_pins_sha256=args.package_pins_sha256,
            prepare_status=args.prepare_status,
            application_source_manifest=args.application_source_manifest,
            application_elf=args.application_elf,
            proof_binary=args.proof_binary,
            proof_binary_sha256=args.proof_binary_sha256,
            input_preparer=args.input_preparer,
            input_preparer_sha256=args.input_preparer_sha256,
            client_source=args.client_source,
            adapter_binary=args.adapter_binary,
        )
    except Exception as error:
        raise SystemExit(f'v2 heldout freeze preflight rejected ({type(error).__name__})') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
