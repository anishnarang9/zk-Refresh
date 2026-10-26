#!/usr/bin/env python3
"""Freeze v2 heldout package identities and an earlier RSA-key inventory.

The output is an owner-only directory under ignored artifacts. An exclusive
directory reservation prevents replacement; the prior-key inventory is
written first, and the fully written v2 boundary is linked into place last as
the completion marker. Partial output is preserved after publication failures.
This tool does not generate keys, certificates, proofs, or application
requests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import freeze_v3_campaign_cohort as prior_freeze
from tools.part5 import preflight_v3_heldout_freeze_v2 as preflight_v2

PART5 = ROOT / 'artifacts/dynark/part5'
FREEZE_SCHEMA = 'credential-v3-frozen-holdout-boundary-v2'
INVENTORY_SCHEMA = 'credential-v3-prior-public-key-inventory-v2'
PACKET_BOUNDARY_FIELDS = frozenset({
    'frozen_at_unix_ns', *preflight_v2.DIRECT_IDENTITY_ROLES,
})
PREFLIGHT_FIELDS = frozenset({
    'schema', 'preflight_passed', 'freeze_published', 'identities',
    *preflight_v2.DIRECT_IDENTITY_ROLES,
})


def _sha(value):
    return (type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value))


def _fresh_output(path):
    path = Path(path)
    try:
        parent = path.parent
        parent_info = parent.lstat()
        if (not path.is_absolute() or path.name in ('', '.', '..')
                or path.resolve(strict=False) != path
                or path.exists() or path.is_symlink()
                or parent.resolve(strict=True) != parent
                or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != os.getuid()
                or parent_info.st_mode & 0o022
                or parent != PART5):
            raise ValueError('fresh direct owner-only artifact directory required')
    except OSError:
        raise ValueError('fresh direct owner-only artifact directory required') from None
    return path


def _validated_preflight(value):
    if (type(value) is not dict or set(value) != PREFLIGHT_FIELDS
            or value.get('schema') != preflight_v2.PREFLIGHT_SCHEMA
            or value.get('preflight_passed') is not True
            or value.get('freeze_published') is not False):
        raise ValueError('successful v2 heldout preflight required')
    identities = value.get('identities')
    if (type(identities) is not dict
            or set(identities) != set(preflight_v2.IDENTITY_ROLES)
            or not all(_sha(digest) for digest in identities.values())):
        raise ValueError('complete v2 preflight identity roles required')
    for field, role in preflight_v2.DIRECT_IDENTITY_ROLES.items():
        if not _sha(value.get(field)) or value[field] != identities[role]:
            raise ValueError(f'v2 preflight direct identity mismatch: {field}')
    return {field: value[field] for field in preflight_v2.DIRECT_IDENTITY_ROLES}


def _prior_inventory():
    fingerprints, sources = prior_freeze.prior_keys()
    if (type(fingerprints) is not list or not fingerprints
            or fingerprints != sorted(set(fingerprints))
            or not all(_sha(value) for value in fingerprints)
            or type(sources) is not list or not sources):
        raise ValueError('earlier RSA key inventory required')
    checked_sources = []
    source_fields = {'path', 'sha256', 'public_key_sha256'}
    for source in sources:
        if (type(source) is not dict or set(source) != source_fields
                or type(source.get('path')) is not str
                or not source['path'].startswith('artifacts/dynark/part5/')
                or Path(source['path']).is_absolute()
                or str(Path(source['path'])) != source['path']
                or not _sha(source.get('sha256'))
                or not _sha(source.get('public_key_sha256'))
                or source['public_key_sha256'] not in fingerprints):
            raise ValueError('reviewable earlier RSA key source inventory required')
        checked_sources.append(dict(source))
    if checked_sources != sorted(checked_sources, key=lambda item: item['path']):
        raise ValueError('sorted earlier RSA key source inventory required')
    if {source['public_key_sha256'] for source in checked_sources} != set(fingerprints):
        raise ValueError('earlier RSA key inventory source mismatch')
    return fingerprints, checked_sources


def _write_file(directory_fd, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_freeze_marker(directory_fd, raw):
    """Atomically add a complete freeze file without replacing any name."""
    pending_name = '.freeze-pending-' + secrets.token_hex(12)
    fd = os.open(pending_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(fd)
    except Exception:
        try:
            os.unlink(pending_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(fd)
    try:
        # link(2) creates the final name atomically and fails if it already
        # exists. Both names live in the reserved directory on the same fs.
        os.link(pending_name, 'freeze.json', src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd, follow_symlinks=False)
    finally:
        try:
            os.unlink(pending_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _publish_pair(output, freeze_raw, inventory_raw):
    """Reserve the output, then publish inventory and freeze marker in order."""
    output = _fresh_output(output)
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY
                        | os.O_NOFOLLOW | os.O_CLOEXEC)
    directory_fd = None
    try:
        parent_info = os.fstat(parent_fd)
        current_parent = output.parent.lstat()
        if ((parent_info.st_dev, parent_info.st_ino) !=
                (current_parent.st_dev, current_parent.st_ino)):
            raise ValueError('artifact directory changed before reservation')
        # mkdir is the no-replace reservation. A competing writer that created
        # this name after _fresh_output keeps its directory untouched.
        os.mkdir(output.name, 0o700, dir_fd=parent_fd)
        directory_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY
                               | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        info = os.fstat(directory_fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('owner0700 output directory required')
        _write_file(directory_fd, 'prior-key-inventory.json', inventory_raw)
        _publish_freeze_marker(directory_fd, freeze_raw)
        os.fsync(directory_fd)
        os.fsync(parent_fd)
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)


def freeze(output_dir, *, package_pins_path, package_pins_sha256,
           prepare_status, application_source_manifest, application_elf,
           proof_binary, proof_binary_sha256, input_preparer,
           input_preparer_sha256, client_source, adapter_binary):
    """Validate a v2 heldout boundary and publish it with a prior-key census."""
    output = _fresh_output(output_dir)
    preflight_inputs = {
        'package_pins_path': package_pins_path,
        'package_pins_sha256': package_pins_sha256,
        'prepare_status': prepare_status,
        'application_source_manifest': application_source_manifest,
        'application_elf': application_elf,
        'proof_binary': proof_binary,
        'proof_binary_sha256': proof_binary_sha256,
        'input_preparer': input_preparer,
        'input_preparer_sha256': input_preparer_sha256,
        'client_source': client_source,
        'adapter_binary': adapter_binary,
    }
    before = _validated_preflight(preflight_v2.preflight(**preflight_inputs))
    fingerprints, sources = _prior_inventory()
    observed_at = time.time_ns()
    if observed_at <= 0:
        raise ValueError('positive prior-key inventory timestamp required')

    # The preflight snapshots every input and rechecks them before returning.
    # Repeat it immediately before publication, then compare the full boundary.
    after = _validated_preflight(preflight_v2.preflight(**preflight_inputs))
    if before != after:
        raise ValueError('v2 preflight inputs changed before publication')
    current_fingerprints, current_sources = _prior_inventory()
    if (current_fingerprints != fingerprints or current_sources != sources):
        raise ValueError('prior RSA inventory changed before publication')

    frozen_at = time.time_ns()
    if frozen_at <= observed_at:
        raise ValueError('prior inventory must predate the freeze')
    boundary = {
        'schema': FREEZE_SCHEMA,
        'frozen_at_unix_ns': frozen_at,
        **after,
    }
    freeze_raw = (json.dumps(boundary, sort_keys=True, indent=2) + '\n').encode()
    freeze_sha = hashlib.sha256(freeze_raw).hexdigest()
    inventory = {
        'schema': INVENTORY_SCHEMA,
        'observed_at_unix_ns': observed_at,
        'freeze_sha256': freeze_sha,
        'public_key_sha256': fingerprints,
        'sources': sources,
    }
    inventory_raw = (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode()
    inventory_sha = hashlib.sha256(inventory_raw).hexdigest()
    _publish_pair(output, freeze_raw, inventory_raw)
    return {
        'freeze_sha256': freeze_sha,
        'prior_key_inventory_sha256': inventory_sha,
        'frozen_at_unix_ns': frozen_at,
        'prior_inventory_observed_at_unix_ns': observed_at,
        'prior_public_key_count': len(fingerprints),
        **after,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-pins', required=True, type=Path)
    parser.add_argument('--package-pins-sha256', required=True)
    parser.add_argument('--prepare-status', required=True, type=Path)
    parser.add_argument('--application-source-manifest', required=True, type=Path)
    parser.add_argument('--application-elf', required=True, type=Path)
    parser.add_argument('--proof-binary', required=True, type=Path)
    parser.add_argument('--proof-binary-sha256', required=True)
    parser.add_argument('--input-preparer', required=True, type=Path)
    parser.add_argument('--input-preparer-sha256', required=True)
    parser.add_argument('--client-source', required=True, type=Path)
    parser.add_argument('--adapter-binary', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = freeze(
            args.output_dir,
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
        raise SystemExit(
            f'v2 heldout freeze rejected ({type(error).__name__})') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
