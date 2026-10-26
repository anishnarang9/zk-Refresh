#!/usr/bin/env python3
"""Generate the frozen v3 unseen-credential acceptance cohort.

This tool only creates a private issuance cohort. It does not enroll issuers,
build witnesses or proofs, execute requests, or establish application acceptance.
The supplied freeze and prior-key inventory must already exist before this
process starts. All key and DER files are written below a fresh ignored 0700
directory; stdout and the cohort receipt contain hashes and counts only.

The inventory JSON has exactly: schema, observed_at_unix_ns, freeze_sha256,
and public_key_sha256. Its fingerprint list must equal the list pinned into the
freeze. See ``INVENTORY_SCHEMA`` for the schema value.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from tools.part5 import generate_v3_heldout_keys as keygen
from tools.part5 import issue_v3_heldout_certificate as issuance
from tools.part5.credential_profile import admit_certificate, public_bindings

INVENTORY_SCHEMA = 'credential-v3-prior-public-key-inventory-v1'
COHORT_SCHEMA = 'credential-v3-heldout-issuance-cohort-v1'
ISSUER_COUNT = 4
HOLDER_COUNT = 8
CERTIFICATE_COUNT = 8
OPENSSL_COUNT = 4


def _hash(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _inventory(path, expected_freeze_sha256, expected_fingerprints, frozen_at):
    raw = issuance._read(path, 1024 * 1024)
    value = issuance.decode_parameters(raw)
    if (type(value) is not dict or set(value) != {
            'schema', 'observed_at_unix_ns', 'freeze_sha256', 'public_key_sha256'}
            or value['schema'] != INVENTORY_SCHEMA
            or type(value['observed_at_unix_ns']) is not int
            or not 0 < value['observed_at_unix_ns'] < frozen_at
            or value['freeze_sha256'] != expected_freeze_sha256
            or type(value['public_key_sha256']) is not list
            or not value['public_key_sha256']
            or not all(_hash(item) for item in value['public_key_sha256'])
            or len(set(value['public_key_sha256'])) != len(value['public_key_sha256'])
            or sorted(value['public_key_sha256']) != sorted(expected_fingerprints)):
        raise ValueError('earlier matching prior-key inventory required')
    return raw, value


def _canonical_output(output):
    if (not isinstance(output, Path) or not output.is_absolute()
            or output.exists() or output.is_symlink()
            or output.parent.resolve(strict=True) / output.name != output):
        raise ValueError('fresh canonical ignored output required')
    issuance._directory(output.parent)
    if not keygen._ignored(output):
        raise ValueError('fresh canonical ignored output required')


def _create_private_output(output):
    parent_fd = os.open(output.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    output_fd = None
    try:
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        output_fd = os.open(output.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd)
        os.fchmod(output_fd, 0o700)
        linked = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(output_fd)
        if (opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o700
                or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)):
            raise ValueError('owner0700 output directory required')
        return output_fd
    except Exception:
        if output_fd is not None:
            os.close(output_fd)
        raise
    finally:
        os.close(parent_fd)


def _new_private_directory(path, parent_fd):
    os.mkdir(path, mode=0o700, dir_fd=parent_fd)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=parent_fd)
    os.fchmod(fd, 0o700)
    info = os.fstat(fd)
    linked = os.stat(path, dir_fd=parent_fd, follow_symlinks=False)
    if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
            or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)):
        os.close(fd)
        raise ValueError('owner0700 output directory required')
    return fd


def _public_key_digest(key):
    public = key.public_key()
    if public.key_size != 2048 or public.public_numbers().e != 65537:
        raise ValueError('RSA-2048/e65537 keys required')
    return hashlib.sha256(public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest()


def _certificate_parameters(variant, issuer_digest):
    policy = variant // 4
    today = datetime.datetime.now(datetime.timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0)
    before = today - datetime.timedelta(days=30 - variant)
    after = before + datetime.timedelta(days=730 + variant)
    return dict(
        variant=variant,
        serial=(1 << 120) + variant + 1,
        not_before=before.strftime('%Y-%m-%dT%H:%M:%SZ'),
        not_after=after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        organization=(bytes([policy + 1]) * 16).hex(),
        group=(bytes([0x40 + policy]) * 32).hex(),
        aki=bytes.fromhex(issuer_digest)[:20].hex(),
    )


def _epoch(text):
    return int(datetime.datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ')
               .replace(tzinfo=datetime.timezone.utc).timestamp())


def _write_cert(output_fd, variant, der):
    directory_name = f'certificate-{variant:02d}'
    directory_fd = _new_private_directory(directory_name, output_fd)
    try:
        issuance._write('credential.der', der, directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def build(freeze_path, freeze_sha256, inventory_path, output, *, inventory_sha256=None):
    """Build and publish one eight-certificate cohort after a pinned freeze."""
    if not _hash(inventory_sha256):
        raise ValueError('pinned prior-key inventory digest required')
    started = time.time_ns()
    raw_freeze, boundary = keygen._freeze(freeze_path, freeze_sha256, started)
    raw_inventory, prior = _inventory(
        inventory_path, freeze_sha256, boundary['forbidden_public_key_sha256'],
        boundary['frozen_at_unix_ns'])
    if hashlib.sha256(raw_inventory).hexdigest() != inventory_sha256:
        raise ValueError('pinned prior-key inventory digest mismatch')
    _canonical_output(output)

    # The public product freeze and exact prior-key census are checked before
    # the first key is generated or any output directory is created.
    output_fd = _create_private_output(output)
    try:
        issuance._directory(output)
        output_stat = os.fstat(output_fd)
        generated_at = time.time_ns()
        if generated_at <= boundary['frozen_at_unix_ns'] or generated_at < started:
            raise ValueError('heldout generation must start after the pinned freeze')

        key_output = output / 'keys'
        key_receipt = keygen.generate(freeze_path, freeze_sha256, key_output)
        key_rows = {(row['role'], row['index']): row for row in key_receipt['keys']}
        keys = {}
        for role, count in (('issuer', ISSUER_COUNT), ('holder', HOLDER_COUNT)):
            for index in range(count):
                pem_path = key_output / f'{role}-{index}.pem'
                raw_key = issuance._read(pem_path, 4096)
                key = serialization.load_pem_private_key(raw_key, password=None)
                fingerprint = _public_key_digest(key)
                if fingerprint != key_rows[(role, index)]['public_key_sha256']:
                    raise ValueError('generated key fingerprint changed before issuance')
                keys[(role, index)] = key

        certificate_rows = []
        openssl_version = None
        previous_time = key_receipt['generation_completed_unix_ns']
        for variant in range(CERTIFICATE_COUNT):
            issuer_index = variant % ISSUER_COUNT
            holder_index = variant
            issuer = keys[('issuer', issuer_index)]
            holder = keys[('holder', holder_index)]
            issuer_digest = key_rows[('issuer', issuer_index)]['public_key_sha256']
            holder_digest = key_rows[('holder', holder_index)]['public_key_sha256']
            params = _certificate_parameters(variant, issuer_digest)
            encoder = 'openssl' if variant < OPENSSL_COUNT else 'cryptography'
            issuance_started = time.time_ns()
            if issuance_started < previous_time:
                raise ValueError('heldout issuance clock moved backward')
            der = issuance.issue_certificate(issuer, holder, params, encoder)
            parsed = admit_certificate(der, issuer.public_key().public_numbers().n)
            issuer_hash, policy_hash = public_bindings(
                parsed, issuer.public_key().public_numbers().n)
            issuance_completed = time.time_ns()
            if (issuance_completed < issuance_started or len(der) != 952
                    or parsed['variant'] != variant
                    or parsed['organization'] != bytes.fromhex(params['organization'])
                    or parsed['group'] != bytes.fromhex(params['group'])
                    or parsed['aki'] != bytes.fromhex(params['aki'])
                    or int.from_bytes(parsed['serial'], 'big') != params['serial']
                    or parsed['not_before'] != _epoch(params['not_before'])
                    or parsed['not_after'] != _epoch(params['not_after'])
                    or parsed['holder_modulus'] != holder.public_key().public_numbers().n):
                raise ValueError('issued certificate failed bounded profile admission')
            _write_cert(output_fd, variant, der)
            certificate_rows.append(dict(
                variant=variant,
                issuer_index=issuer_index,
                holder_index=holder_index,
                encoder=encoder,
                issuance_started_unix_ns=issuance_started,
                issuance_completed_unix_ns=issuance_completed,
                credential_sha256=hashlib.sha256(der).hexdigest(),
                tbs_sha256=hashlib.sha256(parsed['tbs']).hexdigest(),
                issuer_public_key_sha256=issuer_digest,
                holder_public_key_sha256=holder_digest,
                issuer_hash=str(issuer_hash),
                policy_hash=str(policy_hash),
                aki_sha256=hashlib.sha256(parsed['aki']).hexdigest(),
                organization_sha256=hashlib.sha256(parsed['organization']).hexdigest(),
                group_sha256=hashlib.sha256(parsed['group']).hexdigest(),
                serial_hex=parsed['serial'].hex(),
                not_before_unix=parsed['not_before'],
                not_after_unix=parsed['not_after'],
            ))
            previous_time = issuance_completed
            if encoder == 'openssl' and openssl_version is None:
                try:
                    openssl_version = subprocess.run(
                        ['openssl', 'version'], check=True, capture_output=True,
                        timeout=5, text=True).stdout.strip()
                except (OSError, subprocess.SubprocessError):
                    raise ValueError('OpenSSL issuance version unavailable') from None

        policy_hashes = {row['policy_hash'] for row in certificate_rows}
        aki_hashes = {row['aki_sha256'] for row in certificate_rows}
        openssl_issuances = sum(row['encoder'] == 'openssl' for row in certificate_rows)
        if (len(certificate_rows) != CERTIFICATE_COUNT
                or len({row['variant'] for row in certificate_rows}) != 8
                or len({row['issuer_public_key_sha256'] for row in certificate_rows}) != ISSUER_COUNT
                or len({row['holder_public_key_sha256'] for row in certificate_rows}) != HOLDER_COUNT
                or len(policy_hashes) != 2 or len(aki_hashes) != ISSUER_COUNT
                or openssl_issuances < OPENSSL_COUNT):
            raise ValueError('heldout cohort counts, policies, or issuer AKIs incomplete')

        completed = time.time_ns()
        if completed < previous_time or issuance._read(freeze_path, 65536) != raw_freeze:
            raise ValueError('freeze changed or generation clock moved backward')
        if issuance._read(inventory_path, 1024 * 1024) != raw_inventory:
            raise ValueError('prior-key inventory changed during cohort generation')
        if (output.lstat().st_dev, output.lstat().st_ino) != (output_stat.st_dev, output_stat.st_ino):
            raise ValueError('private output directory changed during cohort generation')

        receipt = dict(
            schema=COHORT_SCHEMA,
            status='cohort_issued_pending_application_gate',
            keys_generated_after_freeze=True,
            freeze_sha256=freeze_sha256,
            frozen_at_unix_ns=boundary['frozen_at_unix_ns'],
            prior_key_inventory_sha256=inventory_sha256,
            prior_public_key_count=len(prior['public_key_sha256']),
            key_generation_receipt_sha256=hashlib.sha256(issuance._read(
                key_output / 'key-generation-receipt.json', 65536)).hexdigest(),
            generation_started_unix_ns=generated_at,
            generation_completed_unix_ns=completed,
            counts=dict(issuers=ISSUER_COUNT, holders=HOLDER_COUNT,
                        certificates=CERTIFICATE_COUNT, openssl_issuances=openssl_issuances,
                        policies=len(policy_hashes)),
            policy_hashes=sorted(policy_hashes, key=int),
            issuer_aki_sha256=sorted(aki_hashes),
            openssl_version=openssl_version,
            identities=boundary['identities'],
            certificates=certificate_rows,
        )
        issuance._write('cohort-receipt.json',
            (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode(), output_fd)
        os.fsync(output_fd)
        issuance._directory(output)
        return receipt
    finally:
        os.close(output_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', required=True, type=Path)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--prior-key-inventory', required=True, type=Path)
    parser.add_argument('--prior-key-inventory-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = build(args.freeze, args.freeze_sha256, args.prior_key_inventory,
                        args.output, inventory_sha256=args.prior_key_inventory_sha256)
    except Exception:
        raise SystemExit('frozen heldout cohort generation rejected') from None
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
