#!/usr/bin/env python3
"""Generate a freeze-linked private cohort; issue no certificates.

The freeze extends the issuance tool's boundary with this generator's hash,
exact product identities, and an inventory of all known earlier public keys.
Supply its independently pinned SHA-256. Keys use issuer-0..3.pem and
holder-0..7.pem (PKCS8), compatible with the unchanged issuance tool. The
receipt contains hashes and generation provenance, never key bytes or paths.
Freshness evidence is local execution provenance, not hardware attestation;
reuse rejection covers the supplied earlier-key inventory and this cohort.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.part5 import issue_v3_heldout_certificate as issuance

ISSUANCE_TOOL = Path(issuance.__file__).resolve()
FREEZE_SCHEMA = 'credential-v3-frozen-holdout-boundary-v1'
IDENTITY_ROLES = frozenset({
    'circuit', 'profile', 'r1cs', 'witness_executable', 'setup_manifest',
    'ordinary_vk', 'proof_runner', 'registry', 'client', 'signer_interface',
    'ordinary_adapter', 'application_source', 'loaded_elf'})


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _ignored(path):
    return subprocess.run(['git', '--no-optional-locks', 'check-ignore', '--quiet',
                           '--no-index', '--', str(path)], cwd=ROOT,
                          capture_output=True, timeout=5, check=False).returncode == 0


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _freeze(path, expected, started):
    raw = issuance._read(path, 65536)
    value = issuance.decode_parameters(raw)
    if (not _hash(expected) or hashlib.sha256(raw).hexdigest() != expected
            or type(value) is not dict or set(value) != {
                'schema', 'frozen_at_unix_ns', 'issuance_tool_sha256',
                'key_generation_tool_sha256', 'identities', 'forbidden_public_key_sha256'}
            or value['schema'] != FREEZE_SCHEMA
            or type(value['frozen_at_unix_ns']) is not int
            or not 0 < value['frozen_at_unix_ns'] < started
            or value['issuance_tool_sha256'] != file_sha(ISSUANCE_TOOL)
            or value['key_generation_tool_sha256'] != file_sha(Path(__file__))
            or type(value['identities']) is not dict
            or set(value['identities']) != IDENTITY_ROLES
            or not all(_hash(v) for v in value['identities'].values())
            or type(value['forbidden_public_key_sha256']) is not list
            or not value['forbidden_public_key_sha256']
            or not all(_hash(v) for v in value['forbidden_public_key_sha256'])
            or len(set(value['forbidden_public_key_sha256']))
               != len(value['forbidden_public_key_sha256'])):
        raise ValueError('exact earlier pinned cohort freeze required')
    return raw, value


def generate(freeze_path, expected_freeze_sha256, output):
    """Generate twelve fresh keys; return a scrubbed receipt after publication.

    Freeze identities are pinned receipt assertions; this function does not load
    or qualify the product artifacts. Caller owns the complete prior-key census.
    """
    started = time.time_ns()
    raw_freeze, boundary = _freeze(freeze_path, expected_freeze_sha256, started)
    if (not isinstance(output, Path) or not output.is_absolute()
            or output.exists() or output.is_symlink()):
        raise ValueError('fresh private ignored output required')
    issuance._directory(output.parent)
    if output.parent.resolve(strict=True) / output.name != output or not _ignored(output):
        raise ValueError('canonical ignored output required')
    forbidden = set(boundary['forbidden_public_key_sha256'])
    seen, keys, records = set(), [], []
    previous = started
    for role, count in [('issuer', 4), ('holder', 8)]:
        for index in range(count):
            began = time.time_ns()
            if began < previous:
                raise ValueError('generation clock moved backward')
            key = _new_key()
            if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
                raise ValueError('RSA2048 private key required')
            public = key.public_key()
            numbers = public.public_numbers()
            if numbers.e != 65537 or numbers.n.bit_length() != 2048:
                raise ValueError('RSA2048 e65537 required')
            digest = hashlib.sha256(public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            if digest in seen or digest in forbidden:
                raise ValueError('duplicate or previously recorded public key')
            seen.add(digest)
            ended = time.time_ns()
            if ended < began:
                raise ValueError('generation clock moved backward')
            previous = ended
            keys.append((f'{role}-{index}.pem', key))
            records.append(dict(role=role, index=index, public_key_sha256=digest,
                                generation_started_unix_ns=began, generation_completed_unix_ns=ended))
    completed = time.time_ns()
    if completed < previous or issuance._read(freeze_path, 65536) != raw_freeze:
        raise ValueError('freeze or generation chronology changed')
    receipt = dict(schema='credential-v3-heldout-key-generation-v1',
        freeze_receipt_sha256=expected_freeze_sha256,
        frozen_at_unix_ns=boundary['frozen_at_unix_ns'],
        identities=boundary['identities'],
        issuance_tool_sha256=boundary['issuance_tool_sha256'],
        key_generation_tool_sha256=boundary['key_generation_tool_sha256'],
        generation_started_unix_ns=started, generation_completed_unix_ns=completed,
        counts=dict(issuers=4, holders=8), keys=records,
        prior_public_key_count=len(forbidden),
        provenance=dict(implementation='cryptography.rsa.generate_private_key',
                        cryptography_version=cryptography.__version__,
                        backend=default_backend().openssl_version_text(),
                        key_size=2048, public_exponent=65537,
                        imported_keys=False, certificates_issued=False,
                        reuse_scope='supplied earlier-key inventory and complete new cohort'))
    output.mkdir(mode=0o700)
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = os.fstat(directory_fd)
    created = []
    try:
        os.fchmod(directory_fd, 0o700)
        issuance._directory(output)
        for name, key in keys:
            issuance._write(name, key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), directory_fd)
            created.append(name)
        name = 'key-generation-receipt.json'
        issuance._write(name, (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode(), directory_fd)
        created.append(name)
        os.fsync(directory_fd)
        current = output.lstat()
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('private output directory changed')
    except Exception:
        for name in created:
            os.unlink(name, dir_fd=directory_fd)
        current = output.lstat()
        if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
            output.rmdir()
        raise
    finally:
        os.close(directory_fd)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', required=True, type=Path)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = generate(args.freeze, args.freeze_sha256, args.output)
    except Exception:
        raise SystemExit('heldout key generation rejected') from None
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
