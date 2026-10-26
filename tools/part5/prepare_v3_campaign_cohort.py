#!/usr/bin/env python3
"""Prepare eleven signed training leaves for the frozen ten-revocation schedule.

Creates one issuer and eleven holder keys, eleven bounded certificates, and a
pure tree with holder slot 0 and unrelated slots 16..25. This is training data;
it authenticates no source history, registry allocation or live chain state.
Keys/DER/membership stay in one fresh owner0700 ignored directory. Stdout is a
scrubbed receipt. Fixed operation counts and deadline checks bound admission;
an external bounded runner must enforce hard wall/RSS/storage limits because an
in-process RSA/issuance/tree call cannot be interrupted by these checks.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tools.part5 import generate_v3_heldout_keys as keys
from tools.part5 import issue_v3_heldout_certificate as issuance
from tools.part5 import prepare_v3_revocation_cohort as schedule
from tools.part5.credential_profile import ORGANIZATION, GROUP, admit_certificate, public_bindings

FREEZE_SCHEMA = 'credential-v3-training-campaign-cohort-freeze-v1'
SLOTS = (0, *range(16, 26))


def source_hashes():
    return {name: keys.file_sha(Path(module.__file__)) for name, module in (
        ('campaign', sys.modules[__name__]), ('root_schedule', schedule),
        ('key_generation', keys), ('issuance', issuance))}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _boundary(path, expected, started):
    raw = issuance._read(path, 65536)
    value = issuance.decode_parameters(raw)
    if (not keys._hash(expected) or hashlib.sha256(raw).hexdigest() != expected
            or type(value) is not dict or set(value) != {
                'schema', 'frozen_at_unix_ns', 'identities', 'source_sha256', 'forbidden_public_key_sha256'}
            or value['schema'] != FREEZE_SCHEMA
            or type(value['frozen_at_unix_ns']) is not int
            or not 0 < value['frozen_at_unix_ns'] < started
            or value['source_sha256'] != source_hashes()
            or type(value['identities']) is not dict
            or set(value['identities']) != keys.IDENTITY_ROLES
            or not all(keys._hash(v) for v in value['identities'].values())
            or type(value['forbidden_public_key_sha256']) is not list
            or not value['forbidden_public_key_sha256']
            or not all(keys._hash(v) for v in value['forbidden_public_key_sha256'])
            or len(set(value['forbidden_public_key_sha256'])) != len(value['forbidden_public_key_sha256'])):
        raise ValueError('exact earlier pinned training cohort freeze required')
    return raw, value


def prepare(freeze, freeze_sha256, output, encoder='cryptography', max_seconds=180):
    started, monotonic_start = time.time_ns(), time.monotonic()
    if (encoder not in ('cryptography', 'openssl') or type(max_seconds) not in (int, float)
            or not math.isfinite(max_seconds) or not 0 < max_seconds <= 300):
        raise ValueError('bounded encoder and deadline required')
    raw_freeze, boundary = _boundary(freeze, freeze_sha256, started)
    if not isinstance(output, Path) or not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError('fresh canonical private output required')
    issuance._directory(output.parent)
    if output.parent.resolve(strict=True) / output.name != output or not keys._ignored(output):
        raise ValueError('ignored canonical output required')
    def deadline():
        if time.monotonic() - monotonic_start > max_seconds:
            raise ValueError('campaign cohort deadline exceeded')
    seen = set(boundary['forbidden_public_key_sha256'])
    generated, key_records = [], []
    previous = started
    for index in range(12):
        deadline()
        began = time.time_ns()
        key = keys._new_key()
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
            raise ValueError('RSA2048 private key required')
        public = key.public_key()
        numbers = public.public_numbers()
        if numbers.e != 65537 or numbers.n.bit_length() != 2048:
            raise ValueError('RSA2048 e65537 required')
        digest = hashlib.sha256(public.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        ended = time.time_ns()
        if digest in seen or not previous <= began <= ended:
            raise ValueError('duplicate/reused key or generation clock rollback')
        seen.add(digest)
        previous = ended
        generated.append(key)
        key_records.append(dict(role='issuer' if index == 0 else 'holder',
            index=0 if index == 0 else index - 1, public_key_sha256=digest,
            generation_started_unix_ns=began, generation_completed_unix_ns=ended))
    issuer, holders = generated[0], generated[1:]
    modulus = issuer.public_key().public_numbers().n
    aki = bytes.fromhex(key_records[0]['public_key_sha256'])[:20]
    certificate_records, files, digests = [], {}, []
    expected_issuer = None
    holder_policy = None
    for index, (slot, holder) in enumerate(zip(SLOTS, holders)):
        deadline()
        params = dict(variant=index % 8, serial=(1 << 120) + index + 1,
            not_before='2026-01-01T00:00:00Z', not_after='2028-01-01T00:00:00Z',
            organization=ORGANIZATION.hex(), group=GROUP.hex(), aki=aki.hex())
        der = issuance.issue_certificate(issuer, holder, params, encoder)
        parsed = admit_certificate(der, modulus)
        if (len(der) != 952 or len(parsed['tbs']) != 672
                or parsed['holder_modulus'] != holder.public_key().public_numbers().n
                or parsed['serial'] != params['serial'].to_bytes(16, 'big')
                or parsed['variant'] != params['variant'] or parsed['aki'] != aki
                or parsed['organization'] != ORGANIZATION or parsed['group'] != GROUP
                or parsed['not_before'] != 1767225600 or parsed['not_after'] != 1830297600):
            raise ValueError('admitted certificate does not match planned holder/profile')
        digest = hashlib.sha256(parsed['tbs']).digest()
        if digest in digests:
            raise ValueError('duplicate issuer-signed TBS')
        digests.append(digest)
        issuer_hash, policy_hash = public_bindings(parsed, modulus)
        if index == 0:
            expected_issuer, holder_policy = issuer_hash, policy_hash
        if issuer_hash != expected_issuer or policy_hash != holder_policy:
            raise ValueError('campaign issuer or signed policy mismatch')
        files[f'credential-{index}.der'] = der
        files[f'parameters-{index}.json'] = encoded(params)
        certificate_records.append(dict(slot=slot, variant=parsed['variant'], encoder=encoder,
            credential_sha256=hashlib.sha256(der).hexdigest(), tbs_sha256=digest.hex(),
            holder_public_key_sha256=key_records[index + 1]['public_key_sha256'],
            parameters_sha256=hashlib.sha256(encoded(params)).hexdigest()))
    deadline()
    membership = schedule.membership_for_sequence(digests[0], digests[1:])
    membership.update(schema='v3-eleven-leaf-training-membership-v1', issuer_hash=str(expected_issuer),
        holder_policy_hash=str(holder_policy), allocation_epoch=1,
        allocation_authorized=False, registry_history_authenticated=False, live_state_authenticated=False)
    files['membership.json'] = encoded(membership)
    files['issuer-modulus.bin'] = modulus.to_bytes(256, 'big')
    completed = time.time_ns()
    deadline()
    if (completed < previous or issuance._read(freeze, 65536) != raw_freeze
            or boundary['source_sha256'] != source_hashes()):
        raise ValueError('freeze/source or chronology changed during preparation')
    receipt = dict(schema='v3-eleven-signed-training-credentials-v1', training_only=True,
        heldout_acceptance=False, registry_history_authenticated=False,
        live_state_authenticated=False, allocation_authorized=False,
        freeze_receipt_sha256=freeze_sha256, frozen_at_unix_ns=boundary['frozen_at_unix_ns'],
        source_sha256=boundary['source_sha256'], identities=boundary['identities'],
        preparation_started_unix_ns=started, preparation_completed_unix_ns=completed,
        counts=dict(issuers=1, holders=11, certificates=11, roots=11), keys=key_records,
        certificates=certificate_records, issuer_hash=str(expected_issuer), holder_policy_hash=str(holder_policy),
        membership_sha256=hashlib.sha256(files['membership.json']).hexdigest(),
        root_sequence_sha256=hashlib.sha256(encoded(membership['roots'])).hexdigest(),
        provenance=dict(key_generator='cryptography.rsa.generate_private_key',
            cryptography_version=keys.cryptography.__version__,
            backend=keys.default_backend().openssl_version_text(), public_exponent=65537, key_size=2048,
            prior_public_key_count=len(boundary['forbidden_public_key_sha256']),
            reuse_scope='supplied earlier-key inventory and new cohort', encoder=encoder,
            key_imported=False, pure_tree_schedule=True, deadline_seconds=max_seconds))
    output.mkdir(mode=0o700)
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    original, written = os.fstat(fd), []
    try:
        os.fchmod(fd, 0o700)
        issuance._directory(output)
        private = [('issuer.pem', issuer), *[(f'holder-{i}.pem', key) for i, key in enumerate(holders)]]
        for name, key in private:
            issuance._write(name, key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), fd)
            written.append(name)
        files['cohort-receipt.json'] = encoded(receipt)
        for name, data in files.items():
            issuance._write(name, data, fd)
            written.append(name)
        os.fsync(fd)
        current = output.lstat()
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError('private output changed')
    except Exception:
        for name in written:
            os.unlink(name, dir_fd=fd)
        current = output.lstat()
        if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
            output.rmdir()
        raise
    finally:
        os.close(fd)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', required=True, type=Path)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--encoder', choices=['cryptography', 'openssl'], default='cryptography')
    parser.add_argument('--max-seconds', type=float, default=180)
    args = parser.parse_args()
    try:
        receipt = prepare(args.freeze, args.freeze_sha256, args.output, args.encoder, args.max_seconds)
    except Exception:
        raise SystemExit('training campaign cohort rejected') from None
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
