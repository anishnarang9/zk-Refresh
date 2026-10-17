#!/usr/bin/env python3
"""Prepare one pinned heldout certificate as a local two-leaf stage case.

This writes a private pair view compatible with the existing v3 local stage
and unrelated-root transition tools. It proves certificate/cohort consistency
and tree arithmetic only. It does not authenticate issuer enrollment, signed
registry history, finalized accounts, or current publisher head.
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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import build_v3_heldout_cohort as cohort_builder
from tools.part5 import generate_v3_heldout_keys as keys
from tools.part5 import issue_v3_heldout_certificate as issuance
from tools.part5 import prepare_v3_revocation_cohort as schedule
from tools.part5.credential_profile import admit_certificate, public_bindings

COHORT_SCHEMA = 'credential-v3-heldout-issuance-cohort-v1'
CASE_SCHEMA = 'credential-v3-heldout-case-context-v1'
PAIR_SCHEMA = 'v3-two-signed-training-credentials-v1'
STAGE_SCHEMA = 'part5-v3-local-training-context-v1'
CERTIFICATE_COUNT = 8
ISSUER_COUNT = 4
HOLDER_COUNT = 8
POLICY_COUNT = 2


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _hash(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _decimal(value):
    if type(value) is not str or not value.isdecimal() or str(int(value)) != value:
        raise ValueError('canonical public field hash required')
    number = int(value)
    if not 0 <= number < 1 << 256:
        raise ValueError('bounded public field hash required')
    return number


def _row_index(receipt, variant):
    rows = receipt.get('certificates')
    counts = receipt.get('counts')
    if (receipt.get('schema') != COHORT_SCHEMA
            or receipt.get('status') != 'cohort_issued_pending_application_gate'
            or receipt.get('keys_generated_after_freeze') is not True
            or not _hash(receipt.get('freeze_sha256'))
            or type(counts) is not dict
            or counts.get('issuers') != ISSUER_COUNT
            or counts.get('holders') != HOLDER_COUNT
            or counts.get('certificates') != CERTIFICATE_COUNT
            or type(counts.get('openssl_issuances')) is not int
            or counts['openssl_issuances'] < 4
            or counts.get('policies') != POLICY_COUNT
            or type(rows) is not list or len(rows) != CERTIFICATE_COUNT):
        raise ValueError('pinned eight-certificate heldout receipt required')
    by_variant = {}
    issuer_groups = {}
    all_issuer_keys, all_holder_keys, all_policies = set(), set(), set()
    issuer_key_by_index = {}
    holder_indices = set()
    for row in rows:
        if type(row) is not dict:
            raise ValueError('certificate receipt rows required')
        v, issuer_index, holder_index = (row.get('variant'), row.get('issuer_index'),
                                         row.get('holder_index'))
        if (type(v) is not int or not 0 <= v < CERTIFICATE_COUNT or v in by_variant
                or type(issuer_index) is not int or not 0 <= issuer_index < ISSUER_COUNT
                or type(holder_index) is not int or not 0 <= holder_index < HOLDER_COUNT
                or holder_index in holder_indices):
            raise ValueError('unique bounded heldout certificate identity required')
        for name in ('credential_sha256', 'tbs_sha256', 'issuer_public_key_sha256',
                     'holder_public_key_sha256', 'aki_sha256'):
            if not _hash(row.get(name)):
                raise ValueError('pinned certificate and public key fingerprints required')
        issuer_hash, policy_hash = _decimal(row.get('issuer_hash')), _decimal(row.get('policy_hash'))
        if (type(row.get('not_before_unix')) is not int
                or type(row.get('not_after_unix')) is not int
                or not 0 <= row['not_before_unix'] < row['not_after_unix']):
            raise ValueError('bounded certificate validity required')
        prior_key = issuer_key_by_index.setdefault(issuer_index, row['issuer_public_key_sha256'])
        if prior_key != row['issuer_public_key_sha256']:
            raise ValueError('issuer index maps to multiple public keys')
        by_variant[v] = row
        issuer_groups.setdefault(issuer_index, []).append(row)
        holder_indices.add(holder_index)
        all_issuer_keys.add(row['issuer_public_key_sha256'])
        all_holder_keys.add(row['holder_public_key_sha256'])
        all_policies.add(policy_hash)
        if issuer_hash < 0:
            raise ValueError('invalid issuer hash')
    if (set(by_variant) != set(range(CERTIFICATE_COUNT))
            or set(issuer_groups) != set(range(ISSUER_COUNT))
            or len(all_issuer_keys) != ISSUER_COUNT or len(all_holder_keys) != HOLDER_COUNT
            or len(all_policies) != POLICY_COUNT
            or receipt.get('policy_hashes') != [str(value) for value in sorted(all_policies)]
            or receipt.get('issuer_aki_sha256') != sorted({row['aki_sha256'] for row in rows})
            or any(len(group) != 2 or {int(row['policy_hash']) for row in group} != all_policies
                   or len({row['issuer_hash'] for row in group}) != 1
                   or len({row['aki_sha256'] for row in group}) != 1
                   for group in issuer_groups.values())):
        raise ValueError('heldout issuer/policy coverage is incomplete')
    if type(variant) is not int or variant not in by_variant:
        raise ValueError('heldout target variant must be in [0, 7]')
    target = by_variant[variant]
    partners = [row for row in issuer_groups[target['issuer_index']] if row['variant'] != variant]
    if len(partners) != 1:
        raise ValueError('one same-issuer unrelated certificate required')
    return target, partners[0]


def _load_private_key(path, snapshots):
    raw = issuance._read(path, 4096)
    snapshots[path] = raw
    key = serialization.load_pem_private_key(raw, password=None)
    if (not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048
            or key.public_key().public_numbers().e != 65537):
        raise ValueError('bounded RSA-2048/e65537 private key required')
    return raw, key


def _certificate(cohort, row, issuer_key, holder_key, snapshots):
    path = cohort / f"certificate-{row['variant']:02d}" / 'credential.der'
    raw = issuance._read(path, 952)
    snapshots[path] = raw
    modulus = issuer_key.public_key().public_numbers().n
    parsed = admit_certificate(raw, modulus)
    issuer_hash, policy_hash = public_bindings(parsed, modulus)
    holder_numbers = holder_key.public_key().public_numbers()
    if (len(raw) != 952 or parsed.get('variant') != row['variant']
            or hashlib.sha256(raw).hexdigest() != row['credential_sha256']
            or hashlib.sha256(parsed['tbs']).hexdigest() != row['tbs_sha256']
            or hashlib.sha256(parsed['aki']).hexdigest() != row['aki_sha256']
            or issuer_hash != int(row['issuer_hash']) or policy_hash != int(row['policy_hash'])
            or parsed['not_before'] != row['not_before_unix']
            or parsed['not_after'] != row['not_after_unix']
            or parsed['holder_modulus'] != holder_numbers.n
            or cohort_builder._public_key_digest(issuer_key) != row['issuer_public_key_sha256']
            or cohort_builder._public_key_digest(holder_key) != row['holder_public_key_sha256']):
        raise ValueError('certificate, issuer, holder key, and frozen row do not match')
    return raw, parsed, issuer_hash, policy_hash


def _public_certificate(row):
    return {name: row[name] for name in (
        'variant', 'issuer_index', 'holder_index', 'credential_sha256', 'tbs_sha256',
        'issuer_public_key_sha256', 'holder_public_key_sha256', 'issuer_hash', 'policy_hash',
        'aki_sha256', 'not_before_unix', 'not_after_unix')}


def derive(cohort, cohort_sha256, variant):
    """Return the deterministic case view without publishing or copying keys."""
    issuance._directory(cohort)
    if not _hash(cohort_sha256):
        raise ValueError('exact frozen heldout receipt hash required')
    receipt_path = cohort / 'cohort-receipt.json'
    receipt_raw = issuance._read(receipt_path, 65536)
    if hashlib.sha256(receipt_raw).hexdigest() != cohort_sha256:
        raise ValueError('frozen heldout receipt pin mismatch')
    receipt = issuance.decode_parameters(receipt_raw)
    target_row, other_row = _row_index(receipt, variant)
    if (target_row['issuer_index'] != other_row['issuer_index']
            or target_row['issuer_public_key_sha256'] != other_row['issuer_public_key_sha256']):
        raise ValueError('unrelated certificate must share target issuer')

    snapshots = {receipt_path: receipt_raw}
    issuer_path = cohort / 'keys' / f"issuer-{target_row['issuer_index']}.pem"
    holder_path = cohort / 'keys' / f"holder-{target_row['holder_index']}.pem"
    other_holder_path = cohort / 'keys' / f"holder-{other_row['holder_index']}.pem"
    _, issuer_key = _load_private_key(issuer_path, snapshots)
    holder_raw, holder_key = _load_private_key(holder_path, snapshots)
    _, other_holder_key = _load_private_key(other_holder_path, snapshots)
    own_raw, own, issuer_hash, policy_hash = _certificate(
        cohort, target_row, issuer_key, holder_key, snapshots)
    other_raw, other, other_issuer, _ = _certificate(
        cohort, other_row, issuer_key, other_holder_key, snapshots)
    if (issuer_hash != other_issuer or own['aki'] != other['aki']
            or target_row['issuer_hash'] != other_row['issuer_hash']):
        raise ValueError('selected leaves do not share issuer and AKI')

    own_digest, other_digest = hashlib.sha256(own['tbs']).digest(), hashlib.sha256(other['tbs']).digest()
    slot = int.from_bytes(own_digest[:2], 'big') & 1023
    membership = schedule.membership_for_pair(own_digest, other_digest, slot)
    membership.update(issuer_hash=issuer_hash, policy_hash=policy_hash)
    membership_raw = encoded(membership)
    membership_sha256 = hashlib.sha256(membership_raw).hexdigest()
    pair_receipt = {
        'schema': PAIR_SCHEMA,
        'training_only': True,
        'heldout_acceptance': False,
        'allocation_authorized': False,
        'registry_history_authenticated': False,
        'live_state_authenticated': False,
        'credential_sha256': hashlib.sha256(own_raw).hexdigest(),
        'unrelated_credential_sha256': hashlib.sha256(other_raw).hexdigest(),
        'membership_sha256': membership_sha256,
        'issuer_hash': str(issuer_hash),
        'policy_hash': str(policy_hash),
    }
    pair_receipt_raw = encoded(pair_receipt)
    pair_receipt_sha256 = hashlib.sha256(pair_receipt_raw).hexdigest()
    context_evidence = hashlib.sha256(
        b'credential-v3-heldout-case-evidence/v1\0'
        + bytes.fromhex(cohort_sha256)
        + bytes.fromhex(target_row['credential_sha256'])
        + bytes.fromhex(other_row['credential_sha256'])).hexdigest()
    stage_context = {
        'schema': STAGE_SCHEMA,
        'training_only': True,
        'root': f"{membership['active_root']:064x}",
        'issuer_hash': f'{issuer_hash:064x}',
        'policy_id': f'{policy_hash:064x}',
        'aki': (own['aki'] + bytes(12)).hex(),
        'evidence_digest': context_evidence,
        'not_before': own['not_before'],
        'not_after': own['not_after'],
        'initial_allocations': {
            'own_tbs_digest': own_digest.hex(),
            'unrelated_tbs_digest': other_digest.hex(),
            'slot': slot,
            'allocation_epoch': 1,
            'cohort_receipt_sha256': pair_receipt_sha256,
            'membership_sha256': membership_sha256,
        },
    }
    stage_context_raw = encoded(stage_context)
    case_context = {
        'schema': CASE_SCHEMA,
        'heldout_acceptance': False,
        'authenticated': {
            'registry_history': False,
            'live_state': False,
            'current_head': False,
            'finalized_account_batch': False,
        },
        'frozen_cohort': {
            'schema': COHORT_SCHEMA,
            'freeze_sha256': receipt['freeze_sha256'],
            'cohort_receipt_sha256': cohort_sha256,
        },
        'target': _public_certificate(target_row),
        'unrelated': _public_certificate(other_row),
        'pair_view': {
            'cohort_receipt_sha256': pair_receipt_sha256,
            'membership_sha256': membership_sha256,
            'stage_context_sha256': hashlib.sha256(stage_context_raw).hexdigest(),
        },
        'membership': {
            'slot': slot,
            'unrelated_slot': slot ^ 1,
            'R0': f"{membership['active_root']:064x}",
            'R1': f"{membership['unrelated_root']:064x}",
            'R2': f"{membership['own_revoked_root']:064x}",
            'active_siblings': membership['active_siblings'],
            'unrelated_siblings': membership['unrelated_siblings'],
            'own_revoked_siblings': membership['own_revoked_siblings'],
        },
    }
    case_context_raw = encoded(case_context)
    modulus_raw = issuer_key.public_key().public_numbers().n.to_bytes(256, 'big')

    # Recheck every private input read before the caller writes this derived view.
    for path, raw in snapshots.items():
        if issuance._read(path, max(len(raw), 1)) != raw:
            raise ValueError('heldout cohort changed during context derivation')
    return {
        'credential.der': own_raw,
        'unrelated.der': other_raw,
        'holder.pem': holder_raw,
        'issuer-modulus.bin': modulus_raw,
        'membership.json': membership_raw,
        'cohort-receipt.json': pair_receipt_raw,
        'case-context.json': case_context_raw,
        'stage-context.json': stage_context_raw,
    }


def prepare(cohort, cohort_sha256, variant, output):
    """Write one fresh private two-leaf pair view for a heldout certificate."""
    cohort, output = Path(cohort), Path(output)
    if (not isinstance(output, Path) or not output.is_absolute()
            or not output.exists() or output.is_symlink()
            or output.resolve(strict=True) != output):
        raise ValueError('canonical pre-created private output directory required')
    issuance._directory(output)
    if output == cohort or cohort in output.parents or output in cohort.parents:
        raise ValueError('separate cohort and case output directories required')
    if any(output.iterdir()) or not keys._ignored(output):
        raise ValueError('fresh ignored private case directory required')
    files = derive(cohort, cohort_sha256, variant)
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    written = []
    try:
        opened = os.fstat(fd)
        linked = output.lstat()
        if ((opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
                or os.listdir(fd)):
            raise ValueError('fresh private output directory changed')
        for name, raw in files.items():
            issuance._write(name, raw, directory_fd=fd)
            written.append(name)
        os.fsync(fd)
        for name, raw in files.items():
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size != len(raw)):
                raise ValueError('private case files must remain owner-only')
        current = output.lstat()
        if ((current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
                or set(os.listdir(fd)) != set(files)):
            raise ValueError('private output directory changed during preparation')
    except Exception:
        for name in written:
            os.unlink(name, dir_fd=fd)
        raise
    finally:
        os.close(fd)
    return {
        'schema': 'credential-v3-heldout-case-preparation-v1',
        'case_context_sha256': hashlib.sha256(files['case-context.json']).hexdigest(),
        'stage_context_sha256': hashlib.sha256(files['stage-context.json']).hexdigest(),
        'pair_receipt_sha256': hashlib.sha256(files['cohort-receipt.json']).hexdigest(),
        'membership_sha256': hashlib.sha256(files['membership.json']).hexdigest(),
        'heldout_acceptance': False,
        'registry_history_authenticated': False,
        'live_state_authenticated': False,
        'current_head_authenticated': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', type=Path, required=True)
    parser.add_argument('--cohort-sha256', required=True)
    parser.add_argument('--variant', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.cohort, args.cohort_sha256, args.variant, args.output)
    except Exception:
        raise SystemExit('heldout context preparation rejected') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
