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
from tools.part5.credential_profile import FR, admit_certificate, public_bindings

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


def _public_key_digest_from_modulus(modulus):
    public_key = rsa.RSAPublicNumbers(65537, modulus).public_key()
    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


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
        'heldout-cohort-receipt.json': receipt_raw,
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


def _bytes32(value, name):
    if (type(value) is not list or len(value) != 32
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in value)):
        raise ValueError(f'{name} must be a 32-byte JSON array')
    return bytes(value)


def _b58decode(text):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if type(text) is not str or not text:
        raise ValueError('base58 account address required')
    value = 0
    for character in text:
        if character not in alphabet:
            raise ValueError('invalid base58 account address')
        value = value * 58 + alphabet.index(character)
    body = value.to_bytes((value.bit_length() + 7) // 8, 'big') if value else b''
    decoded = bytes(len(text) - len(text.lstrip('1'))) + body
    if len(decoded) != 32:
        raise ValueError('32-byte account address required')
    return decoded


def _base58(raw):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if type(raw) is not bytes or len(raw) != 32:
        raise ValueError('32-byte public key required')
    value = int.from_bytes(raw, 'big')
    encoded_value = ''
    while value:
        value, remainder = divmod(value, 58)
        encoded_value = alphabet[remainder] + encoded_value
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + (encoded_value or '')


def _check_case_pair(case_root):
    case_root = Path(case_root)
    issuance._directory(case_root)
    names = {
        'case': ('case-context.json', 16384),
        'heldout': ('heldout-cohort-receipt.json', 65536),
        'pair': ('cohort-receipt.json', 8192),
        'membership': ('membership.json', 16384),
        'stage_context': ('stage-context.json', 8192),
        'own': ('credential.der', 952),
        'other': ('unrelated.der', 952),
        'modulus': ('issuer-modulus.bin', 256),
    }
    raw = {key: issuance._read(case_root / filename, cap)
           for key, (filename, cap) in names.items()}
    case, receipt, pair, member, stage_context = (issuance.decode_parameters(raw[key])
                                                  for key in ('case', 'heldout', 'pair', 'membership', 'stage_context'))
    if (type(case) is not dict or case.get('schema') != CASE_SCHEMA
            or case.get('heldout_acceptance') is not False
            or case.get('authenticated') != {
                'registry_history': False, 'live_state': False,
                'current_head': False, 'finalized_account_batch': False}
            or type(case.get('frozen_cohort')) is not dict
            or hashlib.sha256(raw['heldout']).hexdigest()
               != case['frozen_cohort'].get('cohort_receipt_sha256')
            or type(pair) is not dict or pair.get('schema') != PAIR_SCHEMA
            or pair.get('training_only') is not True
            or pair.get('heldout_acceptance') is not False
            or pair.get('registry_history_authenticated') is not False
            or pair.get('live_state_authenticated') is not False
            or type(member) is not dict or type(stage_context) is not dict
            or stage_context.get('schema') != STAGE_SCHEMA
            or stage_context.get('training_only') is not True):
        raise ValueError('exact heldout pair view required')
    variant = case['target'].get('variant')
    target_row, other_row = _row_index(receipt, variant)
    if (_public_certificate(target_row) != case.get('target')
            or _public_certificate(other_row) != case.get('unrelated')
            or target_row['issuer_index'] != other_row['issuer_index']
            or case['frozen_cohort'].get('schema') != COHORT_SCHEMA
            or case['frozen_cohort'].get('freeze_sha256') != receipt.get('freeze_sha256')):
        raise ValueError('case identities differ from frozen cohort receipt')

    own_digest = hashlib.sha256(admit_certificate(raw['own'], int.from_bytes(raw['modulus'], 'big'))['tbs']).digest()
    other_digest = hashlib.sha256(admit_certificate(raw['other'], int.from_bytes(raw['modulus'], 'big'))['tbs']).digest()
    modulus = int.from_bytes(raw['modulus'], 'big')
    own, other = (admit_certificate(raw['own'], modulus), admit_certificate(raw['other'], modulus))
    issuer_hash, policy_hash = public_bindings(own, modulus)
    other_issuer, _ = public_bindings(other, modulus)
    expected_member = schedule.membership_for_pair(
        own_digest, other_digest, member.get('slot'))
    expected_member.update(issuer_hash=issuer_hash, policy_hash=policy_hash)
    allocation = stage_context.get('initial_allocations')
    pair_receipt_sha = hashlib.sha256(raw['pair']).hexdigest()
    member_sha = hashlib.sha256(raw['membership']).hexdigest()
    if (len(raw['own']) != 952 or len(raw['other']) != 952 or len(raw['modulus']) != 256
            or hashlib.sha256(raw['own']).hexdigest() != target_row['credential_sha256']
            or hashlib.sha256(raw['other']).hexdigest() != other_row['credential_sha256']
            or pair.get('credential_sha256') != hashlib.sha256(raw['own']).hexdigest()
            or pair.get('unrelated_credential_sha256') != hashlib.sha256(raw['other']).hexdigest()
            or pair.get('membership_sha256') != member_sha
            or case.get('pair_view', {}).get('cohort_receipt_sha256') != pair_receipt_sha
            or case.get('pair_view', {}).get('membership_sha256') != member_sha
            or hashlib.sha256(raw['stage_context']).hexdigest()
               != case.get('pair_view', {}).get('stage_context_sha256')
            or encoded(member) != encoded(expected_member)
            or case.get('membership', {}).get('slot') != member['slot']
            or case.get('membership', {}).get('unrelated_slot') != member['unrelated_slot']
            or case.get('membership', {}).get('R0') != f"{member['active_root']:064x}"
            or case.get('membership', {}).get('R1') != f"{member['unrelated_root']:064x}"
            or case.get('membership', {}).get('R2') != f"{member['own_revoked_root']:064x}"
            or issuer_hash != other_issuer or own['aki'] != other['aki']
            or issuer_hash != int(target_row['issuer_hash'])
            or policy_hash != int(target_row['policy_hash'])
            or _public_key_digest_from_modulus(modulus) != target_row['issuer_public_key_sha256']
            or _public_key_digest_from_modulus(own['holder_modulus']) != target_row['holder_public_key_sha256']
            or _public_key_digest_from_modulus(other['holder_modulus']) != other_row['holder_public_key_sha256']
            or allocation != {
                'own_tbs_digest': own_digest.hex(),
                'unrelated_tbs_digest': other_digest.hex(),
                'slot': member['slot'], 'allocation_epoch': 1,
                'cohort_receipt_sha256': pair_receipt_sha,
                'membership_sha256': member_sha,
            }
            or stage_context.get('root') != f"{member['active_root']:064x}"
            or stage_context.get('issuer_hash') != f'{issuer_hash:064x}'
            or stage_context.get('policy_id') != f'{policy_hash:064x}'
            or stage_context.get('aki') != (own['aki'] + bytes(12)).hex()
            or stage_context.get('not_before') != own['not_before']
            or stage_context.get('not_after') != own['not_after']):
        raise ValueError('heldout pair, receipt, membership, and stage context differ')
    return case, member, stage_context, own_digest.hex(), other_digest.hex(), pair_receipt_sha, member_sha


def _action_hash(plan, config, request):
    if (len(config) != 381 or config[:8] != b'DYNCONF3'
            or len(request) != 2249 or request[:8] != b'DYNREQ03'):
        raise ValueError('exact staged v3 account bytes required')
    program = _bytes32(plan.get('program'), 'program')
    genesis = _bytes32(plan.get('genesis'), 'genesis')
    if (config[104:136] != genesis or config[136:168] != _bytes32(plan.get('policy_id'), 'policy_id')
            or config[172:204] == bytes(32) or config[332:364] != _bytes32(plan.get('root'), 'root')):
        raise ValueError('staged config differs from pinned plan')
    creator = _bytes32(plan.get('creator'), 'creator')
    nonce = _bytes32(plan.get('nonce'), 'nonce')
    recipient = _bytes32(plan.get('recipient'), 'recipient')
    issuer_hash = _bytes32(plan.get('issuer_hash'), 'issuer_hash')
    if (request[40:72] != creator or request[72:104] != nonce
            or request[104:136] != issuer_hash or request[136:168] != recipient
            or int.from_bytes(request[168:170], 'big') != 1
            or request[183] != 1 or not 2 <= request[184] <= 16):
        raise ValueError('finalized request identity differs from plan')
    payload_len = int.from_bytes(request[178:180], 'big')
    if (payload_len > 1024 or int.from_bytes(request[180:182], 'big') != payload_len
            or request[182] != request[184]):
        raise ValueError('complete finalized request required')
    payload = request[1225:1225 + payload_len]
    if (payload != bytes(plan.get('payload', []))
            or int.from_bytes(request[170:178], 'big', signed=True) != plan.get('deadline')):
        raise ValueError('staged request payload or deadline differs from plan')
    metas = []
    for index in range(request[184]):
        start = 185 + index * 65
        key, flags = request[start:start + 32], request[start + 32]
        if flags > 3:
            raise ValueError('invalid finalized request meta flags')
        metas.extend((key, bytes([flags])))
    preimage = (
        b'DYNARK-WORK-REQUEST\x02' + genesis + program + request[8:40]
        + config[136:168] + config[168:172] + config[172:204] + nonce + recipient
        + request[168:170] + payload_len.to_bytes(4, 'big')
        + hashlib.sha256(payload).digest() + bytes([request[184]])
        + b''.join(metas) + request[170:178]
    )
    return (int.from_bytes(hashlib.sha256(preimage).digest(), 'big') % FR).to_bytes(32, 'big')


def prepare_transition(case_root, stage_root, output_path):
    """Pin a heldout pair to one finalized local R0 stage for R0->R1 refresh."""
    case_root, stage_root, output_path = Path(case_root), Path(stage_root), Path(output_path)
    case, member, stage_context, own_digest, other_digest, pair_sha, member_sha = _check_case_pair(case_root)
    issuance._directory(stage_root)
    report_path, plan_path = stage_root / 'stage-report.json', stage_root / 'plan.json'
    report_raw = issuance._read(report_path, 65536)
    plan_raw = issuance._read(plan_path, 8192)
    report, plan = issuance.decode_parameters(report_raw), issuance.decode_parameters(plan_raw)
    report_sha, plan_sha = hashlib.sha256(report_raw).hexdigest(), hashlib.sha256(plan_raw).hexdigest()
    if (type(report) is not dict or report.get('schema') != 'part5-v3-local-stage-v1'
            or report.get('passed') is not True or report.get('training_only') is not True
            or report.get('proof_created') is not False or report.get('application_effect') is not False
            or report.get('devnet') is not False
            or report.get('upstream_source_authentication') is not True
            or report.get('upstream_publisher_authentication') is not True
            or report.get('registry_history_authenticated') is not True
            or report.get('allocation_history_authenticated') is not True
            or report.get('plan_sha256') != plan_sha
            or type(report.get('finalized_slot')) is not int or report['finalized_slot'] <= 0
            or not isinstance(report.get('account_sha256'), list)
            or len(report['account_sha256']) != 5):
        raise ValueError('authenticated finalized local R0 stage report required')
    account_names = ('config.bin', 'issuer.bin', 'head.bin', 'request.bin', 'queue.bin')
    account_caps = (381, 374, 280, 2249, 2090)
    account_raw = [issuance._read(stage_root / name, cap)
                   for name, cap in zip(account_names, account_caps)]
    if [hashlib.sha256(raw).hexdigest() for raw in account_raw] != report['account_sha256']:
        raise ValueError('stage account files differ from finalized report pins')
    config, issuer_account, head, request, queue = account_raw
    history_raw = issuance._read(stage_root / 'signed-history.json', 65536)
    allocations_raw = issuance._read(stage_root / 'initial-allocations.json', 8192)
    plan_root = _bytes32(plan.get('root'), 'root')
    plan_issuer = _bytes32(plan.get('issuer_hash'), 'issuer_hash')
    plan_policy = _bytes32(plan.get('policy_id'), 'policy_id')
    plan_aki = _bytes32(plan.get('aki'), 'aki')
    # AKI itself is independently bound by the stage context produced from admitted DER.
    expected_aki = bytes.fromhex(stage_context['aki'])
    initial_allocations = issuance.decode_parameters(allocations_raw)
    account_addresses = [report.get(name) for name in ('config', 'issuer', 'head', 'request', 'queue')]
    if (plan_root.hex() != case['membership']['R0']
            or plan_issuer.hex() != stage_context['issuer_hash']
            or plan_policy.hex() != stage_context['policy_id']
            or plan_aki != expected_aki
            or config[332:364] != plan_root or config[136:168] != plan_policy
            or config[104:136] != _bytes32(plan.get('genesis'), 'genesis')
            or int.from_bytes(config[168:172], 'big') <= 0
            or int.from_bytes(config[364:372], 'big') != 0
            or config[380] != 1
            or issuer_account[:8] != b'DYNISS03'
            or issuer_account[40:72] != plan_issuer
            or issuer_account[108:140] != plan_aki
            or issuer_account[172] != 1
            or int.from_bytes(issuer_account[173:181], 'big') <= 0
            or issuer_account[357] != 1
            or issuer_account[229:261] != plan_root
            or int.from_bytes(issuer_account[261:269], 'big') != 0
            or head[:8] != b'DYNHEAD3'
            or head[176:208] != plan_root or int.from_bytes(head[208:216], 'big') != 0
            or int.from_bytes(head[216:224], 'big') != int.from_bytes(issuer_account[173:181], 'big')
            or head[224:256] != issuer_account[181:213]
            or report.get('source_head_digest') != issuer_account[181:213].hex()
            or report.get('publisher_envelope_digest') != head[112:144].hex()
            or report.get('signed_history_sha256') != hashlib.sha256(history_raw).hexdigest()
            or report.get('initial_allocations_sha256') != hashlib.sha256(allocations_raw).hexdigest()
            or initial_allocations != stage_context.get('initial_allocations')
            or any(type(address) is not str or len(_b58decode(address)) != 32
                   for address in account_addresses)
            or request[8:40] != _b58decode(report.get('config'))
            or report.get('genesis') != _base58(_bytes32(plan.get('genesis'), 'genesis'))
            or report.get('program') != _base58(_bytes32(plan.get('program'), 'program'))
            or len(queue) != 2090 or queue[:8] != b'DYNQUE03'):
        raise ValueError('stage plan or finalized R0 account identity mismatch')
    action = _action_hash(plan, config, request)
    transition = {
        'schema': 'part5-v3-unrelated-training-transition-v1',
        'training_only': True,
        'stage_report_sha256': report_sha,
        'cohort_receipt_sha256': pair_sha,
        'membership_sha256': member_sha,
        'own_tbs_digest': own_digest,
        'unrelated_tbs_digest': other_digest,
        'slot': member['slot'],
        'unrelated_slot': member['unrelated_slot'],
        'base_root': f"{member['active_root']:064x}",
        'near_root': f"{member['unrelated_root']:064x}",
    }
    if (not output_path.is_absolute() or output_path.exists() or output_path.is_symlink()
            or output_path.parent.resolve(strict=True) / output_path.name != output_path
            or not keys._ignored(output_path)):
        raise ValueError('fresh canonical ignored transition context required')
    issuance._directory(output_path.parent)
    transition_raw = encoded(transition)
    issuance._write(output_path, transition_raw)
    return {
        'schema': 'credential-v3-heldout-transition-context-preparation-v1',
        'transition_context_sha256': hashlib.sha256(transition_raw).hexdigest(),
        'stage_report_sha256': report_sha,
        'stage_plan_sha256': plan_sha,
        'cohort_receipt_sha256': pair_sha,
        'membership_sha256': member_sha,
        'action_hash': action.hex(),
        'base_root': transition['base_root'],
        'near_root': transition['near_root'],
        'live_state_authenticated': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', type=Path)
    parser.add_argument('--cohort-sha256')
    parser.add_argument('--variant', type=int)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--case-root', type=Path)
    parser.add_argument('--stage-root', type=Path)
    parser.add_argument('--transition-output', type=Path)
    args = parser.parse_args()
    case_mode = (args.case_root, args.stage_root, args.transition_output)
    cohort_mode = (args.cohort, args.cohort_sha256, args.variant, args.output)
    if any(value is not None for value in case_mode):
        if not all(value is not None for value in case_mode) or any(value is not None for value in cohort_mode):
            parser.error('transition mode requires --case-root, --stage-root, and --transition-output only')
        operation = lambda: prepare_transition(*case_mode)
    else:
        if not all(value is not None for value in cohort_mode):
            parser.error('case mode requires --cohort, --cohort-sha256, --variant, and --output')
        operation = lambda: prepare(*cohort_mode)
    try:
        result = operation()
    except Exception:
        raise SystemExit('heldout context preparation rejected') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
