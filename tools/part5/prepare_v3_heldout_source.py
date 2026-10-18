#!/usr/bin/env python3
"""Prepare one private heldout R0 or R1 request-bound source.

This consumes a frozen eight-certificate cohort, one independently checked
target/unrelated pair view, and the local two-leaf stage/transition reports.
Rust's V3F1-to-V3F2 exporter finalizes the request action. The generic native
helper then builds the request-bound V3Q1 and witness inputs; this tool never
creates a proof or claims live account authentication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
import types

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import generate_v3_heldout_keys as keygen
from tools.part5 import prepare_v3_request_fixture as bridge
from tools.part5 import prepare_v3_revocation_cohort as pair_schedule
from tools.part5.credential_profile import admit_certificate, public_bindings

SCHEMA = 'credential-v3-heldout-request-source-v1'
COHORT_SCHEMA = 'credential-v3-heldout-issuance-cohort-v1'
CASE_SCHEMA = 'credential-v3-heldout-case-context-v1'
PAIR_SCHEMA = 'v3-two-signed-training-credentials-v1'
STAGE_SCHEMA = 'part5-v3-local-stage-v1'
TRANSITION_SCHEMA = 'part5-v3-unrelated-local-transition-v1'
SUPPORT = REPO / 'crates/dynark-native-client/tests/support'
PREPARER = SUPPORT / 'prepare_v3_request_bound_training.py'
PREPARER_SHA256 = 'de37e94a4319c34439fe656aba702a05a1469fc08940113b4012289a8f8bfe19'
BRIDGE_SHA256 = '2b97cd1e02174ff67203f4b107923501a20b5d24bf11de03f204b77980f5691f'
ARTIFACT_LIMITS = {
    'request.bin': 1918, 'summary.bin': 459, 'input.json': 65536,
    'public.json': 1024, 'input-coordinates.bin': 4096,
    'internal-coordinate.bin': 4, 'training-receipt.json': 8192,
}
ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def private_dir(path, *, empty=False):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or (empty and any(path.iterdir()))):
        raise ValueError('canonical owner0700 directory required')
    return path


def _read(path, cap, *, private=True, expected=None):
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > cap
            or before.st_nlink != 1 or before.st_uid != os.getuid()
            or (private and stat.S_IMODE(before.st_mode) != 0o600)):
        raise ValueError('bounded single-link source file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError('source changed at open')
        raw = stream.read(cap + 1)
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError('source changed during read')
    if (len(raw) != before.st_size or _identity(path.lstat()) != _identity(before)
            or (expected is not None and digest(raw) != expected)):
        raise ValueError('source changed or digest mismatch')
    return raw


def _json(raw):
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def _hash(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _bytes(value, width=32):
    if (type(value) is not list or len(value) != width
            or any(type(part) is not int or not 0 <= part <= 255 for part in value)):
        raise ValueError('canonical plan byte array required')
    return bytes(value)


def spki_fingerprint(key):
    public = key.public_key()
    if (not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048
            or public.public_numbers().e != 65537 or public.public_numbers().n.bit_length() != 2048):
        raise ValueError('RSA-2048/e65537 private key required')
    der = public.public_bytes(serialization.Encoding.DER,
                              serialization.PublicFormat.SubjectPublicKeyInfo)
    return digest(der)


def _load_key(raw):
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
        raise ValueError('bounded RSA private key required')
    if key.public_key().public_numbers().e != 65537:
        raise ValueError('RSA exponent 65537 required')
    return key


def load_preparer():
    raw = _read(PREPARER, 131072, private=False, expected=PREPARER_SHA256)
    module = types.ModuleType('heldout_request_bound_preparer')
    module.__file__ = str(PREPARER)
    exec(compile(raw, str(PREPARER), 'exec'), module.__dict__)
    _read(REPO / 'tools/part5/prepare_v3_request_fixture.py', 131072,
          private=False, expected=BRIDGE_SHA256)
    return module


def _validate_cohort(cohort_root, case_root, freeze_path, freeze_sha256, snapshots, started):
    freeze_raw = _read(freeze_path, 65536, expected=freeze_sha256)
    snapshots[Path(freeze_path)] = (freeze_raw, 65536, True)
    _, boundary = keygen._freeze(freeze_path, freeze_sha256, started)
    if (boundary.get('schema') != keygen.FREEZE_SCHEMA
            or type(boundary.get('frozen_at_unix_ns')) is not int
            or boundary['frozen_at_unix_ns'] <= 0):
        raise ValueError('exact frozen heldout boundary required')

    cohort_raw = _read(cohort_root / 'cohort-receipt.json', 65536)
    snapshots[cohort_root / 'cohort-receipt.json'] = (cohort_raw, 65536, True)
    cohort = _json(cohort_raw)
    case_cohort_raw = _read(case_root / 'heldout-cohort-receipt.json', 65536)
    snapshots[case_root / 'heldout-cohort-receipt.json'] = (case_cohort_raw, 65536, True)
    if case_cohort_raw != cohort_raw:
        raise ValueError('case pair view differs from full heldout cohort receipt')
    rows = cohort.get('certificates')
    if (cohort.get('schema') != COHORT_SCHEMA
            or cohort.get('status') != 'cohort_issued_pending_application_gate'
            or cohort.get('keys_generated_after_freeze') is not True
            or cohort.get('freeze_sha256') != freeze_sha256
            or cohort.get('frozen_at_unix_ns') != boundary['frozen_at_unix_ns']
            or type(cohort.get('generation_started_unix_ns')) is not int
            or cohort['generation_started_unix_ns'] <= boundary['frozen_at_unix_ns']
            or type(cohort.get('generation_completed_unix_ns')) is not int
            or cohort['generation_completed_unix_ns'] < cohort['generation_started_unix_ns']
            or cohort.get('counts') != {'issuers': 4, 'holders': 8, 'certificates': 8,
                                        'openssl_issuances': 4, 'policies': 2}
            or type(rows) is not list or len(rows) != 8):
        raise ValueError('pinned post-freeze eight-certificate cohort required')
    by_variant = {}
    holders, issuers = set(), set()
    issuer_keys, holder_keys, policies = {}, set(), set()
    for row in rows:
        if type(row) is not dict:
            raise ValueError('heldout certificate receipt rows required')
        variant, issuer_index, holder_index = (row.get('variant'), row.get('issuer_index'),
                                               row.get('holder_index'))
        if (type(variant) is not int or variant in by_variant or not 0 <= variant < 8
                or type(issuer_index) is not int or not 0 <= issuer_index < 4
                or type(holder_index) is not int or not 0 <= holder_index < 8
                or holder_index in holders):
            raise ValueError('unique heldout variant and key indexes required')
        for field in ('credential_sha256', 'tbs_sha256', 'issuer_public_key_sha256',
                      'holder_public_key_sha256', 'aki_sha256'):
            if not _hash(row.get(field)):
                raise ValueError('heldout certificate fingerprints required')
        if row.get('encoder') not in ('openssl', 'cryptography'):
            raise ValueError('pinned certificate encoder required')
        if type(row.get('issuer_hash')) is not str or not row['issuer_hash'].isdecimal():
            raise ValueError('issuer field hash required')
        if type(row.get('policy_hash')) is not str or not row['policy_hash'].isdecimal():
            raise ValueError('policy field hash required')
        if (type(row.get('not_before_unix')) is not int
                or type(row.get('not_after_unix')) is not int
                or not 0 <= row['not_before_unix'] < row['not_after_unix']):
            raise ValueError('bounded certificate validity required')
        if issuer_index in issuer_keys and issuer_keys[issuer_index] != row['issuer_public_key_sha256']:
            raise ValueError('issuer index fingerprint changed')
        by_variant[variant] = row
        issuer_keys[issuer_index] = row['issuer_public_key_sha256']
        holders.add(holder_index)
        issuers.add(issuer_index)
        holder_keys.add(row['holder_public_key_sha256'])
        policies.add(row['policy_hash'])
    if (set(by_variant) != set(range(8)) or issuers != set(range(4))
            or holders != set(range(8)) or len(holder_keys) != 8
            or len(set(issuer_keys.values())) != 4 or len(policies) != 2
            or sum(row.get('encoder') == 'openssl' for row in rows) < 4
            or sum(row.get('encoder') == 'openssl' for row in rows)
               != cohort['counts']['openssl_issuances']):
        raise ValueError('four-issuer/eight-holder profile and encoder coverage required')

    case_raw = _read(case_root / 'case-context.json', 16384)
    snapshots[case_root / 'case-context.json'] = (case_raw, 16384, True)
    context = _json(case_raw)
    case_pair_raw = _read(case_root / 'cohort-receipt.json', 8192)
    snapshots[case_root / 'cohort-receipt.json'] = (case_pair_raw, 8192, True)
    pair = _json(case_pair_raw)
    member_raw = _read(case_root / 'membership.json', 16384)
    snapshots[case_root / 'membership.json'] = (member_raw, 16384, True)
    member = _json(member_raw)
    stage_context_raw = _read(case_root / 'stage-context.json', 8192)
    snapshots[case_root / 'stage-context.json'] = (stage_context_raw, 8192, True)
    stage_context = _json(stage_context_raw)
    cohort_sha = digest(cohort_raw)
    member_sha = digest(member_raw)
    pair_sha = digest(case_pair_raw)
    target = context.get('target')
    unrelated = context.get('unrelated')
    frozen = context.get('frozen_cohort')
    pair_pin = context.get('pair_view')
    if (context.get('schema') != CASE_SCHEMA or context.get('heldout_acceptance') is not False
            or context.get('authenticated') != {
                'registry_history': False, 'live_state': False,
                'current_head': False, 'finalized_account_batch': False}
            or frozen != {'schema': COHORT_SCHEMA, 'freeze_sha256': freeze_sha256,
                          'cohort_receipt_sha256': cohort_sha}
            or type(target) is not dict or type(unrelated) is not dict
            or type(pair_pin) is not dict
            or pair_pin.get('cohort_receipt_sha256') != pair_sha
            or pair_pin.get('membership_sha256') != member_sha
            or pair_pin.get('stage_context_sha256') != digest(stage_context_raw)):
        raise ValueError('heldout pair context does not pin frozen cohort')
    target_variant, unrelated_variant = target.get('variant'), unrelated.get('variant')
    if (type(target_variant) is not int or target_variant not in by_variant
            or type(unrelated_variant) is not int or unrelated_variant not in by_variant
            or target_variant == unrelated_variant):
        raise ValueError('heldout target and unrelated variants required')
    target_row, unrelated_row = by_variant[target_variant], by_variant[unrelated_variant]
    if (target != {key: target_row[key] for key in (
            'variant', 'issuer_index', 'holder_index', 'credential_sha256', 'tbs_sha256',
            'issuer_public_key_sha256', 'holder_public_key_sha256', 'issuer_hash', 'policy_hash',
            'aki_sha256', 'not_before_unix', 'not_after_unix')}
            or unrelated != {key: unrelated_row[key] for key in (
                'variant', 'issuer_index', 'holder_index', 'credential_sha256', 'tbs_sha256',
                'issuer_public_key_sha256', 'holder_public_key_sha256', 'issuer_hash', 'policy_hash',
                'aki_sha256', 'not_before_unix', 'not_after_unix')}
            or target_row['issuer_index'] != unrelated_row['issuer_index']
            or target_row['issuer_public_key_sha256'] != unrelated_row['issuer_public_key_sha256']):
        raise ValueError('heldout pair target identity differs from frozen cohort')

    target_path = cohort_root / f"certificate-{target_variant:02d}" / 'credential.der'
    other_path = cohort_root / f"certificate-{unrelated_variant:02d}" / 'credential.der'
    target_der = _read(target_path, 952)
    other_der = _read(other_path, 952)
    snapshots[target_path] = (target_der, 952, True)
    snapshots[other_path] = (other_der, 952, True)
    pair_der = _read(case_root / 'credential.der', 952)
    pair_other = _read(case_root / 'unrelated.der', 952)
    snapshots[case_root / 'credential.der'] = (pair_der, 952, True)
    snapshots[case_root / 'unrelated.der'] = (pair_other, 952, True)
    if (len(target_der) != 952 or len(other_der) != 952 or pair_der != target_der
            or pair_other != other_der or digest(target_der) != target_row['credential_sha256']
            or digest(other_der) != unrelated_row['credential_sha256']
            or pair.get('schema') != PAIR_SCHEMA or pair.get('training_only') is not True
            or pair.get('heldout_acceptance') is not False
            or pair.get('allocation_authorized') is not False
            or pair.get('registry_history_authenticated') is not False
            or pair.get('live_state_authenticated') is not False
            or pair.get('credential_sha256') != digest(target_der)
            or pair.get('unrelated_credential_sha256') != digest(other_der)
            or pair.get('membership_sha256') != member_sha):
        raise ValueError('heldout pair bytes differ from frozen cohort')

    issuer_index, holder_index = target_row['issuer_index'], target_row['holder_index']
    other_holder_index = unrelated_row['holder_index']
    issuer_raw = _read(cohort_root / 'keys' / f'issuer-{issuer_index}.pem', 4096)
    holder_raw = _read(cohort_root / 'keys' / f'holder-{holder_index}.pem', 4096)
    other_holder_raw = _read(cohort_root / 'keys' / f'holder-{other_holder_index}.pem', 4096)
    snapshots[cohort_root / 'keys' / f'issuer-{issuer_index}.pem'] = (issuer_raw, 4096, True)
    snapshots[cohort_root / 'keys' / f'holder-{holder_index}.pem'] = (holder_raw, 4096, True)
    snapshots[cohort_root / 'keys' / f'holder-{other_holder_index}.pem'] = (other_holder_raw, 4096, True)
    pair_holder_raw = _read(case_root / 'holder.pem', 4096)
    modulus_raw = _read(case_root / 'issuer-modulus.bin', 256)
    snapshots[case_root / 'holder.pem'] = (pair_holder_raw, 4096, True)
    snapshots[case_root / 'issuer-modulus.bin'] = (modulus_raw, 256, True)
    issuer_key, holder_key, other_holder_key = map(_load_key,
                                                   (issuer_raw, holder_raw, other_holder_raw))
    if (pair_holder_raw != holder_raw or len(modulus_raw) != 256
            or spki_fingerprint(issuer_key) != target_row['issuer_public_key_sha256']
            or spki_fingerprint(holder_key) != target_row['holder_public_key_sha256']
            or spki_fingerprint(other_holder_key) != unrelated_row['holder_public_key_sha256']
            or issuer_key.public_key().public_numbers().n.to_bytes(256, 'big') != modulus_raw):
        raise ValueError('heldout pair private/public key identity mismatch')
    modulus = int.from_bytes(modulus_raw, 'big')
    parsed = admit_certificate(target_der, modulus)
    other_parsed = admit_certificate(other_der, modulus)
    issuer_hash, policy_hash = public_bindings(parsed, modulus)
    other_issuer, _ = public_bindings(other_parsed, modulus)
    if (parsed.get('variant') != target_variant or other_parsed.get('variant') != unrelated_variant
            or digest(parsed['tbs']) != target_row['tbs_sha256']
            or digest(other_parsed['tbs']) != unrelated_row['tbs_sha256']
            or digest(parsed['aki']) != target_row['aki_sha256']
            or digest(other_parsed['aki']) != unrelated_row['aki_sha256']
            or parsed['not_before'] != target_row['not_before_unix']
            or parsed['not_after'] != target_row['not_after_unix']
            or other_parsed['not_before'] != unrelated_row['not_before_unix']
            or other_parsed['not_after'] != unrelated_row['not_after_unix']
            or parsed['holder_modulus'] != holder_key.public_key().public_numbers().n
            or other_parsed['holder_modulus'] != other_holder_key.public_key().public_numbers().n
            or issuer_hash != other_issuer or issuer_hash != int(target_row['issuer_hash'])
            or policy_hash != int(target_row['policy_hash'])
            or int(unrelated_row['issuer_hash']) != issuer_hash
            or member.get('issuer_hash') != issuer_hash or member.get('policy_hash') != policy_hash
            or pair.get('issuer_hash') != str(issuer_hash) or pair.get('policy_hash') != str(policy_hash)):
        raise ValueError('heldout DER, issuer, holder or signed profile mismatch')

    own_digest = hashlib.sha256(parsed['tbs']).digest()
    other_digest = hashlib.sha256(other_parsed['tbs']).digest()
    expected_membership = pair_schedule.membership_for_pair(
        own_digest, other_digest, int.from_bytes(own_digest[:2], 'big') & 1023)
    expected_membership.update(issuer_hash=issuer_hash, policy_hash=policy_hash)
    if member != expected_membership:
        raise ValueError('heldout pair membership roots and paths do not rebuild')
    membership_context = context.get('membership')
    expected_roots = {
        'R0': f"{expected_membership['active_root']:064x}",
        'R1': f"{expected_membership['unrelated_root']:064x}",
        'R2': f"{expected_membership['own_revoked_root']:064x}",
    }
    if (type(membership_context) is not dict
            or any(membership_context.get(name) != root for name, root in expected_roots.items())
            or membership_context.get('slot') != expected_membership['slot']
            or membership_context.get('unrelated_slot') != expected_membership['unrelated_slot']
            or membership_context.get('active_siblings') != expected_membership['active_siblings']
            or membership_context.get('unrelated_siblings') != expected_membership['unrelated_siblings']
            or membership_context.get('own_revoked_siblings') != expected_membership['own_revoked_siblings']):
        raise ValueError('heldout case context roots differ from independent pair tree')

    expected_pair_sha = pair_sha
    stage_context = _json(stage_context_raw)
    expected_stage_context = {
        'schema': 'part5-v3-local-training-context-v1', 'training_only': True,
        'root': expected_roots['R0'], 'issuer_hash': f'{issuer_hash:064x}',
        'policy_id': f'{policy_hash:064x}', 'aki': (parsed['aki'] + bytes(12)).hex(),
        'evidence_digest': hashlib.sha256(
            b'credential-v3-heldout-case-evidence/v1\0' + bytes.fromhex(cohort_sha)
            + bytes.fromhex(target_row['credential_sha256'])
            + bytes.fromhex(unrelated_row['credential_sha256'])).hexdigest(),
        'not_before': parsed['not_before'], 'not_after': parsed['not_after'],
        'initial_allocations': {
            'own_tbs_digest': own_digest.hex(), 'unrelated_tbs_digest': other_digest.hex(),
            'slot': expected_membership['slot'], 'allocation_epoch': 1,
            'cohort_receipt_sha256': expected_pair_sha, 'membership_sha256': member_sha,
        },
    }
    if stage_context != expected_stage_context:
        raise ValueError('heldout stage context differs from independently admitted pair')

    return {
        'freeze_raw': freeze_raw, 'boundary': boundary,
        'cohort_raw': cohort_raw, 'cohort': cohort, 'cohort_sha256': cohort_sha,
        'case_raw': case_raw, 'context': context, 'case_sha256': digest(case_raw),
        'pair_raw': case_pair_raw, 'pair_sha256': pair_sha,
        'stage_context_raw': stage_context_raw, 'stage_context': stage_context,
        'stage_context_sha256': digest(stage_context_raw),
        'target_row': target_row, 'unrelated_row': unrelated_row,
        'target_der': target_der, 'unrelated_der': other_der, 'parsed': parsed,
        'membership_raw': member_raw, 'membership': expected_membership,
        'membership_sha256': member_sha, 'roots': expected_roots,
        'modulus_raw': modulus_raw, 'holder_raw': holder_raw,
        'issuer_hash': issuer_hash, 'policy_hash': policy_hash,
        'snapshots': snapshots,
    }


def _stage_evidence(stage_root, case, snapshots):
    def read(path, cap):
        raw = _read(path, cap)
        snapshots[path] = (raw, cap, True)
        return raw

    report_raw = read(stage_root / 'stage-report.json', 65536)
    report = _json(report_raw)
    plan_raw = read(stage_root / 'plan.json', 8192)
    plan = _json(plan_raw)
    history_raw = read(stage_root / 'signed-history.json', 1024 * 1024)
    allocations_raw = read(stage_root / 'initial-allocations.json', 8192)
    allocations = _json(allocations_raw)
    if (report.get('schema') != STAGE_SCHEMA or report.get('passed') is not True
            or report.get('training_only') is not True
            or report.get('registry_history_authenticated') is not True
            or report.get('allocation_history_authenticated') is not True
            or report.get('proof_created') is not False or report.get('application_effect') is not False
            or report.get('plan_sha256') != digest(plan_raw)
            or report.get('signed_history_sha256') != digest(history_raw)
            or report.get('initial_allocations_sha256') != digest(allocations_raw)
            or allocations != case['stage_context']['initial_allocations']
            or type(report.get('account_sha256')) is not list
            or len(report['account_sha256']) != len(ACCOUNT_NAMES)):
        raise ValueError('pinned local heldout stage evidence required')
    accounts = []
    for name, expected in zip(ACCOUNT_NAMES, report['account_sha256']):
        if not _hash(expected):
            raise ValueError('stage account digests required')
        data = read(stage_root / (name + '.bin'), 4096)
        if digest(data) != expected:
            raise ValueError('staged local account snapshot differs from report')
        accounts.append(data)
    if (len(accounts[0]) != 381 or accounts[0][:8] != b'DYNCONF3'
            or accounts[0][332:364].hex() != case['roots']['R0']
            or int.from_bytes(accounts[0][364:372], 'little') != 0
            or len(accounts[3]) != 2249
            or accounts[3][:8] != b'DYNREQ03'):
        raise ValueError('bounded finalized staged request required')
    if (_bytes(plan.get('root')) != int(case['roots']['R0'], 16).to_bytes(32, 'big')
            or _bytes(plan.get('issuer_hash')) != case['issuer_hash'].to_bytes(32, 'big')
            or _bytes(plan.get('policy_id')) != case['policy_hash'].to_bytes(32, 'big')
            or type(plan.get('deadline')) is not int
            or type(plan.get('payload')) is not list
            or any(type(value) is not int or not 0 <= value <= 255 for value in plan['payload'])):
        raise ValueError('heldout stage plan differs from target and R0 root')
    transactions = report.get('transactions')
    bind = next((row for row in reversed(transactions or [])
                 if type(row) is dict and row.get('scenario') == 'v3-bind-head'), None)
    now = bind.get('blockTime') if bind else None
    if (type(now) is not int or not case['parsed']['not_before'] <= now < case['parsed']['not_after']
            or now >= plan['deadline']):
        raise ValueError('staged request clock is outside the heldout certificate or deadline')
    return {'report_raw': report_raw, 'report': report, 'plan_raw': plan_raw,
            'plan': plan, 'history_raw': history_raw, 'accounts': accounts, 'now': now}


def _variant_evidence(variant, stage, transition_root, case, snapshots):
    if variant == 'R0':
        return stage['accounts'][0], stage['accounts'][3], None, None
    if variant != 'R1' or transition_root is None:
        raise ValueError('R0 or R1 source variant required')
    transition_root = private_dir(transition_root)

    def read(path, cap):
        raw = _read(path, cap)
        snapshots[path] = (raw, cap, True)
        return raw

    raw_report = read(transition_root / 'transition-report.json', 65536)
    report = _json(raw_report)
    history = read(transition_root / 'signed-history.json', 1024 * 1024)
    if (report.get('schema') != TRANSITION_SCHEMA or report.get('passed') is not True
            or report.get('training_only') is not True
            or report.get('request_unconsumed') is not True
            or report.get('upstream_source_authentication') is not True
            or report.get('application_effect') is not False
            or report.get('devnet') is not False
            or report.get('stage_report_sha256') != digest(stage['report_raw'])
            or report.get('stage_plan_sha256') != digest(stage['plan_raw'])
            or report.get('cohort_receipt_sha256') != case['pair_sha256']
            or report.get('membership_sha256') != case['membership_sha256']
            or report.get('base_root') != case['roots']['R0']
            or report.get('near_root') != case['roots']['R1']
            or report.get('signed_history_sha256') != digest(history)
            or type(report.get('account_sha256')) is not list
            or len(report['account_sha256']) != len(ACCOUNT_NAMES)):
        raise ValueError('pinned R1 unrelated-root transition evidence required')
    accounts = []
    for name, expected in zip(ACCOUNT_NAMES, report['account_sha256']):
        if not _hash(expected):
            raise ValueError('transition account digests required')
        data = read(transition_root / (name + '.bin'), 4096)
        if digest(data) != expected:
            raise ValueError('transition account snapshot differs from report')
        accounts.append(data)
    if (len(accounts[0]) != 381 or accounts[0][:8] != b'DYNCONF3'
            or accounts[0][332:364].hex() != case['roots']['R1']
            or int.from_bytes(accounts[0][364:372], 'big') != 1
            or accounts[3] != stage['accounts'][3] or accounts[4] != stage['accounts'][4]):
        raise ValueError('R1 transition must preserve request and queue under expected root')
    return accounts[0], accounts[3], raw_report, digest(raw_report)


def _transition_context(path, expected_sha256, stage, case, snapshots):
    if not isinstance(path, Path) or not _hash(expected_sha256):
        raise ValueError('R1 transition context and digest are required')
    raw = _read(path, 8192, expected=expected_sha256)
    snapshots[path] = (raw, 8192, True)
    value = _json(raw)
    if (value.get('schema') != 'part5-v3-unrelated-training-transition-v1'
            or value.get('training_only') is not True
            or value.get('stage_report_sha256') != digest(stage['report_raw'])
            or value.get('cohort_receipt_sha256') != case['pair_sha256']
            or value.get('membership_sha256') != case['membership_sha256']
            or value.get('own_tbs_digest') != case['target_row']['tbs_sha256']
            or value.get('unrelated_tbs_digest') != case['unrelated_row']['tbs_sha256']
            or value.get('slot') != case['membership']['slot']
            or value.get('unrelated_slot') != case['membership']['unrelated_slot']
            or value.get('base_root') != case['roots']['R0']
            or value.get('near_root') != case['roots']['R1']):
        raise ValueError('heldout R0-to-R1 transition context mismatch')
    return value, digest(raw)


def _write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _clear_output(output):
    for child in list(output.iterdir()):
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def _prepare(case_root, cohort_root, freeze_receipt, freeze_sha256, stage_root,
             exporter, variant, output, *, transition_root=None,
             r0_source_receipt=None, r0_source_receipt_sha256=None,
             transition_context=None, transition_context_sha256=None):
    """Create R0 or R1 private training artifacts and a scrubbed source receipt."""
    case_root, cohort_root, stage_root = map(private_dir, (case_root, cohort_root, stage_root))
    output = private_dir(output, empty=True)
    freeze_receipt, exporter = Path(freeze_receipt), Path(exporter)
    if (variant not in ('R0', 'R1') or not _hash(freeze_sha256)
            or output in (case_root, cohort_root, stage_root)
            or output in case_root.parents or output in cohort_root.parents
            or output in stage_root.parents):
        raise ValueError('canonical heldout source request required')
    identities = {path: _identity(path.lstat()) for path in
                  (case_root, cohort_root, stage_root)}
    output_identity = output.lstat()
    output_identity = (output_identity.st_dev, output_identity.st_ino,
                       output_identity.st_uid, output_identity.st_mode)
    snapshots = {}
    started = time.time_ns()
    case = _validate_cohort(cohort_root, case_root, freeze_receipt,
                            freeze_sha256, snapshots, started)
    stage = _stage_evidence(stage_root, case, snapshots)
    config, staged_request, transition_raw, transition_sha = _variant_evidence(
        variant, stage, transition_root, case, snapshots)
    if variant == 'R1':
        transition_context_value, transition_context_sha = _transition_context(
            transition_context, transition_context_sha256, stage, case, snapshots)
        if _json(transition_raw).get('transition_context_sha256') != transition_context_sha:
            raise ValueError('R1 transition report does not pin heldout transition context')
    else:
        if transition_context is not None or transition_context_sha256 is not None:
            raise ValueError('R0 does not consume a transition context')
        transition_context_value, transition_context_sha = None, None
    if variant == 'R1':
        if not isinstance(r0_source_receipt, Path) or not _hash(r0_source_receipt_sha256):
            raise ValueError('R1 source must pin the reviewed R0 source receipt')
        r0_raw = _read(r0_source_receipt, 16384, expected=r0_source_receipt_sha256)
        snapshots[r0_source_receipt] = (r0_raw, 16384, True)
        r0_receipt = _json(r0_raw)
        if (r0_receipt.get('schema') != SCHEMA or r0_receipt.get('variant') != 'R0'
                or r0_receipt.get('transition_report_sha256') is not None
                or r0_receipt.get('freeze_sha256') != freeze_sha256
                or r0_receipt.get('cohort_receipt_sha256') != case['cohort_sha256']
                or r0_receipt.get('case_context_sha256') != case['case_sha256']
                or r0_receipt.get('pair_receipt_sha256') != case['pair_sha256']
                or r0_receipt.get('context_sha256') != case['case_sha256']
                or r0_receipt.get('stage_context_sha256') != case['stage_context_sha256']
                or r0_receipt.get('membership_sha256') != case['membership_sha256']
                or r0_receipt.get('membership_roots') != case['roots']
                or r0_receipt.get('target_variant') != case['target_row']['variant']
                or r0_receipt.get('issuer_index') != case['target_row']['issuer_index']
                or r0_receipt.get('holder_index') != case['target_row']['holder_index']
                or r0_receipt.get('target_der_sha256') != case['target_row']['credential_sha256']
                or r0_receipt.get('target_tbs_sha256') != case['target_row']['tbs_sha256']
                or r0_receipt.get('issuer_public_key_sha256') != case['target_row']['issuer_public_key_sha256']
                or r0_receipt.get('holder_public_key_sha256') != case['target_row']['holder_public_key_sha256']
                or r0_receipt.get('stage_report_sha256') != digest(stage['report_raw'])
                or r0_receipt.get('stage_plan_sha256') != digest(stage['plan_raw'])
                or r0_receipt.get('selected_root') != case['roots']['R0']
                or r0_receipt.get('staged_request_sha256') != digest(staged_request)):
            raise ValueError('R1 source does not match pinned R0 case/request')
    else:
        r0_receipt, r0_source_receipt_sha256 = None, None

    info = exporter.lstat()
    if (not exporter.is_absolute() or exporter.resolve(strict=True) != exporter
            or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o022 or not info.st_mode & 0o111
            or not 0 < info.st_size <= 64 * 1024 * 1024):
        raise ValueError('pinned executable Rust exporter required')
    exporter_raw = _read(exporter, 64 * 1024 * 1024, private=False)
    snapshots[exporter] = (exporter_raw, 64 * 1024 * 1024, False)
    exporter_sha = digest(exporter_raw)

    row, membership = case['target_row'], case['membership']
    root_name, sibling_name = ('R0', 'active_siblings') if variant == 'R0' else ('R1', 'unrelated_siblings')
    source_membership = {
        'slot': membership['slot'], 'issuer_hash': case['issuer_hash'],
        'policy_hash': case['policy_hash'], 'active_root': int(case['roots'][root_name], 16),
        'active_siblings': membership[sibling_name],
    }
    plan = stage['plan']
    params = {
        'program_id': _bytes(plan.get('program')).hex(),
        'genesis': _bytes(plan.get('genesis')).hex(),
        'creator': _bytes(plan.get('creator')).hex(),
        'nonce': _bytes(plan.get('nonce')).hex(),
        'recipient': _bytes(plan.get('recipient')).hex(),
        'payload': bytes(plan['payload']).hex(), 'request_type': 1,
        'deadline': plan['deadline'], 'now': stage['now'], 'exporter_sha256': exporter_sha,
    }
    plan_wire = bridge.build_v3p1(
        case['target_der'], int.from_bytes(case['modulus_raw'], 'big'), source_membership,
        config_bytes=config, program_id=_bytes(plan['program']), creator=_bytes(plan['creator']),
        nonce=_bytes(plan['nonce']), recipient=_bytes(plan['recipient']), request_type=1,
        deadline=plan['deadline'], payload=bytes(plan['payload']), now=stage['now'])
    finalized = bridge.finalize_v3p1(plan_wire, exporter)
    if (finalized.get('exporter_sha256') != exporter_sha
            or finalized.get('v3f1', b'')[:4] != b'V3F1'
            or finalized.get('v3f2', b'')[:4] != b'V3F2'
            or len(finalized['v3f1']) != 2874 or len(finalized['v3f2']) != 561
            or finalized['v3f1'][625:] != staged_request
            or len(finalized['v3f2'][164:196]) != 32
            or int.from_bytes(finalized['v3f2'][164:196], 'big') >= FR):
        raise ValueError('Rust finalized request differs from staged account or action is noncanonical')
    action = finalized['v3f2'][164:196]
    if variant == 'R1' and (
            r0_receipt.get('action_hash') != action.hex()
            or r0_receipt.get('finalized_action_transport_sha256') != digest(finalized['v3f2'])):
        raise ValueError('R1 action differs from pinned R0 action')

    if not output.exists() or not output.is_dir():
        raise ValueError('fresh private source output required')
    source_dir, training_dir = output / 'source-input', output / 'training-output'
    source_dir.mkdir(mode=0o700)
    training_dir.mkdir(mode=0o700)
    for name, raw in {
        'credential.der': case['target_der'], 'holder.pem': case['holder_raw'],
        'issuer-modulus.bin': case['modulus_raw'], 'config.bin': config,
        'membership.json': encoded(source_membership), 'parameters.json': encoded(params),
    }.items():
        _write_new(source_dir / name, raw)
    helper = load_preparer()
    helper.prepare(source_dir, training_dir, exporter)
    training_receipt_raw = _read(training_dir / 'training-receipt.json', 8192)
    training_receipt = _json(training_receipt_raw)
    source_receipt_sha = digest(training_receipt_raw)
    if (training_receipt.get('schema') != 'v3-request-bound-training-input-v1'
            or training_receipt.get('training_only') is not True
            or training_receipt.get('live_state_authenticated') is not False
            or training_receipt.get('proof_created') is not False
            or training_receipt.get('complete_relation_checked') is not False
            or training_receipt.get('bridge_sha256') != helper.BRIDGE_SHA
            or training_receipt.get('worker_sha256') != helper.WORKER_SHA
            or training_receipt.get('exporter_sha256') != exporter_sha
            or training_receipt.get('config_sha256') != digest(config)
            or training_receipt.get('membership_sha256') != digest(encoded(source_membership))
            or training_receipt.get('parameters_sha256') != digest(encoded(params))
            or training_receipt.get('finalized_fixture_sha256') != digest(finalized['v3f1'])
            or training_receipt.get('finalized_action_transport_sha256') != digest(finalized['v3f2'])):
        raise ValueError('generic request-bound helper did not reproduce Rust finalized source')
    training_artifacts = {}
    for name, cap in ARTIFACT_LIMITS.items():
        raw = _read(training_dir / name, cap)
        snapshots[training_dir / name] = (raw, cap, True)
        training_artifacts[name] = raw
    if (training_artifacts['request.bin'][:4] != b'V3Q1'
            or len(training_artifacts['request.bin']) != 1918
            or type(training_receipt.get('artifact_sha256')) is not dict
            or any(training_receipt['artifact_sha256'].get(name) != digest(training_artifacts[name])
                   for name in ('request.bin', 'input.json', 'public.json'))):
        raise ValueError('generic request-bound training artifacts are incomplete')

    public_outputs = {
        'staged-request.bin': staged_request,
        'finalized-request.bin': finalized['v3f1'],
        'action-transport.bin': finalized['v3f2'],
    }
    artifact_hashes = {name: digest(raw) for name, raw in training_artifacts.items()}
    artifact_hashes.update({name: digest(raw) for name, raw in public_outputs.items()})
    receipt = {
        'schema': SCHEMA, 'freeze_sha256': freeze_sha256,
        'cohort_receipt_sha256': case['cohort_sha256'],
        'case_context_sha256': case['case_sha256'],
        'pair_receipt_sha256': case['pair_sha256'],
        'case_index': row['variant'], 'target_variant': row['variant'],
        'unrelated_variant': case['unrelated_row']['variant'],
        'issuer_index': row['issuer_index'], 'holder_index': row['holder_index'],
        'target_der_sha256': digest(case['target_der']),
        'target_tbs_sha256': digest(case['parsed']['tbs']),
        'unrelated_der_sha256': digest(case['unrelated_der']),
        'issuer_public_key_sha256': row['issuer_public_key_sha256'],
        'holder_public_key_sha256': row['holder_public_key_sha256'],
        'variant': variant,
        'stage_report_sha256': digest(stage['report_raw']),
        'stage_plan_sha256': digest(stage['plan_raw']),
        'transition_report_sha256': transition_sha,
        'transition_context_sha256': transition_context_sha,
        'context_sha256': case['case_sha256'],
        'stage_context_sha256': case['stage_context_sha256'],
        'membership_sha256': case['membership_sha256'],
        'membership_roots': case['roots'],
        'selected_root': case['roots'][root_name],
        'staged_request_sha256': digest(staged_request),
        'finalized_request_sha256': digest(finalized['v3f1']),
        'finalized_action_transport_sha256': digest(finalized['v3f2']),
        'action_hash': action.hex(), 'exporter_sha256': exporter_sha,
        'training_helper_sha256': PREPARER_SHA256,
        'training_receipt_sha256': source_receipt_sha,
        'artifacts_sha256': artifact_hashes,
        'proof_created': False, 'application_effect': False,
        'live_state_authenticated': False,
    }
    if variant == 'R1':
        receipt['r0_source_receipt_sha256'] = r0_source_receipt_sha256

    for path, (raw, cap, private) in snapshots.items():
        if _read(path, cap, private=private) != raw:
            raise ValueError('heldout source changed while building request')
    if digest(exporter.read_bytes()) != exporter_sha:
        raise ValueError('Rust exporter changed while finalizing request')
    for path, identity in identities.items():
        if _identity(path.lstat()) != identity:
            raise ValueError('heldout source or output directory changed')
    current_output = output.lstat()
    if ((current_output.st_dev, current_output.st_ino, current_output.st_uid,
         current_output.st_mode) != output_identity):
        raise ValueError('heldout output directory changed')

    # Publish only the training artifacts and public exporter transports. The
    # transient source-input directory contains the holder key and is removed.
    for name, raw in {**training_artifacts, **public_outputs}.items():
        _write_new(output / name, raw)
    shutil.rmtree(source_dir)
    shutil.rmtree(training_dir)
    receipt_raw = encoded(receipt)
    _write_new(output / 'source-receipt.json', receipt_raw)
    return receipt


def prepare(case_root, cohort_root, freeze_receipt, freeze_sha256, stage_root,
            exporter, variant, output, *, transition_root=None,
            r0_source_receipt=None, r0_source_receipt_sha256=None,
            transition_context=None, transition_context_sha256=None):
    """Prepare one source, scrubbing partial outputs after any failed run."""
    output = Path(output)
    cleanable = False
    identity = None
    try:
        info = output.lstat()
        cleanable = (output.is_absolute() and output.resolve(strict=True) == output
                     and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                     and stat.S_IMODE(info.st_mode) == 0o700 and not any(output.iterdir()))
        identity = (info.st_dev, info.st_ino)
    except OSError:
        pass
    try:
        return _prepare(case_root, cohort_root, freeze_receipt, freeze_sha256,
                        stage_root, exporter, variant, output,
                        transition_root=transition_root,
                        r0_source_receipt=r0_source_receipt,
                        r0_source_receipt_sha256=r0_source_receipt_sha256,
                        transition_context=transition_context,
                        transition_context_sha256=transition_context_sha256)
    except Exception:
        if cleanable:
            try:
                current = output.lstat()
                if (stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid()
                        and (current.st_dev, current.st_ino) == identity
                        and stat.S_IMODE(current.st_mode) == 0o700):
                    _clear_output(output)
            except OSError:
                pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('case-root', 'cohort-root', 'freeze-receipt', 'freeze-sha256',
                 'stage-root', 'exporter', 'variant', 'output'):
        parser.add_argument('--' + name, required=True, type=Path if name not in ('freeze-sha256', 'variant') else str)
    parser.add_argument('--transition-root', type=Path)
    parser.add_argument('--transition-context', type=Path)
    parser.add_argument('--transition-context-sha256')
    parser.add_argument('--r0-source-receipt', type=Path)
    parser.add_argument('--r0-source-receipt-sha256')
    args = parser.parse_args()
    try:
        result = prepare(
            case_root=args.case_root, cohort_root=args.cohort_root,
            freeze_receipt=args.freeze_receipt, freeze_sha256=args.freeze_sha256,
            stage_root=args.stage_root, exporter=args.exporter,
            variant=args.variant, output=args.output,
            transition_root=args.transition_root,
            transition_context=args.transition_context,
            transition_context_sha256=args.transition_context_sha256,
            r0_source_receipt=args.r0_source_receipt,
            r0_source_receipt_sha256=args.r0_source_receipt_sha256)
    except Exception:
        raise SystemExit('heldout request source preparation rejected') from None
    print(json.dumps({'schema': result['schema'], 'variant': result['variant'],
                      'source_receipt_sha256': digest(_read(args.output / 'source-receipt.json', 16384))},
                     sort_keys=True))


if __name__ == '__main__':
    main()
