#!/usr/bin/env python3
"""Bind the existing two-leaf training stage context to admitted cohort bytes.

Certificate admission and pure tree reconstruction grant no registry allocation,
source-history or chain authority. The harness must separately establish those
boundaries. This does not accept the eleven-leaf campaign cohort format.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.part5 import generate_v3_heldout_keys as keys
from tools.part5 import issue_v3_heldout_certificate as issuance
from tools.part5 import prepare_v3_revocation_cohort as schedule
from tools.part5.credential_profile import admit_certificate, public_bindings


def prepare(cohort, cohort_sha256, membership_sha256, context_path, context_sha256, frozen_root, output):
    issuance._directory(cohort)
    issuance._directory(output.parent)
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or output.parent.resolve(strict=True) / output.name != output or not keys._ignored(output)):
        raise ValueError('fresh canonical ignored context output required')
    files = {name: issuance._read(cohort / name, cap) for name, cap in (
        ('cohort-receipt.json', 8192), ('membership.json', 16384),
        ('credential.der', 952), ('unrelated.der', 952), ('issuer-modulus.bin', 256))}
    raw_context = issuance._read(context_path, 8192)
    digest = lambda raw: hashlib.sha256(raw).hexdigest()
    for raw, expected in [(files['cohort-receipt.json'], cohort_sha256),
                          (files['membership.json'], membership_sha256), (raw_context, context_sha256)]:
        if not keys._hash(expected) or digest(raw) != expected:
            raise ValueError('exact cohort/membership/context pins required')
    receipt = issuance.decode_parameters(files['cohort-receipt.json'])
    member = issuance.decode_parameters(files['membership.json'])
    context = issuance.decode_parameters(raw_context)
    if (type(receipt) is not dict or receipt.get('schema') != 'v3-two-signed-training-credentials-v1'
            or receipt.get('training_only') is not True
            or receipt.get('registry_history_authenticated') is not False
            or receipt.get('live_state_authenticated') is not False
            or receipt.get('credential_sha256') != digest(files['credential.der'])
            or receipt.get('unrelated_credential_sha256') != digest(files['unrelated.der'])
            or receipt.get('membership_sha256') != membership_sha256
            or len(files['issuer-modulus.bin']) != 256
            or type(member) is not dict or type(member.get('slot')) is not int
            or not 0 <= member['slot'] < 1024 or member.get('unrelated_slot') != member['slot'] ^ 1):
        raise ValueError('admitted two-leaf training cohort required')
    modulus = int.from_bytes(files['issuer-modulus.bin'], 'big')
    own = admit_certificate(files['credential.der'], modulus)
    other = admit_certificate(files['unrelated.der'], modulus)
    own_digest, other_digest = hashlib.sha256(own['tbs']).digest(), hashlib.sha256(other['tbs']).digest()
    if own_digest == other_digest:
        raise ValueError('distinct issuer-signed TBS required')
    rebuilt = schedule.membership_for_pair(own_digest, other_digest, member['slot'])
    issuer_hash, policy_hash = public_bindings(own, modulus)
    other_issuer, _ = public_bindings(other, modulus)
    if (other_issuer != issuer_hash or own['aki'] != other['aki']
            or json.dumps(member, sort_keys=True, separators=(',', ':')) != json.dumps(
                {**rebuilt, 'issuer_hash': issuer_hash, 'policy_hash': policy_hash},
                sort_keys=True, separators=(',', ':'))
            or member['own_tbs_digest'] != own_digest.hex()
            or member['unrelated_tbs_digest'] != other_digest.hex()
            or receipt.get('issuer_hash') != str(issuer_hash) or receipt.get('policy_hash') != str(policy_hash)):
        raise ValueError('cohort does not match independently admitted tree')
    if (not keys._hash(frozen_root) or frozen_root != f"{rebuilt['active_root']:064x}"
            or type(context) is not dict or set(context) != {'schema', 'training_only', 'root',
                'issuer_hash', 'policy_id', 'aki', 'evidence_digest', 'not_before', 'not_after'}
            or context['schema'] != 'part5-v3-local-training-context-v1' or context['training_only'] is not True
            or context['root'] != frozen_root or context['issuer_hash'] != f'{issuer_hash:064x}'
            or context['policy_id'] != f'{policy_hash:064x}' or context['aki'] != (own['aki'] + bytes(12)).hex()
            or type(context['not_before']) is not int or type(context['not_after']) is not int
            or not 0 <= context['not_before'] < context['not_after']
            or context['not_before'] != own['not_before'] or context['not_after'] != own['not_after']
            or not keys._hash(context['evidence_digest']) or context['evidence_digest'] == '0' * 64):
        raise ValueError('frozen context does not match admitted credential and root')
    context['initial_allocations'] = dict(own_tbs_digest=own_digest.hex(), unrelated_tbs_digest=other_digest.hex(),
        slot=member['slot'], allocation_epoch=1, cohort_receipt_sha256=cohort_sha256,
        membership_sha256=membership_sha256)
    for name, raw in files.items():
        if issuance._read(cohort / name, max(len(raw), 1)) != raw:
            raise ValueError('cohort changed during preparation')
    if issuance._read(context_path, 8192) != raw_context:
        raise ValueError('context changed during preparation')
    raw = (json.dumps(context, sort_keys=True, separators=(',', ':')) + '\n').encode()
    issuance._write(output, raw)
    return dict(schema='v3-initial-allocation-context-preparation-v1', context_sha256=digest(raw),
        cohort_receipt_sha256=cohort_sha256, membership_sha256=membership_sha256,
        training_only=True, allocation_authorized=False, registry_history_authenticated=False,
        live_state_authenticated=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cohort', 'context', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('cohort-sha256', 'membership-sha256', 'context-sha256', 'frozen-root'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        receipt = prepare(args.cohort, args.cohort_sha256, args.membership_sha256,
            args.context, args.context_sha256, args.frozen_root, args.output)
    except Exception:
        raise SystemExit('initial allocation preparation rejected') from None
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
