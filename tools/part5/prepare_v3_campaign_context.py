#!/usr/bin/env python3
"""Admit the frozen eleven-leaf training cohort into a private R0..R10 context.

This checks signed certificates and pure tree arithmetic. A later finalized
source/publisher replay must authorize allocations and current roots.
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

SLOTS = (0, *range(16, 26))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def derive(cohort, cohort_sha256, membership_sha256):
    issuance._directory(cohort)
    if not keys._hash(cohort_sha256) or not keys._hash(membership_sha256):
        raise ValueError('campaign receipt hashes required')
    receipt_raw = issuance._read(cohort / 'cohort-receipt.json', 65536)
    membership_raw = issuance._read(cohort / 'membership.json', 65536)
    receipt = issuance.decode_parameters(receipt_raw)
    member = issuance.decode_parameters(membership_raw)
    modulus_raw = issuance._read(cohort / 'issuer-modulus.bin', 256)
    if (hashlib.sha256(receipt_raw).hexdigest() != cohort_sha256
            or hashlib.sha256(membership_raw).hexdigest() != membership_sha256
            or receipt.get('schema') != 'v3-eleven-signed-training-credentials-v1'
            or receipt.get('training_only') is not True
            or receipt.get('heldout_acceptance') is not False
            or receipt.get('registry_history_authenticated') is not False
            or receipt.get('membership_sha256') != membership_sha256
            or receipt.get('counts') != {'issuers': 1, 'holders': 11, 'certificates': 11, 'roots': 11}
            or member.get('schema') != 'v3-eleven-leaf-training-membership-v1'
            or member.get('allocation_authorized') is not False
            or member.get('registry_history_authenticated') is not False
            or member.get('holder_slot') != 0
            or member.get('unrelated_slots') != list(range(16, 26))
            or member.get('allocation_epoch') != 1
            or len(modulus_raw) != 256
            or not isinstance(receipt.get('certificates'), list)
            or len(receipt['certificates']) != 11):
        raise ValueError('registered frozen training cohort required')
    modulus = int.from_bytes(modulus_raw, 'big')
    digests = []
    issuer, policy, aki = None, None, None
    for index, slot in enumerate(SLOTS):
        raw = issuance._read(cohort / f'credential-{index}.der', 952)
        parsed = admit_certificate(raw, modulus)
        actual_issuer, actual_policy = public_bindings(parsed, modulus)
        signed = hashlib.sha256(parsed['tbs']).digest()
        record = receipt['certificates'][index]
        if (len(raw) != 952 or len(parsed['tbs']) != 672
                or record.get('slot') != slot
                or record.get('variant') != index % 8
                or record.get('credential_sha256') != hashlib.sha256(raw).hexdigest()
                or record.get('tbs_sha256') != signed.hex()
                or parsed['not_before'] != 1767225600
                or parsed['not_after'] != 1830297600):
            raise ValueError('campaign certificate/receipt mismatch')
        if index == 0:
            issuer, policy, aki = actual_issuer, actual_policy, parsed['aki']
        if (actual_issuer, actual_policy, parsed['aki']) != (issuer, policy, aki):
            raise ValueError('campaign issuer or signed policy changed')
        digests.append(signed)
    roots = schedule.membership_for_sequence(digests[0], digests[1:])
    if (len(set(digests)) != 11
            or member.get('tbs_digests') != [value.hex() for value in digests]
            or member.get('roots') != roots['roots']
            or member.get('holder_siblings') != roots['holder_siblings']
            or member.get('issuer_hash') != str(issuer)
            or member.get('holder_policy_hash') != str(policy)
            or receipt.get('issuer_hash') != str(issuer)
            or receipt.get('holder_policy_hash') != str(policy)
            or receipt.get('root_sequence_sha256') != hashlib.sha256(encoded(roots['roots'])).hexdigest()):
        raise ValueError('independently rebuilt R0..R10 schedule mismatch')
    cohort_recheck = issuance._read(cohort / 'cohort-receipt.json', 65536)
    member_recheck = issuance._read(cohort / 'membership.json', 65536)
    if cohort_recheck != receipt_raw or member_recheck != membership_raw:
        raise ValueError('campaign cohort changed')
    evidence = hashlib.sha256(b'part5-v3-campaign-enrollment-evidence/v1\0'
                              + bytes.fromhex(cohort_sha256)).hexdigest()
    context = {'schema': 'part5-v3-campaign-context-v1', 'training_only': True,
               'root': f"{roots['roots'][0]:064x}", 'issuer_hash': f'{issuer:064x}',
               'policy_id': f'{policy:064x}', 'aki': (aki + bytes(12)).hex(),
               'evidence_digest': evidence, 'not_before': 1767225600,
               'not_after': 1830297600,
               'initial_allocations': {
                   'holder_slot': 0, 'unrelated_slots': list(range(16, 26)),
                   'tbs_digests': [value.hex() for value in digests],
                   'allocation_epoch': 1,
                   'cohort_receipt_sha256': cohort_sha256,
                   'membership_sha256': membership_sha256,
                   'root_sequence_sha256': receipt['root_sequence_sha256']},
               'root_sequence': [f'{root:064x}' for root in roots['roots']]}
    return context


def prepare(cohort, cohort_sha256, membership_sha256, output):
    issuance._directory(output.parent)
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or output.parent.resolve(strict=True) / output.name != output
            or not keys._ignored(output)):
        raise ValueError('fresh ignored private campaign context required')
    context = derive(cohort, cohort_sha256, membership_sha256)
    raw = encoded(context)
    issuance._write(output, raw)
    return {'schema': 'part5-v3-campaign-context-preparation-v1',
            'training_only': True, 'allocation_authorized': False,
            'registry_history_authenticated': False,
            'context_sha256': hashlib.sha256(raw).hexdigest(),
            'cohort_receipt_sha256': cohort_sha256,
            'root_sequence_sha256': context['initial_allocations']['root_sequence_sha256']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cohort', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('cohort_sha256', 'membership_sha256'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    args = parser.parse_args()
    try:
        result = prepare(**vars(args))
    except Exception:
        raise SystemExit('campaign context preparation rejected') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
