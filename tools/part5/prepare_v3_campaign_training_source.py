#!/usr/bin/env python3
"""Build private R0 request-bound training sources from a signed campaign stage.

This checks retained local evidence, never authenticates current chain state.
Output must be a fresh, empty, canonical owner0700 directory.
"""
import argparse
import json
import os
import stat
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from tools.part5.prepare_v3_matched_training_source import (
    digest, private_dir, private_file, write_new)
from tools.part5.prepare_v3_campaign_context import derive, encoded
from tools.part5 import prepare_v3_request_fixture as bridge
from tools.part5.credential_profile import admit_certificate, public_bindings
from harness.tests.queue_v3_local_campaign_transition import checked_history


def prepare(stage_root, cohort_root, context_path, output, exporter):
    stage_root, cohort_root = private_dir(stage_root), private_dir(cohort_root)
    output = private_dir(output, empty=True)
    context_path, exporter = Path(context_path), Path(exporter)
    private_dir(context_path.parent)
    if output in (stage_root, cohort_root, context_path.parent):
        raise ValueError('separate fresh output required')
    snapshots = {}

    def read(path, cap):
        raw = private_file(path, cap)
        snapshots[path] = (raw, cap)
        return raw

    context_raw = read(context_path, 8192)
    context = json.loads(context_raw)
    receipt_raw = read(cohort_root / 'cohort-receipt.json', 65536)
    member_raw = read(cohort_root / 'membership.json', 65536)
    receipt, member = json.loads(receipt_raw), json.loads(member_raw)
    if encoded(derive(cohort_root, digest(receipt_raw), digest(member_raw))) != context_raw:
        raise ValueError('exact independently derived campaign context required')
    stage_raw = read(stage_root / 'stage-report.json', 65536)
    plan_raw = read(stage_root / 'plan.json', 8192)
    staged, plan = json.loads(stage_raw), json.loads(plan_raw)
    history_raw = read(stage_root / 'signed-history.json', 1024 * 1024)
    allocation_raw = read(stage_root / 'initial-allocations.json', 8192)
    config = read(stage_root / 'config.bin', 381)
    request = read(stage_root / 'request.bin', 2249)
    if (staged.get('schema') != 'part5-v3-campaign-stage-v1'
            or any(staged.get(k) is not True for k in (
                'passed', 'training_only', 'registry_history_authenticated',
                'allocation_history_authenticated', 'upstream_source_authentication',
                'upstream_publisher_authentication'))
            or staged.get('application_effect') is not False
            or staged.get('proof_created') is not False
            or staged.get('plan_sha256') != digest(plan_raw)
            or staged.get('signed_history_sha256') != digest(history_raw)
            or staged.get('initial_allocations_sha256') != digest(allocation_raw)
            or json.loads(allocation_raw) != context['initial_allocations']
            or not isinstance(staged.get('account_sha256'), list)
            or len(staged['account_sha256']) != 5
            or staged['account_sha256'][0] != digest(config)
            or staged['account_sha256'][3] != digest(request)):
        raise ValueError('authenticated signed campaign stage pins required')
    checked_history(json.loads(history_raw), context, plan,
                    {'target_count': 0}, staged)
    own = read(cohort_root / 'credential-0.der', 952)
    holder = read(cohort_root / 'holder-0.pem', 4096)
    modulus_raw = read(cohort_root / 'issuer-modulus.bin', 256)
    modulus = int.from_bytes(modulus_raw, 'big')
    parsed = admit_certificate(own, modulus)
    issuer, policy = public_bindings(parsed, modulus)
    if (len(own) != 952 or len(modulus_raw) != 256
            or digest(own) != receipt['certificates'][0]['credential_sha256']
            or digest(parsed['tbs']) != context['initial_allocations']['tbs_digests'][0]
            or member['roots'] != [int(x, 16) for x in context['root_sequence']]
            or bytes(plan['root']).hex() != context['root']
            or bytes(plan['issuer_hash']) != issuer.to_bytes(32, 'big')
            or bytes(plan['policy_id']) != policy.to_bytes(32, 'big')
            or context['issuer_hash'] != f'{issuer:064x}'
            or context['policy_id'] != f'{policy:064x}'
            or len(config) != 381 or config[:8] != b'DYNCONF3'
            or config[104:136] != bytes(plan['genesis'])
            or config[136:168] != bytes(plan['policy_id'])
            or config[332:364] != bytes(plan['root'])):
        raise ValueError('campaign membership or finalized context mismatch')
    membership = dict(slot=0, issuer_hash=issuer, policy_hash=policy,
                      active_root=member['roots'][0], active_siblings=member['holder_siblings'][0])
    last = next((row for row in reversed(staged['transactions'])
                 if row['scenario'] == 'v3-bind-head'), None)
    now = last['blockTime'] if last else None
    if type(now) is not int or now <= 0 or now >= plan['deadline']:
        raise ValueError('staged request clock invalid')
    info = exporter.lstat()
    if (not exporter.is_absolute() or exporter.resolve(strict=True) != exporter
            or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o022 or not info.st_mode & 0o111
            or not 0 < info.st_size <= 64 * 1024 * 1024):
        raise ValueError('pinned exporter binary required')
    exporter_sha = digest(exporter.read_bytes())
    wire = bridge.build_v3p1(own, modulus, membership, config_bytes=config,
        program_id=bytes(plan['program']), creator=bytes(plan['creator']),
        nonce=bytes(plan['nonce']), recipient=bytes(plan['recipient']), request_type=1,
        deadline=plan['deadline'], payload=bytes(plan['payload']), now=now)
    finalized = bridge.finalize_v3p1(wire, exporter)
    if (finalized['exporter_sha256'] != exporter_sha
            or finalized['v3f1'][625:] != request):
        raise ValueError('staged request differs from campaign action')
    # Verify that the copied holder key signs this exact admitted holder/action.
    bridge.build_request_bound_v3q1(own, modulus, cohort_root / 'holder-0.pem',
                                    membership, wire, finalized, exporter)
    params = {k: bytes(plan[k]).hex() for k in ('genesis', 'creator', 'nonce', 'recipient')}
    params.update(program_id=bytes(plan['program']).hex(), payload=bytes(plan['payload']).hex(),
                  request_type=1, deadline=plan['deadline'], now=now, exporter_sha256=exporter_sha)
    for path, (raw, cap) in snapshots.items():
        if private_file(path, cap) != raw:
            raise ValueError('source changed')
    if digest(exporter.read_bytes()) != exporter_sha:
        raise ValueError('exporter changed')
    outputs = {'credential.der': own, 'holder.pem': holder, 'issuer-modulus.bin': modulus_raw,
               'config.bin': config, 'membership.json': encoded(membership),
               'parameters.json': encoded(params)}
    result = dict(schema='part5-v3-campaign-training-source-v1', training_only=True,
        live_state_authenticated=False, application_effect=False, proof_created=False,
        context_sha256=digest(context_raw), cohort_receipt_sha256=digest(receipt_raw),
        cohort_membership_sha256=digest(member_raw),
        root_sequence_sha256=context['initial_allocations']['root_sequence_sha256'],
        stage_report_sha256=digest(stage_raw), stage_plan_sha256=digest(plan_raw),
        signed_history_sha256=digest(history_raw), initial_allocations_sha256=digest(allocation_raw),
        exporter_sha256=exporter_sha,
        source_sha256={name: digest(raw) for name, raw in outputs.items()})
    for name, raw in outputs.items():
        write_new(output, name, raw)
    write_new(output, 'source-receipt.json', encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stage_root', 'cohort_root', 'context_path', 'output', 'exporter'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(**vars(args))
    except Exception:
        raise SystemExit('campaign training source preparation rejected') from None
    print(json.dumps({'schema': result['schema'], 'stage_report_sha256': result['stage_report_sha256'],
        'source_receipt_sha256': digest(private_file(args.output / 'source-receipt.json', 8192))}))


if __name__ == '__main__':
    main()
