#!/usr/bin/env python3
"""Pin complete training inputs for one signed R0..Rk request campaign.

The packet is a proof-runner input, not an authorization decision. The effect
supervisor independently checks the finalized current accounts before submit.
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
from tools.part5 import build_v3_request_bound_anchor_packet as prior
from tools.part5.prepare_v3_campaign_context import derive, encoded
from tools.part5.credential_profile import FR
from harness.tests.queue_v3_local_campaign_transition import checked_history


COUNTS = (0, 1, 2, 5, 10)


def receipt(path, cap=65536):
    return json.loads(prior.private_file(path, cap))


def case(directory, version):
    prior.private_directory(directory)
    files = {'wtns': directory / 'output.wtns',
             'public': directory / 'public.json',
             'input': directory / 'input.json'}
    for kind, path in files.items():
        prior.private_file(path, 32 * 1024 * 1024 if kind == 'wtns' else 65536)
    return {**{kind + '_path': str(path) for kind, path in files.items()},
            **{kind + '_sha256': prior.digest(path) for kind, path in files.items()},
            'issuer_version': 1, 'policy_version': 1,
            'allocation_epoch': 1, 'root_version': version}


def accounts(directory, report):
    raw = [prior.private_file(directory / (name + '.bin'), 4096)
           for name in ('config', 'issuer', 'head', 'request', 'queue')]
    if report.get('account_sha256') != [hashlib.sha256(data).hexdigest() for data in raw]:
        raise ValueError('complete report account pins required')
    return raw


def action(config, request, plan):
    if (len(config) != 381 or config[:8] != b'DYNCONF3'
            or len(request) != 2249 or request[:8] != b'DYNREQ03'):
        raise ValueError('bounded action accounts required')
    size, uploaded = (int.from_bytes(request[i:i + 2], 'big') for i in (178, 180))
    count = request[184]
    if (size > 1024 or uploaded != size or not 2 <= count <= 16
            or request[182] != count or request[183] != 1
            or request[168:170] != b'\x00\x01'
            or int.from_bytes(request[170:178], 'big', signed=True) <= 0
            or any(request[185 + count * 65:1225]) or any(request[1225 + size:])):
        raise ValueError('finalized bounded action request required')
    metas = b''.join(request[185 + i * 65:218 + i * 65] for i in range(count))
    if any(request[217 + i * 65] > 3 for i in range(count)):
        raise ValueError('canonical action metadata required')
    preimage = (b'DYNARK-WORK-REQUEST' + b'\x02' + config[104:136]
                + bytes(plan['program']) + request[8:40] + config[136:172]
                + config[172:204] + request[72:104] + request[136:170]
                + size.to_bytes(4, 'big') + hashlib.sha256(request[1225:1225 + size]).digest()
                + bytes([count]) + metas + request[170:178])
    return str(int.from_bytes(hashlib.sha256(preimage).digest(), 'big') % FR)


def build(stage_root, transition_root, cohort_root, context_path, fixtures,
          old_packet, count, coalesced=False):
    if type(count) is not int or count not in COUNTS:
        raise ValueError('registered complete checkpoint prefix required')
    expected_fixtures = 1 if coalesced else count + 1
    if len(fixtures) != expected_fixtures:
        raise ValueError('registered complete checkpoint prefix required')
    for directory in (stage_root, cohort_root, old_packet.parent, context_path.parent):
        prior.private_directory(directory)
    if count:
        prior.private_directory(transition_root)
    elif transition_root != stage_root:
        raise ValueError('zero-update final state is the R0 stage')
    staged = receipt(stage_root / 'stage-report.json')
    plan = receipt(stage_root / 'plan.json', 8192)
    cohort = receipt(cohort_root / 'cohort-receipt.json')
    context_raw = prior.private_file(context_path, 8192)
    context = json.loads(context_raw)
    if (staged.get('schema') != 'part5-v3-campaign-stage-v1'
            or staged.get('passed') is not True
            or staged.get('registry_history_authenticated') is not True
            or staged.get('allocation_history_authenticated') is not True
            or staged.get('application_effect') is not False
            or staged.get('proof_created') is not False
            or staged.get('plan_sha256') != prior.digest(stage_root / 'plan.json')
            or staged.get('signed_history_sha256')
               != prior.digest(stage_root / 'signed-history.json')
            or staged.get('account_sha256', [None])[0]
               != prior.digest(stage_root / 'config.bin')
            or context_raw != encoded(derive(cohort_root,
                context['initial_allocations']['cohort_receipt_sha256'],
                context['initial_allocations']['membership_sha256']))
            or bytes(plan['root']).hex() != context['root_sequence'][0]
            or cohort.get('freeze_receipt_sha256') is None):
        raise ValueError('signed frozen campaign R0 stage required')
    base_accounts = accounts(stage_root, staged)
    allocations = receipt(stage_root / 'initial-allocations.json', 8192)
    if (allocations != context['initial_allocations']
            or staged.get('initial_allocations_sha256') != prior.digest(stage_root / 'initial-allocations.json')
            or any(staged.get(key) is not True for key in ('training_only', 'upstream_source_authentication', 'upstream_publisher_authentication'))):
        raise ValueError('exact admitted signed campaign allocations required')
    checked_history(receipt(stage_root / 'signed-history.json', 1024 * 1024), context, plan, {'target_count': 0}, staged)
    if count:
        changed = receipt(transition_root / 'transition-report.json', 1024 * 1024)
        accounts(transition_root, changed)
        if (changed.get('schema') != 'part5-v3-campaign-transition-v1'
                or changed.get('passed') is not True
                or changed.get('target_count') != count
                or changed.get('registry_history_authenticated') is not True
                or changed.get('allocation_history_authenticated') is not True
                or changed.get('request_unconsumed') is not True
                or changed.get('application_effect') is not False
                or changed.get('stage_report_sha256')
                   != prior.digest(stage_root / 'stage-report.json')
                or changed.get('stage_plan_sha256')
                   != prior.digest(stage_root / 'plan.json')
                or any(changed.get(key) is not True for key in ('training_only', 'upstream_source_authentication', 'upstream_publisher_authentication'))
                or changed.get('context_sha256') != prior.digest(context_path)
                or changed.get('root_sequence_sha256') != context['initial_allocations']['root_sequence_sha256']
                or changed.get('initial_allocations_sha256') != staged['initial_allocations_sha256']
                or changed.get('loaded_program') != staged['loaded_program']
                or changed.get('base_finalized_slot') != staged['finalized_slot']
                or type(changed.get('finalized_slot')) is not int
                or changed['finalized_slot'] <= staged['finalized_slot']
                or len(changed.get('checkpoints', [])) != count
                or changed.get('program') != staged['program']
                or changed.get('genesis') != staged['genesis']
                or changed.get('base_root') != context['root_sequence'][0]
                or changed.get('current_root') != context['root_sequence'][count]
                or changed.get('signed_history_sha256')
                   != prior.digest(transition_root / 'signed-history.json')
                or changed.get('account_sha256', [None] * 5)[3:5]
                   != staged['account_sha256'][3:5]
                or any(prior.digest(stage_root / (name + '.bin'))
                       != prior.digest(transition_root / (name + '.bin'))
                       for name in ('request', 'queue'))):
            raise ValueError('signed current campaign transition required')
        checked_history(receipt(transition_root / 'signed-history.json', 1024 * 1024), context, plan, changed, staged)
        if (changed['checkpoints'][-1]['account_sha256'] != changed['account_sha256']
                or changed['checkpoints'][-1]['finalized_slot'] != changed['finalized_slot']):
            raise ValueError('final checkpoint report pins required')
        final_root = transition_root
        final_report = transition_root / 'transition-report.json'
        history = transition_root / 'signed-history.json'
    else:
        changed = staged
        final_root = stage_root
        final_report = stage_root / 'stage-report.json'
        history = stage_root / 'signed-history.json'
    final_config = prior.private_file(final_root / 'config.bin', 4096)
    if (base_accounts[0][104:136] != bytes(plan['genesis'])
            or base_accounts[0][136:168].hex() != context['policy_id']
            or base_accounts[3][104:136].hex() != context['issuer_hash']
            or base_accounts[0][332:364].hex() != context['root_sequence'][0]
            or len(final_config) != 381 or final_config[:8] != b'DYNCONF3'
            or final_config[332:364].hex() != context['root_sequence'][count]):
        raise ValueError('campaign account context/root bindings required')
    publics = [receipt(path / 'public.json', 1024) for path in fixtures]
    base_public = [str(int(context['root_sequence'][0], 16)),
                   str(int(context['issuer_hash'], 16)),
                   str(context['not_before']), str(context['not_after']),
                   action(base_accounts[0], base_accounts[3], plan),
                   str(int(context['policy_id'], 16))]
    if (type(staged.get('finalized_slot')) is not int or staged['finalized_slot'] <= 0
            or any(len(row) != 6 or row[1:] != base_public[1:]
                   for row in publics)
            or (coalesced and publics[0][0] != str(int(context['root_sequence'][count], 16)))
            or (not coalesced and any(row[0] != str(int(context['root_sequence'][i], 16))
                                      for i, row in enumerate(publics)))
            or bytes(plan['root']).hex() != context['root_sequence'][0]
            or prior.digest(stage_root / 'request.bin') != staged['account_sha256'][3]
            or prior.digest(stage_root / 'queue.bin') != staged['account_sha256'][4]):
        raise ValueError('same-action complete public root prefix required')
    for i, directory in enumerate(fixtures):
        private = receipt(directory / 'input.json')
        if any(str(private.get(key)) != publics[i][j] for j, key in enumerate(
                ('root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash'))):
            raise ValueError('complete fixture public/input identity required')
    template = receipt(old_packet, 262144)
    app = {'program_id': staged['program'], 'genesis_hash': staged['genesis'],
           'loaded_elf_sha256': staged['loaded_program']['elf_sha256'],
           'base_stage_report_sha256': prior.digest(stage_root / 'stage-report.json'),
           'base_config_sha256': prior.digest(stage_root / 'config.bin'),
           'finalized_request_sha256': prior.digest(stage_root / 'request.bin'),
           'request_address': staged['request'],
           'base_finalized_slot': staged['finalized_slot'],
           'near_state_report_sha256': prior.digest(final_report),
           'near_config_sha256': prior.digest(final_root / 'config.bin'),
           'near_finalized_slot': changed['finalized_slot'],
           'base_root': base_public[0], 'near_root': publics[-1][0],
           'action_hash': base_public[4]}
    packet = {name: template[name] for name in (
        'package_digest', 'setup_manifest_path', 'setup_manifest_sha256',
        'package_check_path', 'package_check_sha256', 'r1cs_path',
        'wasm_path', 'profile_path', 'input_map_path', 'input_map_sha256')}
    packet.update(schema=('credential-v3-cumulative-coalesced-request-v1' if coalesced
                          else 'credential-v3-cumulative-request-v1'),
                  synthetic_only=False, application_verified=False,
                  cohort='cumulative-training-v1',
                  proof_source_identity=prior.proof_source_identity(),
                  application_stage=app, update_count=count,
                  freeze_receipt_sha256=cohort['freeze_receipt_sha256'],
                  history_receipt_sha256=prior.digest(history),
                  root_schedule_sha256=context['initial_allocations']['root_sequence_sha256'])
    case_versions = [count] if coalesced else list(range(len(fixtures)))
    cases = [case(directory, version)
             for version, directory in zip(case_versions, fixtures)]
    if coalesced:
        packet['final'] = cases[-1]
    else:
        base = cases[0]
        packet['pairs'] = [{'name': f'request_bound_training_r{generation}',
                            'base': base, 'near': cases[generation]}
                           for generation in (range(1, count + 1) if count else (0,))]
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stage_root', 'transition_root', 'cohort_root',
                 'context', 'old_packet', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), required=True, type=Path)
    parser.add_argument('--fixture', action='append', type=Path, required=True)
    parser.add_argument('--count', type=int, choices=COUNTS, required=True)
    parser.add_argument('--coalesced', action='store_true')
    args = parser.parse_args()
    packet = build(args.stage_root, args.transition_root, args.cohort_root,
                   args.context, args.fixture, args.old_packet, args.count,
                   args.coalesced)
    prior.private_directory(args.output.parent)
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    main()
