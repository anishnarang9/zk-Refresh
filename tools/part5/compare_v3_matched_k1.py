#!/usr/bin/env python3
"""Publish a scrubbed, evidence-checked comparison of one frozen training pair."""
import argparse
import hashlib
import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTERED_LIMITS = {'runtime_seconds': 2400.0,
                     'owned_tree_rss_bytes': 4 * 1024**3,
                     'storage_growth_bytes': 1024**3,
                     'poll_seconds': 0.25}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_invocation(mode, invocation, monitor, work, clone_root, branch_output,
                     session, outer):
    argv = invocation.get('argv', [])
    require(isinstance(argv, list) and len(argv) == 15,
            mode + ' invocation shape')
    freeze_path = Path(argv[6])
    control_output = Path(argv[14])
    expected = ['python3', '-B', 'tools/part5/run_v3_matched_k1.py',
                '--mode', mode, '--freeze', str(freeze_path),
                '--clone-report', str(clone_root / 'clone-report.json'),
                '--work-root', str(work), '--branch-output', str(branch_output),
                '--control-output', str(control_output)]
    require(argv == expected and invocation.get('owner') == outer['owner']
            and invocation.get('cwd') == str(REPO)
            and freeze_path.parent == REPO / 'results/dynark/part5'
            and sha(freeze_path) == session['freeze_sha256']
            and control_output.parent == REPO / 'artifacts/dynark/part5'
            and sha(control_output / 'status.json') == session['branch_status_sha256']
            and invocation.get('storage_roots') == list(map(str, (
                monitor, work, clone_root, branch_output, control_output)))
            and outer['duration_seconds'] >= session['total_command_wall_seconds'],
            mode + ' outer invocation/session mismatch')


def mode_result(mode, work, outer_path, clone_root, branch_output, monitor):
    work, clone_root, branch_output, monitor = map(
        Path, (work, clone_root, branch_output, monitor))
    outer = read(outer_path)
    session_path = work / 'session-report.json'
    session = read(session_path)
    packet_path = work / 'packet.json'
    packet = read(packet_path)
    proof_path = work / 'proof/proof-report.json'
    proof = read(proof_path)
    branch_path = branch_output / 'branch-report.json'
    branch = read(branch_path)
    clone = read(clone_root / 'clone-report.json')
    require(sha(monitor / 'report.json') == sha(outer_path),
            mode + ' private/public outer report mismatch')
    invocation = read(monitor / 'invocation.json')
    require(outer.get('passed') is True and outer.get('censored') is False
            and outer.get('measurement') == 'bounded_complete_session'
            and outer.get('owner', '').startswith('part5-v3-matched-k1-' + mode + '-')
            and outer.get('exit_code') == 0
            and outer.get('stop_reason') is None
            and outer.get('cleanup_remaining_owned_processes') == 0
            and outer.get('cleanup_status_unknown') is False
            and outer.get('sample_count', 0) > 0
            and outer.get('duration_seconds', 0) > 0,
            mode + ' outer session incomplete')
    require(outer.get('limits') == REGISTERED_LIMITS,
            mode + ' unregistered measurement limits')
    require(session.get('passed') is True and session.get('effect_verified') is True
            and session.get('mode') == mode
            and session.get('supervisor_status') == 'failed'
            and session.get('validator_cleanup', {}).get('exit_code') == -2
            and session.get('ledger_reuse_requires_review') is True
            and session.get('proof_report_sha256') == sha(proof_path)
            and session.get('packet_sha256') == sha(packet_path)
            and session.get('branch_report_sha256') == sha(branch_path),
            mode + ' private session/effect mismatch')
    check_invocation(mode, invocation, monitor, work, clone_root,
                     branch_output, session, outer)
    counts = {'proofs': 2, 'positive_checks': 2, 'altered_public_checks': 12,
              'cross_root_checks': 2, 'ordinary_checks': 16}
    require(proof.get('schema') == 'credential-v3-matched-k1-proof-v1'
            and proof.get('passed') is True
            and proof.get('mode') == 'matched-' + mode + '-k1'
            and proof.get('counts') == counts
            and proof.get('packet_sha256') == session['packet_sha256']
            and proof.get('qualification_extras_executed') is False
            and proof.get('application_verified') is False,
            mode + ' unequal proof work')
    require(branch.get('schema') == 'part5-v3-r1-branch-v1'
            and branch.get('passed') is True and branch.get('mode') == mode
            and branch.get('application_effect') is True
            and branch.get('effect_count') == 1
            and branch.get('request_consumed') is True
            and int(branch.get('base_root', ''), 16)
                == int(proof['application_stage_pins']['base_root'])
            and int(branch.get('near_root', ''), 16)
                == int(proof['application_stage_pins']['near_root'])
            and branch.get('current_root') == branch.get('near_root')
            and branch.get('upstream_source_authentication') is True
            and branch.get('loaded_program', {}).get('elf_match') is True
            and branch.get('loaded_program', {}).get('elf_sha256')
                == proof['application_stage_pins']['loaded_elf_sha256']
            and branch.get('stage_report_sha256')
                == proof['application_stage_pins']['base_stage_report_sha256']
            and branch.get('transition_report_sha256')
                == proof['application_stage_pins']['near_state_report_sha256'],
            mode + ' finalized application effect mismatch')
    effects = [row for row in branch['transactions']
               if row.get('scenario') == 'v3-valid-' + mode + '-R1']
    require(len(effects) == 1 and effects[0].get('err') is None
            and effects[0].get('transactionBytes', 0) > 0
            and effects[0].get('computeUnits', 0) > 0,
            mode + ' effect transaction missing')
    require(clone.get('schema') == 'part5-v3-r1-ledger-clone-v1'
            and clone.get('copy_identical') is True
            and clone.get('entry_count') == 63,
            mode + ' ledger clone mismatch')
    pair = packet['pairs'][0]
    stages = session['stages']
    require([s['stage'] for s in stages] == [
        'base_input', 'near_input', 'base_witness', 'base_relation',
        'near_witness', 'near_relation', 'proof', 'adapter',
        'branch_config', 'application']
        and all(s['exit_code'] == 0 for s in stages[:-1])
        and stages[-1]['exit_code'] == 1,
        mode + ' stage sequence incomplete')
    require(outer['cpu']['complete_tree_cpu_qualified'] is False
            and session['complete_tree_cpu_qualified'] is False,
            mode + ' CPU interpretation changed')
    return {
        'mode': mode,
        'freeze_sha256': session['freeze_sha256'],
        'packet_sha256': session['packet_sha256'],
        'source_sha256': session['source_sha256'],
        'clone_inventory_sha256': clone['tree_sha256'],
        'clone_source': clone['source'],
        'base_input_sha256': pair['base']['input_sha256'],
        'near_input_sha256': pair['near']['input_sha256'],
        'base_public_sha256': pair['base']['public_sha256'],
        'near_public_sha256': pair['near']['public_sha256'],
        'base_wtns_sha256': pair['base']['wtns_sha256'],
        'near_wtns_sha256': pair['near']['wtns_sha256'],
        'application_stage_pins': proof['application_stage_pins'],
        'package_digest': proof['package_digest'],
        'setup_manifest_sha256': proof['setup_manifest_sha256'],
        'ordinary_vk_file_sha256': proof['ordinary_vk_file_sha256'],
        'proof_binary_sha256': proof['proof_binary_sha256'],
        'proof_source_identity': proof['proof_source_identity'],
        'proof_identity': proof['identity'],
        'proof_support_preflight': proof['preflights'],
        'outer_report_sha256': sha(outer_path),
        'session_report_sha256': sha(session_path),
        'proof_report_sha256': sha(proof_path),
        'branch_report_sha256': sha(branch_path),
        'outer_wall_seconds': outer['duration_seconds'],
        'outer_limits': outer['limits'],
        'outer_environment': outer['environment'],
        'outer_sample_count': outer['sample_count'],
        'command_wall_seconds': session['total_command_wall_seconds'],
        'sampled_peak_owned_tree_rss_bytes': outer['sampled_peak_owned_tree_rss_bytes'],
        'sampled_peak_storage_growth_bytes': outer['sampled_peak_storage_growth_bytes'],
        'partial_wait4_user_seconds': outer['cpu']['leader_wait4_user_seconds'],
        'partial_wait4_system_seconds': outer['cpu']['leader_wait4_system_seconds'],
        'proof_public_material_prepare_ms': proof['public_material_prepare_ms'],
        'proof_private_anchor_prepare_ms': proof['cases'][0].get('private_anchor_prepare_ms'),
        'proof_refresh_and_verify_ms': proof['cases'][0].get('refresh_and_verify_ms'),
        'proof_total_paid_session_ms': proof['total_paid_session_ms'],
        'stage_wall_seconds': {s['stage']: s['wall_seconds'] for s in stages},
        'final_account_sha256': branch['account_sha256'],
        'finalized_slot': branch['finalized_slot'],
        'registry_history_authenticated': branch['registry_history_authenticated'],
        'effect_transaction_bytes': effects[0]['transactionBytes'],
        'effect_compute_units': effects[0]['computeUnits'],
    }


def compare(full, anchor):
    for key in ('freeze_sha256', 'source_sha256', 'clone_inventory_sha256',
                'clone_source', 'base_input_sha256', 'near_input_sha256',
                'base_public_sha256', 'near_public_sha256',
                'base_wtns_sha256', 'near_wtns_sha256',
                'application_stage_pins', 'package_digest',
                'setup_manifest_sha256', 'ordinary_vk_file_sha256',
                'proof_binary_sha256', 'proof_source_identity', 'proof_identity',
                'proof_support_preflight', 'outer_limits', 'outer_environment'):
        require(full[key] == anchor[key], 'unmatched ' + key)
    require(all(full['final_account_sha256'][i] == anchor['final_account_sha256'][i]
                for i in (0, 1, 3, 4)), 'different final protected state')
    require(full['proof_public_material_prepare_ms'] == 0.0
            and full['proof_private_anchor_prepare_ms'] is None
            and anchor['proof_public_material_prepare_ms'] > 0
            and anchor['proof_private_anchor_prepare_ms'] > 0,
            'private Anchor cost not charged')
    wall_difference = full['outer_wall_seconds'] - anchor['outer_wall_seconds']
    return {
        'schema': 'part5-v3-matched-k1-pair-v1', 'training_only': True,
        'complete_pair': True, 'update_count': 1,
        'proofs_and_ordinary_checks_per_mode': {'proofs': 2, 'ordinary_checks': 16},
        'pilot_full_included_anchor_support_preflight': True,
        'same_source_witness_request_roots_setup_elf_and_final_effect': True,
        'registry_history_authenticated': (full['registry_history_authenticated']
                                           and anchor['registry_history_authenticated']),
        'full': {k: v for k, v in full.items() if k not in ('source_sha256', 'clone_source')},
        'anchor': {k: v for k, v in anchor.items() if k not in ('source_sha256', 'clone_source')},
        'full_minus_anchor_wall_seconds': wall_difference,
        'wall_savings_fraction': wall_difference / full['outer_wall_seconds'],
        'cpu_savings': None,
        'cpu_unavailable_reason': 'complete owned-tree CPU accounting not qualified',
        'measured_break_even': None,
        'break_even_note': 'one training pair at k=1 is not a measured crossing distribution',
        'application_benefit_established': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for mode in ('full', 'anchor'):
        for role in ('work', 'outer', 'clone', 'branch_output', 'monitor'):
            parser.add_argument('--' + mode + '-' + role.replace('_', '-'), required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    full = mode_result('full', args.full_work, args.full_outer,
                       args.full_clone, args.full_branch_output, args.full_monitor)
    anchor = mode_result('anchor', args.anchor_work, args.anchor_outer,
                         args.anchor_clone, args.anchor_branch_output, args.anchor_monitor)
    result = compare(full, anchor)
    target = Path(args.output)
    if target.exists() or target.is_symlink():
        raise FileExistsError('fresh report required')
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    print(json.dumps({'complete_pair': True,
                      'wall_difference_seconds': result['full_minus_anchor_wall_seconds']}))


if __name__ == '__main__':
    main()
