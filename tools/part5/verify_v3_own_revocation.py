#!/usr/bin/env python3
"""Check a signed R2 holder-revocation branch and publish a scrubbed receipt."""
import argparse
import hashlib
import json
import os
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify(config_path, status_path, outer_path, output):
    config, status, outer = map(read, (config_path, status_path, outer_path))
    branch = Path(config['branch_output'])
    report_path = branch / 'branch-report.json'
    report = read(report_path)
    stage = read(Path(config['stage_root']) / 'stage-report.json')
    transition = read(Path(config['transition_root']) / 'transition-report.json')
    allocations_path = Path(config['stage_root']) / 'initial-allocations.json'
    allocations = read(allocations_path)
    history_path = branch / 'signed-history.json'
    history = read(history_path)
    clone = read(config['clone_report'])
    require(config['mode'] == 'own-revocation'
            and config['scope'] == 'part5-v3-r1-branch'
            and status['config_sha256'] == sha(config_path)
            and status['branch_output'] == str(branch)
            and status['branch_report_sha256'] == sha(report_path)
            and status['branch_verified'] is True
            and status['application_effect'] is False
            and status['effect_count'] == 0
            and status['ledger_reuse_requires_review'] is True,
            'verified R2 branch and exact config required')
    require(report['schema'] == 'part5-v3-r1-branch-v1'
            and report['passed'] is True
            and report['mode'] == 'own-revocation'
            and report['registry_history_authenticated'] is True
            and report['allocation_history_authenticated'] is True
            and report['upstream_source_authentication'] is True
            and report['upstream_publisher_authentication'] is True
            and report['request_unconsumed'] is True
            and report['request_consumed'] is False
            and report['application_effect'] is False
            and report['effect_count'] == 0
            and report['stage_report_sha256'] == sha(Path(config['stage_root']) / 'stage-report.json')
            and report['transition_report_sha256'] == sha(Path(config['transition_root']) / 'transition-report.json')
            and report['initial_allocations_sha256'] == sha(allocations_path)
            and report['signed_history_sha256'] == sha(history_path)
            and report['loaded_program']['elf_match'] is True
            and report['loaded_program']['elf_sha256'] == transition['loaded_program']['elf_sha256']
            and report['base_root'] == transition['base_root']
            and report['near_root'] == transition['near_root']
            and len({report['base_root'], report['near_root'], report['current_root']}) == 3
            and report['account_sha256'][3:] == transition['account_sha256'][3:]
            and report['finalized_slot'] >= report['bound_finalized_slot'] > transition['finalized_slot'],
            'signed R2 account and unconsumed effect evidence required')
    changes = [checkpoint['source']['observation']['changes']
               for checkpoint in history['checkpoints']]
    own = bytes.fromhex(allocations['own_tbs_digest'])
    other = bytes.fromhex(allocations['unrelated_tbs_digest'])
    require(history['schema'] == 'part5-v3-two-leaf-signed-history-v1'
            and len(changes) == 3
            and len(changes[0]) == 2
            and changes[1] == [{'Revoke': {'tbs_digest': list(other)}}]
            and changes[2] == [{'Revoke': {'tbs_digest': list(own)}}],
            'complete signed own-revocation history required')
    expected = [('v3-publish-own-revocation', None),
                ('v3-observe-signed-own-revocation', None),
                ('v3-bind-current-branch-head', None),
                ('v3-stale-R0-full', {'InstructionError': [1, {'Custom': 713}]}),
                ('v3-own-revoked-R1-anchor', {'InstructionError': [1, {'Custom': 713}]})]
    require([(row['scenario'], row['err']) for row in report['transactions']] == expected,
            'one signed R2 publication and two policy rejections required')
    require(clone['schema'] == 'part5-v3-r1-ledger-clone-v1'
            and clone['copy_identical'] is True
            and clone['destination'] == config['ledger']
            and clone['transition_report_sha256'] == sha(Path(config['transition_root']) / 'transition-report.json')
            and outer['exit_code'] == 1
            and outer['stop_reason'] is None
            and outer['cleanup_remaining_owned_processes'] == 0
            and outer['cleanup_status_unknown'] is False
            and status['validator_cleanup']['exit_code'] == -2
            and status['validator_cleanup']['reaped'] is True
            and status['runner_cleanup']['exit_code'] == 0
            and status['runner_cleanup']['reaped'] is True,
            'bounded clone and observed cleanup policy required')
    result = {'schema': 'part5-v3-own-revocation-evidence-v1',
              'verified': True, 'training_only': True,
              'registry_history_authenticated': True,
              'application_effect': False, 'request_unconsumed': True,
              'rejected_wires': ['R0 Full', 'R1 Anchor'],
              'policy_error_code': 713,
              'base_root': report['base_root'], 'near_root': report['near_root'],
              'revoked_root': report['current_root'],
              'finalized_slot': report['finalized_slot'],
              'loaded_elf_sha256': report['loaded_program']['elf_sha256'],
              'stage_report_sha256': report['stage_report_sha256'],
              'transition_report_sha256': report['transition_report_sha256'],
              'branch_report_sha256': sha(report_path),
              'outer_report_sha256': sha(outer_path),
              'signed_history_sha256': report['signed_history_sha256'],
              'request_sha256': report['account_sha256'][3],
              'queue_sha256': report['account_sha256'][4],
              'clone_inventory_sha256': clone['tree_sha256'],
              'outer_wall_seconds': outer['duration_seconds'],
              'outer_passed': False,
              'outer_exit_note': 'branch supervisor returns one after expected validator SIGINT; finalized branch verified',
              'complete_tree_cpu_qualified': False}
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('fresh scrubbed receipt required')
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('config', 'status', 'outer', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = verify(args.config, args.status, args.outer, args.output)
    print(json.dumps({'verified': result['verified'],
                      'branch_report_sha256': result['branch_report_sha256']}))


if __name__ == '__main__':
    main()
