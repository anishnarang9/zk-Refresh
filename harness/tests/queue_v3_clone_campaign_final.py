#!/usr/bin/env python3
"""Copy a reviewed stopped Rk ledger; restart must reattest identity and finality."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from harness.tests.queue_v3_clone_ledger import inventory, stale_admin_socket
from harness.tests.queue_v3_local_prepare import ports_free
from harness.tests import queue_v3_local_campaign_transition as transition
from harness.tests import queue_v3_local_execute as execute


def pinned(path, expected):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('campaign final evidence pin mismatch')
    return json.loads(raw)


def clone(transition_config, config_sha, transition_report, report_sha,
          transition_status, status_sha, transition_monitor, monitor_sha,
          monitor_owner, target_count, destination):
    ports_free()
    config = pinned(transition_config, config_sha)
    report = pinned(transition_report, report_sha)
    status = pinned(transition_status, status_sha)
    monitor = pinned(transition_monitor, monitor_sha)
    limits = monitor.get('limits', {})
    if (type(target_count) is not int or target_count not in transition.COUNTS
            or config.get('schema') != 1
            or config.get('scope') != 'part5-v3-campaign-transition'
            or config.get('target_count') != target_count
            or config.get('outer_limits_required') != transition.LIMITS
            or config.get('transition_output') != str(Path(transition_report).parent)
            or status.get('scope') != 'part5-v3-campaign-transition'
            or status.get('target_count') != target_count
            or status.get('config_sha256') != config_sha
            or status.get('transition_report_sha256') != report_sha
            or status.get('transition_output') != config['transition_output']
            or status.get('transition_verified') is not True
            or status.get('application_effect') is not False
            or status.get('ledger_reuse_requires_review') is not True
            or status.get('validator_cleanup', {}).get('exit_code') != -2
            or status['validator_cleanup'].get('reaped') is not True
            or status.get('runner_cleanup', {}).get('exit_code') != 0
            or status['runner_cleanup'].get('reaped') is not True
            or not monitor_owner or monitor.get('owner') != monitor_owner
            or monitor.get('exit_code') != 1
            or monitor.get('stop_reason') is not None
            or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False
            or limits.get('runtime_seconds') != transition.LIMITS['runtime_seconds']
            or limits.get('owned_tree_rss_bytes') != transition.LIMITS['rss_bytes']
            or limits.get('storage_growth_bytes') != transition.LIMITS['storage_growth_bytes']
            or not isinstance(limits.get('poll_seconds'), (int, float))
            or not 0 < limits['poll_seconds'] <= 1
            or report.get('schema') != 'part5-v3-campaign-transition-v1'
            or report.get('passed') is not True
            or report.get('target_count') != target_count
            or report.get('registry_history_authenticated') is not True
            or report.get('allocation_history_authenticated') is not True
            or report.get('request_unconsumed') is not True
            or report.get('application_effect') is not False
            or report.get('loaded_program', {}).get('elf_match') is not True):
        raise ValueError('reviewed stopped signed campaign Rk ledger required')
    execute.same_loaded(status.get('loaded_program', {}), report['loaded_program'])
    context = pinned(config['context'], config['context_sha256'])
    staged = pinned(Path(config['stage_root']) / 'stage-report.json', config['stage_report_sha256'])
    plan = pinned(Path(config['stage_root']) / 'plan.json', config['stage_plan_sha256'])
    if (any(report.get(key) != config[key] for key in
            ('context_sha256', 'stage_report_sha256', 'stage_plan_sha256'))
            or report.get('current_root') != context['root_sequence'][target_count]
            or report.get('base_root') != context['root_sequence'][0]):
        raise ValueError('exact campaign root and evidence required')
    history = pinned(Path(config['transition_output']) / 'signed-history.json',
                     report['signed_history_sha256'])
    transition.checked_history(history, context, plan, report, staged)
    source = execute.private_directory(config['ledger'])
    destination = Path(destination)
    boundary = (REPO / 'artifacts/dynark/part5').resolve(strict=True)
    if (not destination.is_absolute() or destination.exists() or destination.is_symlink()
            or destination.name != 'ledger' or source.name != 'ledger'
            or not destination.is_relative_to(boundary)
            or destination.parent.resolve(strict=True) != destination.parent
            or source == destination or source in destination.parents
            or destination in source.parents):
        raise ValueError('fresh separate absolute campaign ledger destination required')
    execute.private_directory(destination.parent)
    if (destination.parent / 'clone-report.json').exists():
        raise ValueError('fresh clone receipt required')
    excluded = stale_admin_socket(source)
    before = inventory(source)
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2,
                    ignore=lambda directory, names: {'admin.rpc'}
                    if excluded and Path(directory) == source else set())
    if before != inventory(source) or before != inventory(destination):
        raise ValueError('campaign Rk ledger changed or clone differs')
    result = {'schema': 'part5-v3-campaign-final-ledger-clone-v1', 'training_only': True,
        'transition_config_sha256': config_sha, 'transition_report_sha256': report_sha,
        'transition_status_sha256': status_sha, 'transition_monitor_sha256': monitor_sha,
        'signed_history_sha256': report['signed_history_sha256'], 'monitor_owner': monitor_owner,
        'target_count': target_count, 'current_root': report['current_root'],
        'source': str(source), 'destination': str(destination), 'entry_count': len(before),
        'tree_sha256': hashlib.sha256(json.dumps(before, separators=(',', ':')).encode()).hexdigest(),
        'source_stable': True, 'copy_identical': True, 'excluded_stale_admin_socket': excluded,
        'loaded_program': status['loaded_program'], 'ledger_reuse_requires_review': True,
        'loaded_identity_rechecked_after_restart': False, 'finality_rechecked_after_restart': False,
        'application_effect': False}
    path = destination.parent / 'clone-report.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write((json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('transition_config', 'config_sha', 'transition_report', 'report_sha',
                 'transition_status', 'status_sha', 'transition_monitor', 'monitor_sha',
                 'monitor_owner', 'destination'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    parser.add_argument('--target-count', required=True, type=int, choices=transition.COUNTS)
    result = clone(**vars(parser.parse_args()))
    print(json.dumps({'copy_identical': result['copy_identical'],
                      'target_count': result['target_count'], 'current_root': result['current_root'],
                      'tree_sha256': result['tree_sha256'], 'entries': result['entry_count']}))


if __name__ == '__main__':
    main()
