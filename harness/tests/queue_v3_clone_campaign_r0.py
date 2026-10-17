#!/usr/bin/env python3
"""Clone a stopped, signed eleven-leaf R0 ledger for one campaign count."""
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


def pinned(path, expected):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('campaign R0 evidence pin mismatch')
    return json.loads(raw)


def clone(stage_config, config_sha, stage_report, report_sha, stage_status,
          status_sha, stage_monitor, monitor_sha, monitor_owner, destination):
    ports_free()
    config = pinned(stage_config, config_sha)
    report = pinned(stage_report, report_sha)
    status = pinned(stage_status, status_sha)
    monitor = pinned(stage_monitor, monitor_sha)
    if (config.get('scope') != 'part5-v3-campaign-stage'
            or config.get('stage_output') != str(Path(stage_report).parent)
            or status.get('scope') != 'part5-v3-campaign-stage'
            or status.get('config_sha256') != config_sha
            or status.get('stage_report_sha256') != report_sha
            or status.get('stage_verified') is not True
            or status.get('stage_output') != config['stage_output']
            or status.get('application_effect') is not False
            or status.get('ledger_reuse_requires_review') is not True
            or status.get('validator_cleanup', {}).get('exit_code') != -2
            or status['validator_cleanup'].get('reaped') is not True
            or status.get('runner_cleanup', {}).get('exit_code') != 0
            or status['runner_cleanup'].get('reaped') is not True
            or monitor.get('owner') != monitor_owner
            or monitor.get('stop_reason') is not None
            or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False
            or report.get('schema') != 'part5-v3-campaign-stage-v1'
            or report.get('passed') is not True
            or report.get('registry_history_authenticated') is not True
            or report.get('allocation_history_authenticated') is not True
            or report.get('application_effect') is not False
            or report.get('loaded_program', {}).get('elf_match') is not True):
        raise ValueError('reviewed stopped signed campaign R0 ledger required')
    source, destination = Path(config['ledger']), Path(destination)
    if (not source.is_absolute() or source.resolve(strict=True) != source
            or not destination.is_absolute() or destination.exists()
            or destination.is_symlink() or destination.name != 'ledger'
            or source.name != 'ledger'
            or destination.parent.resolve(strict=True) != destination.parent
            or source in destination.parents or destination in source.parents
            or source == destination):
        raise ValueError('fresh separate campaign ledger destination required')
    excluded_socket = stale_admin_socket(source)
    before = inventory(source)
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2,
                    ignore=lambda directory, names: {'admin.rpc'}
                    if excluded_socket and Path(directory) == source else set())
    if before != inventory(source) or before != inventory(destination):
        raise ValueError('R0 ledger changed or clone differs')
    result = {'schema': 'part5-v3-campaign-r0-ledger-clone-v1',
              'training_only': True, 'stage_report_sha256': report_sha,
              'stage_status_sha256': status_sha, 'stage_monitor_sha256': monitor_sha,
              'source': str(source), 'destination': str(destination),
              'entry_count': len(before),
              'tree_sha256': hashlib.sha256(json.dumps(before, separators=(',', ':')).encode()).hexdigest(),
              'source_stable': True, 'copy_identical': True,
              'excluded_stale_admin_socket': excluded_socket,
              'loaded_identity_rechecked_after_restart': False,
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
    for name in ('stage_config', 'config_sha', 'stage_report', 'report_sha',
                 'stage_status', 'status_sha', 'stage_monitor', 'monitor_sha',
                 'monitor_owner', 'destination'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    result = clone(**vars(parser.parse_args()))
    print(json.dumps({'copy_identical': result['copy_identical'],
                      'tree_sha256': result['tree_sha256'],
                      'entries': result['entry_count']}))


if __name__ == '__main__':
    main()
