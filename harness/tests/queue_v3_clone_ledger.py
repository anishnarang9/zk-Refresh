#!/usr/bin/env python3
"""Clone a stopped, reviewed v3 R1 ledger into an owner-only training branch.

The copy is checked against a second source inventory after copying. A restart
must still reattest the loaded ELF and exact finalized application accounts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def stale_admin_socket(root):
    path = Path(root) / 'admin.rpc'
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISSOCK(info.st_mode):
        return False
    if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1):
        raise ValueError('unexpected administrative socket shape')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(0.2)
        try:
            client.connect(str(path))
        except ConnectionRefusedError:
            return True
    raise ValueError('active administrative socket; ledger is not stopped')


def inventory(root):
    root = Path(root)
    base = root.resolve(strict=True)
    if base != root or not root.is_dir():
        raise ValueError('canonical ledger directory required')
    rows = []
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if relative == 'admin.rpc' and stale_admin_socket(root):
                continue
            info = path.lstat()
            if info.st_uid != os.getuid():
                raise ValueError('foreign ledger entry')
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError('owner-only ledger directory required')
                rows.append([relative, 'directory', 0, ''])
            elif stat.S_ISREG(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError('owner-only ledger file required')
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(65536), b''):
                        digest.update(chunk)
                rows.append([relative, 'file', info.st_size, digest.hexdigest()])
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                try:
                    internal = path.resolve(strict=True).is_relative_to(base)
                except OSError:
                    internal = False
                if Path(target).is_absolute() or not internal:
                    raise ValueError('ledger link escapes its tree')
                rows.append([relative, 'link', 0, target])
            else:
                raise ValueError('unsupported ledger entry')
    rows.sort()
    return rows


def clone(source, destination, transition_report, transition_sha, transition_status,
          status_sha, transition_monitor, monitor_sha):
    from harness.tests.queue_v3_local_prepare import PORT_WAIT_SECONDS, ports_free
    ports_free(timeout_seconds=PORT_WAIT_SECONDS)
    def pinned(path, expected):
        data = Path(path).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('transition evidence pin mismatch')
        return json.loads(data)
    report = pinned(transition_report, transition_sha)
    status = pinned(transition_status, status_sha)
    monitor = pinned(transition_monitor, monitor_sha)
    if (report.get('schema') != 'part5-v3-unrelated-local-transition-v1'
            or report.get('passed') is not True or report.get('request_unconsumed') is not True
            or status.get('transition_verified') is not True
            or status.get('transition_report_sha256') != transition_sha
            or status.get('ledger_reuse_requires_review') is not True
            or status.get('validator_cleanup', {}).get('exit_code') != -2
            or monitor.get('stop_reason') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False):
        raise ValueError('reviewed stopped R1 ledger required')
    source = Path(source)
    destination = Path(destination)
    if (not source.is_absolute() or not destination.is_absolute()
            or source.resolve(strict=True) != source
            or destination.exists() or destination.is_symlink()
            or destination.parent.resolve(strict=True) != destination.parent
            or source == destination or source in destination.parents
            or destination in source.parents):
        raise ValueError('fresh separate canonical clone target required')
    if source.name != 'ledger' or destination.name != 'ledger':
        raise ValueError('ledger path required')
    excluded_socket = stale_admin_socket(source)
    before = inventory(source)
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2,
                    ignore=lambda directory, names: {'admin.rpc'}
                    if excluded_socket and Path(directory) == source else set())
    after_source = inventory(source)
    after_target = inventory(destination)
    if before != after_source or before != after_target:
        raise ValueError('ledger changed during copy or clone differs')
    encoded = json.dumps(before, separators=(',', ':')).encode()
    result = {'schema': 'part5-v3-r1-ledger-clone-v1', 'training_only': True,
              'transition_report_sha256': transition_sha,
              'transition_status_sha256': status_sha,
              'transition_monitor_sha256': monitor_sha,
              'source': str(source), 'destination': str(destination),
              'entry_count': len(before), 'tree_sha256': hashlib.sha256(encoded).hexdigest(),
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
    for name in ('source', 'destination', 'transition_report', 'transition_sha',
                 'transition_status', 'status_sha', 'transition_monitor', 'monitor_sha'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    args = parser.parse_args()
    result = clone(**vars(args))
    print(json.dumps({'copy_identical': result['copy_identical'],
                      'tree_sha256': result['tree_sha256'], 'entries': result['entry_count']}))


if __name__ == '__main__':
    main()
