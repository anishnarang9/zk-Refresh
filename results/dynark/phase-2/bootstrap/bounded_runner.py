#!/usr/bin/env python3
"""Sampled limits for explicitly owned foreground process trees (Python stdlib).

No benchmark is authorized by this helper. Caller must obtain the execution slot,
provide credential-free argv, and name fresh public/private output paths. Children
must not daemonize or deliberately escape ancestry/group tracking. Limits are
sampled: a short RSS/storage spike between polls can be missed. RSS is resident
memory, not heap allocations; storage is logical file-byte growth, not disk blocks.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_new(path, value, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def file_bytes(path):
    """Logical regular-file sizes; never follow symlinks."""
    if not path.exists():
        return 0
    if path.is_symlink():
        raise ValueError('storage root must not be a symlink')
    if path.is_file():
        return path.stat().st_size
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
        for name in files:
            p = Path(root) / name
            try:
                if not p.is_symlink() and p.is_file():
                    total += p.stat().st_size
            except FileNotFoundError:
                pass
    return total


def processes():
    # ps reports RSS in KiB on macOS/Linux. lstart guards against PID reuse.
    result = subprocess.run(['ps', '-axo', 'pid=,ppid=,pgid=,rss=,stat=,lstart='],
                            capture_output=True, text=True, check=True, timeout=5)
    out = {}
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6:
            pid, ppid, pgid, rss = map(int, fields[:4])
            out[pid] = {'ppid': ppid, 'pgid': pgid, 'rss_bytes': rss * 1024,
                        'state': fields[4], 'birth': fields[5]}
    return out


def owned_processes(snapshot, leader_pid, known):
    # The group is fresh (start_new_session), so surviving same-group children
    # remain owned even after reparenting. Remember escaped descendants by birth.
    selected = {p for p, row in snapshot.items()
                if row['pgid'] == leader_pid or known.get(p) == row['birth']}
    while True:
        new = {p for p, row in snapshot.items() if row['ppid'] in selected}
        if new <= selected:
            break
        selected |= new
    for p in selected:
        known[p] = snapshot[p]['birth']
    return {p: snapshot[p] for p in selected if not snapshot[p]['state'].startswith('Z')}


def signal_owned(leader_pid, known, sig):
    if leader_pid == os.getpgrp():
        raise RuntimeError('refusing to signal caller process group')
    # Popen(start_new_session=True) established this fresh group. Kill it
    # without depending on process inspection, including monitor failures.
    try:
        os.killpg(leader_pid, sig)
    except ProcessLookupError:
        pass
    snapshot = processes()
    owned = owned_processes(snapshot, leader_pid, known)
    for pid, row in owned.items():
        if row['pgid'] != leader_pid:
            # Recheck birth immediately before signaling a PID outside the group.
            current = processes().get(pid)
            if current and current['birth'] == row['birth']:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass


def run(*, owner, command, cwd, private_output, report, runtime_seconds,
        rss_bytes, storage_bytes, storage_paths=(), poll_seconds=0.2,
        environment=None):
    if not owner or not command:
        raise ValueError('named owner and nonempty argv required')
    if min(runtime_seconds, rss_bytes, storage_bytes, poll_seconds) <= 0:
        raise ValueError('limits must be positive')
    private_output, report = Path(private_output).absolute(), Path(report).absolute()
    if private_output.exists() or report.exists():
        raise FileExistsError('fresh output paths required')
    roots = [private_output] + [Path(p).absolute() for p in storage_paths]
    for i, p in enumerate(roots):
        for q in roots[i+1:]:
            if p == q or p in q.parents or q in p.parents:
                raise ValueError('storage roots must be disjoint')
    baseline = [file_bytes(p) for p in roots]
    private_output.mkdir(mode=0o700, parents=False)
    env = os.environ.copy()
    env.update(environment or {})
    private_meta = {'owner': owner, 'argv': command, 'cwd': str(Path(cwd).absolute()),
                    'started_at_utc': utc(), 'storage_roots': [str(p) for p in roots]}
    write_new(private_output / 'invocation.json', private_meta, 0o600)
    samples, known, proc, stop = [], {}, None, None
    began = time.monotonic()
    initial_utc = utc()
    stdout_fd = os.open(private_output / 'stdout.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    stderr_fd = os.open(private_output / 'stderr.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    cleanup_remaining = []
    cleanup_unknown = False
    internal_error = None
    try:
        # Always creates a new session/group in the child, including when this
        # runner is already the execution service's session/group leader.
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout_fd,
                                stderr=stderr_fd, start_new_session=True)
        while True:
            snapshot = processes()
            owned = owned_processes(snapshot, proc.pid, known)
            elapsed = time.monotonic() - began
            growth = sum(max(0, file_bytes(p)-b) for p, b in zip(roots, baseline))
            sample = {'elapsed_seconds': elapsed,
                      'owned_process_count': len(owned),
                      'owned_tree_rss_bytes': sum(row['rss_bytes'] for row in owned.values()),
                      'storage_growth_bytes': growth}
            samples.append(sample)
            if elapsed >= runtime_seconds:
                stop = 'runtime_seconds'
            elif sample['owned_tree_rss_bytes'] > rss_bytes:
                stop = 'owned_tree_rss_bytes'
            elif growth > storage_bytes:
                stop = 'storage_growth_bytes'
            if stop or (proc.poll() is not None and not owned):
                break
            time.sleep(poll_seconds)
    except BaseException as error:
        stop = 'runner_error'
        internal_error = type(error).__name__
    finally:
        if proc is not None:
            if stop:
                # TERM, KILL and wait are independent: ps failure must never
                # bypass signaling the established group or prevent evidence.
                try:
                    signal_owned(proc.pid, known, signal.SIGTERM)
                except Exception as error:
                    internal_error = type(error).__name__
                    cleanup_unknown = True
                until = time.monotonic()+2
                while time.monotonic()<until:
                    proc.poll()
                    try:
                        if not owned_processes(processes(), proc.pid, known):
                            break
                    except Exception as error:
                        internal_error = type(error).__name__
                        cleanup_unknown = True
                        break
                    time.sleep(min(poll_seconds, 0.1))
                try:
                    signal_owned(proc.pid, known, signal.SIGKILL)
                except Exception as error:
                    internal_error = type(error).__name__
                    cleanup_unknown = True
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                internal_error = 'cleanup_timeout'
                cleanup_unknown = True
            try:
                cleanup_remaining = list(owned_processes(processes(), proc.pid, known))
            except Exception as error:
                internal_error = type(error).__name__
                cleanup_unknown = True
        os.close(stdout_fd)
        os.close(stderr_fd)
    result = {'schema': 1, 'owner': owner, 'started_at_utc': initial_utc,
              'ended_at_utc': utc(), 'timezone': time.tzname,
              'duration_seconds': time.monotonic()-began,
              'limits': {'runtime_seconds': runtime_seconds, 'owned_tree_rss_bytes': rss_bytes,
                         'storage_growth_bytes': storage_bytes, 'poll_seconds': poll_seconds},
              'stop_reason': stop, 'exit_code': proc.returncode if proc else None,
              'runner_error_type': internal_error,
              'cleanup_remaining_owned_processes': len(cleanup_remaining),
              'cleanup_status_unknown': cleanup_unknown,
              'sample_count': len(samples), 'samples': samples,
              'sampled_peak_owned_tree_rss_bytes': max((s['owned_tree_rss_bytes'] for s in samples), default=0),
              'sampled_peak_storage_growth_bytes': max((s['storage_growth_bytes'] for s in samples), default=0),
              'environment': {k: env.get(k) for k in ['RAYON_NUM_THREADS', 'OMP_NUM_THREADS', 'TZ']},
              'measurement_notes': ['RSS from ps KiB converted to bytes; sum of live owned tree; not heap allocation',
                  'storage is positive logical file-size growth per supplied root; excludes deleted-file peak between samples',
                  'limits sampled; short spikes and daemonized ancestry escape between samples may be missed',
                  'samples exclude runner/ps RSS; storage report written after the measured command',
                  'child stdout/stderr/argv retained only in protected output'],
              'passed': stop is None and proc is not None and proc.returncode == 0
                        and not cleanup_remaining and not cleanup_unknown and internal_error is None}
    write_new(private_output / 'report.json', result, 0o600)
    write_new(report, result, 0o644)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--owner', required=True)
    p.add_argument('--cwd', required=True)
    p.add_argument('--private-output', required=True)
    p.add_argument('--report', required=True)
    p.add_argument('--runtime-seconds', required=True, type=float)
    p.add_argument('--rss-bytes', required=True, type=int)
    p.add_argument('--storage-bytes', required=True, type=int)
    p.add_argument('--storage-path', action='append', default=[])
    p.add_argument('--poll-seconds', type=float, default=0.2)
    p.add_argument('command', nargs=argparse.REMAINDER)
    a = p.parse_args()
    command = a.command[1:] if a.command[:1] == ['--'] else a.command
    result = run(owner=a.owner, command=command, cwd=a.cwd,
                 private_output=a.private_output, report=a.report,
                 runtime_seconds=a.runtime_seconds, rss_bytes=a.rss_bytes,
                 storage_bytes=a.storage_bytes, storage_paths=a.storage_path,
                 poll_seconds=a.poll_seconds)
    print(json.dumps({'passed': result['passed'], 'exit_code': result['exit_code'],
                      'stop_reason': result['stop_reason'], 'sample_count': result['sample_count']}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
