"""Finite, read-only macOS host policy; thresholds are experiment choices.

No pressure generation. Percentage and occupied swap are telemetry, not available
physical capacity or swap activity. Callers retain all samples and stop causes.
"""
import os
import math
import re
import signal
import subprocess
import time

QUERY_TIMEOUT = 2
ADMISSION_SAMPLES = 31
INTERVAL_SECONDS = 1
COOPERATIVE_GRACE_SECONDS = 30
FALLBACK_GRACE_SECONDS = 5


def query(argv):
    began = time.monotonic()
    result = subprocess.run(argv, capture_output=True, text=True,
                            timeout=QUERY_TIMEOUT, check=True)
    return result.stdout, time.monotonic() - began


def percent(text):
    matches = re.findall(r'^System-wide memory free percentage: (\d+)%$', text, re.M)
    if len(matches) != 1 or not 0 <= int(matches[0]) <= 100:
        raise ValueError('percentage_parse')
    return int(matches[0])


def vm(text):
    matches = re.findall(r'page size of (\d+) bytes', text)
    if len(matches) != 1 or int(matches[0]) <= 0:
        raise ValueError('vm_page_size_parse')
    result = {'page_size': int(matches[0])}
    for key, label in [('swapins', 'Swapins'), ('swapouts', 'Swapouts')]:
        matches = re.findall(r'^' + label + r':\s+(\d+)\.$', text, re.M)
        if len(matches) != 1:
            raise ValueError('vm_swap_parse')
        result[key] = int(matches[0])
    return result


def pressure(text):
    if not re.fullmatch(r'\d+\s*', text):
        raise ValueError('pressure_parse')
    value = int(text)
    if value not in (1, 2, 4):
        raise ValueError('unknown_pressure')
    return value


def swap_occupancy(text):
    matches = re.findall(r'used = (\d+(?:\.\d+)?)M', text)
    if len(matches) != 1:
        raise ValueError('swap_occupancy_parse')
    return float(matches[0])


def host():
    began = time.monotonic()
    p, pd = query(['/usr/sbin/sysctl', '-n', 'kern.memorystatus_vm_pressure_level'])
    v, vd = query(['/usr/bin/vm_stat'])
    s, sd = query(['/usr/sbin/sysctl', 'vm.swapusage'])
    ended = time.monotonic()
    return dict(vm(v), pressure=pressure(p), swap_used_m=swap_occupancy(s),
                monotonic=ended, query_ns=int((ended-began)*1e9),
                command_seconds=[pd, vd, sd])


def deltas(samples):
    if any(not math.isfinite(x['monotonic']) for x in samples):
        raise ValueError('sample_time_order')
    result = []
    for a, b in zip(samples, samples[1:]):
        if b['monotonic'] <= a['monotonic']:
            raise ValueError('sample_time_order')
        di, do = b['swapins']-a['swapins'], b['swapouts']-a['swapouts']
        if min(di, do) < 0 or a['page_size'] != b['page_size']:
            raise ValueError('vm_counter_reset')
        result.append((di, do))
    return result


def active_three(ds):
    return any(all(sum(x) > 0 for x in ds[i:i+3]) for i in range(len(ds)-2))


def occupancy_growth(samples):
    low = samples[0]['swap_used_m']
    growth = 0
    for sample in samples:
        value = sample['swap_used_m']
        growth = max(growth, value-low)
        low = min(low, value)
    return growth


def admission_failure(samples):
    if len(samples) != ADMISSION_SAMPLES:
        return 'admission_sample_count'
    if any(x['pressure'] != 1 for x in samples):
        return 'pressure_not_normal'
    # No short/duplicate observation window may satisfy the 30-second gate.
    if samples[-1]['monotonic']-samples[0]['monotonic'] < 30:
        return 'admission_window_short'
    ds = deltas(samples)
    if sum(x[1] for x in ds) > 0:
        return 'swapout_activity'
    if sum(x[0] for x in ds) > 128:
        return 'swapin_budget'
    if active_three(ds):
        return 'sustained_swap_activity'
    if occupancy_growth(samples) > 16:
        return 'swap_occupancy_growth'
    return None


def runtime_failure(samples):
    deltas(samples)  # Reject reordered samples even outside the rolling window.
    last = samples[-1]
    if last['pressure'] not in (1, 2, 4):
        return 'unknown_pressure'
    if last['pressure'] == 4:
        return 'critical_pressure'
    if len(samples) >= 3 and all(x['pressure'] == 2 for x in samples[-3:]):
        return 'sustained_warning'
    # Include the last sample at/before 30s for a conservative full window.
    first = len(samples)-1
    while first > 0 and last['monotonic']-samples[first]['monotonic'] < 30:
        first -= 1
    window = samples[first:]
    ds = deltas(window)
    if len(ds) >= 3 and all(sum(x) > 0 for x in ds[-3:]):
        return 'sustained_swap_activity'
    if sum(x[1] for x in ds) > 0:
        return 'rolling_swapout_activity'
    if sum(x[0] for x in ds) > 128:
        return 'rolling_swapin_budget'
    if occupancy_growth(window) > 16:
        return 'swap_occupancy_growth'
    return None


def parse_processes(text):
    result = {}
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6:
            raise ValueError('process_parse')
        pid, ppid, pgid, rss = map(int, fields[:4])
        if pid in result or pid <= 0 or min(ppid, pgid, rss) < 0:
            raise ValueError('process_parse')
        result[pid] = dict(ppid=ppid, pgid=pgid, rss_bytes=rss*1024,
                           state=fields[4], birth=fields[5])
    return result


def processes():
    text, _ = query(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,rss=,stat=,lstart='])
    return parse_processes(text)


def owned_processes(snapshot, leader_pid, leader_birth, known):
    # A PID is never evidence by itself. Retain observed births after reparenting.
    selected = {pid for pid, birth in known.items()
                if pid in snapshot and snapshot[pid]['birth'] == birth}
    leader = snapshot.get(leader_pid)
    if leader and leader['birth'] == leader_birth:
        selected.add(leader_pid)
    while True:
        new = {pid for pid, row in snapshot.items() if row['ppid'] in selected}
        if new <= selected:
            break
        selected |= new
    for pid in selected:
        known[pid] = snapshot[pid]['birth']
    return {pid: snapshot[pid] for pid in selected
            if not snapshot[pid]['state'].startswith('Z')}


class OwnedChild:
    """Only a caller-created Popen child and observed descendants are signalable.

No broad process-group kill. macOS lstart has one-second resolution; birth plus
tracked ancestry narrows PID reuse but is not a kernel process handle guarantee.
Unobserved descendants that escape/reparent before a snapshot may be missed.
"""
    def __init__(self, child):
        self.child = child
        snapshot = processes()
        row = snapshot.get(child.pid)
        if row is None and child.poll() is None:
            raise ValueError('owned_birth_missing')
        self.birth = row['birth'] if row else None
        self.known = {child.pid: self.birth} if row else {}

    def sample(self):
        return owned_processes(processes(), self.child.pid, self.birth, self.known)

    def signal(self, sig):
        candidates = self.sample()
        for pid, row in sorted(candidates.items(), reverse=True):
            current = processes().get(pid)
            if current and current['birth'] == row['birth'] and pid != os.getpid():
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass

    def signal_runner(self, sig):
        # Only the still-owned report-producing bounded runner receives SIGINT.
        self.sample()  # Record descendants before cooperative cleanup starts.
        current = processes().get(self.child.pid)
        if current and current['birth'] == self.birth and self.child.pid != os.getpid():
            try:
                os.kill(self.child.pid, sig)
                return True
            except ProcessLookupError:
                pass
        return False

    def stop(self, primary, emit):
        issues = []
        def issue(error, phase):
            issues.append(type(error).__name__)
            emit({'event': 'owned_cleanup_issue', 'primary_cause': primary,
                  'supplemental_cause': type(error).__name__, 'phase': phase})
        def wait_empty(seconds, phase):
            until = time.monotonic()+seconds
            while time.monotonic() < until:
                try:
                    exited = self.child.poll() is not None
                    if not self.sample() and exited:
                        return True
                    time.sleep(0.2)
                except BaseException as error:
                    issue(error, phase)
                    try:
                        time.sleep(0.2)
                    except BaseException as interruption:
                        issue(interruption, phase)
            return False
        emit({'event': 'owned_stop', 'primary_cause': primary,
              'runner_pid': self.child.pid, 'runner_birth': self.birth})
        try:
            sent = self.signal_runner(signal.SIGINT)
            emit({'event': 'cooperative_sigint', 'primary_cause': primary,
                  'runner_pid': self.child.pid, 'runner_birth': self.birth,
                  'signal_sent': sent, 'grace_seconds': COOPERATIVE_GRACE_SECONDS})
        except BaseException as error:
            issue(error, 'cooperative_sigint')
        if wait_empty(COOPERATIVE_GRACE_SECONDS, 'cooperative_wait'):
            emit({'event': 'cooperative_stop_complete', 'primary_cause': primary,
                  'cleanup_verified': not issues})
            return not issues
        for sig, phase in ((signal.SIGTERM, 'fallback_term'), (signal.SIGKILL, 'fallback_kill')):
            emit({'event': phase, 'primary_cause': primary,
                  'grace_seconds': FALLBACK_GRACE_SECONDS})
            try:
                self.signal(sig)
            except BaseException as error:
                issue(error, phase)
            if wait_empty(FALLBACK_GRACE_SECONDS, phase):
                emit({'event': 'fallback_stop_complete', 'primary_cause': primary,
                      'cleanup_verified': not issues})
                return not issues
        emit({'event': 'owned_cleanup_issue', 'primary_cause': primary,
              'supplemental_cause': 'cleanup_remaining_or_unverified'})
        return False
