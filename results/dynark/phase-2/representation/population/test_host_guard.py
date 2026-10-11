"""Deterministic authored tests. No test invocation or host queries at import."""
import signal
import subprocess
import unittest
from unittest.mock import Mock, patch
import host_guard as h


def samples(count=31):
    return [dict(pressure=1, swapins=0, swapouts=0, swap_used_m=12082.62,
                 page_size=16384, monotonic=float(i)) for i in range(count)]


def row(ppid=0, birth='Sat Oct 10 23:00:00 2026', state='S'):
    return dict(ppid=ppid, pgid=100, rss_bytes=1024, state=state, birth=birth)


class HostPolicy(unittest.TestCase):
    def test_percentage_is_telemetry(self):
        self.assertEqual(h.percent('System-wide memory free percentage: 51%\n'), 51)
        for text in ('normal', 'System-wide memory free percentage: 101%',
                     'System-wide memory free percentage: 1%\n'*2):
            with self.assertRaises(ValueError): h.percent(text)

    def test_vm_and_pressure_parsers_fail_closed(self):
        self.assertEqual(h.vm('Mach Virtual Memory Statistics: (page size of 16384 bytes)\nSwapins: 12.\nSwapouts: 3.\n'),
                         dict(page_size=16384, swapins=12, swapouts=3))
        for flag in (1, 2, 4): self.assertEqual(h.pressure(str(flag)+'\n'), flag)
        for text in ('0', '3', '1\n2', 'normal'):
            with self.assertRaises(ValueError): h.pressure(text)
        with self.assertRaises(ValueError): h.vm('Swapins: 1.')
        with self.assertRaises(ValueError): h.swap_occupancy('used = nanM')
        self.assertEqual(h.swap_occupancy('vm.swapusage: used = 12082.62M'), 12082.62)

    def test_query_timeout_is_finite(self):
        with patch.object(h.subprocess, 'run', side_effect=subprocess.TimeoutExpired('q', 2)) as run:
            with self.assertRaises(subprocess.TimeoutExpired): h.query(['read-only'])
            self.assertEqual(run.call_args.kwargs['timeout'], 2)

    def test_admission_normal_window_occupancy_and_activity(self):
        s=samples(); self.assertIsNone(h.admission_failure(s))
        self.assertEqual(h.admission_failure(s[:-1]), 'admission_sample_count')
        s[-1]['monotonic']=29.9
        self.assertEqual(h.admission_failure(s), 'admission_window_short')
        for flag in (2, 4, 3):
            s=samples();s[4]['pressure']=flag
            self.assertEqual(h.admission_failure(s), 'pressure_not_normal')
        s=samples();s[-1]['swapouts']=1
        self.assertEqual(h.admission_failure(s), 'swapout_activity')
        s=samples();s[-1]['swapins']=129
        self.assertEqual(h.admission_failure(s), 'swapin_budget')
        s=samples();s[-1]['swap_used_m']+=16
        self.assertIsNone(h.admission_failure(s))
        s[-1]['swap_used_m']+=0.01
        self.assertEqual(h.admission_failure(s), 'swap_occupancy_growth')

    def test_isolated_swapins_and_three_consecutive_activity(self):
        s=samples()
        for i,x in enumerate(s): x['swapins']=min(i,2)
        self.assertIsNone(h.admission_failure(s))
        for i,x in enumerate(s): x['swapins']=i
        self.assertEqual(h.admission_failure(s), 'sustained_swap_activity')

    def test_counter_reset_and_page_size_drift(self):
        for key,value in [('swapins',-1), ('swapouts',-1), ('page_size',4096)]:
            s=samples();s[-1][key]=value
            with self.assertRaises(ValueError): h.deltas(s)

    def test_runtime_warning_critical_and_unknown(self):
        s=samples(2);s[-1]['pressure']=2
        self.assertIsNone(h.runtime_failure(s))
        s=[dict(x,pressure=2) for x in samples(3)]
        self.assertEqual(h.runtime_failure(s), 'sustained_warning')
        for flag,reason in [(4,'critical_pressure'),(0,'unknown_pressure')]:
            s=samples(1);s[-1]['pressure']=flag
            self.assertEqual(h.runtime_failure(s), reason)

    def test_runtime_window_uses_time_not_sample_count(self):
        s=samples(61)
        for i,x in enumerate(s): x['monotonic']=i*0.5;x['swapins']=129 if i>0 else 0
        self.assertEqual(h.runtime_failure(s), 'rolling_swapin_budget')
        s=samples(40);s[0]['swapouts']=0
        for x in s[1:]: x['swapouts']=1
        self.assertIsNone(h.runtime_failure(s))

    def test_reordered_or_duplicate_intermediate_samples_rejected(self):
        for value in (3.0,5.0,float('nan')):
            s=samples();s[4]['monotonic']=value
            with self.assertRaises(ValueError):h.admission_failure(s)
            with self.assertRaises(ValueError):h.runtime_failure(s)

    def test_occupancy_peak_cannot_be_hidden_by_endpoint(self):
        s=samples();s[5]['swap_used_m']+=16.01
        self.assertEqual(h.admission_failure(s),'swap_occupancy_growth')
        self.assertEqual(h.runtime_failure(s),'swap_occupancy_growth')
        s=samples();s[4]['swap_used_m']-=17
        self.assertEqual(h.admission_failure(s),'swap_occupancy_growth')


class OwnedStop(unittest.TestCase):
    def test_process_parser(self):
        text='100 1 100 12 S Sat Oct 10 23:00:00 2026\n'
        self.assertEqual(h.parse_processes(text)[100]['rss_bytes'],12*1024)
        with self.assertRaises(ValueError): h.parse_processes('100 1')

    def test_birth_and_ancestry_not_unrelated_or_reused_pid(self):
        snapshot={100:row(),101:row(100),200:row(1),300:row(1,birth='new')}
        known={300:'old'}
        selected=h.owned_processes(snapshot,100,snapshot[100]['birth'],known)
        self.assertEqual(set(selected),{100,101})
        reparented={101:row(1),200:row(1)}
        self.assertEqual(set(h.owned_processes(reparented,100,'old',known)),{101})
        reused={100:row(birth='different'),101:row(100,birth='different')}
        self.assertEqual(h.owned_processes(reused,100,'old',{}),{})

    def test_recheck_birth_before_each_signal(self):
        child=Mock(pid=100)
        with patch.object(h,'processes',return_value={100:row()}): owned=h.OwnedChild(child)
        with patch.object(owned,'sample',return_value={100:row(),101:row(100)}), \
             patch.object(h,'processes',return_value={100:row(),101:row(100,birth='reused')}), \
             patch.object(h.os,'kill') as kill, patch.object(h.os,'getpid',return_value=999):
            owned.signal(signal.SIGTERM)
            kill.assert_called_once_with(100,signal.SIGTERM)

    def make_owned(self):
        child=Mock(pid=100)
        with patch.object(h,'processes',return_value={100:row()}):
            return h.OwnedChild(child)

    def test_runner_only_first_sigint(self):
        owned=self.make_owned()
        with patch.object(owned,'sample',return_value={100:row(),101:row(100)}), \
             patch.object(h,'processes',return_value={100:row(),101:row(100)}), \
             patch.object(h.os,'kill') as kill, patch.object(h.os,'getpid',return_value=999):
            self.assertTrue(owned.signal_runner(signal.SIGINT))
            kill.assert_called_once_with(100,signal.SIGINT)

    def test_cooperative_stop_success_does_not_fallback(self):
        owned=self.make_owned();owned.child.poll.return_value=0;events=[]
        with patch.object(owned,'signal_runner',return_value=True) as first, \
             patch.object(owned,'sample',return_value={}), patch.object(owned,'signal') as fallback:
            self.assertTrue(owned.stop('critical_pressure',events.append))
            first.assert_called_once_with(signal.SIGINT);fallback.assert_not_called()
        self.assertEqual(events[-1]['event'],'cooperative_stop_complete')
        self.assertTrue(events[-1]['cleanup_verified'])

    def test_cooperative_timeout_logs_verified_fallback(self):
        owned=self.make_owned();owned.child.poll.return_value=0;events=[]
        # Expire cooperative grace, then observe TERM success immediately.
        with patch.object(owned,'signal_runner',return_value=True), \
             patch.object(h.time,'monotonic',side_effect=[0,31,32,33]), \
             patch.object(owned,'sample',return_value={}), patch.object(owned,'signal') as fallback:
            self.assertTrue(owned.stop('sustained_warning',events.append))
            fallback.assert_called_once_with(signal.SIGTERM)
        self.assertEqual([e['event'] for e in events],
                         ['owned_stop','cooperative_sigint','fallback_term','fallback_stop_complete'])

    def test_reused_runner_birth_gets_no_sigint(self):
        owned=self.make_owned()
        with patch.object(owned,'sample',return_value={}), \
             patch.object(h,'processes',return_value={100:row(birth='new'),999:row()}), \
             patch.object(h.os,'kill') as kill:
            self.assertFalse(owned.signal_runner(signal.SIGINT));kill.assert_not_called()

    def test_ps_failure_cannot_be_cleanup_success(self):
        owned=self.make_owned();owned.child.poll.return_value=0;events=[]
        with patch.object(owned,'signal_runner',side_effect=ValueError('ps')), \
             patch.object(owned,'sample',return_value={}):
            self.assertFalse(owned.stop('rolling_swapout_activity',events.append))
        self.assertTrue(all(e['primary_cause']=='rolling_swapout_activity' for e in events))
        self.assertFalse(events[-1]['cleanup_verified'])

    def test_repeated_interrupts_preserve_primary_and_unverified(self):
        owned=self.make_owned();owned.child.poll.return_value=0;events=[]
        with patch.object(owned,'signal_runner',side_effect=KeyboardInterrupt), \
             patch.object(owned,'sample',side_effect=[KeyboardInterrupt(),{}]), \
             patch.object(h.time,'sleep',side_effect=KeyboardInterrupt):
            self.assertFalse(owned.stop('critical_pressure',events.append))
        self.assertTrue(all(e['primary_cause']=='critical_pressure' for e in events))
        self.assertGreaterEqual(sum(e['event']=='owned_cleanup_issue' for e in events),3)
        self.assertFalse(events[-1]['cleanup_verified'])


if __name__=='__main__': unittest.main()
