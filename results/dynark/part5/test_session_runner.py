"""Small public dummy processes only; no proving, builds, or validator."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


class SessionRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('session_runner', HERE / 'session_runner.py')
        cls.r = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.r)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='session-runner-public-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def trial(self, code, **changes):
        args = dict(owner='public_dummy', command=[sys.executable, '-c', code],
                    cwd=self.root, private_output=self.root/'private', report=self.root/'report.json',
                    runtime_seconds=5, rss_bytes=128*1024*1024, storage_bytes=4*1024*1024,
                    poll_seconds=0.03)
        args.update(changes)
        result = self.r.run(**args)
        self.assertEqual(result['cleanup_remaining_owned_processes'], 0)
        self.assertFalse(result['cleanup_status_unknown'])
        return result, args

    def test_success_cpu_and_private_reports(self):
        code = 'import time; end=time.process_time()+0.15\nwhile time.process_time()<end: pass'
        result, args = self.trial(code)
        self.assertTrue(result['passed'])
        self.assertGreater(result['cpu']['leader_wait4_user_seconds'], 0)
        self.assertGreater(result['cpu']['leader_wait4_user_seconds'] +
                           result['cpu']['leader_wait4_system_seconds'], 0.1)
        self.assertGreaterEqual(result['cpu']['leader_wait4_system_seconds'], 0)
        self.assertGreater(result['cpu']['sampled_tree_self_seconds_lower_bound'], 0)
        self.assertFalse(result['cpu']['complete_tree_cpu_qualified'])
        self.assertEqual(args['report'].stat().st_mode & 0o777, 0o600)
        self.assertEqual(args['private_output'].stat().st_mode & 0o777, 0o700)
        for path in args['private_output'].iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('argv', json.loads(args['report'].read_text()))
        with self.assertRaises(FileExistsError):
            self.r.run(**args)

    def test_waited_descendant_cpu_is_reported_without_adding_sampled_cpu(self):
        worker = 'import time; end=time.process_time()+0.12\nwhile time.process_time()<end: pass'
        code = 'import subprocess,sys; subprocess.run([sys.executable,"-c",'+repr(worker)+'],check=True)'
        result, _ = self.trial(code)
        self.assertTrue(result['passed'])
        self.assertGreater(result['cpu']['leader_wait4_user_seconds'], 0)
        self.assertGreater(result['cpu']['leader_wait4_user_seconds'] +
                           result['cpu']['leader_wait4_system_seconds'], 0.1)
        self.assertGreaterEqual(max(s['owned_process_count'] for s in result['samples']), 2)
        self.assertIn('not additive', ' '.join(result['measurement_notes']))

    def test_timeout_cleans_descendants_and_preserves_unrelated_process(self):
        unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'], start_new_session=True)
        try:
            code = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c","import time; time.sleep(5)"]); time.sleep(5)'
            result, _ = self.trial(code, runtime_seconds=0.3)
            self.assertEqual(result['stop_reason'], 'runtime_seconds')
            self.assertTrue(result['censored'])
            self.assertIsNone(unrelated.poll())
            self.assertIsNotNone(result['cpu']['leader_wait4_user_seconds'])
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=3)

    def test_nonzero_is_failed_but_not_censored(self):
        result, _ = self.trial('raise SystemExit(7)')
        self.assertFalse(result['passed'])
        self.assertFalse(result['censored'])
        self.assertEqual(result['exit_code'], 7)

    def test_launch_failure_cpu_is_unavailable(self):
        result, _ = self.trial('pass', command=[str(self.root/'nonexistent-command')])
        self.assertFalse(result['passed'])
        self.assertTrue(result['censored'])
        self.assertIsNone(result['cpu']['leader_wait4_user_seconds'])
        self.assertIsNone(result['cpu']['leader_wait4_system_seconds'])
        self.assertIsNone(result['cpu']['sampled_tree_self_seconds_lower_bound'])

    def test_rss_cap(self):
        result, _ = self.trial('import time; b=bytearray(24*1024*1024); time.sleep(3)', rss_bytes=20*1024*1024)
        self.assertEqual(result['stop_reason'], 'owned_tree_rss_bytes')

    def test_storage_cap(self):
        target = self.root/'storage'
        target.mkdir()
        code = 'from pathlib import Path; import time; Path('+repr(str(target/'public.bin'))+').write_bytes(b"x"*1048576); time.sleep(3)'
        result, _ = self.trial(code, storage_paths=[target], storage_bytes=512*1024)
        self.assertEqual(result['stop_reason'], 'storage_growth_bytes')

    def test_inspection_failure_is_censored_and_cleanup_unknown(self):
        with mock.patch.object(self.r, 'processes', side_effect=RuntimeError('public dummy')):
            result = self.r.run(owner='public_dummy', command=[sys.executable,'-c','import time; time.sleep(5)'],
                                cwd=self.root, private_output=self.root/'private', report=self.root/'report.json',
                                runtime_seconds=1, rss_bytes=128*1024*1024, storage_bytes=1024*1024)
        self.assertFalse(result['passed'])
        self.assertTrue(result['censored'])
        self.assertTrue(result['cleanup_status_unknown'])
        self.assertEqual(result['stop_reason'], 'runner_error')
        self.assertIsNotNone(result['cpu']['leader_wait4_user_seconds'])

    def test_cpu_clock_parser_and_pid_reuse(self):
        self.assertEqual(self.r.cpu_seconds('01:02.50'), 62.5)
        self.assertEqual(self.r.cpu_seconds('1-02:03:04'), 93784)
        totals = {}
        self.r.update_cpu(totals, {12: dict(birth='first', cpu_seconds=0.2)})
        self.r.update_cpu(totals, {12: dict(birth='first', cpu_seconds=0.1)})
        self.r.update_cpu(totals, {12: dict(birth='second', cpu_seconds=0.3)})
        self.assertAlmostEqual(sum(totals.values()), 0.5)

    def test_rejects_nonfinite_limits_before_launch(self):
        for bad in (float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                self.trial('pass', runtime_seconds=bad)


if __name__ == '__main__':
    unittest.main(verbosity=2)
