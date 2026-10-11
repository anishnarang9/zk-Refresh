"""Public dummy tests only; no repository cryptography or builds."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bounded_runner', HERE/'bounded_runner.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
ROOT = HERE.parents[3]
PRIVATE = ROOT/'artifacts/dynark/phase-2/bootstrap'


class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stamp = str(time.time_ns())
        cls.aggregate = []

    def trial(self, name, code, **overrides):
        prefix = name+'-'+self.stamp
        args = dict(owner='evidence_steward_dummy', command=[sys.executable, '-c', code],
                    cwd=ROOT, private_output=PRIVATE/prefix, report=HERE/(prefix+'.json'),
                    runtime_seconds=5, rss_bytes=134217728, storage_bytes=4194304,
                    poll_seconds=0.05)
        args.update(overrides)
        result = r.run(**args)
        self.aggregate.append({'name': name, 'passed': result['passed'],
                               'stop_reason': result['stop_reason'], 'report': prefix+'.json'})
        self.assertEqual(result['cleanup_remaining_owned_processes'], 0)
        self.assertEqual(args['private_output'].stat().st_mode & 0o777, 0o700)
        for p in args['private_output'].iterdir():
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        return result, args

    def test_success_and_fresh_output(self):
        result, args = self.trial('success', "print('public dummy')")
        self.assertTrue(result['passed'])
        with self.assertRaises(FileExistsError):
            r.run(**args)

    def test_nonzero_exit(self):
        result, _ = self.trial('nonzero', 'raise SystemExit(7)')
        self.assertEqual(result['exit_code'], 7)
        self.assertFalse(result['passed'])
        self.assertIsNone(result['stop_reason'])

    def test_timeout_descendants_and_unrelated_process(self):
        unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'],
                                      start_new_session=True)
        try:
            code = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)']); time.sleep(10)"
            result, _ = self.trial('timeout', code, runtime_seconds=0.5)
            self.assertEqual(result['stop_reason'], 'runtime_seconds')
            self.assertGreaterEqual(max(s['owned_process_count'] for s in result['samples']), 2)
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=3)

    def test_rss_limit(self):
        result, _ = self.trial('rss', 'import time; b=bytearray(24*1024*1024); time.sleep(3)',
                               rss_bytes=20*1024*1024)
        self.assertEqual(result['stop_reason'], 'owned_tree_rss_bytes')

    def test_storage_limit(self):
        target = PRIVATE/('storage-target-'+self.stamp)
        target.mkdir(mode=0o700)
        # Retained growth is outside output directory, as with a Cargo target.
        code = "from pathlib import Path; import time; Path("+repr(str(target/'dummy.bin'))+").write_bytes(b'x'*1048576); time.sleep(3)"
        result, _ = self.trial('storage', code, storage_bytes=524288, storage_paths=[target])
        os.chmod(target/'dummy.bin', 0o600)
        self.assertEqual(result['stop_reason'], 'storage_growth_bytes')

    def test_process_inspection_failure_cleanup_and_report(self):
        spawned = []
        original = subprocess.Popen
        def capture(*a, **kw):
            process = original(*a, **kw)
            spawned.append(process)
            return process
        with mock.patch.object(r, 'processes', side_effect=RuntimeError('dummy ps failure')):
            with mock.patch.object(r.subprocess, 'Popen', side_effect=capture):
                result, args = self.trial('inspection-failure', 'import time; time.sleep(10)')
        self.assertEqual(result['stop_reason'], 'runner_error')
        self.assertTrue(result['cleanup_status_unknown'])
        self.assertFalse(result['passed'])
        self.assertIsNotNone(spawned[0].poll())
        self.assertTrue(args['report'].exists())

    def test_group_leader_invocation(self):
        name = 'leader-'+self.stamp
        command = [sys.executable, str(HERE/'bounded_runner.py'), '--owner', 'dummy_group_leader',
                   '--cwd', str(ROOT), '--private-output', str(PRIVATE/name),
                   '--report', str(HERE/(name+'.json')), '--runtime-seconds', '3',
                   '--rss-bytes', '134217728', '--storage-bytes', '4194304', '--',
                   sys.executable, '-c', "print('public dummy')"]
        completed = subprocess.run(command, start_new_session=True, capture_output=True,
                                   text=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.aggregate.append({'name': 'group_leader', 'passed': True, 'report': name+'.json'})

    @classmethod
    def tearDownClass(cls):
        r.write_new(HERE/('dummy-tests-'+cls.stamp+'.json'),
                    {'schema': 1, 'trials': cls.aggregate}, 0o644)


if __name__ == '__main__':
    unittest.main(verbosity=2)
