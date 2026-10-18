import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from tools.part5 import record_v3_direct_arm_span as recorder


STEP_NAMES = ('prepare', 'stage', 'transition', 'source-r0', 'source-r1',
              'proof', 'clone', 'effect', 'cleanup')


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        self.value += 1.0
        return self.value

    def utc_now(self):
        return f'2026-10-18T00:00:{int(self.value):02d}Z'


def _identity(mode='Full-B'):
    return {
        'mode': mode,
        'credential_sha256': hashlib.sha256(b'credential').hexdigest(),
        'action_sha256': hashlib.sha256(b'action').hexdigest(),
        'root_sha256': hashlib.sha256(b'root').hexdigest(),
        'setup_sha256': hashlib.sha256(b'setup').hexdigest(),
        'vk_sha256': hashlib.sha256(b'vk').hexdigest(),
        'elf_sha256': hashlib.sha256(b'elf').hexdigest(),
    }


def _steps(order=None, fail=None):
    calls = []
    steps = []
    for name in (order or STEP_NAMES):
        def run(name=name):
            calls.append(name)
            result = {'passed': True, 'private_path': '/private/should/not/appear'}
            if name == 'effect':
                result['effect_verified'] = True
            if name == 'cleanup':
                result.update(remaining_owned_processes=0, status_known=True)
            if name == fail:
                result['passed'] = False
            return result
        steps.append((name, run))
    return steps, calls


class DirectArmSpanTests(unittest.TestCase):
    def test_direct_span_includes_interstep_gaps_and_writes_private_free_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'arm.json'
            clock = FakeClock()
            steps, calls = _steps()
            report = recorder.record_arm(_identity(), steps, output, clock=clock)

            self.assertEqual(calls, list(STEP_NAMES))
            self.assertTrue(report['directly_timed'])
            self.assertFalse(report['full_application_evidence_established'])
            self.assertEqual(report['integration_status'], 'source-level-helper-only')
            self.assertEqual(report['direct_duration_seconds'], 19.0)
            self.assertEqual(report['utc_monotonic_disagreement_seconds'], 0.0)
            self.assertEqual(sum(report['step_durations_seconds'].values()), 9.0)
            self.assertGreater(report['direct_duration_seconds'],
                               sum(report['step_durations_seconds'].values()))
            self.assertEqual(report['start_utc'], '2026-10-18T00:00:01Z')
            self.assertEqual(report['end_utc'], '2026-10-18T00:00:20Z')
            raw = output.read_bytes()
            self.assertEqual(json.loads(raw), report)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            self.assertNotIn(b'/private/', raw)

    def test_failed_step_leaves_no_success_receipt_and_uses_path_free_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'arm.json'
            steps, calls = _steps(fail='proof')
            with self.assertRaisesRegex(ValueError, '^arm step failed$') as caught:
                recorder.record_arm(_identity(), steps, output, clock=FakeClock())
            self.assertEqual(calls, list(STEP_NAMES[:6]) + ['cleanup'])
            self.assertFalse(output.exists())
            self.assertNotIn(temporary, str(caught.exception))

    def test_failed_step_with_failed_cleanup_reports_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'arm.json'
            steps, calls = _steps(fail='proof')
            steps[-1] = ('cleanup', lambda: {'passed': False})
            with self.assertRaisesRegex(ValueError, 'arm cleanup is incomplete'):
                recorder.record_arm(_identity(), steps, output, clock=FakeClock())
            self.assertEqual(calls, list(STEP_NAMES[:6]))
            self.assertFalse(output.exists())

    def test_rejects_wrong_order_effect_or_cleanup_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'arm.json'
            wrong_order, _ = _steps(order=STEP_NAMES[::-1])
            with self.assertRaisesRegex(ValueError, 'step order'):
                recorder.record_arm(_identity(), wrong_order, output, clock=FakeClock())
            effect, _ = _steps()
            effect[7] = ('effect', lambda: {'passed': True, 'effect_verified': False})
            with self.assertRaisesRegex(ValueError, 'effect verification'):
                recorder.record_arm(_identity(), effect, output, clock=FakeClock())
            cleanup, _ = _steps()
            cleanup[-1] = ('cleanup', lambda: {
                'passed': True, 'remaining_owned_processes': 1, 'status_known': True})
            with self.assertRaisesRegex(ValueError, 'cleanup'):
                recorder.record_arm(_identity(), cleanup, output, clock=FakeClock())
            self.assertFalse(output.exists())

    def test_validates_identity_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'arm.json'
            output.write_text('keep')
            steps, _ = _steps()
            with self.assertRaisesRegex(ValueError, 'fresh output'):
                recorder.record_arm(_identity(), steps, output, clock=FakeClock())
            self.assertEqual(output.read_text(), 'keep')

            output.unlink()
            identity = _identity()
            identity['vk_sha256'] = 'not-a-hash'
            steps, _ = _steps()
            with self.assertRaisesRegex(ValueError, 'identity'):
                recorder.record_arm(identity, steps, output, clock=FakeClock())
            self.assertFalse(output.exists())

    def test_clock_disagreement_fails_closed_without_receipt(self):
        class SuspendedClock(FakeClock):
            def utc_now(self):
                return '2026-10-18T00:00:01Z' if self.value < 20 else '2026-10-18T01:00:20Z'

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'arm.json'
            steps, calls = _steps()
            with self.assertRaisesRegex(ValueError, 'clock disagreement'):
                recorder.record_arm(_identity(), steps, output, clock=SuspendedClock())
            self.assertEqual(calls, list(STEP_NAMES))
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
