"""A direct timer receipt is consistency evidence, not a loaded result."""
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.part5 import record_v3_direct_arm_span as recorder


IDENTITY = {'mode': 'Full-B', **{name: 'a' * 64 for name in recorder.IDENTITY_FIELDS}}


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        self.value += 1.0
        return self.value

    def utc_now(self):
        start = datetime(2026, 10, 18, tzinfo=timezone.utc)
        return (start + timedelta(seconds=self.value)).isoformat().replace('+00:00', 'Z')


def _receipt(root):
    steps = []
    for name in recorder.STEP_NAMES:
        def run(name=name):
            result = {'passed': True}
            if name == 'effect':
                result['effect_verified'] = True
            if name == 'cleanup':
                result.update(remaining_owned_processes=0, status_known=True)
            return result
        steps.append((name, run))
    path = root / 'arm.json'
    recorder.record_arm(IDENTITY, steps, path, clock=FakeClock())
    return path


def _verifier(test):
    try:
        return importlib.import_module('tools.part5.verify_v3_direct_arm_span')
    except ImportError:
        test.fail('direct arm receipt verifier is missing')


class VerifyDirectArmSpanTests(unittest.TestCase):
    def test_accepts_recorded_span_with_external_pin_but_claims_no_loaded_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = _receipt(Path(temporary).resolve())
            raw = path.read_bytes()
            result = _verifier(self).verify_file(path, hashlib.sha256(raw).hexdigest(), IDENTITY)
            self.assertTrue(result['direct_span_consistent'])
            self.assertEqual(result['direct_duration_seconds'], 19.0)
            self.assertFalse(result['loaded_application_evidence_established'])
            self.assertNotIn(temporary, json.dumps(result))

    def test_rejects_rehashed_duration_step_and_clock_forgery(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = _receipt(Path(temporary).resolve())
            original = json.loads(path.read_bytes())
            verifier = _verifier(self)
            mutations = [
                lambda r: r.update(direct_duration_seconds=8.0),
                lambda r: r['step_durations_seconds'].update(proof=30.0),
                lambda r: r.update(utc_monotonic_disagreement_seconds=4.0),
                lambda r: r.update(end_utc='2026-10-18T01:00:20Z'),
                lambda r: r.update(full_application_evidence_established=True),
                lambda r: r.update(secret_path='/private/key'),
                lambda r: r.update(direct_duration_seconds=10 ** 1000),
            ]
            for index, mutate in enumerate(mutations):
                report = copy.deepcopy(original)
                mutate(report)
                raw = json.dumps(report).encode()
                path.write_bytes(raw)
                with self.subTest(index=index), self.assertRaises(ValueError):
                    verifier.verify_file(path, hashlib.sha256(raw).hexdigest(), IDENTITY)

    def test_refuses_wrong_trust_pin_identity_symlink_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = _receipt(root)
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            verifier = _verifier(self)
            with self.assertRaises(ValueError):
                verifier.verify_file(path, 'b' * 64, IDENTITY)
            wrong = {**IDENTITY, 'vk_sha256': 'b' * 64}
            with self.assertRaises(ValueError):
                verifier.verify_file(path, digest, wrong)
            link = root / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                verifier.verify_file(link, digest, IDENTITY)
            duplicate = raw.rstrip(b'\n} ') + b',"schema":"duplicate"}'
            path.write_bytes(duplicate)
            with self.assertRaises(ValueError):
                verifier.verify_file(path, hashlib.sha256(duplicate).hexdigest(), IDENTITY)


if __name__ == '__main__':
    unittest.main()
