import importlib.util
import json
from pathlib import Path
import signal
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('v3_stage', Path(__file__).with_name('queue_v3_local_stage.py'))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class StageTests(unittest.TestCase):
    def test_generated_report_is_bounded_and_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.json'
            report.write_bytes(b'{"passed":true}')
            report.chmod(0o600)
            raw, digest = stage.snapshot_generated(report, 64)
            self.assertEqual(json.loads(raw), {'passed': True})
            self.assertEqual(digest, stage.base.sha(raw))
            report.write_bytes(b'a' * 65)
            with self.assertRaises(ValueError):
                stage.snapshot_generated(report, 64)
            report.unlink()
            report.symlink_to(Path(directory) / 'target')
            with self.assertRaises((ValueError, OSError)):
                stage.snapshot_generated(report, 64)

    def test_stage_outputs_must_be_distinct_direct_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            left = root / 'application-v3-stage'
            right = root / 'application-v3-control'
            stage.validate_stage_paths(left, right, root)
            for invalid in (left, root / 'nested/application-v3-control', root / 'other'):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    stage.validate_stage_paths(left, invalid, root)

    def test_interrupted_prior_is_reviewed_before_reuse(self):
        genesis = 'genesis'
        prior = {'schema': 1, 'scope': 'part5-v3-local-prepare', 'config_sha256': 'a' * 64,
                 'application_effect': False, 'prepared_application_accounts': False,
                 'loaded_program': {'elf_match': True, 'elf_sha256': 'b' * 64,
                                    'program': 'program', 'genesis': genesis},
                 'ledger': '/ledger', 'cleanup': {'reaped': True, 'exit_code': -signal.SIGINT},
                 'ledger_reuse_requires_review': True, 'status': 'failed'}
        monitor = {'owner': 'part5-v3-local-prepare-001', 'stop_reason': None,
                   'runner_error_type': None, 'cleanup_remaining_owned_processes': 0,
                   'cleanup_status_unknown': False}
        original = {'elf_sha256': 'b' * 64, 'program': 'program'}
        config = {'prior_config_sha256': 'a' * 64, 'expected_genesis': genesis,
                  'ledger': '/ledger'}
        stage.review_prior(prior, monitor, original, config)
        second = dict(config, prior_monitor_owner='part5-v3-local-prepare-002')
        with self.assertRaises(ValueError):
            stage.review_prior(prior, monitor, original, second)
        stage.review_prior(prior, dict(monitor, owner='part5-v3-local-prepare-002'), original, second)
        prior['loaded_program']['genesis'] = 'changed'
        with self.assertRaises(ValueError):
            stage.review_prior(prior, monitor, original, config)


if __name__ == '__main__':
    unittest.main()
