import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from harness.tests import queue_v3_clone_heldout_r0 as tool


class HeldoutR0CloneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.source = root / 'runtime' / 'ledger'
        self.source.mkdir(parents=True, mode=0o700)
        self.source.chmod(0o700)
        (self.source / 'genesis.bin').write_bytes(b'local-genesis')
        (self.source / 'genesis.bin').chmod(0o600)
        self.stage = root / 'stage'
        self.stage.mkdir(mode=0o700)
        self.destination = root / 'clone' / 'ledger'
        self.destination.parent.mkdir(mode=0o700)
        self.config_path = root / 'stage-config.json'
        self.report_path = self.stage / 'stage-report.json'
        self.status_path = root / 'stage-status.json'
        self.monitor_path = root / 'stage-monitor.json'
        self.write(self.config_path, {'scope': 'part5-v3-local-stage',
                                      'stage_output': str(self.stage),
                                      'ledger': str(self.source)})
        self.write(self.report_path, {'schema': 'part5-v3-local-stage-v1',
            'passed': True, 'registry_history_authenticated': True,
            'allocation_history_authenticated': True, 'application_effect': False,
            'loaded_program': {'elf_match': True}})
        self.write(self.status_path, {'scope': 'part5-v3-local-stage',
            'config_sha256': self.sha(self.config_path),
            'stage_report_sha256': self.sha(self.report_path),
            'stage_verified': True, 'stage_output': str(self.stage),
            'application_effect': False, 'ledger_reuse_requires_review': True,
            'validator_cleanup': {'exit_code': -2, 'reaped': True},
            'runner_cleanup': {'exit_code': 0, 'reaped': True}})
        self.write(self.monitor_path, {'owner': 'heldout-stage-test',
            'stop_reason': None, 'runner_error_type': None,
            'cleanup_remaining_owned_processes': 0,
            'cleanup_status_unknown': False})

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def clone(self):
        with mock.patch.object(tool, 'ports_free'):
            return tool.clone(self.config_path, self.sha(self.config_path),
                self.report_path, self.sha(self.report_path),
                self.status_path, self.sha(self.status_path),
                self.monitor_path, self.sha(self.monitor_path),
                'heldout-stage-test', self.destination)

    def test_clones_only_reviewed_stopped_stage_and_keeps_byte_inventory(self):
        result = self.clone()
        self.assertEqual(result['schema'], 'part5-v3-heldout-r0-ledger-clone-v1')
        self.assertTrue(result['copy_identical'])
        self.assertEqual((self.destination / 'genesis.bin').read_bytes(), b'local-genesis')
        self.assertEqual(json.loads((self.destination.parent / 'clone-report.json').read_text()),
                         result)

    def test_rejects_unverified_stage_before_copy(self):
        status = json.loads(self.status_path.read_text())
        status['stage_verified'] = False
        self.write(self.status_path, status)
        with self.assertRaisesRegex(ValueError, 'reviewed stopped'):
            self.clone()
        self.assertFalse(self.destination.exists())


if __name__ == '__main__':
    unittest.main()
