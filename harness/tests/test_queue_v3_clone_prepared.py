import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from harness.tests import queue_v3_clone_prepared as tool
from harness.tests import queue_v3_local_stage as stage
from tools.part5 import run_v3_heldout_case as case


class PreparedImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.runtime = self.root / 'source'
        self.runtime.mkdir(mode=0o700)
        self.ledger = self.runtime / 'ledger'
        self.ledger.mkdir(mode=0o700)
        (self.ledger / 'genesis.bin').write_bytes(b'genesis')
        (self.ledger / 'genesis.bin').chmod(0o600)
        self.original = {'schema': 1, 'scope': 'part5-v3-local-prepare',
                         'outer_limits_required': tool.LIMITS,
                         'runtime_output': str(self.runtime), 'elf_sha256': 'e' * 64,
                         'program': 'program', 'control_output': '/old-control'}
        self.original_ref = self.write('source-config.json', self.original)
        self.loaded = {'genesis': 'genesis-hash', 'program': 'program',
                       'elf_sha256': 'e' * 64, 'elf_match': True,
                       'programdata': 'programdata', 'program_account_sha256': 'a' * 64,
                       'programdata_account_sha256': 'b' * 64}
        self.status = {'schema': 1, 'scope': 'part5-v3-local-prepare',
                       'config_sha256': self.original_ref['sha256'],
                       'ledger': str(self.ledger), 'loaded_program': self.loaded,
                       'status': 'failed', 'application_effect': False,
                       'prepared_application_accounts': False,
                       'ledger_reuse_requires_review': True,
                       'cleanup': {'spawned': True, 'reaped': True,
                                   'graceful': False, 'exit_code': -2}}
        self.monitor = {'schema': 1, 'measurement': 'bounded_complete_session',
                        'owner': 'source-prepare', 'passed': False, 'exit_code': 1,
                        'censored': False, 'stop_reason': None,
                        'runner_error_type': None, 'cleanup_remaining_owned_processes': 0,
                        'cleanup_status_unknown': False, 'sample_count': 2,
                        'duration_seconds': 1.0}

    def write(self, name, value):
        path = self.root / name
        raw = (json.dumps(value, sort_keys=True) + '\n').encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

    def source(self):
        return {'config': self.original_ref,
                'status': self.write('source-status.json', self.status),
                'monitor': self.write('source-monitor.json', self.monitor),
                'monitor_owner': 'source-prepare'}

    def imported(self):
        source = self.source()
        with mock.patch.object(tool, 'ports_free'):
            record = tool.clone(source, self.root / 'imported-runtime',
                                self.root / 'imported-control')
        config = json.loads(Path(record['config']).read_bytes())
        status = json.loads(Path(record['status_path']).read_bytes())
        stage_config = {'prior_config_sha256': record['config_sha256'],
                        'prior_monitor_owner': 'source-prepare',
                        'prior_monitor_sha256': source['monitor']['sha256'],
                        'expected_genesis': 'genesis-hash',
                        'ledger': str(self.root / 'imported-runtime' / 'ledger')}
        return record, config, status, stage_config

    def test_import_is_distinct_truthful_and_stage_admitted(self):
        record, config, status, stage_config = self.imported()
        self.assertEqual(status['scope'], tool.SCOPE)
        self.assertEqual(status['status'], 'imported_pending_live_reattestation')
        self.assertNotIn('cleanup', status)
        self.assertFalse(status['loaded_identity_rechecked_after_restart'])
        self.assertEqual((Path(record['runtime']) / 'ledger/genesis.bin').read_bytes(), b'genesis')
        stage.review_prior(status, self.monitor, config, stage_config)
        self.assertEqual(self.ledger.joinpath('genesis.bin').read_bytes(), b'genesis')

    def test_frozen_case_stage_provenance_accepts_truthful_import_config(self):
        record, config, imported_status, stage_config = self.imported()
        stage_config.update(scope='part5-v3-local-stage', prior_config=record['config'],
                            prior_status=record['status_path'],
                            prior_status_sha256=record['status_sha256'], stage_output='/stage')
        stage_sha = 'c' * 64
        report_sha = 'd' * 64
        loaded_stage_status = {'scope': 'part5-v3-local-stage', 'status': 'failed',
            'stage_verified': True, 'ledger_reuse_requires_review': True,
            'config_sha256': stage_sha, 'stage_report_sha256': report_sha,
            'stage_output': '/stage', 'loaded_program': self.loaded,
            'validator_cleanup': {'spawned': True, 'reaped': True,
                                  'graceful': False, 'exit_code': -2},
            'runner_cleanup': {'spawned': True, 'reaped': True, 'exit_code': 0}}
        report = {'schema': 'part5-v3-local-stage-v1', 'passed': True,
                  'genesis': 'genesis-hash'}
        self.assertEqual(case.verified_stage_ledger(stage_config, stage_sha,
            loaded_stage_status, report, report_sha), stage_config['ledger'])
        self.assertEqual(imported_status['status'], 'imported_pending_live_reattestation')

    def test_changed_import_tree_is_rejected_before_stage(self):
        _, config, status, stage_config = self.imported()
        Path(stage_config['ledger'], 'genesis.bin').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            stage.review_prior(status, self.monitor, config, stage_config)

    def test_source_pin_and_monitor_cleanup_fail_closed(self):
        for change in ('bad-status-pin', 'live-source', 'censored', 'wrong-elf'):
            with self.subTest(change=change):
                status, monitor = copy.deepcopy(self.status), copy.deepcopy(self.monitor)
                if change == 'live-source':
                    status['cleanup']['reaped'] = False
                elif change == 'censored':
                    monitor['censored'] = True
                elif change == 'wrong-elf':
                    status['loaded_program']['elf_sha256'] = 'f' * 64
                source = {'config': self.original_ref,
                          'status': self.write('reject-status.json', status),
                          'monitor': self.write('reject-monitor.json', monitor),
                          'monitor_owner': 'source-prepare'}
                if change == 'bad-status-pin':
                    source['status']['sha256'] = '0' * 64
                with mock.patch.object(tool, 'ports_free'), self.assertRaises(ValueError):
                    tool.clone(source, self.root / change, self.root / (change + '-control'))
                self.assertFalse((self.root / change).exists())

    def test_symlink_hardlink_and_changed_source_are_rejected(self):
        source = self.source()
        original = self.ledger / 'genesis.bin'
        os.link(original, self.root / 'alias')
        with mock.patch.object(tool, 'ports_free'), self.assertRaises(ValueError):
            tool.clone(source, self.root / 'hardlink', self.root / 'hardlink-control')
        (self.root / 'alias').unlink()
        original.unlink()
        original.symlink_to(self.root / 'source-config.json')
        with mock.patch.object(tool, 'ports_free'), self.assertRaises(ValueError):
            tool.clone(source, self.root / 'symlink', self.root / 'symlink-control')

    def test_imported_scope_cannot_recurse_to_fabricated_prepare(self):
        self.status['scope'] = tool.SCOPE
        with mock.patch.object(tool, 'ports_free'), self.assertRaises(ValueError):
            tool.clone(self.source(), self.root / 'recursive', self.root / 'recursive-control')

    def test_source_changed_during_copy_leaves_no_import_receipts(self):
        real_copy = tool.shutil.copytree
        def change_source(*args, **kwargs):
            result = real_copy(*args, **kwargs)
            (self.ledger / 'genesis.bin').write_bytes(b'changed-after-copy')
            return result
        with mock.patch.object(tool, 'ports_free'), mock.patch.object(
                tool.shutil, 'copytree', side_effect=change_source), self.assertRaises(ValueError):
            tool.clone(self.source(), self.root / 'raced', self.root / 'raced-control')
        self.assertFalse((self.root / 'raced-control/status.json').exists())

    def test_source_changed_before_stage_and_destination_substitution_are_rejected(self):
        _, config, status, stage_config = self.imported()
        forged = copy.deepcopy(status)
        forged['loaded_program']['genesis'] = 'substituted-genesis'
        with self.assertRaises(ValueError):
            stage.review_prior(forged, self.monitor, config, stage_config)
        (self.ledger / 'genesis.bin').write_bytes(b'changed-baseline')
        with self.assertRaises(ValueError):
            stage.review_prior(status, self.monitor, config, stage_config)
