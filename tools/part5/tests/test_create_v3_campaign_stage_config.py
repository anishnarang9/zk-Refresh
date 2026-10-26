import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tools.part5 import create_v3_campaign_stage_config as tool
from harness.tests import queue_v3_local_stage as stage


class CampaignStageConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.ledger = self.root / 'prepare' / 'ledger'
        self.ledger.mkdir(parents=True, mode=0o700)
        (self.ledger / 'genesis.bin').write_bytes(b'genesis')
        (self.ledger / 'genesis.bin').chmod(0o600)
        self.previous = dict(schema=1, scope='part5-v3-local-prepare',
                             runtime_output=str(self.ledger.parent), elf_sha256='a' * 64, program='program')
        self.context = dict(schema='part5-v3-campaign-context-v1', training_only=True,
                            initial_allocations=dict(cohort_receipt_sha256='b' * 64, membership_sha256='c' * 64))
        self.args = argparse.Namespace(**{name: str(self.root / (name + '.json')) for name in
            ('prior_config', 'prior_status', 'prior_monitor', 'context', 'output')},
            prior_monitor_owner='campaign-prepare', campaign_cohort=str(self.root / 'cohort'),
            runner=str(self.root / 'runner'), stage_output=str(self.root / 'application-v3-stage'),
            control_output=str(self.root / 'application-v3-control'))
        self.save('prior_config', self.previous)
        self.status = dict(schema=1, scope='part5-v3-local-prepare', status='failed',
            config_sha256=self.digest(Path(self.args.prior_config).read_bytes()), application_effect=False,
            prepared_application_accounts=False, ledger_reuse_requires_review=True,
            loaded_program=dict(elf_match=True, elf_sha256='a' * 64, program='program', genesis='genesis'),
            cleanup=dict(exit_code=-2, reaped=True), ledger=str(self.ledger))
        self.monitor = dict(owner='campaign-prepare', stop_reason=None, runner_error_type=None,
                            cleanup_remaining_owned_processes=0, cleanup_status_unknown=False)
        self.save('prior_status', self.status)
        self.save('prior_monitor', self.monitor)
        self.save('context', self.context)
        Path(self.args.runner).write_bytes(b'synthetic runner')
        self.root_patch = mock.patch.object(tool, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.derive_patch = mock.patch.object(tool, 'derive', return_value=copy.deepcopy(self.context))
        self.derive = self.derive_patch.start()
        self.addCleanup(self.derive_patch.stop)

    @staticmethod
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def save(self, name, value):
        path = Path(getattr(self.args, name))
        path.write_bytes(tool.encoded(value))
        path.chmod(0o600)

    def reject(self):
        with self.assertRaises((ValueError, FileExistsError, FileNotFoundError)):
            tool.create(self.args)
        self.assertFalse(Path(self.args.output).exists())

    def test_valid_generation_pins_reviewed_bytes_and_runtime_contract(self):
        digest = tool.create(self.args)
        raw = Path(self.args.output).read_bytes()
        config = json.loads(raw)
        self.assertEqual(self.digest(raw), digest)
        self.assertEqual(stat.S_IMODE(Path(self.args.output).stat().st_mode), 0o600)
        self.assertEqual(config['scope'], 'part5-v3-campaign-stage')
        self.assertEqual(config['outer_limits_required'], stage.LIMITS)
        self.assertEqual(config['ledger'], str(self.ledger))
        for name in ('prior_config', 'prior_status', 'prior_monitor', 'context', 'runner'):
            self.assertEqual(config[name + '_sha256'], self.digest(Path(getattr(self.args, name)).read_bytes()))
        stage.review_prior(self.status, self.monitor, self.previous, config)
        self.derive.assert_called_once_with(Path(self.args.campaign_cohort), 'b' * 64, 'c' * 64)
        self.assertFalse(Path(self.args.stage_output).exists())
        self.assertFalse(Path(self.args.control_output).exists())

    def test_mismatched_prepare_status_rejected(self):
        for key, value in [('schema', 2), ('status', 'passed'), ('config_sha256', 'f' * 64),
                           ('application_effect', True), ('prepared_application_accounts', True),
                           ('ledger', str(self.root / 'different'))]:
            with self.subTest(key=key):
                self.save('prior_status', dict(self.status, **{key: value}))
                self.reject()

    def test_loaded_identity_and_cleanup_rejected(self):
        for key, value in [('elf_sha256', 'f' * 64), ('program', 'other'), ('genesis', ''), ('elf_match', False)]:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.status)
                changed['loaded_program'][key] = value
                self.save('prior_status', changed)
                self.reject()
        for cleanup in (dict(exit_code=0, reaped=True), dict(exit_code=-2, reaped=False)):
            self.save('prior_status', dict(self.status, cleanup=cleanup))
            self.reject()

    def test_monitor_owner_caps_and_cleanup_rejected(self):
        for key, value in [('owner', 'other'), ('stop_reason', 'runtime'), ('runner_error_type', 'Error'),
                           ('cleanup_remaining_owned_processes', 1), ('cleanup_status_unknown', True)]:
            with self.subTest(key=key):
                self.save('prior_monitor', dict(self.monitor, **{key: value}))
                self.reject()

    def test_changed_or_noncanonical_context_rejected(self):
        for value in (dict(self.context, root='changed'), dict(self.context, training_only=False),
                      dict(self.context, initial_allocations=None)):
            self.save('context', value)
            self.reject()
        Path(self.args.context).write_text(json.dumps(self.context))
        self.reject()

    def test_existing_alias_and_outside_stage_paths_rejected(self):
        original = self.args.stage_output
        for value in (self.args.control_output, str(self.root / 'outside'),
                      str(self.root / 'nested' / 'application-v3-stage'), 'application-v3-relative',
                      str(self.root / '..' / self.root.name / 'application-v3-stage')):
            self.args.stage_output = value
            self.reject()
        self.args.stage_output = original
        Path(original).mkdir()
        self.reject()
        Path(original).rmdir()
        Path(original).symlink_to(self.root / 'missing')
        self.reject()

    def test_config_output_cannot_alias_stage_or_parent_symlink(self):
        self.args.output = self.args.stage_output
        self.reject()
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.args.output = str(alias / 'config.json')
        self.reject()

    def test_existing_config_is_never_overwritten(self):
        output = Path(self.args.output)
        output.write_bytes(b'preserve')
        with self.assertRaises(ValueError):
            tool.create(self.args)
        self.assertEqual(output.read_bytes(), b'preserve')

    def test_symlinked_input_and_public_ledger_rejected(self):
        runner = Path(self.args.runner)
        runner.unlink()
        runner.symlink_to(self.args.prior_config)
        self.reject()
        runner.unlink()
        runner.write_bytes(b'runner')
        self.ledger.chmod(0o755)
        self.reject()
        self.ledger.chmod(0o700)
        (self.ledger / 'genesis.bin').chmod(0o644)
        self.reject()

    def test_changed_input_is_detected_during_snapshot(self):
        original = os.fstat
        count = 0
        def changed(fd):
            nonlocal count
            count += 1
            if count == 2:
                Path(self.args.prior_config).write_bytes(b'changed')
            return original(fd)
        with mock.patch.object(tool.os, 'fstat', side_effect=changed):
            self.reject()


if __name__ == '__main__':
    unittest.main()
