import hashlib
import json
import socket
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from harness.tests import queue_v3_clone_campaign_final as clone
from harness.tests import test_queue_v3_local_campaign_transition as fixtures

pinned_json = fixtures.pinned_json

def history_pin(path, value):
    raw = json.dumps(value, separators=(',', ':')).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class CampaignFinalCloneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()
        self.root = self.repo / 'artifacts/dynark/part5'
        self.root.mkdir(parents=True, mode=0o700)
        self.source = self.root / 'source' / 'ledger'
        self.source.mkdir(parents=True, mode=0o700)
        (self.source / 'genesis.bin').write_bytes(b'Rk ledger')
        (self.source / 'genesis.bin').chmod(0o600)
        self.output = self.root / 'transition'
        self.output.mkdir(mode=0o700)
        self.stage = self.root / 'stage'
        self.stage.mkdir(mode=0o700)
        history, context, plan, report, staged = fixtures.CampaignHistoryTests().signed_chain(1)
        self.context = context
        loaded = {'program': 'program', 'programdata': 'programdata',
            'elf_sha256': 'a' * 64, 'program_account_sha256': 'b' * 64,
            'programdata_account_sha256': 'c' * 64, 'genesis': 'genesis',
            'elf_bytes': 4096, 'loader': 'BPFLoaderUpgradeab1e11111111111111111111111'}
        compact_loaded = {'elf_match': True, 'elf_sha256': loaded['elf_sha256'],
            'loader': loaded['loader'], 'local_bytes': loaded['elf_bytes'],
            'remote_bytes': loaded['elf_bytes']}
        staged['loaded_program'] = compact_loaded.copy()
        self.report = {**report, 'schema': 'part5-v3-campaign-transition-v1',
            'passed': True, 'registry_history_authenticated': True,
            'allocation_history_authenticated': True, 'request_unconsumed': True,
            'application_effect': False, 'loaded_program': compact_loaded.copy(),
            'base_root': context['root_sequence'][0], 'current_root': context['root_sequence'][1],
            'signed_history_sha256': history_pin(self.output / 'signed-history.json', history)}
        stage_control = self.root / 'stage-control'
        stage_control.mkdir(mode=0o700)
        stage_report_sha = pinned_json(self.stage / 'stage-report.json', staged)
        self.stage_status = {'scope': 'part5-v3-campaign-stage', 'stage_verified': True,
            'stage_report_sha256': stage_report_sha, 'loaded_program': loaded.copy()}
        stage_status_path = stage_control / 'status.json'
        stage_status_sha = pinned_json(stage_status_path, self.stage_status)
        self.config = {'schema': 1, 'scope': 'part5-v3-campaign-transition',
            'target_count': 1, 'ledger': str(self.source), 'transition_output': str(self.output),
            'outer_limits_required': clone.transition.LIMITS, 'stage_root': str(self.stage),
            'stage_status': str(stage_status_path), 'stage_status_sha256': stage_status_sha,
            'context': str(self.root / 'context.json'),
            'context_sha256': pinned_json(self.root / 'context.json', context),
            'stage_report_sha256': stage_report_sha,
            'stage_plan_sha256': pinned_json(self.stage / 'plan.json', plan)}
        self.report.update({name: self.config[name] for name in
            ('context_sha256', 'stage_report_sha256', 'stage_plan_sha256')})
        self.status = {'scope': 'part5-v3-campaign-transition', 'target_count': 1,
            'transition_verified': True, 'transition_output': str(self.output),
            'application_effect': False, 'ledger_reuse_requires_review': True,
            'loaded_program': loaded, 'validator_cleanup': {'exit_code': -2, 'reaped': True},
            'runner_cleanup': {'exit_code': 0, 'reaped': True}}
        self.monitor = {'owner': 'transition-owner', 'stop_reason': None,
            'runner_error_type': None, 'cleanup_remaining_owned_processes': 0,
            'cleanup_status_unknown': False, 'exit_code': 1,
            'limits': {'runtime_seconds': 420, 'owned_tree_rss_bytes': 4294967296,
                       'storage_growth_bytes': 268435456, 'poll_seconds': 0.1}}
        (self.root / 'branch').mkdir(mode=0o700)
        self.args = dict(monitor_owner='transition-owner', target_count=1,
                         destination=str(self.root / 'branch/ledger'))
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(clone, 'REPO', self.repo).start()
        mock.patch.object(clone, 'ports_free').start()
        self.pin()

    def pin(self):
        for kind, value in (('config', self.config), ('report', self.report),
                            ('status', self.status), ('monitor', self.monitor)):
            if kind == 'status':
                value['config_sha256'] = self.args['config_sha']
                value['transition_report_sha256'] = self.args['report_sha']
            path = self.output / (kind + '.json')
            self.args['transition_' + kind] = str(path)
            self.args[kind + '_sha'] = pinned_json(path, value)

    def test_clone_pins_identity_and_does_not_claim_restart_finality(self):
        result = clone.clone(**self.args)
        self.assertTrue(result['copy_identical'])
        self.assertEqual(result['current_root'], self.context['root_sequence'][1])
        self.assertEqual(result['loaded_program'], self.status['loaded_program'])
        self.assertTrue(result['ledger_reuse_requires_review'])
        self.assertFalse(result['finality_rechecked_after_restart'])
        self.assertFalse(result['application_effect'])
        self.assertEqual((Path(self.args['destination']) / 'genesis.bin').read_bytes(), b'Rk ledger')

    def test_only_stale_admin_socket_is_excluded(self):
        path = self.source / 'admin.rpc'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            path.chmod(0o600)
        result = clone.clone(**self.args)
        self.assertTrue(result['excluded_stale_admin_socket'])
        self.assertTrue(path.exists())
        self.assertFalse((Path(self.args['destination']) / 'admin.rpc').exists())

    def test_tampered_report_rejected(self):
        Path(self.args['transition_report']).write_text('{}')
        with self.assertRaises(ValueError):
            clone.clone(**self.args)

    def test_dirty_monitor_rejected(self):
        for key, value in (('stop_reason', 'runtime'), ('runner_error_type', 'Error'),
                           ('cleanup_remaining_owned_processes', 1), ('cleanup_status_unknown', True),
                           ('owner', 'other-owner'), ('exit_code', 0)):
            with self.subTest(key=key):
                original = self.monitor[key]
                self.monitor[key] = value
                self.pin()
                with self.assertRaises(ValueError):
                    clone.clone(**self.args)
                self.monitor[key] = original

    def test_wrong_count_rejected(self):
        self.args['target_count'] = 2
        with self.assertRaises(ValueError):
            clone.clone(**self.args)

    def test_signed_history_tamper_rejected_even_when_repinned(self):
        path = self.output / 'signed-history.json'
        history = json.loads(path.read_bytes())
        history['checkpoints'][1]['source']['observation']['sequence'] = 99
        self.report['signed_history_sha256'] = history_pin(path, history)
        self.pin()
        with self.assertRaises(ValueError):
            clone.clone(**self.args)

    def test_current_root_and_loaded_identity_mismatch_rejected(self):
        for key, value in (('current_root', '00' * 32),):
            with self.subTest(key=key):
                original = self.report[key]
                self.report[key] = value
                self.pin()
                with self.assertRaises(ValueError):
                    clone.clone(**self.args)
                self.report[key] = original
        original = self.status['loaded_program']
        self.status['loaded_program'] = {**original, 'genesis': 'other'}
        self.pin()
        with self.assertRaises(ValueError):
            clone.clone(**self.args)
        self.status['loaded_program'] = original

    def test_report_loaded_elf_loader_and_sizes_must_match_full_identity(self):
        for key, value in (('elf_sha256', 'd' * 64),
                           ('loader', 'other-loader'),
                           ('local_bytes', 4095), ('remote_bytes', 4095)):
            with self.subTest(key=key):
                original = self.report['loaded_program'][key]
                self.report['loaded_program'][key] = value
                self.pin()
                with self.assertRaises(ValueError):
                    clone.clone(**self.args)
                self.report['loaded_program'][key] = original

    def test_destination_must_be_private_and_under_artifact_boundary(self):
        parent = Path(self.args['destination']).parent
        parent.chmod(0o755)
        with self.assertRaises(ValueError):
            clone.clone(**self.args)
        parent.chmod(0o700)
        outside = self.repo / 'outside'
        outside.mkdir(mode=0o700)
        self.args['destination'] = str(outside / 'ledger')
        with self.assertRaises(ValueError):
            clone.clone(**self.args)

    def test_source_changed_during_copy_rejected(self):
        original = clone.shutil.copytree
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.source / 'genesis.bin').write_bytes(b'mutated')
            return result
        with mock.patch.object(clone.shutil, 'copytree', changed), self.assertRaises(ValueError):
            clone.clone(**self.args)
        self.assertFalse((self.root / 'branch/clone-report.json').exists())


if __name__ == '__main__':
    unittest.main()
