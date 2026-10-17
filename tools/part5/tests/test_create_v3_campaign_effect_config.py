import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.part5 import create_v3_campaign_effect_config as tool


class CampaignEffectConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        self.clone = self.root / 'clone'
        self.clone.mkdir()

    def save(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = ((json.dumps(value, separators=(',', ':')) + '\n').encode()
               if not isinstance(value, bytes) else value)
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def loaded_identity(self):
        return {'elf_match': True, 'elf_sha256': 'a' * 64, 'elf_bytes': 4096,
                'program': 'program', 'programdata': 'programdata',
                'program_account_sha256': 'b' * 64,
                'programdata_account_sha256': 'c' * 64, 'genesis': 'genesis',
                'loader': 'BPFLoaderUpgradeab1e11111111111111111111111'}

    def loaded_report(self):
        loaded = self.loaded_identity()
        return {'elf_match': True, 'elf_sha256': loaded['elf_sha256'],
                'loader': loaded['loader'], 'local_bytes': loaded['elf_bytes'],
                'remote_bytes': loaded['elf_bytes']}

    def fixture(self, count=0, mode='coalesced-full', proof_mode=None):
        proof_mode = proof_mode or ('full' if mode == 'own-revocation' else mode)
        context = self.root / 'context.json'
        context_sha = self.save(context, {'schema': 'part5-v3-campaign-context-v1',
                                          'root_sequence': ['00' * 32, '01' * 32]})
        stage_config = self.root / 'stage-config.json'
        self.save(stage_config, {'scope': 'part5-v3-campaign-stage',
                                 'stage_output': str(self.stage),
                                 'ledger': str(self.root / 'original-ledger'),
                                 'context': str(context), 'context_sha256': context_sha,
                                 'expected_genesis': 'genesis'})
        stage_report = self.stage / 'stage-report.json'
        stage_sha = self.save(stage_report, {'schema': 'part5-v3-campaign-stage-v1',
                                             'passed': True,
                                             'loaded_program': self.loaded_report()})
        stage_plan = self.stage / 'plan.json'
        plan_sha = self.save(stage_plan, {'root': []})
        stage_status = self.root / 'stage-status.json'
        stage_status_sha = self.save(stage_status, {'stage_verified': True,
                                                   'stage_report_sha256': stage_sha,
                                                   'loaded_program': self.loaded_identity()})
        stage_monitor = self.root / 'stage-monitor.json'
        stage_monitor_sha = self.save(stage_monitor, {'owner': 'stage-owner',
                                                     'stop_reason': None,
                                                     'cleanup_remaining_owned_processes': 0})
        clone_report = self.clone / 'clone-report.json'
        runner = self.root / 'runner'
        self.save(runner, b'runner')
        proof_packet = self.root / 'packet.json'
        packet_sha = self.save(proof_packet, {
            'schema': ('credential-v3-cumulative-coalesced-request-v1'
                       if proof_mode == 'coalesced-full'
                       else 'credential-v3-cumulative-request-v1'),
            'update_count': count, 'application_stage': {'pin': 'same'}})
        proof_report = self.root / 'proof-report.json'
        self.save(proof_report, {'schema': 'credential-v3-cumulative-proof-v1',
                                 'passed': True, 'mode': f'campaign-{proof_mode}-k{count}',
                                 'update_count': count, 'packet_sha256': packet_sha,
                                 'application_stage_pins': {'pin': 'same'}})
        current_wire = self.root / 'current-wire.bin'
        self.save(current_wire, bytes(448))
        base_wire = self.root / 'base-wire.bin'
        self.save(base_wire, bytes([1]) * 448)
        args = argparse.Namespace(mode=mode, proof_mode=proof_mode, target_count=count,
            transition_config=None, transition_report=None, transition_status=None,
            transition_monitor=None, transition_monitor_owner=None,
            stage_config=str(stage_config), stage_status=str(stage_status),
            stage_monitor=str(stage_monitor), stage_monitor_owner='stage-owner',
            cohort_root=str(self.root / 'cohort'), clone_report=str(clone_report),
            proof_packet=str(proof_packet), proof_report=str(proof_report),
            stage_report=str(stage_report), stage_plan=str(stage_plan),
            base_wire=None if proof_mode == 'coalesced-full' else str(base_wire),
            current_wire=str(current_wire), runner=str(runner),
            effect_output=str(self.root / 'application-v3-effect'),
            control_output=str(self.root / 'application-v3-control'),
            output=str(self.root / 'effect-config.json'))
        if count:
            transition = self.root / 'transition'
            transition.mkdir()
            changed = transition / 'transition-report.json'
            changed_sha = self.save(changed, {
                'schema': 'part5-v3-campaign-transition-v1', 'passed': True,
                'target_count': count, 'stage_report_sha256': stage_sha,
                'stage_plan_sha256': plan_sha, 'context_sha256': context_sha,
                'current_root': '01' * 32,
                'loaded_program': self.loaded_report()})
            transition_config = self.root / 'transition-config.json'
            transition_config_sha = self.save(transition_config, {
                'schema': 1, 'scope': 'part5-v3-campaign-transition',
                'target_count': count, 'transition_output': str(transition),
                'stage_config': str(stage_config),
                'stage_config_sha256': tool.read(stage_config)[1],
                'stage_status': str(stage_status),
                'stage_status_sha256': stage_status_sha,
                'stage_monitor': str(stage_monitor),
                'stage_monitor_sha256': stage_monitor_sha,
                'stage_monitor_owner': 'stage-owner',
                'stage_root': str(self.stage), 'stage_report_sha256': stage_sha,
                'stage_plan_sha256': plan_sha, 'context': str(context),
                'context_sha256': context_sha, 'cohort_root': args.cohort_root,
                'expected_genesis': 'genesis',
                'ledger': str(self.root / 'transition-ledger')})
            transition_status = self.root / 'transition-status.json'
            transition_status_sha = self.save(transition_status, {
                'scope': 'part5-v3-campaign-transition', 'transition_verified': True,
                'config_sha256': transition_config_sha,
                'transition_report_sha256': changed_sha,
                'transition_output': str(transition),
                'loaded_program': self.loaded_identity()})
            transition_monitor = self.root / 'transition-monitor.json'
            transition_monitor_sha = self.save(transition_monitor, {
                'owner': 'transition-owner', 'stop_reason': None,
                'cleanup_remaining_owned_processes': 0})
            self.save(clone_report, {
                'schema': 'part5-v3-campaign-final-ledger-clone-v1',
                'copy_identical': True, 'source': str(self.root / 'transition-ledger'),
                'destination': str(self.clone / 'ledger'),
                'transition_config_sha256': transition_config_sha,
                'transition_report_sha256': changed_sha,
                'transition_status_sha256': transition_status_sha,
                'transition_monitor_sha256': transition_monitor_sha,
                'target_count': count, 'current_root': '01' * 32})
            args.transition_config = str(transition_config)
            args.transition_report = str(changed)
            args.transition_status = str(transition_status)
            args.transition_monitor = str(transition_monitor)
            args.transition_monitor_owner = 'transition-owner'
        else:
            self.save(clone_report, {
                'schema': 'part5-v3-campaign-r0-ledger-clone-v1',
                'copy_identical': True, 'source': str(self.root / 'original-ledger'),
                'destination': str(self.clone / 'ledger'),
                'stage_report_sha256': stage_sha,
                'stage_status_sha256': stage_status_sha,
                'stage_monitor_sha256': stage_monitor_sha})
        return args

    def test_r0_coalesced_final_only_config(self):
        args = self.fixture()
        digest = tool.create(args)
        config, actual = tool.document(args.output)
        self.assertEqual(digest, actual)
        self.assertEqual(config['target_count'], 0)
        self.assertIsNone(config['base_wire'])
        self.assertIsNone(config['transition_root'])
        self.assertEqual(config['outer_limits_required'], tool.LIMITS)

    def test_rk_anchor_config_pins_transition_and_two_wires(self):
        args = self.fixture(1, 'anchor')
        tool.create(args)
        config, _ = tool.document(args.output)
        self.assertEqual(config['target_count'], 1)
        self.assertEqual(config['mode'], 'anchor')
        self.assertEqual(config['transition_root'], str(self.root / 'transition'))
        self.assertIsNotNone(config['base_wire_sha256'])

    def test_rk_own_revocation_config_pins_full_proof_and_both_wires(self):
        args = self.fixture(1, 'own-revocation')
        tool.create(args)
        config, _ = tool.document(args.output)
        self.assertEqual(config['mode'], 'own-revocation')
        self.assertEqual(config['proof_mode'], 'full')
        self.assertEqual(config['target_count'], 1)
        self.assertIsNotNone(config['base_wire_sha256'])
        self.assertIsNotNone(config['current_wire_sha256'])

    def test_own_revocation_cannot_use_final_only_coalesced_proof(self):
        args = self.fixture(1, 'own-revocation', 'coalesced-full')
        with self.assertRaisesRegex(ValueError, 'Full or Anchor proof pair'):
            tool.create(args)

    def test_clone_or_proof_role_mismatch_is_rejected(self):
        args = self.fixture(1, 'anchor')
        clone, _ = tool.document(args.clone_report)
        clone['current_root'] = 'ff' * 32
        self.save(Path(args.clone_report), clone)
        with self.assertRaisesRegex(ValueError, 'roles differ'):
            tool.create(args)
        args = self.fixture(0, 'coalesced-full')
        proof, _ = tool.document(args.proof_report)
        proof['mode'] = 'campaign-full-k0'
        self.save(Path(args.proof_report), proof)
        with self.assertRaisesRegex(ValueError, 'roles differ'):
            tool.create(args)

    def test_coalesced_r0_wire_is_rejected(self):
        args = self.fixture()
        args.base_wire = args.current_wire
        with self.assertRaisesRegex(ValueError, 'no R0 proof wire'):
            tool.create(args)

    def test_minimal_stage_report_identity_must_match_full_status(self):
        for key, value in (('elf_sha256', 'f' * 64), ('loader', 'other-loader'),
                           ('local_bytes', 4095), ('remote_bytes', 4095)):
            with self.subTest(key=key):
                args = self.fixture()
                report, _ = tool.document(args.stage_report)
                report['loaded_program'][key] = value
                stage_sha = self.save(Path(args.stage_report), report)
                status, _ = tool.document(args.stage_status)
                status['stage_report_sha256'] = stage_sha
                self.save(Path(args.stage_status), status)
                with self.assertRaisesRegex(ValueError, 'report loaded program'):
                    tool.create(args)


if __name__ == '__main__':
    unittest.main()
