import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import run_v3_campaign_session as tool


class CampaignSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)

    def args(self, mode, count):
        work = self.root / f'{mode}-k{count}'
        work.mkdir(mode=0o700)
        return argparse.Namespace(mode=mode, target_count=count, repetition=1,
            work_root=work, freeze=self.root / 'freeze.json',
            cohort_root=self.root / 'cohort', context=self.root / 'context.json',
            stage_root=self.root / 'stage', clone_report=self.root / 'clone-report.json',
            effect_output=self.root / 'effect', control_output=self.root / 'control',
            proof_binary=self.root / 'proof', adapter_binary=self.root / 'adapter',
            exporter=self.root / 'exporter', node=self.root / 'node',
            old_packet=self.root / 'old-packet.json', effect_runner=self.root / 'runner',
            exporter_sha256='a' * 64, node_sha256='b' * 64,
            old_packet_sha256='c' * 64, effect_config_sha256='e' * 64,
            effect_supervisor_sha256='d' * 64, bounded_runner_sha256='f' * 64,
            transition_root=self.root / 'transition',
            transition_config=self.root / 'transition-config.json',
            transition_report=self.root / 'transition-report.json',
            transition_status=self.root / 'transition-status.json',
            transition_monitor=self.root / 'transition-monitor.json',
            transition_monitor_owner='transition',
            stage_config=self.root / 'stage-config.json',
            stage_status=self.root / 'stage-status.json',
            stage_monitor=self.root / 'stage-monitor.json',
            stage_monitor_owner='stage')

    def write(self, path, value):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def synthetic(self, args, bad_effect=False, bad_monitor=False, clean_shutdown=False):
        calls = []
        boundary = {'freeze_sha256': 'f' * 64,
                    'cohort_receipt_sha256': 'c' * 64,
                    'clone_report_sha256': 'd' * 64,
                    'current_root': str(args.stage_root if args.target_count == 0 else args.transition_root),
                    'current_report_sha256': 'e' * 64,
                    'source_identities': {'proof_runner': 'p' * 64}}

        def stage(stages, work, name, command, environment=None, accepted=(0,)):
            calls.append((name, list(command), dict(environment or {})))
            stages.append({'stage': name, 'wall_seconds': 0.1,
                           'waited_child_cpu_seconds': 0.01, 'exit_code': 0})
            if name == 'source_import':
                self.write(work / 'source/source-receipt.json', {'source': True})
            elif name == 'r0_input':
                self.write(work / 'r0/training-receipt.json', {'base': True})
            elif name.endswith('_input'):
                number = name.split('_')[0]
                self.write(work / number / 'training-receipt.json', {'generation': number})
            elif name == 'packet':
                self.write(work / 'packet.json', {'application_stage': {'root': 1}})
            elif name == 'proof':
                (work / 'proof').mkdir(mode=0o700)
                proofs = 1 if args.mode == 'coalesced-full' else args.target_count + 1
                cross = 0 if args.mode == 'coalesced-full' else 2 * args.target_count
                self.write(work / 'proof/proof-report.json', {
                    'schema': 'credential-v3-cumulative-proof-v1', 'passed': True,
                    'mode': f'campaign-{args.mode}-k{args.target_count}',
                    'update_count': args.target_count,
                    'packet_sha256': tool.digest(work / 'packet.json'),
                    'application_stage_pins': {'root': 1},
                    'counts': {'proofs': proofs, 'ordinary_checks': 7 * proofs + cross}})
            elif name == 'adapter':
                fixture = Path(environment['M2_V3_CAMPAIGN_FINAL_FIXTURE'])
                wire = fixture / f'campaign-{args.mode}-k{args.target_count}-solana-wire.bin'
                wire.write_bytes(b'\x01' * 448)
                wire.chmod(0o600)
                if args.mode != 'coalesced-full' and args.target_count:
                    base = Path(environment['M2_V3_CAMPAIGN_BASE_FIXTURE'])
                    wire = base / 'campaign-full-k0-solana-wire.bin'
                    wire.write_bytes(b'\x02' * 448)
                    wire.chmod(0o600)
            elif name == 'effect_config':
                self.write(work / 'effect-config.json', {'config': True})
            elif name == 'application':
                private = Path(command[command.index('--private-output') + 1])
                private.mkdir(mode=0o700)
                self.write(work / 'effect-monitor.json', {
                    'owner': f'v3-campaign-{args.mode}-k{args.target_count}',
                    'stop_reason': 'runtime_seconds' if bad_monitor else None,
                    'runner_error_type': None,
                    'cleanup_remaining_owned_processes': 0,
                    'cleanup_status_unknown': False,
                    'exit_code': 0 if clean_shutdown else 1,
                    'limits': {'runtime_seconds': 180,
                               'owned_tree_rss_bytes': 4294967296,
                               'storage_growth_bytes': 268435456}})
                loaded = {key: key for key in ('program', 'programdata', 'elf_sha256',
                    'program_account_sha256', 'programdata_account_sha256', 'genesis')}
                loaded['elf_match'] = True
                self.write(args.effect_output / 'effect-report.json', {
                    'schema': 'part5-v3-campaign-effect-v1', 'passed': True,
                    'mode': args.mode, 'target_count': args.target_count,
                    'application_effect': True, 'effect_count': 1,
                    'request_consumed': True,
                    'stale_r0_rejected': args.target_count > 0 and args.mode != 'coalesced-full',
                    'finalized_slot': 5, 'loaded_program': loaded})
                self.write(args.control_output / 'status.json', {
                    'scope': 'part5-v3-campaign-effect',
                    'status': 'passed' if clean_shutdown else 'failed',
                    'mode': args.mode, 'target_count': args.target_count,
                    'effect_verified': not bad_effect, 'application_effect': True,
                    'effect_outcome': 'verified' if not bad_effect else 'requires_reconciliation',
                    'effect_count': 1,
                    'effect_report_sha256': tool.digest(args.effect_output / 'effect-report.json'),
                    'effect_output': str(args.effect_output),
                    'finalized_slot': 6,
                    'loaded_program': loaded,
                    'ledger_reuse_requires_review': not clean_shutdown,
                    'validator_cleanup': {'exit_code': 0 if clean_shutdown else -2,
                                          'reaped': True, 'graceful': clean_shutdown},
                    'runner_cleanup': {'exit_code': 0, 'reaped': True}})

        with mock.patch.dict('os.environ',
                             {'P5_V3_CAMPAIGN_SESSION_SUPERVISOR': 'bounded-complete-session'}), \
             mock.patch.object(tool, 'verify_boundary', return_value=boundary), \
             mock.patch.object(tool, 'fresh_output', side_effect=lambda p: p), \
             mock.patch.object(tool, 'run_stage', side_effect=stage):
            result = tool.run(args)
        return result, calls, json.loads((args.work_root / 'session-report.json').read_text())

    def test_registered_checkpoint_plan(self):
        self.assertEqual(tool.planned_checkpoints('full', 5),
                         (tuple(range(1, 6)), tuple(range(6))))
        self.assertEqual(tool.planned_checkpoints('anchor', 0), ((), (0,)))
        self.assertEqual(tool.planned_checkpoints('coalesced-full', 5), ((5,), (5,)))
        for mode, count in [('full', 3), ('coalesced', 1), ('anchor', -1)]:
            with self.subTest(mode=mode, count=count), self.assertRaises(ValueError):
                tool.planned_checkpoints(mode, count)
        self.assertEqual(tool.ORDERS, (
            ('full', 'anchor', 'coalesced-full'),
            ('anchor', 'coalesced-full', 'full'),
            ('full', 'coalesced-full', 'anchor'),
            ('coalesced-full', 'anchor', 'full')))

    def test_full_charges_every_input_witness_and_relation(self):
        result, calls, report = self.synthetic(self.args('full', 2))
        self.assertEqual(result, 0)
        names = [row[0] for row in calls]
        self.assertEqual(names[:10], ['source_import', 'r0_input', 'r1_input', 'r2_input',
            'r0_witness', 'r0_relation', 'r1_witness', 'r1_relation',
            'r2_witness', 'r2_relation'])
        self.assertTrue(report['effect_verified'])
        self.assertEqual(report['stage_wall_seconds_sum'], 1.5)
        self.assertFalse(report['complete_tree_cpu_qualified'])
        packet = next(command for name, command, _ in calls if name == 'packet')
        self.assertEqual(packet.count('--fixture'), 3)
        config = next(command for name, command, _ in calls if name == 'effect_config')
        self.assertIn('--base-wire', config)
        self.assertIn('--transition-config', config)

    def test_clean_validator_shutdown_matches_supervisor_success_contract(self):
        result, _, report = self.synthetic(self.args('full', 1), clean_shutdown=True)
        self.assertEqual(result, 0)
        self.assertTrue(report['effect_verified'])
        self.assertEqual(report['effect_supervisor_status'], 'passed')
        self.assertFalse(report['ledger_reuse_requires_review'])

    def test_coalesced_builds_only_final_complete_witness_and_no_base_wire(self):
        result, calls, report = self.synthetic(self.args('coalesced-full', 5))
        self.assertEqual(result, 0)
        names = [row[0] for row in calls]
        self.assertEqual([name for name in names if name.endswith('_input')],
                         ['r0_input', 'r5_input'])
        self.assertEqual([name for name in names if name.endswith('_witness')], ['r5_witness'])
        packet = next(command for name, command, _ in calls if name == 'packet')
        self.assertEqual(packet.count('--fixture'), 1)
        self.assertIn('--coalesced', packet)
        config = next(command for name, command, _ in calls if name == 'effect_config')
        self.assertNotIn('--base-wire', config)
        self.assertNotIn('base_wire_sha256', report)

    def test_zero_update_uses_stage_as_current_and_submits_one_effect(self):
        result, calls, report = self.synthetic(self.args('anchor', 0))
        self.assertEqual(result, 0)
        self.assertEqual([name for name, _, _ in calls if name.endswith('_input')], ['r0_input'])
        config = next(command for name, command, _ in calls if name == 'effect_config')
        self.assertIn('--stage-config', config)
        self.assertNotIn('--transition-config', config)
        self.assertEqual(report['base_wire_sha256'], report['current_wire_sha256'])

    def test_successful_child_commands_do_not_override_failed_effect(self):
        result, calls, report = self.synthetic(self.args('full', 1), bad_effect=True)
        self.assertEqual(result, 2)
        self.assertFalse(report['passed'])
        self.assertFalse(report['effect_verified'])
        self.assertEqual(report['error_type'], 'ValueError')
        self.assertEqual(calls[-1][0], 'application')

    def test_bounded_effect_timeout_cannot_be_reported_as_success(self):
        result, calls, report = self.synthetic(self.args('anchor', 1), bad_monitor=True)
        self.assertEqual(result, 2)
        self.assertFalse(report['passed'])
        self.assertFalse(report['effect_verified'])
        self.assertNotIn('effect_report_sha256', report)


if __name__ == '__main__':
    unittest.main()
