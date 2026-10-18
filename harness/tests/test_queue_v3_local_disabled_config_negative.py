import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    'queue_v3_disabled_config_negative',
    Path(__file__).with_name('queue_v3_local_disabled_config_negative.py'))
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')
SCENARIOS = (
    'v3-disabled-negative-refresh-source',
    'v3-disabled-negative-refresh-head',
    'v3-disabled-negative-disable-config',
    'v3-disabled-negative-valid-full-execute',
    'v3-disabled-negative-reenable-config',
    'v3-disabled-negative-refresh-issuer-source',
    'v3-disabled-negative-rebind-issuer-head',
    'v3-disabled-negative-disable-issuer',
    'v3-disabled-negative-valid-full-execute-issuer',
)


def fixture_report(output):
    stage_report = {
        'genesis': 'local-genesis', 'program': 'local-program',
        'finalized_slot': 40,
        **{name: 'address-' + name for name in ACCOUNT_NAMES},
    }
    report = {
        'schema': supervisor.REPORT_SCHEMA,
        'variant': 3, 'request_slot': 'A', 'passed': True,
        'program': 'local-program', 'genesis': 'local-genesis',
        'loaded_elf_sha256': 'e' * 64,
        'stage_report_sha256': 'a' * 64,
        'stage_plan_sha256': 'b' * 64,
        'full_wire_sha256': 'c' * 64,
        'clone_receipt_sha256': 'd' * 64,
        'config_disabled': True, 'execute_rejected': True,
        'refresh_and_bind_succeeded': True,
        'disable_changed_only_enabled_and_epoch': True,
        'accounts_unchanged_after_rejection': True,
        'issuer_disabled': True, 'issuer_execute_rejected': True,
        'issuer_disable_changed_only_enabled_epoch_status': True,
        'issuer_accounts_unchanged_after_rejection': True,
        'expected_custom_error': 713,
        'addresses': {name: stage_report[name] for name in ACCOUNT_NAMES},
        'source_finalized_slot': 40,
        'eligible_finalized_slot': 43,
        'disabled_finalized_slot': 45,
        'rejected_finalized_slot': 46,
        'issuer_eligible_finalized_slot': 48,
        'issuer_disabled_finalized_slot': 50,
        'issuer_rejected_finalized_slot': 51,
        'issuer_eligible_clock': 111,
        'refresh_transaction': {'signature': 'sig-0', 'slot': 41},
        'bind_transaction': {'signature': 'sig-1', 'slot': 42},
        'disable_transaction': {'signature': 'sig-2', 'slot': 43,
                                'finalized_slot': 45},
        'execute_transaction': {'signature': 'sig-3', 'slot': 44,
                                 'custom_error': 713, 'finalized_slot': 46},
        'reenable_transaction': {'signature': 'sig-4', 'slot': 45},
        'issuer_refresh_transaction': {'signature': 'sig-5', 'slot': 46},
        'issuer_bind_transaction': {'signature': 'sig-6', 'slot': 47},
        'issuer_disable_transaction': {'signature': 'sig-7', 'slot': 48,
                                       'finalized_slot': 50},
        'issuer_execute_transaction': {'signature': 'sig-8', 'slot': 49,
                                       'custom_error': 713,
                                       'finalized_slot': 51},
    }
    summaries = (
        'refresh_transaction', 'bind_transaction', 'disable_transaction',
        'execute_transaction', 'reenable_transaction',
        'issuer_refresh_transaction', 'issuer_bind_transaction',
        'issuer_disable_transaction', 'issuer_execute_transaction',
    )
    report['transactions'] = []
    for index, (scenario, summary_name) in enumerate(zip(SCENARIOS, summaries)):
        summary = report[summary_name]
        failed = index in (3, 8)
        report['transactions'].append({
            'scenario': scenario, 'signature': summary['signature'],
            'slot': summary['slot'], 'customError': 713 if failed else None,
            'err': {'InstructionError': [1, {'Custom': 713}]} if failed else None,
        })

    groups = ('eligible', 'before', 'after', 'issuer_eligible',
              'issuer_before', 'issuer_after')
    snapshots = {}
    for group_index, group in enumerate(groups):
        snapshots[group] = {}
        (output / group).mkdir()
        for account_index, name in enumerate(ACCOUNT_NAMES):
            if group == 'after':
                data = snapshots['before'][name]
            elif group == 'issuer_after':
                data = snapshots['issuer_before'][name]
            else:
                data = bytes([group_index + account_index + 1]) * (8 + account_index)
            path = output / group / (name + '.bin')
            path.write_bytes(data)
            path.chmod(0o600)
            digest = hashlib.sha256(data).hexdigest()
            snapshots[group][name] = data
            report.setdefault(group + '_sha256', []).append(digest)
            report.setdefault(group + '_accounts', []).append(
                {'name': name, 'path': str(path), 'sha256': digest})
    return report, stage_report


class DisabledConfigNegativeReportTests(unittest.TestCase):
    def test_run_checks_stage_report_with_wrapper_config(self):
        config = {
            'prior_stage_config': '/unused/stage-config.json',
            'prior_stage_config_sha256': 'd' * 64,
            'prior_stage_status': '/unused/stage-status.json',
            'prior_stage_status_sha256': 'e' * 64,
            'prior_stage_monitor': '/unused/stage-monitor.json',
            'prior_stage_monitor_sha256': 'f' * 64,
            'stage_root': '/unused/stage',
            'stage_report_sha256': 'a' * 64,
            'stage_plan_sha256': 'b' * 64,
            'expected_genesis': 'local-genesis',
        }
        encoded = (json.dumps(config, sort_keys=True, separators=(',', ':'),
                              allow_nan=False) + '\n').encode()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp).resolve() / 'config.json'
            config_path.write_bytes(encoded)
            stage_config = {'prior_config': '/unused/prepared.json',
                            'prior_config_sha256': 'c' * 64}
            pinned_json = [stage_config, {}, {}, {}]
            stage_report = {'stage': 'report'}
            stage_plan = {'stage': 'plan'}

            class StageReportChecked(Exception):
                pass

            with mock.patch.dict(supervisor.os.environ, {
                    'P5_V3_DISABLED_CONFIG_NEGATIVE_SCOPE': supervisor.SCOPE}), \
                    mock.patch.object(supervisor, '_validate_config'), \
                    mock.patch.object(supervisor.execute, 'pinned_json',
                                      side_effect=pinned_json), \
                    mock.patch.object(supervisor.execute, 'review_stage'), \
                    mock.patch.object(supervisor, '_pinned',
                                      side_effect=[stage_report, stage_plan]), \
                    mock.patch.object(supervisor.execute, 'check_stage_report',
                                      side_effect=StageReportChecked) as check_report:
                with self.assertRaises(StageReportChecked):
                    supervisor.run(config, hashlib.sha256(encoded).hexdigest(),
                                   config_path)

        self.assertIs(check_report.call_args.args[2], config)

    def test_run_passes_pinned_elf_bytes_to_loaded_identity_check(self):
        config = {
            'prior_stage_config': '/unused/stage-config.json',
            'prior_stage_config_sha256': 'd' * 64,
            'prior_stage_status': '/unused/stage-status.json',
            'prior_stage_status_sha256': 'e' * 64,
            'prior_stage_monitor': '/unused/stage-monitor.json',
            'prior_stage_monitor_sha256': 'f' * 64,
            'stage_root': '/unused/stage',
            'stage_report_sha256': 'a' * 64,
            'stage_plan_sha256': 'b' * 64,
            'ledger': '/unused/heldout/ledger',
            'heldout_r0_clone_report': '/unused/heldout/clone-report.json',
            'heldout_r0_clone_report_sha256': '1' * 64,
            'expected_genesis': 'local-genesis',
            'runner': '/unused/stage/runner',
            'runner_sha256': '2' * 64,
            'full_wire': '/unused/full-wire.bin',
            'full_wire_sha256': '3' * 64,
            'expected_program': 'local-program',
            'expected_elf_sha256': '4' * 64,
            'output_dir': '/unused/output',
            'control_output': '/unused/control',
            'rust_config_path': '/unused/rust-config.json',
            'rust_config_sha256': '5' * 64,
            'variant': 3,
        }
        encoded = (json.dumps(config, sort_keys=True, separators=(',', ':'),
                              allow_nan=False) + '\n').encode()
        stage_report_path = str(Path(config['stage_root']) / 'stage-report.json')
        stage_plan_path = str(Path(config['stage_root']) / 'plan.json')
        rust_config = {
            'schema': 'part5-v3-disabled-config-negative-config-v1',
            'variant': 3, 'request_slot': 'A', 'stage_root': config['stage_root'],
            'stage_report': stage_report_path,
            'stage_report_sha256': config['stage_report_sha256'],
            'stage_plan': stage_plan_path,
            'stage_plan_sha256': config['stage_plan_sha256'],
            'ledger': config['ledger'],
            'heldout_r0_clone_report': config['heldout_r0_clone_report'],
            'heldout_r0_clone_report_sha256': config['heldout_r0_clone_report_sha256'],
            'full_wire': config['full_wire'],
            'full_wire_sha256': config['full_wire_sha256'],
            'expected_program': config['expected_program'],
            'expected_genesis': config['expected_genesis'],
            'expected_elf_sha256': config['expected_elf_sha256'],
            'output_dir': config['output_dir'], 'control_output': config['control_output'],
            'runner': config['runner'], 'runner_sha256': config['runner_sha256'],
        }
        stage_config = {
            'prior_config': '/unused/prepared.json',
            'prior_config_sha256': 'c' * 64,
            'runner': config['runner'],
            'runner_sha256': config['runner_sha256'],
        }
        prepared = {'program': config['expected_program'],
                    'validator': '/unused/validator',
                    'elf': '/unused/program.so',
                    'elf_sha256': config['expected_elf_sha256']}
        stage_report = {'genesis': config['expected_genesis']}
        elf_bytes = b'pinned ELF bytes'

        class LoadedCheckReached(Exception):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            config_path = root / 'config.json'
            config_path.write_bytes(encoded)
            rpc = object()
            validator = object()

            def checked(path, digest, cap):
                if path == config['runner']:
                    return b'pinned runner'
                if path == prepared['elf']:
                    return elf_bytes
                self.fail(f'unexpected checked input: {path}')

            with mock.patch.dict(supervisor.os.environ, {
                    'P5_V3_DISABLED_CONFIG_NEGATIVE_SCOPE': supervisor.SCOPE}), \
                    mock.patch.object(supervisor, '_validate_config'), \
                    mock.patch.object(supervisor.execute, 'pinned_json',
                                      side_effect=[stage_config, {}, {}, prepared]), \
                    mock.patch.object(supervisor.execute, 'review_stage'), \
                    mock.patch.object(supervisor, '_pinned',
                                      side_effect=[stage_report, {}]), \
                    mock.patch.object(supervisor.execute, 'check_stage_report'), \
                    mock.patch.object(supervisor.execute, 'report_loaded'), \
                    mock.patch.object(supervisor, '_clone_is_initial'), \
                    mock.patch.object(supervisor.execute.stage, 'snapshot_generated',
                                      side_effect=[(b'rust config', config['rust_config_sha256']),
                                                   (b'x' * 448, config['full_wire_sha256'])]), \
                    mock.patch.object(supervisor.execute.base, 'decode_json',
                                      return_value=rust_config), \
                    mock.patch.object(supervisor.execute.base, 'checked',
                                      side_effect=checked) as checked_input, \
                    mock.patch.object(supervisor.execute.base, 'fresh_child',
                                      side_effect=[root / 'output', root / 'control']), \
                    mock.patch.object(supervisor.execute.base, 'ports_free'), \
                    mock.patch.object(supervisor.execute.stage, 'resume_argv',
                                      return_value=['validator']), \
                    mock.patch.object(supervisor.execute.base, 'LocalRpc',
                                      return_value=rpc), \
                    mock.patch.object(supervisor.execute, 'wait_loaded_after_start',
                                      side_effect=LoadedCheckReached) as wait_loaded, \
                    mock.patch.object(supervisor.subprocess, 'Popen',
                                      return_value=validator) as popen, \
                    mock.patch.object(supervisor.execute.base, 'cleanup',
                                      return_value={'reaped': True}):
                supervisor.run(config, hashlib.sha256(encoded).hexdigest(),
                               config_path)

            status = json.loads((root / 'control' / 'status.json').read_text())
            self.assertEqual(status['error_type'], 'LoadedCheckReached', status)
        self.assertEqual(checked_input.call_args_list, [
            mock.call(config['runner'], config['runner_sha256'], 128 * 1024 * 1024),
            mock.call(prepared['elf'], prepared['elf_sha256'], 4 * 1024 * 1024),
        ])
        wait_loaded.assert_called_once_with(
            rpc, validator, prepared['program'], elf_bytes, prepared['elf_sha256'])
        popen.assert_called_once()

    def test_clone_receipt_checks_initial_clone_after_source_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / 'source' / 'ledger'
            clone = root / 'heldout' / 'ledger'
            for path in (source.parent, source, clone.parent, clone):
                path.mkdir(mode=0o700)
            for ledger in (source, clone):
                genesis = ledger / 'genesis.bin'
                genesis.write_bytes(b'initial R0 ledger')
                genesis.chmod(0o600)

            clone_rows = supervisor.ledger_inventory(clone)
            receipt = {
                'schema': 'part5-v3-heldout-r0-ledger-clone-v1',
                'heldout_acceptance': False,
                'stage_report_sha256': 'a' * 64,
                'stage_status_sha256': 'b' * 64,
                'stage_monitor_sha256': 'c' * 64,
                'source': str(source), 'destination': str(clone),
                'entry_count': len(clone_rows),
                'tree_sha256': hashlib.sha256(
                    json.dumps(clone_rows, separators=(',', ':')).encode()).hexdigest(),
                'source_stable': True, 'copy_identical': True,
                'loaded_identity_rechecked_after_restart': False,
                'application_effect': False,
            }
            receipt_path = clone.parent / 'clone-report.json'
            receipt_path.write_text(json.dumps(receipt))
            receipt_path.chmod(0o600)
            config = {
                'ledger': str(clone),
                'heldout_r0_clone_report': str(receipt_path),
                'heldout_r0_clone_report_sha256': hashlib.sha256(
                    receipt_path.read_bytes()).hexdigest(),
                'stage_report_sha256': 'a' * 64,
                'prior_stage_status_sha256': 'b' * 64,
                'prior_stage_monitor_sha256': 'c' * 64,
            }
            stage_config = {'ledger': str(source)}

            (source / 'genesis.bin').write_bytes(b'transitioned to R1')
            self.assertEqual(
                supervisor._clone_is_initial(config, stage_config, {}, {}, {}),
                receipt)

            (clone / 'genesis.bin').write_bytes(b'tampered clone')
            with self.assertRaisesRegex(ValueError, 'clone must start byte-identical'):
                supervisor._clone_is_initial(config, stage_config, {}, {}, {})

    def test_accepts_complete_v2_report_and_all_six_pinned_snapshot_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            report, stage_report = fixture_report(output)
            result = supervisor._validate_report(
                report, {'variant': 3, 'expected_program': 'local-program',
                         'expected_genesis': 'local-genesis',
                         'expected_elf_sha256': 'e' * 64,
                         'stage_report_sha256': 'a' * 64,
                         'stage_plan_sha256': 'b' * 64,
                         'full_wire_sha256': 'c' * 64,
                         'heldout_r0_clone_report_sha256': 'd' * 64},
                stage_report, output)
            self.assertEqual(set(result), {
                'eligible', 'before', 'after', 'issuer_eligible',
                'issuer_before', 'issuer_after'})

    def test_supervisor_budget_is_enforced_at_the_165_second_boundary(self):
        with mock.patch.object(supervisor.time, 'monotonic', return_value=164.9):
            supervisor._check_supervisor_budget(0)
        with mock.patch.object(supervisor.time, 'monotonic', return_value=165):
            with self.assertRaises(TimeoutError):
                supervisor._check_supervisor_budget(0)

    def test_distinct_transactions_can_land_in_the_same_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            report, stage_report = fixture_report(output)
            report['bind_transaction']['slot'] = 41
            report['transactions'][1]['slot'] = 41
            supervisor._validate_report(
                report, {'variant': 3, 'expected_program': 'local-program',
                         'expected_genesis': 'local-genesis',
                         'expected_elf_sha256': 'e' * 64,
                         'stage_report_sha256': 'a' * 64,
                         'stage_plan_sha256': 'b' * 64,
                         'full_wire_sha256': 'c' * 64,
                         'heldout_r0_clone_report_sha256': 'd' * 64},
                stage_report, output)
            report['bind_transaction']['signature'] = 'sig-0'
            report['transactions'][1]['signature'] = 'sig-0'
            with self.assertRaisesRegex(ValueError, 'distinct ordered transactions'):
                supervisor._validate_report(
                    report, {'variant': 3, 'expected_program': 'local-program',
                             'expected_genesis': 'local-genesis',
                             'expected_elf_sha256': 'e' * 64,
                             'stage_report_sha256': 'a' * 64,
                             'stage_plan_sha256': 'b' * 64,
                             'full_wire_sha256': 'c' * 64,
                             'heldout_r0_clone_report_sha256': 'd' * 64},
                    stage_report, output)

    def test_finality_must_follow_events_advance_and_match_direct_transaction_pins(self):
        config = {'variant': 3, 'expected_program': 'local-program',
                  'expected_genesis': 'local-genesis',
                  'expected_elf_sha256': 'e' * 64,
                  'stage_report_sha256': 'a' * 64,
                  'stage_plan_sha256': 'b' * 64,
                  'full_wire_sha256': 'c' * 64,
                  'heldout_r0_clone_report_sha256': 'd' * 64}
        for field, value in (
                ('eligible_finalized_slot', 41),
                ('disabled_finalized_slot', 44),
                ('eligible_finalized_slot', 49)):
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp)
                report, stage_report = fixture_report(output)
                report[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    supervisor._validate_report(report, config, stage_report, output)

    def test_rejects_missing_issuer_claim_or_either_policy_713(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            report, stage_report = fixture_report(output)
            config = {'variant': 3, 'expected_program': 'local-program',
                      'expected_genesis': 'local-genesis',
                      'expected_elf_sha256': 'e' * 64,
                      'stage_report_sha256': 'a' * 64,
                      'stage_plan_sha256': 'b' * 64,
                      'full_wire_sha256': 'c' * 64,
                      'heldout_r0_clone_report_sha256': 'd' * 64}
            for field in ('issuer_disabled', 'issuer_execute_rejected',
                          'issuer_disable_changed_only_enabled_epoch_status',
                          'issuer_accounts_unchanged_after_rejection'):
                altered = dict(report)
                altered[field] = False
                with self.subTest(field=field), self.assertRaises(ValueError):
                    supervisor._validate_report(altered, config, stage_report, output)
            for field in ('execute_transaction', 'issuer_execute_transaction'):
                altered = json.loads(json.dumps(report))
                altered[field]['custom_error'] = 714
                with self.subTest(field=field), self.assertRaises(ValueError):
                    supervisor._validate_report(altered, config, stage_report, output)

    def test_rejects_incomplete_or_reordered_transactions_and_changed_rejection_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            report, stage_report = fixture_report(output)
            config = {'variant': 3, 'expected_program': 'local-program',
                      'expected_genesis': 'local-genesis',
                      'expected_elf_sha256': 'e' * 64,
                      'stage_report_sha256': 'a' * 64,
                      'stage_plan_sha256': 'b' * 64,
                      'full_wire_sha256': 'c' * 64,
                      'heldout_r0_clone_report_sha256': 'd' * 64}
            altered = dict(report, transactions=report['transactions'][:-1])
            with self.assertRaises(ValueError):
                supervisor._validate_report(altered, config, stage_report, output)

            altered = json.loads(json.dumps(report))
            altered['transactions'][5], altered['transactions'][6] = (
                altered['transactions'][6], altered['transactions'][5])
            with self.assertRaises(ValueError):
                supervisor._validate_report(altered, config, stage_report, output)

            (output / 'issuer_after' / 'request.bin').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                supervisor._validate_report(report, config, stage_report, output)


if __name__ == '__main__':
    unittest.main()
