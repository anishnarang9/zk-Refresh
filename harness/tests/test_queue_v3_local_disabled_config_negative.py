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
