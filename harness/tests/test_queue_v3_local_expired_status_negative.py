import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from tools.part5 import heldout_expired_status_evidence as evidence

spec = importlib.util.spec_from_file_location(
    'queue_v3_expired_status_negative',
    Path(__file__).with_name('queue_v3_local_expired_status_negative.py'))
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


def config():
    value = {
        'schema': supervisor.CONFIG_SCHEMA,
        'scope': supervisor.SCOPE,
        'variant': 3,
        'request_slot': 'A',
        'freeze_report': '/pinned/freeze.json',
        'stage_report': '/pinned/stage.json',
        'stage_plan': '/pinned/plan.json',
        'source_receipt': '/pinned/source.json',
        'clone_receipt': '/pinned/clone.json',
        'full_proof_receipt': '/pinned/proof-receipt.json',
        'full_proof': '/pinned/full-proof.bin',
        'full_wire': '/pinned/full-wire.bin',
        'runner': '/pinned/runner',
        'expected_program': 'local-program',
        'expected_genesis': 'local-genesis',
        'ledger': '/pinned/clone/ledger',
        'stage_root': '/pinned/stage',
        'output_dir': '/repo/artifacts/dynark/part5/expired-output',
        'control_output': '/repo/artifacts/dynark/part5/expired-control',
        'owner': 'test-owner',
        'observation_lifetime_seconds': 20,
        'wait_deadline_seconds': 45,
        'owner_process_limits': {'validators': 1, 'runners': 1},
        'outer_limits_required': supervisor.LIMITS,
    }
    for field in supervisor.PIN_FIELDS:
        value[field] = 'a' * 64
    return value


def valid_report(root, value):
    receipt = root / 'proof-receipt.json'
    wire = root / 'full-wire.bin'
    receipt.write_bytes(b'{"receipt":"pinned"}')
    wire.write_bytes(b'complete-full-wire')
    value['full_proof_receipt'] = str(receipt)
    value['full_proof_receipt_sha256'] = hashlib.sha256(receipt.read_bytes()).hexdigest()
    value['full_wire'] = str(wire)
    value['full_wire_sha256'] = hashlib.sha256(wire.read_bytes()).hexdigest()

    snapshots = []
    snapshot_root = root / 'snapshots'
    snapshot_root.mkdir()
    for index, name in enumerate(supervisor.ACCOUNT_NAMES):
        raw = bytes([index + 1]) * (8 + index)
        refs = {}
        for phase in ('before', 'after'):
            path = snapshot_root / f'{name}-{phase}.bin'
            path.write_bytes(raw)
            refs[phase] = {'path': str(path),
                           'sha256': hashlib.sha256(raw).hexdigest()}
        snapshots.append({'name': name, **refs})

    return {
        'schema': evidence.SCHEMA,
        'identities': supervisor._expected_identities(value),
        'clock': {'observed_at': 100, 'expires_at': 120,
                  'now': 120, 'rpc_finalized': True},
        'preconditions': {'status_active': True, 'issuer_active': True,
                          'head_bound': True, 'request_live': True,
                          'full_wire_valid': True},
        'transaction': {
            'signature': '1' * 64, 'slot': 17, 'finalized': True,
            'error': {'InstructionError': [1, {'Custom': 705}]},
        },
        'source_refs': {
            'full_proof': {'path': str(receipt),
                           'sha256': value['full_proof_receipt_sha256']},
            'full_wire': {'path': str(wire), 'sha256': value['full_wire_sha256']},
        },
        'snapshots': snapshots,
        'limits': {'owner_wall_seconds': 180, 'rss_bytes': 4294967296,
                   'storage_growth_bytes': 268435456, 'clock_wait_seconds': 60},
        'measured': {'owner_wall_seconds': 30, 'clock_wait_seconds': 20,
                     'peak_owned_rss_bytes': 1024, 'storage_growth_bytes': 100},
        'cleanup': {'remaining_owned_processes': 0, 'status_unknown': False,
                    'runner_reaped': True, 'validator_reaped': True,
                    'censored': False, 'stop_reason': None,
                    'runner_error_type': None},
        'application_effect': False,
    }


class ExpiredStatusNegativeTests(unittest.TestCase):
    def test_cli_failure_does_not_echo_private_paths(self):
        argv = ['expired', '--config', '/PRIVATE/config.json', '--config-sha256', 'a' * 64]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(
                supervisor.execute, 'pinned_json', side_effect=ValueError('/PRIVATE/key')):
            with self.assertRaises(SystemExit) as caught:
                supervisor.main()
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_requires_external_proof_wire_and_identity_pins(self):
        value = config()
        supervisor._validate_config(value)
        for field in ('full_proof_sha256', 'full_proof_receipt_sha256',
                      'full_wire_sha256', 'freeze_sha256',
                      'expected_genesis_sha256', 'stage_report_sha256',
                      'clone_receipt_sha256', 'expected_elf_sha256'):
            altered = dict(value)
            altered[field] = 'not-a-pin'
            with self.subTest(field=field), self.assertRaises(ValueError):
                supervisor._validate_config(altered)

    def test_checks_external_artifact_bytes_against_each_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            value = config()
            contents = {
                'freeze_report': b'freeze', 'stage_report': b'stage',
                'stage_plan': b'plan', 'source_receipt': b'source',
                'clone_receipt': b'clone', 'full_proof_receipt': b'proof-receipt',
                'full_proof': b'proof-bytes', 'full_wire': b'w' * 448,
            }
            for field, raw in contents.items():
                path = root / (field + '.bin')
                path.write_bytes(raw)
                path.chmod(0o600)
                value[field] = str(path)
                pin = {'freeze_report': 'freeze_sha256',
                       'stage_report': 'stage_report_sha256',
                       'stage_plan': 'stage_plan_sha256',
                       'source_receipt': 'source_receipt_sha256',
                       'clone_receipt': 'clone_receipt_sha256',
                       'full_proof_receipt': 'full_proof_receipt_sha256',
                       'full_proof': 'full_proof_sha256',
                       'full_wire': 'full_wire_sha256'}[field]
                value[pin] = hashlib.sha256(raw).hexdigest()
            runner = root / 'runner'
            runner.write_bytes(b'runner-binary-pin')
            runner.chmod(0o600)
            value['runner'] = str(runner)
            value['runner_sha256'] = hashlib.sha256(runner.read_bytes()).hexdigest()
            for field in ('ledger', 'stage_root', 'output_dir', 'control_output'):
                value[field] = str(root / field)
            value['expected_elf_sha256'] = 'e' * 64

            supervisor._validate_config(value)
            supervisor._check_input_pins(value)
            (root / 'full_wire.bin').write_bytes(b'x' * 448)
            with self.assertRaisesRegex(ValueError, 'full_wire input pin mismatch'):
                supervisor._check_input_pins(value)

    def test_finalized_time_gate_waits_for_expiry_and_enforces_age(self):
        values = iter([(7, 119), (8, 120)])
        calls = []
        current = [None]

        def rpc(method, params):
            calls.append((method, params))
            if method == 'getSlot':
                current[0] = values.__next__()
                return current[0][0]
            return current[0][1]

        result = supervisor._wait_for_finalized_expiry(
            rpc, observed_at=100, expires_at=120,
            wait_deadline_seconds=5, monotonic=lambda: 0, sleep=lambda _: None)
        self.assertEqual(result, {'slot': 8, 'unix_time': 120, 'age_seconds': 20})
        self.assertEqual(calls[0], ('getSlot', [{'commitment': 'finalized'}]))
        self.assertEqual(calls[1], ('getBlockTime', [7]))

        with self.assertRaisesRegex(ValueError, 'observation age'):
            supervisor._wait_for_finalized_expiry(
                lambda method, params: 9 if method == 'getSlot' else 401,
                observed_at=100, expires_at=120,
                wait_deadline_seconds=5, monotonic=lambda: 0, sleep=lambda _: None)

    def test_finalized_time_gate_times_out_without_expiry(self):
        ticks = iter([0, 0, 6])
        def rpc(method, params):
            return 7 if method == 'getSlot' else 119

        with self.assertRaises(TimeoutError):
            supervisor._wait_for_finalized_expiry(
                rpc, observed_at=100, expires_at=120,
                wait_deadline_seconds=5, monotonic=lambda: next(ticks),
                sleep=lambda _: None)

    def test_valid_prospective_report_passes_supervisor_and_existing_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            value = config()
            report = valid_report(root, value)
            expected = supervisor._expected_identities(value)
            direct = evidence.validate_report(report, expected)
            report_path = root / 'prospective-report.json'
            report_path.write_text(json.dumps(report, sort_keys=True) + '\n')
            file_facts = evidence.verify_file(report_path, expected)
            wrapped = supervisor._validate_report(report, value)
            self.assertEqual(wrapped, direct)
            self.assertEqual(file_facts, direct)
            self.assertEqual(wrapped['custom_error'], 705)
            self.assertFalse(wrapped['loaded_run_established'])

    def test_existing_contract_rejects_wrong_instruction_changed_bytes_and_limit_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            value = config()
            report = valid_report(root, value)
            report['transaction']['error'] = {'InstructionError': [0, {'Custom': 705}]}
            with self.assertRaisesRegex(ValueError, 'exact instruction/custom'):
                supervisor._validate_report(report, value)

        for failure in ('snapshot', 'limit', 'cleanup'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                value = config()
                report = valid_report(root, value)
                if failure == 'snapshot':
                    changed = b'changed'
                    path = Path(report['snapshots'][-1]['after']['path'])
                    path.write_bytes(changed)
                    report['snapshots'][-1]['after']['sha256'] = hashlib.sha256(changed).hexdigest()
                    message = 'application account changed'
                elif failure == 'limit':
                    report['measured']['peak_owned_rss_bytes'] = report['limits']['rss_bytes'] + 1
                    message = 'resource or clock wait limit'
                else:
                    report['cleanup']['remaining_owned_processes'] = 1
                    message = 'cleanup required'
                with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, message):
                    supervisor._validate_report(report, value)

    def test_missing_rust_entrypoint_fails_closed_with_specific_integration_need(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
                supervisor, 'REPO', Path(tmp).resolve()):
            with self.assertRaisesRegex(supervisor.IntegrationRequired,
                                       'publisher observation.*finalized.*705'):
                supervisor._require_rust_entrypoint()

    def test_blocked_status_is_private_and_records_no_process_or_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output_root = root / 'artifacts/dynark/part5'
            output_root.mkdir(parents=True)
            value = config()
            value['output_dir'] = str(output_root / 'out')
            value['control_output'] = str(output_root / 'control')
            with mock.patch.object(supervisor, 'REPO', root):
                path = supervisor._write_blocked_status(value, 'a' * 64,
                                                        root / 'config.json')
            status = supervisor.execute.base.decode_json(path.read_bytes())
            self.assertEqual(status['status'], 'blocked_integration')
            self.assertIs(status['application_effect'], False)
            self.assertIs(status['loaded_execution_claimed'], False)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_run_accepts_external_raw_config_hash_and_reaches_blocked_integration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output_root = root / 'artifacts/dynark/part5'
            output_root.mkdir(parents=True)
            value = config()
            for field in supervisor.CONFIG_PATH_FIELDS:
                value[field] = str(root / field)
            value['output_dir'] = str(output_root / 'out')
            value['control_output'] = str(output_root / 'control')
            config_path = root / 'supervisor-config.json'
            raw = (json.dumps(value, indent=2, sort_keys=False) + '\n').encode()
            config_path.write_bytes(raw)
            config_path.chmod(0o600)
            config_sha = hashlib.sha256(raw).hexdigest()

            with mock.patch.object(supervisor, 'REPO', root), \
                    mock.patch.object(supervisor, '_check_input_pins'), \
                    mock.patch.dict(os.environ,
                                    {'P5_V3_EXPIRED_STATUS_NEGATIVE_SCOPE': supervisor.SCOPE}):
                result = supervisor.run(value, config_sha, config_path)

            self.assertEqual(result, 2)
            status = supervisor.execute.base.decode_json(
                (output_root / 'control/status.json').read_bytes())
            self.assertEqual(status['status'], 'blocked_integration')
            self.assertIs(status['loaded_execution_claimed'], False)


if __name__ == '__main__':
    unittest.main()
