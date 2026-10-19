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
        'stage_config': '/pinned/stage-config.json',
        'stage_status': '/pinned/stage-control/status.json',
        'stage_report': '/pinned/stage.json',
        'stage_plan': '/pinned/plan.json',
        'source_receipt': '/pinned/source.json',
        'clone_receipt': '/pinned/clone.json',
        'full_proof_receipt': '/pinned/proof-receipt.json',
        'full_proof': '/pinned/full-proof.bin',
        'full_wire': '/pinned/full-wire.bin',
        'runner': '/pinned/runner',
        'expected_elf': '/pinned/program.so',
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
    value['stage_config_sha256'] = 'b' * 64
    value['stage_status_sha256'] = 'c' * 64
    return value


def _write_private(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(raw)
    path.chmod(0o600)
    return hashlib.sha256(raw).hexdigest()


def make_preflight_artifacts(root, value):
    """Create a hash-consistent synthetic stage/source/clone provenance chain."""
    from harness.tests.queue_v3_clone_ledger import inventory

    for field in supervisor.CONFIG_PATH_FIELDS:
        value[field] = str(root / field)

    stage_root = root / 'stage'
    stage_root.mkdir(mode=0o700)
    program = bytes(range(1, 33))
    genesis_identity = bytes(range(33, 65))
    value['expected_program'] = supervisor.execute.base.b58(program)
    value['expected_genesis'] = supervisor.execute.base.b58(genesis_identity)
    value['stage_root'] = str(stage_root)
    value['stage_plan'] = str(stage_root / 'plan.json')
    value['stage_report'] = str(stage_root / 'stage-report.json')

    plan = {'program': list(program), 'genesis': list(genesis_identity)}
    plan_raw = (json.dumps(plan, sort_keys=True, separators=(',', ':')) + '\n').encode()
    value['stage_plan_sha256'] = _write_private(Path(value['stage_plan']), plan_raw)

    expected_elf = root / 'accepted-program.so'
    value['expected_elf'] = str(expected_elf)
    value['expected_elf_sha256'] = _write_private(expected_elf, b'synthetic-accepted-elf')
    freeze = {'schema': 'credential-v3-frozen-holdout-boundary-v1',
              'identities': {'loaded_elf': value['expected_elf_sha256']}}
    freeze_raw = (json.dumps(freeze, sort_keys=True, separators=(',', ':')) + '\n').encode()
    value['freeze_sha256'] = _write_private(Path(value['freeze_report']), freeze_raw)

    stage_report = {
        'schema': 'part5-v3-local-stage-v1', 'passed': True,
        'training_only': True, 'application_effect': False, 'proof_created': False,
        'registry_history_authenticated': True, 'allocation_history_authenticated': True,
        'plan_sha256': value['stage_plan_sha256'],
        'program': value['expected_program'], 'genesis': value['expected_genesis'],
        'loaded_program': {'elf_match': True, 'elf_sha256': value['expected_elf_sha256']},
    }
    stage_raw = (json.dumps(stage_report, sort_keys=True, separators=(',', ':')) + '\n').encode()
    value['stage_report_sha256'] = _write_private(Path(value['stage_report']), stage_raw)

    source_root = root / 'stage-ledger'
    clone_root = root / 'clone'
    source_ledger = source_root / 'ledger'
    ledger = clone_root / 'ledger'
    source_ledger.mkdir(mode=0o700, parents=True)
    ledger.mkdir(mode=0o700, parents=True)
    genesis_bytes = b'synthetic ledger genesis bytes'
    genesis_sha = _write_private(source_ledger / 'genesis.bin', genesis_bytes)
    _write_private(ledger / 'genesis.bin', genesis_bytes)
    value['ledger'] = str(ledger)
    value['expected_genesis_sha256'] = genesis_sha
    value['clone_receipt'] = str(clone_root / 'clone-report.json')

    stage_control = root / 'stage-control'
    stage_control.mkdir(mode=0o700)
    value['stage_config'] = str(root / 'stage-config.json')
    value['stage_status'] = str(stage_control / 'status.json')
    stage_config = {
        'schema': 1, 'scope': 'part5-v3-local-stage',
        'expected_genesis': value['expected_genesis'],
        'ledger': str(source_ledger), 'stage_output': str(stage_root),
        'control_output': str(stage_control),
    }
    stage_config_raw = (json.dumps(stage_config, sort_keys=True, separators=(',', ':')) + '\n').encode()
    value['stage_config_sha256'] = _write_private(Path(value['stage_config']), stage_config_raw)
    stage_status = {
        'schema': 1, 'scope': 'part5-v3-local-stage', 'status': 'failed',
        'stage_verified': True, 'ledger_reuse_requires_review': True,
        'application_effect': False, 'devnet': False,
        'config_sha256': value['stage_config_sha256'],
        'stage_report_sha256': value['stage_report_sha256'],
        'stage_output': str(stage_root),
        'validator_cleanup': {'spawned': True, 'reaped': True,
                              'graceful': False, 'exit_code': -2},
        'runner_cleanup': {'spawned': True, 'reaped': True, 'exit_code': 0},
    }
    status_raw = (json.dumps(stage_status, sort_keys=True, separators=(',', ':')) + '\n').encode()
    value['stage_status_sha256'] = _write_private(Path(value['stage_status']), status_raw)

    source_receipt = {
        'schema': 'credential-v3-heldout-request-source-v1', 'variant': 'R0',
        'case_index': value['variant'], 'target_variant': value['variant'],
        'freeze_sha256': value['freeze_sha256'],
        'stage_report_sha256': value['stage_report_sha256'],
        'stage_plan_sha256': value['stage_plan_sha256'],
        'proof_created': False, 'application_effect': False,
        'live_state_authenticated': False,
    }
    source_raw = (json.dumps(source_receipt, sort_keys=True, separators=(',', ':')) + '\n').encode()
    value['source_receipt'] = str(root / 'r0-source-receipt.json')
    value['source_receipt_sha256'] = _write_private(Path(value['source_receipt']), source_raw)

    rows = inventory(source_ledger)
    clone_receipt = {
        'schema': 'part5-v3-heldout-r0-ledger-clone-v1',
        'heldout_acceptance': False,
        'stage_report_sha256': value['stage_report_sha256'],
        'stage_status_sha256': value['stage_status_sha256'],
        'stage_monitor_sha256': hashlib.sha256(b'synthetic stage monitor').hexdigest(),
        'source': str(source_ledger), 'destination': str(ledger),
        'source_stable': True, 'copy_identical': True,
        'loaded_identity_rechecked_after_restart': False,
        'application_effect': False, 'excluded_stale_admin_socket': False,
        'entry_count': len(rows),
        'tree_sha256': hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest(),
    }
    clone_raw = (json.dumps(clone_receipt, sort_keys=True, separators=(',', ':')) + '\n').encode()
    value['clone_receipt_sha256'] = _write_private(Path(value['clone_receipt']), clone_raw)

    proof_dir = root / 'full-proof'
    proof_dir.mkdir(mode=0o700)
    proof_path = proof_dir / 'base.proof'
    value['full_proof'] = str(proof_path)
    value['full_proof_sha256'] = _write_private(proof_path, b'synthetic full proof bytes')
    wire_path = proof_dir / 'full-wire.bin'
    value['full_wire'] = str(wire_path)
    value['full_wire_sha256'] = _write_private(wire_path, b'w' * 448)
    proof_receipt = {
        'schema': 'credential-v3-heldout-proof-evidence-v1', 'mode': 'full',
        'target_variant': value['variant'],
        'freeze_sha256': value['freeze_sha256'],
        'stage_report_sha256': value['stage_report_sha256'],
        'stage_plan_sha256': value['stage_plan_sha256'],
        'source_receipts': {'R0': {'path': value['source_receipt'],
                                   'sha256': value['source_receipt_sha256']}},
        'artifacts': {'proof/base.proof': {'path': str(proof_path),
                                           'sha256': value['full_proof_sha256']}},
        'wires': {'r0_full_wire': {'path': str(wire_path),
                                   'sha256': value['full_wire_sha256']}},
        'proof_created': True, 'application_verified': False,
        'validator_run': False, 'application_effect': False,
    }
    receipt_path = root / 'full-proof-receipt.json'
    value['full_proof_receipt'] = str(receipt_path)
    value['full_proof_receipt_sha256'] = _write_private(
        receipt_path, (json.dumps(proof_receipt, sort_keys=True, separators=(',', ':')) + '\n').encode())
    runner = root / 'runner'
    value['runner'] = str(runner)
    value['runner_sha256'] = _write_private(runner, b'synthetic runner')
    return {'plan': plan, 'stage_report': stage_report, 'source_receipt': source_receipt,
            'clone_receipt': clone_receipt, 'proof_receipt': proof_receipt,
            'source_ledger': source_ledger, 'ledger': ledger,
            'stage_report_path': Path(value['stage_report']),
            'stage_config_path': Path(value['stage_config']),
            'stage_status_path': Path(value['stage_status']),
            'stage_plan_path': Path(value['stage_plan']),
            'source_receipt_path': Path(value['source_receipt']),
            'clone_receipt_path': Path(value['clone_receipt']),
            'proof_receipt_path': Path(value['full_proof_receipt']),
            'expected_elf_path': Path(value['expected_elf'])}


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
                   'storage_growth_bytes': 268435456, 'clock_wait_seconds': 45},
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
                      'stage_config_sha256', 'stage_status_sha256',
                      'clone_receipt_sha256', 'expected_elf_sha256'):
            altered = dict(value)
            altered[field] = 'not-a-pin'
            with self.subTest(field=field), self.assertRaises(ValueError):
                supervisor._validate_config(altered)

    def test_checks_external_artifact_bytes_against_each_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            value = config()
            make_preflight_artifacts(root, value)
            for field in ('ledger', 'stage_root', 'output_dir', 'control_output'):
                if field not in ('ledger', 'stage_root'):
                    value[field] = str(root / field)

            supervisor._validate_config(value)
            supervisor._check_input_pins(value)
            Path(value['full_wire']).write_bytes(b'x' * 448)
            with self.assertRaisesRegex(ValueError, 'full_wire input pin mismatch'):
                supervisor._check_input_pins(value)

    def test_preflight_rejects_hash_valid_stage_source_clone_elf_and_genesis_drift(self):
        for mutation in ('stage', 'plan', 'source', 'clone', 'clone_status', 'clone_socket',
                         'status_report', 'status_config', 'elf',
                         'source_genesis', 'genesis'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                value = config()
                paths = make_preflight_artifacts(root, value)
                if mutation == 'stage':
                    report = dict(paths['stage_report'])
                    report['program'] = 'other-program'
                    raw = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    value['stage_report_sha256'] = _write_private(paths['stage_report_path'], raw)
                elif mutation == 'plan':
                    plan = dict(paths['plan'])
                    plan['genesis'] = list(bytes([99]) * 32)
                    raw = (json.dumps(plan, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    value['stage_plan_sha256'] = _write_private(paths['stage_plan_path'], raw)
                elif mutation == 'source':
                    source = dict(paths['source_receipt'])
                    source['target_variant'] += 1
                    raw = (json.dumps(source, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    value['source_receipt_sha256'] = _write_private(paths['source_receipt_path'], raw)
                elif mutation == 'clone':
                    clone = dict(paths['clone_receipt'])
                    clone['stage_report_sha256'] = 'f' * 64
                    raw = (json.dumps(clone, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    value['clone_receipt_sha256'] = _write_private(paths['clone_receipt_path'], raw)
                elif mutation == 'clone_socket':
                    clone = dict(paths['clone_receipt'])
                    clone['excluded_stale_admin_socket'] = True
                    raw = (json.dumps(clone, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    value['clone_receipt_sha256'] = _write_private(paths['clone_receipt_path'], raw)
                elif mutation == 'clone_status':
                    clone = dict(paths['clone_receipt'])
                    clone['stage_status_sha256'] = 'f' * 64
                    raw = (json.dumps(clone, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    value['clone_receipt_sha256'] = _write_private(paths['clone_receipt_path'], raw)
                elif mutation == 'status_report':
                    status = json.loads(paths['stage_status_path'].read_text())
                    status['stage_report_sha256'] = 'f' * 64
                    raw = (json.dumps(status, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    value['stage_status_sha256'] = _write_private(paths['stage_status_path'], raw)
                elif mutation == 'status_config':
                    stage_config = json.loads(paths['stage_config_path'].read_text())
                    stage_config['runner_sha256'] = 'f' * 64
                    raw = (json.dumps(stage_config, sort_keys=True,
                                      separators=(',', ':')) + '\n').encode()
                    value['stage_config_sha256'] = _write_private(paths['stage_config_path'], raw)
                elif mutation == 'elf':
                    _write_private(paths['expected_elf_path'], b'wrong elf bytes')
                elif mutation == 'source_genesis':
                    _write_private(paths['source_ledger'] / 'genesis.bin', b'wrong genesis bytes')
                else:
                    _write_private(paths['ledger'] / 'genesis.bin', b'wrong genesis bytes')
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    supervisor._check_input_pins(value)

    def test_preflight_rejects_clone_source_disconnected_from_pinned_stage_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            value = config()
            paths = make_preflight_artifacts(root, value)
            disconnected = root / 'unrelated-stage' / 'ledger'
            disconnected.mkdir(mode=0o700, parents=True)
            _write_private(disconnected / 'genesis.bin', b'synthetic ledger genesis bytes')
            stage_config = {
                'schema': 1, 'scope': 'part5-v3-local-stage',
                'expected_genesis': value['expected_genesis'],
                'ledger': str(disconnected), 'stage_output': str(root / 'stage'),
                'control_output': str(root / 'stage-control'),
            }
            raw = (json.dumps(stage_config, sort_keys=True, separators=(',', ':')) + '\n').encode()
            value['stage_config_sha256'] = _write_private(paths['stage_config_path'], raw)
            status = {
                'schema': 1, 'scope': 'part5-v3-local-stage', 'status': 'failed',
                'stage_verified': True, 'ledger_reuse_requires_review': True,
                'application_effect': False, 'devnet': False,
                'config_sha256': value['stage_config_sha256'],
                'stage_report_sha256': value['stage_report_sha256'],
                'stage_output': str(root / 'stage'),
                'validator_cleanup': {'spawned': True, 'reaped': True,
                                      'graceful': False, 'exit_code': -2},
                'runner_cleanup': {'spawned': True, 'reaped': True, 'exit_code': 0},
            }
            status_raw = (json.dumps(status, sort_keys=True, separators=(',', ':')) + '\n').encode()
            value['stage_status_sha256'] = _write_private(paths['stage_status_path'], status_raw)
            clone = dict(paths['clone_receipt'])
            clone['stage_status_sha256'] = value['stage_status_sha256']
            clone_raw = (json.dumps(clone, sort_keys=True, separators=(',', ':')) + '\n').encode()
            value['clone_receipt_sha256'] = _write_private(paths['clone_receipt_path'], clone_raw)
            with self.assertRaisesRegex(ValueError, 'stage ledger differs from clone source'):
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

    def test_report_limits_must_match_supervisor_and_configured_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            value = config()
            report = valid_report(root, value)
            for key, larger in (('owner_wall_seconds', 181),
                                ('rss_bytes', 4294967297),
                                ('storage_growth_bytes', 268435457),
                                ('clock_wait_seconds', 46)):
                changed = json.loads(json.dumps(report))
                changed['limits'][key] = larger
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'supervisor limit'):
                    supervisor._validate_report(changed, value)

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


class ExpiredSupervisorLaunchTests(unittest.TestCase):
    def test_rust_names_in_comments_do_not_enable_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            paths = {
                'harness/tests/queue_v3.rs': '// root_pinned_queue_v3_expired_status_negative',
                'harness/src/solana/queue_v3.rs': '// mod expired_status_negative; expired_status_negative_from_env',
                'harness/src/solana/queue_v3/expired_status_negative.rs': '// expired_status_negative_from_env',
            }
            for relative, source in paths.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            with mock.patch.object(supervisor, 'REPO', root), self.assertRaises(
                    supervisor.IntegrationRequired):
                supervisor._require_rust_entrypoint()

    def test_raw_string_only_rust_declarations_do_not_enable_launch(self):
        sources = {
            'harness/tests/queue_v3.rs': '#[test]\n#[ignore = "loaded validator required"]\n'
                'fn root_pinned_queue_v3_expired_status_negative() {\n'
                'zk_fresh_benchmark::solana::queue_v3::expired_status_negative_from_env().unwrap();\n}',
            'harness/src/solana/queue_v3.rs': 'mod expired_status_negative;\n'
                'pub use expired_status_negative::expired_status_negative_from_env;',
            'harness/src/solana/queue_v3/expired_status_negative.rs':
                'pub fn expired_status_negative_from_env() -> Result<()> {}\n'
                + 'const REPORT: &str = "' + supervisor.CANDIDATE_SCHEMA + '";\n'
                + 'const ENV: &str = "P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG_SHA256";\n'
                + 'const FILE: &str = "expired-status-negative-report.json";',
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for relative, source in sources.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('const DECOY: &str = r###"\n' + source + '\n"###;')
            with mock.patch.object(supervisor, 'REPO', root), self.assertRaises(
                    supervisor.IntegrationRequired):
                supervisor._require_rust_entrypoint()

    def test_reviewed_entrypoint_dispatches_loaded_supervisor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            value = config()
            path = root / 'config.json'
            raw = json.dumps(value).encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            digest = hashlib.sha256(raw).hexdigest()
            with mock.patch.dict(os.environ, {'P5_V3_EXPIRED_STATUS_NEGATIVE_SCOPE': supervisor.SCOPE}), \
                    mock.patch.object(supervisor, '_check_input_pins'), \
                    mock.patch.object(supervisor, '_require_rust_entrypoint'), \
                    mock.patch.object(supervisor, '_write_blocked_status'), \
                    mock.patch.object(supervisor, '_run_loaded', create=True, return_value=0) as launch:
                self.assertEqual(supervisor.run(value, digest, path), 0)
            launch.assert_called_once_with(value, digest, path)

    def test_exact_entrypoint_and_report_markers_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            paths = {
                'harness/tests/queue_v3.rs': '#[test]\n#[ignore = "loaded validator required"]\n'
                    'fn root_pinned_queue_v3_expired_status_negative() {\n'
                    'zk_fresh_benchmark::solana::queue_v3::expired_status_negative_from_env().unwrap();\n}',
                'harness/src/solana/queue_v3.rs': 'mod expired_status_negative;\n'
                    'pub use expired_status_negative::expired_status_negative_from_env;',
                'harness/src/solana/queue_v3/expired_status_negative.rs':
                    'pub fn expired_status_negative_from_env() -> Result<()> {}\n'
                    + 'const REPORT: &str = "' + supervisor.CANDIDATE_SCHEMA + '";\n'
                    + 'const ENV: &str = "P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG_SHA256";\n'
                    + 'const FILE: &str = "expired-status-negative-report.json";',
            }
            for relative, source in paths.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            with mock.patch.object(supervisor, 'REPO', root):
                supervisor._require_rust_entrypoint()
                module = root / 'harness/src/solana/queue_v3/expired_status_negative.rs'
                module.write_text(module.read_text().replace(supervisor.CANDIDATE_SCHEMA, 'wrong-schema'))
                with self.assertRaises(supervisor.IntegrationRequired):
                    supervisor._require_rust_entrypoint()



def candidate_fixture(root, value):
    output = root / 'output'
    output.mkdir(mode=0o700, exist_ok=True)
    loaded = {key: 'pinned-' + key for key in supervisor.execute.IDENTITY_FIELDS}
    loaded.update({'elf_match': True, 'elf_bytes': 32, 'loader': 'loader',
                   'elf_sha256': value['expected_elf_sha256'],
                   'program': value['expected_program'], 'genesis': value['expected_genesis']})
    rust_loaded = {'elf_match': True, 'elf_sha256': value['expected_elf_sha256'],
                   'loader': 'loader', 'local_bytes': 32, 'remote_bytes': 64}
    refs = {path: {'path': value[path], 'sha256': value[digest]}
            for path, digest, _ in supervisor.INPUT_ARTIFACTS}
    refs['runner'] = {'path': value['runner'], 'sha256': value['runner_sha256']}
    report = {
        'schema': supervisor.CANDIDATE_SCHEMA,
        'config_ref': {'path': str(root / 'config.json'), 'sha256': 'd' * 64},
        'identities': supervisor._expected_identities(value), 'input_refs': refs,
        'source_refs': {'full_proof': refs['full_proof_receipt'], 'full_wire': refs['full_wire']},
        'program': value['expected_program'], 'genesis': value['expected_genesis'],
        'loaded_program_before': rust_loaded, 'loaded_program_after': dict(rust_loaded),
        'clock': {'observed_at': 100, 'expires_at': 120, 'now': 122, 'rpc_finalized': True},
        'clock_observations': {'expiry_slot': 18, 'expiry_now': 121,
                               'submit_slot': 20, 'execution_now': 123},
        'preconditions': {'status_active': True, 'issuer_active': True, 'head_bound': True,
                          'request_live': True, 'full_wire_statement_matches': True},
        'publisher_transactions': {
            'source': {'signature': '1' * 64, 'slot': 11, 'finalized': True,
                       'error': None, 'block_time': 101},
            'bind': {'signature': '2' * 64, 'slot': 12, 'finalized': True,
                     'error': None, 'block_time': 102}},
        'transaction': {'signature': '3' * 64, 'slot': 21, 'finalized': True,
                        'error': {'InstructionError': [1, {'Custom': 705}]}},
        'account_slots': {'initial': 10, 'bound': 15, 'before': 19, 'after': 22},
        'snapshots': [],
        'runner_observations': {'pid': 123, 'elapsed_seconds': 30, 'clock_wait_seconds': 20},
        'external_finalization_required': True, 'full_proof_verified_in_rust': False,
        'application_effect': False,
    }
    for index, name in enumerate(supervisor.ACCOUNT_NAMES):
        row = {'name': name}
        for phase in ('before', 'after'):
            path = output / phase / (name + '.bin')
            row[phase] = {'path': str(path), 'sha256': _write_private(path, bytes([index + 1]) * 8)}
        report['snapshots'].append(row)
    return report, loaded, output


class ExpiredCandidateTests(unittest.TestCase):
    def test_candidate_schema_is_distinct_from_final_external_evidence(self):
        self.assertEqual(getattr(supervisor, 'CANDIDATE_SCHEMA', None),
                         'credential-v3-expired-status-negative-rust-candidate-v1')
        self.assertNotEqual(supervisor.CANDIDATE_SCHEMA, evidence.SCHEMA)
        supervisor._require_rust_entrypoint()
        self.assertEqual(set(supervisor.RUST_REPORT_CONTRACT['report_fields']),
                         supervisor.CANDIDATE_FIELDS)

    def test_candidate_checks_pins_finalized_error_clocks_and_five_snapshot_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, value = Path(tmp).resolve(), config()
            report, loaded, output = candidate_fixture(root, value)
            validate = lambda candidate: supervisor._validate_candidate(
                candidate, value, root / 'config.json', 'd' * 64, output, loaded, 123)
            hashes, sizes = validate(report)
            self.assertEqual(len(hashes), 5)
            self.assertEqual(sizes, [8] * 5)
            mutations = (
                ('config', lambda r: r['config_ref'].update(sha256='e' * 64)),
                ('input', lambda r: r['input_refs']['runner'].update(sha256='e' * 64)),
                ('identity', lambda r: r['identities'].update(clone='e' * 64)),
                ('proof', lambda r: r['source_refs']['full_proof'].update(path='/other')),
                ('loaded', lambda r: r['loaded_program_after'].update(loader='other')),
                ('clock', lambda r: r['clock'].update(now=120)),
                ('slot', lambda r: r['account_slots'].update(before=14)),
                ('error', lambda r: r['transaction'].update(error={'InstructionError': [0, {'Custom': 705}]})),
                ('bool_error', lambda r: r['transaction'].update(error={'InstructionError': [True, {'Custom': 705}]})),
                ('float_error', lambda r: r['transaction'].update(error={'InstructionError': [1, {'Custom': 705.0}]})),
                ('publisher', lambda r: r['publisher_transactions']['bind'].update(finalized=False)),
                ('pid', lambda r: r['runner_observations'].update(pid=999)),
                ('wait', lambda r: r['runner_observations'].update(clock_wait_seconds=46)),
                ('external', lambda r: r.update(measured={'peak_owned_rss_bytes': 0})),
                ('snapshot', lambda r: r['snapshots'][0]['after'].update(path='/other')),
            )
            for name, mutate in mutations:
                changed = json.loads(json.dumps(report))
                mutate(changed)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    validate(changed)
            path = Path(report['snapshots'][-1]['after']['path'])
            report['snapshots'][-1]['after']['sha256'] = _write_private(path, b'changed!')
            with self.assertRaisesRegex(ValueError, 'application account changed'):
                validate(report)

    def test_live_recheck_requires_finalized_rpc_error_clock_and_snapshot_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, value = Path(tmp).resolve(), config()
            report, loaded, output = candidate_fixture(root, value)
            hashes, sizes = supervisor._validate_candidate(
                report, value, root / 'config.json', 'd' * 64, output, loaded, 123)
            txs = {tx['signature']: tx for tx in [report['transaction'],
                    *report['publisher_transactions'].values()]}
            def rpc(method, params):
                if method == 'getSlot':
                    self.assertEqual(params, [{'commitment': 'finalized'}])
                    return 23
                if method == 'getBlockTime':
                    return {18: 121, 20: 122, 23: 124}[params[0]]
                tx = txs[params[0][0] if method == 'getSignatureStatuses' else params[0]]
                if method == 'getSignatureStatuses':
                    return {'value': [{'confirmationStatus': 'finalized', 'slot': tx['slot'], 'err': tx['error']}]}
                self.assertEqual(params[1]['commitment'], 'finalized')
                return {'slot': tx['slot'], 'meta': {'err': tx['error']},
                        'blockTime': tx.get('block_time', 123),
                        'transaction': {'signatures': [tx['signature']]}}
            with mock.patch.object(supervisor.execute, 'finalized_accounts', return_value=(24, [])) as accounts:
                self.assertEqual(supervisor._recheck_candidate(rpc, report, value, {}, hashes, sizes), 24)
                accounts.assert_called_once_with(rpc, {}, 22, value['expected_program'], hashes, sizes)
            for failure in ('error', 'clock', 'slot', 'finality', 'signature'):
                def wrong_rpc(method, params):
                    result = rpc(method, params)
                    if failure == 'error' and method == 'getTransaction':
                        result['meta']['err'] = {'InstructionError': [1, {'Custom': 708}]}
                    if failure == 'clock' and method == 'getBlockTime':
                        return 120
                    if failure == 'slot' and method == 'getTransaction':
                        result['slot'] = True
                    if failure == 'finality' and method == 'getSignatureStatuses':
                        result['value'][0]['confirmationStatus'] = 'confirmed'
                    if failure == 'signature' and method == 'getTransaction':
                        result['transaction']['signatures'] = ['4' * 64]
                    return result
                with self.subTest(failure=failure), self.assertRaises(ValueError):
                    supervisor._recheck_candidate(wrong_rpc, report, value, {}, hashes, sizes)

    def test_candidate_validation_rejects_final_evidence_as_runner_output(self):
        with self.assertRaisesRegex(ValueError, 'candidate'):
            supervisor._validate_candidate({'schema': evidence.SCHEMA}, config(),
                                           Path('/config'), 'a' * 64,
                                           Path('/output'), {}, 123)


class ExpiredSupervisorLifecycleTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            artifact_root = root / 'artifacts/dynark/part5'
            artifact_root.mkdir(parents=True)
            value = config()
            value['output_dir'] = str(artifact_root / 'output')
            value['control_output'] = str(artifact_root / 'control')
            value['stage_root'] = str(root / 'stage')
            value['ledger'] = str(root / 'clone/ledger')
            Path(value['ledger']).mkdir(parents=True)
            config_path = root / 'config.json'
            raw = json.dumps(value).encode()
            digest = _write_private(config_path, raw)
            report, loaded, output = candidate_fixture(artifact_root, value)
            report['config_ref'] = {'path': str(config_path), 'sha256': digest}
            initial, initial_hashes = [], []
            for index, name in enumerate(supervisor.ACCOUNT_NAMES):
                data = bytes([index + 1]) * 8
                initial.append(data)
                initial_hashes.append(_write_private(Path(value['stage_root']) / (name + '.bin'), data))
            # Candidate fixture files are written by the fake Rust runner after launch.
            for path in output.rglob('*.bin'):
                path.unlink()
            for path in output.iterdir():
                path.rmdir()
            output.rmdir()
            stage_report = {'loaded_program': loaded, 'account_sha256': initial_hashes, 'finalized_slot': 9}
            prepared = {'validator': '/pinned/validator', 'validator_sha256': 'e' * 64}
            staged = {'context': '/pinned/context.json', 'context_sha256': 'f' * 64}
            validator = mock.Mock(pid=122)
            validator.poll.return_value = 7 if mode == 'validator_exit' else None
            runner = mock.Mock(pid=123)
            runner.poll.return_value = None if mode in ('timeout', 'validator_exit') else 0
            runner.wait.return_value = 1 if mode == 'runner_error' else 0
            commands = []
            clock = [0]
            loaded_reads = [0]
            original_snapshot = supervisor.execute.stage.snapshot_generated
            def snapshot(path, cap):
                result = original_snapshot(path, cap)
                if mode == 'before_cleanup_exit' and Path(path) == config_path:
                    validator.poll.return_value = 7
                return result
            def wait_loaded(*args):
                loaded_reads[0] += 1
                if mode == 'final_window_exit' and loaded_reads[0] == 2:
                    validator.poll.return_value = 7
                return loaded
            def spawn(command, **kwargs):
                commands.append((command, kwargs))
                if len(commands) == 1:
                    return validator
                if mode not in ('missing_report', 'runner_error', 'timeout', 'validator_exit'):
                    generated, _, _ = candidate_fixture(artifact_root, value)
                    generated['config_ref'] = report['config_ref']
                    _write_private(output / supervisor.REPORT_NAME, json.dumps(generated).encode())
                return runner
            def cleanup(proc):
                if mode == 'cleanup_error' and proc is validator:
                    raise OSError('cannot reap')
                if mode == 'cleanup_overrun' and proc is validator:
                    clock[0] = supervisor.SUPERVISOR_BUDGET_SECONDS + 1
                return {'spawned': proc is not None, 'reaped': True,
                        'graceful': False, 'exit_code': 0 if proc is runner else
                        (7 if mode == 'unexpected_cleanup_exit' else -2)}
            with mock.patch.object(supervisor, 'REPO', root), \
                    mock.patch.object(supervisor, '_runtime_inputs', return_value=(prepared, staged, stage_report)), \
                    mock.patch.object(supervisor.execute.base, 'checked', return_value=b'elf'), \
                    mock.patch.object(supervisor.execute.base, 'ports_free'), \
                    mock.patch.object(supervisor.execute.base, 'LocalRpc'), \
                    mock.patch.object(supervisor.execute, 'wait_loaded_after_start', side_effect=wait_loaded), \
                    mock.patch.object(supervisor.execute, 'wait_staged_finality', return_value=(10, initial)), \
                    mock.patch.object(supervisor.execute.stage, 'snapshot_generated', side_effect=snapshot), \
                    mock.patch.object(supervisor, '_recheck_candidate', return_value=24), \
                    mock.patch.object(supervisor.subprocess, 'Popen', side_effect=spawn), \
                    mock.patch.object(supervisor.execute.base, 'cleanup', side_effect=cleanup) as reaped, \
                    mock.patch.object(supervisor.time, 'monotonic', side_effect=range(0, 400, 40)
                                      if mode == 'timeout' else lambda: clock[0]), \
                    mock.patch.dict(os.environ, {'LD_PRELOAD': 'untrusted', 'DYLD_INSERT_LIBRARIES': 'untrusted'}):
                result = supervisor._run_loaded(value, digest, config_path)
            status_path = Path(value['control_output']) / 'status.json'
            status = json.loads(status_path.read_text())
            self.assertEqual(status_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(status_path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(len(commands), 2)
            self.assertEqual(commands[1][0], [value['runner'], supervisor.RUST_TEST,
                                            '--exact', '--ignored', '--test-threads=1'])
            env = commands[1][1]['env']
            self.assertEqual(env['P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG'], str(config_path))
            self.assertEqual(env['P5_V3_EXPIRED_STATUS_NEGATIVE_CONFIG_SHA256'], digest)
            self.assertNotIn('LD_PRELOAD', env)
            self.assertNotIn('DYLD_INSERT_LIBRARIES', env)
            self.assertEqual(reaped.call_args_list, [mock.call(runner), mock.call(validator)])
            self.assertNotIn('measured', status)
            self.assertNotIn('remaining_owned_processes', status)
            self.assertFalse(status['effect_verified'])
            self.assertFalse(status['application_effect'])
            self.assertTrue(status['external_finalization_required'])
            return result, status

    def test_verified_candidate_records_direct_cleanup_and_pending_external_finalization(self):
        result, status = self.exercise('success')
        self.assertEqual(result, 0)
        self.assertEqual(status['status'], 'candidate_verified_pending_external_finalization')
        self.assertTrue(status['candidate_verified'])
        self.assertEqual(status['candidate_schema'], supervisor.CANDIDATE_SCHEMA)
        self.assertTrue(status['runner_cleanup']['reaped'])
        self.assertTrue(status['validator_cleanup']['reaped'])
        self.assertFalse(status['validator_cleanup']['graceful'])

    def test_missing_or_uncompiled_entrypoint_and_process_failures_cannot_verify_candidate(self):
        for mode, error in (('missing_report', 'FileNotFoundError'),
                            ('runner_error', 'RuntimeError'),
                            ('validator_exit', 'RuntimeError'), ('timeout', 'TimeoutError')):
            with self.subTest(mode=mode):
                result, status = self.exercise(mode)
                self.assertEqual(result, 1)
                self.assertEqual(status['status'], 'failed')
                self.assertEqual(status['error_type'], error)
                self.assertFalse(status['candidate_verified'])
                self.assertTrue(status['validator_cleanup']['reaped'])

    def test_abnormal_final_window_validator_exit_fails_supervisor(self):
        result, status = self.exercise('final_window_exit')
        self.assertEqual(result, 1)
        self.assertEqual(status['status'], 'failed')
        self.assertEqual(status['error_type'], 'RuntimeError')
        self.assertFalse(status['candidate_verified'])

    def test_validator_exit_between_final_rpc_and_cleanup_fails_supervisor(self):
        result, status = self.exercise('before_cleanup_exit')
        self.assertEqual(result, 1)
        self.assertEqual(status['status'], 'failed')
        self.assertTrue(status['candidate_verified'])
        self.assertFalse(status['validator_alive_before_cleanup'])
        self.assertEqual(status['error_type'], 'RuntimeError')

    def test_unexpected_validator_cleanup_exit_fails_supervisor(self):
        result, status = self.exercise('unexpected_cleanup_exit')
        self.assertEqual(result, 1)
        self.assertEqual(status['status'], 'failed')
        self.assertTrue(status['candidate_verified'])
        self.assertEqual(status['validator_cleanup']['exit_code'], 7)
        self.assertEqual(status['error_type'], 'RuntimeError')

    def test_cleanup_budget_overrun_fails_despite_verified_candidate(self):
        result, status = self.exercise('cleanup_overrun')
        self.assertEqual(result, 1)
        self.assertEqual(status['status'], 'failed')
        self.assertTrue(status['candidate_verified'])
        self.assertGreater(status['elapsed_seconds'], supervisor.SUPERVISOR_BUDGET_SECONDS)
        self.assertEqual(status['error_type'], 'TimeoutError')

    def test_cleanup_failure_keeps_candidate_facts_but_fails_supervisor(self):
        result, status = self.exercise('cleanup_error')
        self.assertEqual(result, 1)
        self.assertEqual(status['status'], 'failed')
        self.assertTrue(status['candidate_verified'])
        self.assertFalse(status['validator_cleanup']['reaped'])
        self.assertEqual(status['validator_cleanup']['error_type'], 'OSError')


if __name__ == '__main__':
    unittest.main()
