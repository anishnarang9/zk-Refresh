import base64
import importlib.util
import contextlib
import io
import json
import os
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('v3_prepare', Path(__file__).with_name('queue_v3_local_prepare.py'))
m = importlib.util.module_from_spec(spec)
if Path(spec.origin).exists():
    spec.loader.exec_module(m)


class PrepareTests(unittest.TestCase):
    def api(self):
        self.assertTrue(hasattr(m, 'loaded_identity'), 'v3 local prepare supervisor is missing')

    def fixture(self):
        self.api()
        program, mint, pd = (m.b58(bytes([n]) * 32) for n in (11, 12, 13))
        elf = b'\x7fELF' + bytes(80)
        account = lambda data, executable: {'owner': m.LOADER, 'executable': executable,
            'data': [base64.b64encode(data).decode(), 'base64']}
        program_bytes = (2).to_bytes(4, 'little') + bytes([13]) * 32
        pd_bytes = (3).to_bytes(4, 'little') + (7).to_bytes(8, 'little') + b'\x00' + bytes(32) + elf + bytes(16)
        return program, mint, pd, elf, [account(program_bytes, True), account(pd_bytes, False)]

    def test_exact_finalized_upgradeable_program_and_elf_accept(self):
        program, _, pd, elf, accounts = self.fixture()
        report = m.loaded_identity(program, pd, accounts, 8, elf, m.sha(elf))
        self.assertEqual(report['programdata'], pd)
        self.assertEqual(report['elf_sha256'], m.sha(elf))
        self.assertEqual(report['finalized_slot'], 8)
        self.assertTrue(report['elf_match'])
        self.assertFalse(report['application_effect'])
        self.assertNotIn('data', report)

    def test_loader_link_owner_executable_slot_and_padding_mutations_reject(self):
        import copy
        program, _, pd, elf, accounts = self.fixture()
        for change in range(7):
            wrong = copy.deepcopy(accounts)
            if change == 0: wrong[0]['owner'] = program
            if change == 1: wrong[0]['executable'] = False
            if change == 2: wrong[1]['executable'] = True
            if change == 3:
                data = bytearray(base64.b64decode(wrong[0]['data'][0])); data[-1] ^= 1
                wrong[0]['data'][0] = base64.b64encode(data).decode()
            if change == 4:
                data = bytearray(base64.b64decode(wrong[1]['data'][0])); data[4:12] = (9).to_bytes(8, 'little')
                wrong[1]['data'][0] = base64.b64encode(data).decode()
            if change == 5:
                data = bytearray(base64.b64decode(wrong[1]['data'][0])); data[-1] = 1
                wrong[1]['data'][0] = base64.b64encode(data).decode()
            if change == 6: wrong[1]['data'][1] = 'base64+zstd'
            with self.subTest(change=change), self.assertRaises(ValueError):
                m.loaded_identity(program, pd, wrong, 8, elf, m.sha(elf))

    def test_validator_argv_requires_explicit_ids_fresh_ledger_and_loopback(self):
        program, mint, _, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp).resolve() / 'ledger'
            argv = m.validator_argv('/validator', ledger, '/v3.so', program, mint)
            self.assertEqual(argv[argv.index('--bind-address') + 1], '127.0.0.1')
            self.assertEqual(argv[argv.index('--bpf-program') + 1:][:2], [program, '/v3.so'])
            self.assertEqual(argv[argv.index('--mint') + 1], mint)
            self.assertIn('--reset', argv)
            with self.assertRaises(ValueError): m.validator_argv('/v', ledger, '/e', program, program)
            ledger.mkdir()
            with self.assertRaises(ValueError): m.validator_argv('/v', ledger, '/e', program, mint)

    def test_discovery_and_finalized_batch_require_same_link_and_genesis(self):
        program, _, pd, elf, accounts = self.fixture()
        genesis = m.b58(bytes([15]) * 32)
        calls = []
        def rpc(method, params):
            calls.append((method, params))
            if method == 'getGenesisHash': return genesis
            if method == 'getAccountInfo': return {'context': {'slot': 7}, 'value': accounts[0]}
            return {'context': {'slot': 8}, 'value': accounts}
        class Proc:
            def poll(self): return None
        report = m.wait_loaded(rpc, Proc(), program, elf, m.sha(elf), 1)
        self.assertEqual(report['genesis'], genesis)
        method, params = next(c for c in calls if c[0] == 'getMultipleAccounts')
        self.assertEqual(params[0], [program, pd])
        self.assertEqual(params[1]['commitment'], 'finalized')
        self.assertEqual(params[1]['minContextSlot'], 7)
        self.assertGreaterEqual(sum(c[0] == 'getGenesisHash' for c in calls), 2)
        self.assertNotIn('sendTransaction', [c[0] for c in calls])

    def test_initial_slot_zero_is_readiness_pending_then_finalizes(self):
        program, _, _, elf, accounts = self.fixture()
        discovery_count = 0
        def rpc(method, params):
            nonlocal discovery_count
            if method == 'getGenesisHash': return m.b58(bytes([15]) * 32)
            if method == 'getAccountInfo':
                discovery_count += 1
                if discovery_count == 1: return {'context': {'slot': 0}, 'value': None}
                return {'context': {'slot': 7}, 'value': accounts[0]}
            return {'context': {'slot': 8}, 'value': accounts}
        class Proc:
            def poll(self): return None
        with patch.object(m.time, 'sleep'):
            report = m.wait_loaded(rpc, Proc(), program, elf, m.sha(elf), 1)
        self.assertEqual(report['attempts'], 2)

    def test_genesis_change_during_identity_read_rejects(self):
        program, _, _, elf, accounts = self.fixture()
        count = 0
        def rpc(method, params):
            nonlocal count
            if method == 'getGenesisHash':
                count += 1
                return m.b58(bytes([15 + count]) * 32)
            if method == 'getAccountInfo': return {'context': {'slot': 7}, 'value': accounts[0]}
            return {'context': {'slot': 8}, 'value': accounts}
        class Proc:
            def poll(self): return None
        with self.assertRaises(ValueError): m.wait_loaded(rpc, Proc(), program, elf, m.sha(elf), 1)

    def test_dead_child_is_not_retried_as_rpc_readiness(self):
        program, _, _, elf, _ = self.fixture()
        class Proc:
            def poll(self): return 1
        with self.assertRaises(RuntimeError):
            m.wait_loaded(lambda *_: self.fail('RPC after child exit'), Proc(), program, elf, m.sha(elf), 1)

    def test_cleanup_reaps_and_marks_escalation_not_graceful(self):
        self.api()
        import subprocess
        class Proc:
            def __init__(self): self.code = None; self.signals = []
            def poll(self): return self.code
            def send_signal(self, sig): self.signals.append(sig)
            def terminate(self): self.signals.append('terminate'); self.code = -15
            def kill(self): self.signals.append('kill'); self.code = -9
            def wait(self, timeout):
                if self.code is None: raise subprocess.TimeoutExpired('validator', timeout)
                return self.code
        proc = Proc()
        result = m.cleanup(proc)
        self.assertTrue(result['reaped'])
        self.assertFalse(result['graceful'])
        self.assertIn('terminate', proc.signals)

    def test_shutdown_nonzero_or_signal_exit_is_never_graceful(self):
        self.api()
        class Proc:
            def __init__(self, shutdown_code):
                self.returncode = None
                self.shutdown_code = shutdown_code
            def poll(self): return self.returncode
            def send_signal(self, sig): self.returncode = self.shutdown_code
            def wait(self, timeout): return self.returncode
        for code in (1, 101, -2, -9, -15):
            with self.subTest(code=code):
                result = m.cleanup(Proc(code))
                self.assertTrue(result['reaped'])
                self.assertFalse(result['graceful'])
                self.assertEqual(result['exit_code'], code)
        self.assertTrue(m.cleanup(Proc(0))['graceful'])

    def configuration(self, tmp):
        self.api()
        repo = Path(tmp).resolve() / 'repo'
        original = Path(__file__).resolve().parents[2]
        shutil.copytree(original / 'program/src', repo / 'program/src')
        for name in ('Cargo.toml', 'Cargo.lock'):
            shutil.copyfile(original / 'program' / name, repo / 'program' / name)
        base = repo / 'artifacts/dynark/part5'
        base.mkdir(parents=True)
        builder, validator = repo / 'builder', repo / 'validator'
        builder.write_bytes(b'not executed builder'); validator.write_bytes(b'not executed validator')
        output = base / 'application-v3-sbf-test'
        plan = m.prep.prepare_build(repo, m.prep.source_manifest(repo), builder, m.sha(builder.read_bytes()), output)
        (output / 'elf').mkdir(parents=True)
        elf = output / 'elf/zk_fresh_program.so'
        elf.write_bytes(b'\x7fELF' + bytes(80))
        plan_path = base / 'build-plan.json'
        plan_path.write_text(json.dumps(plan))
        program, mint = (m.b58(bytes([n]) * 32) for n in (11, 12))
        return repo, {'schema': 1, 'scope': 'part5-v3-local-prepare',
            'outer_limits_required': m.LIMITS, 'build_plan': str(plan_path),
            'build_plan_sha256': m.sha(plan_path.read_bytes()), 'elf': str(elf),
            'elf_sha256': m.sha(elf.read_bytes()), 'validator': str(validator),
            'validator_sha256': m.sha(validator.read_bytes()), 'program': program, 'mint': mint,
            'runtime_output': str(base / 'application-v3-local-runtime-test'),
            'control_output': str(base / 'application-v3-local-control-test')}

    def test_admission_rejects_plan_source_elf_and_validator_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, config = self.configuration(tmp)
            with patch.object(m, 'REPO', repo):
                m.admit(config)
                for field in ('build_plan_sha256', 'elf_sha256', 'validator_sha256'):
                    wrong = dict(config); wrong[field] = '0' * 64
                    with self.subTest(field=field), self.assertRaises(ValueError): m.admit(wrong)
                (repo / 'program/src/lib.rs').write_text('// changed')
                with self.assertRaises(ValueError): m.admit(config)

    def test_simulated_success_reaps_validator_and_retains_private_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, config = self.configuration(tmp)
            class Proc:
                returncode = None
                def poll(self): return self.returncode
                def send_signal(self, sig): self.returncode = 0
                def wait(self, timeout): return self.returncode
            def spawn(argv, **kwargs):
                self.assertFalse(kwargs['start_new_session'])
                ledger = Path(argv[argv.index('--ledger') + 1])
                ledger.mkdir(mode=0o700)
                fd = os.open(ledger / 'genesis.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                return Proc()
            _, _, _, elf, accounts = self.fixture()
            def rpc(method, params):
                if method == 'getGenesisHash': return m.b58(bytes([15]) * 32)
                if method == 'getAccountInfo': return {'context': {'slot': 7}, 'value': accounts[0]}
                return {'context': {'slot': 8}, 'value': accounts}
            with patch.object(m, 'REPO', repo), patch.object(m, 'ports_free'), \
                 patch.object(m.subprocess, 'Popen', side_effect=spawn) as popen, \
                 patch.object(m, 'LocalRpc', return_value=rpc), \
                 patch.dict(os.environ, {'P5_V3_PREPARE_SCOPE': 'local-validator-prepare'}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.run(config, '1' * 64), 0)
            self.assertEqual(popen.call_count, 1)
            status_path = Path(config['control_output']) / 'status.json'
            status = json.loads(status_path.read_text())
            self.assertEqual(status['status'], 'passed')
            self.assertTrue(status['cleanup']['reaped'])
            self.assertFalse(status['ledger_reuse_requires_review'])
            self.assertFalse(status['application_effect'])
            self.assertTrue((Path(config['runtime_output']) / 'ledger/genesis.bin').is_file())
            self.assertEqual(status_path.stat().st_mode & 0o777, 0o600)

    def test_abnormal_shutdown_rejects_otherwise_verified_ledger_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, config = self.configuration(tmp)
            class Proc:
                returncode = None
                def poll(self): return self.returncode
                def send_signal(self, sig): self.returncode = 101
                def wait(self, timeout): return self.returncode
            def spawn(argv, **kwargs):
                ledger = Path(argv[argv.index('--ledger') + 1])
                ledger.mkdir(mode=0o700)
                fd = os.open(ledger / 'genesis.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                return Proc()
            _, _, _, elf, accounts = self.fixture()
            def rpc(method, params):
                if method == 'getGenesisHash': return m.b58(bytes([15]) * 32)
                if method == 'getAccountInfo': return {'context': {'slot': 7}, 'value': accounts[0]}
                return {'context': {'slot': 8}, 'value': accounts}
            with patch.object(m, 'REPO', repo), patch.object(m, 'ports_free'), \
                 patch.object(m.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(m, 'LocalRpc', return_value=rpc), \
                 patch.dict(os.environ, {'P5_V3_PREPARE_SCOPE': 'local-validator-prepare'}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.run(config, '1' * 64), 1)
            status = json.loads((Path(config['control_output']) / 'status.json').read_text())
            self.assertTrue(status['loaded_program']['elf_match'])
            self.assertEqual(status['status'], 'failed')
            self.assertTrue(status['ledger_reuse_requires_review'])
            self.assertFalse(status['cleanup']['graceful'])
            self.assertEqual(status['cleanup']['exit_code'], 101)

    def test_spawn_failure_marks_persistent_runtime_unusable_without_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, config = self.configuration(tmp)
            with patch.object(m, 'REPO', repo), patch.object(m, 'ports_free'), \
                 patch.object(m.subprocess, 'Popen', side_effect=OSError('simulated spawn failure')), \
                 patch.dict(os.environ, {'P5_V3_PREPARE_SCOPE': 'local-validator-prepare'}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.run(config, '1' * 64), 1)
            status = json.loads((Path(config['control_output']) / 'status.json').read_text())
            self.assertEqual(status['status'], 'failed')
            self.assertTrue(status['ledger_reuse_requires_review'])
            self.assertFalse(status['cleanup']['spawned'])
            self.assertFalse(status['application_effect'])

    def test_json_parser_rejects_duplicates_wrong_ids_errors_and_incomplete_results(self):
        self.api()
        for raw in (b'{"id":1,"id":1,"jsonrpc":"2.0","result":1}',
                    b'{"id":2,"jsonrpc":"2.0","result":1}',
                    b'{"id":1,"jsonrpc":"2.0","error":{}}',
                    b'{"id":1,"jsonrpc":"2.0"}'):
            with self.assertRaises(ValueError): m.rpc_result(raw, 1)
        self.assertEqual(m.rpc_result(b'{"id":1,"jsonrpc":"2.0","result":1}', 1), 1)


if __name__ == '__main__': unittest.main()
