import importlib.util
import signal
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('v3_execute', Path(__file__).with_name('queue_v3_local_execute.py'))
m = importlib.util.module_from_spec(spec)
if Path(spec.origin).exists():
    spec.loader.exec_module(m)


class ExecuteTests(unittest.TestCase):
    def test_validator_startup_retries_only_rpc_readiness_envelopes(self):
        calls = []
        def delayed(*args, **kwargs):
            calls.append(kwargs['timeout'])
            if len(calls) == 1:
                raise ValueError('invalid RPC envelope')
            return {'program': 'loaded'}
        with patch.object(m.base, 'wait_loaded', side_effect=delayed), patch.object(m.time, 'sleep'):
            self.assertEqual(m.wait_loaded_after_start(None, None, 'program', b'elf', 'a' * 64),
                             {'program': 'loaded'})
        self.assertEqual(len(calls), 2)
        with patch.object(m.base, 'wait_loaded', side_effect=ValueError('local genesis changed')):
            with self.assertRaisesRegex(ValueError, 'local genesis changed'):
                m.wait_loaded_after_start(None, None, 'program', b'elf', 'a' * 64)

    def test_staged_finality_waits_for_replay_but_rejects_changed_accounts(self):
        expected = (44, [b'exact'] * 5)
        with patch.object(m, 'finalized_accounts', side_effect=[m.base.NotReady(),
                ValueError('invalid RPC envelope'), expected]) as checked, patch.object(m.time, 'sleep'):
            result = m.wait_staged_finality(None, {'finalized_slot': 44}, 'program', ['a'] * 5, [5] * 5)
        self.assertEqual(result, expected)
        self.assertEqual(checked.call_count, 3)
        with patch.object(m, 'finalized_accounts', side_effect=ValueError('finalized exact account bytes mismatch')):
            with self.assertRaisesRegex(ValueError, 'finalized exact account bytes mismatch'):
                m.wait_staged_finality(None, {'finalized_slot': 44}, 'program', ['a'] * 5, [5] * 5)

    def test_effect_requires_only_consumption_and_one_exact_queue_append(self):
        self.assertTrue(hasattr(m, 'check_effect_bytes'), 'independent effect-byte check missing')
        config = bytearray(381); config[:8] = b'DYNCONF3'
        request = bytearray(2249); request[:8] = b'DYNREQ03'; request[183] = 1
        queue = bytearray(2090); queue[:8] = b'DYNQUE03'
        config_key = bytes([4]) * 32
        request[8:40] = queue[8:40] = config_key
        before = [bytes(config), b'issuer', b'head', bytes(request), bytes(queue)]
        after = list(before)
        request[183] = 2; queue[40:42] = (1).to_bytes(2, 'big'); queue[42:74] = bytes([9]) * 32
        after[3], after[4] = bytes(request), bytes(queue)
        report = {'config': m.base.b58(config_key), 'request': m.base.b58(bytes([9]) * 32)}
        m.check_effect_bytes(before, after, report)
        for index, offset in [(0, 50), (3, 100), (3, 183), (4, 40), (4, 42), (4, 80)]:
            changed = list(after); raw = bytearray(changed[index]); raw[offset] ^= 1; changed[index] = bytes(raw)
            with self.subTest(index=index, offset=offset), self.assertRaises(ValueError):
                m.check_effect_bytes(before, changed, report)
        malformed = list(before); malformed[3] = b'bad' + malformed[3][3:]
        with self.assertRaises(ValueError): m.check_effect_bytes(malformed, after, report)

    def test_interrupted_stage_requires_verified_effect_free_stage_and_clean_outer_monitor(self):
        self.assertTrue(hasattr(m, 'review_stage'), 'execute supervisor is missing')
        prior = {'scope': 'part5-v3-local-stage', 'schema': 1, 'status': 'failed',
                 'stage_verified': True, 'application_effect': False, 'config_sha256': 'a' * 64,
                 'stage_report_sha256': 'b' * 64, 'stage_output': '/stage',
                 'ledger_reuse_requires_review': True,
                 'validator_cleanup': {'reaped': True, 'graceful': False, 'exit_code': -signal.SIGINT},
                 'runner_cleanup': {'reaped': True, 'exit_code': 0}}
        monitor = {'owner': 'stage-owner', 'stop_reason': None, 'runner_error_type': None,
                   'cleanup_remaining_owned_processes': 0, 'cleanup_status_unknown': False}
        config = {'prior_stage_config_sha256': 'a' * 64, 'stage_report_sha256': 'b' * 64,
                  'stage_root': '/stage', 'prior_monitor_owner': 'stage-owner'}
        m.review_stage(prior, monitor, config)
        for field, value in [('stage_verified', False), ('application_effect', True), ('error_type', 'ValueError')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.review_stage(dict(prior, **{field: value}), monitor, config)
        with self.assertRaises(ValueError):
            m.review_stage(prior, dict(monitor, stop_reason='rss'), config)

    def test_loaded_identity_requires_exact_programdata_and_genesis(self):
        self.assertTrue(hasattr(m, 'same_loaded'), 'execute supervisor is missing')
        loaded = {name: name for name in m.IDENTITY_FIELDS}
        m.same_loaded(loaded, dict(loaded))
        for field in m.IDENTITY_FIELDS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.same_loaded(loaded, dict(loaded, **{field: 'changed'}))

    def test_cleanup_separates_effect_evidence_from_ledger_persistence(self):
        self.assertTrue(hasattr(m, 'finish_status'), 'execute supervisor is missing')
        status = {'effect_verified': True, 'status': 'failed', 'ledger_reuse_requires_review': True,
                  'runner_cleanup': {'reaped': True, 'exit_code': 0},
                  'validator_cleanup': {'reaped': True, 'graceful': False, 'exit_code': -2}}
        m.finish_status(status)
        self.assertTrue(status['effect_verified'])
        self.assertEqual(status['status'], 'failed')
        self.assertTrue(status['ledger_reuse_requires_review'])
        status['validator_cleanup'] = {'reaped': True, 'graceful': True, 'exit_code': 0}
        m.finish_status(status)
        self.assertEqual(status['status'], 'passed')
        self.assertFalse(status['ledger_reuse_requires_review'])

    def test_finalized_batch_requires_exact_hash_owner_length_and_minimum_slot(self):
        report = {name: name for name in m.ACCOUNT_NAMES}
        data = [bytes([index]) * 12 for index in range(5)]
        accounts = [{'owner': 'program', 'executable': False,
                     'data': [base64.b64encode(raw).decode(), 'base64']} for raw in data]
        calls = []
        def rpc(method, params):
            calls.append((method, params))
            return {'context': {'slot': 12}, 'value': accounts}
        digests = [m.base.sha(raw) for raw in data]
        self.assertEqual(m.finalized_accounts(rpc, report, 10, 'program', digests, [12] * 5), (12, data))
        self.assertEqual(calls[0][1][1]['commitment'], 'finalized')
        self.assertEqual(calls[0][1][1]['minContextSlot'], 10)
        accounts[0]['owner'] = 'wrong'
        with self.assertRaises(ValueError):
            m.finalized_accounts(rpc, report, 10, 'program', digests, [12] * 5)
        accounts[0]['owner'] = 'program'
        with self.assertRaises(ValueError):
            m.finalized_accounts(rpc, report, 10, 'program', ['0' * 64] * 5, [12] * 5)
        with self.assertRaises(ValueError):
            m.finalized_accounts(rpc, report, 10, 'program', digests, [13] * 5)
        with self.assertRaises(m.base.NotReady):
            m.finalized_accounts(rpc, report, 13, 'program', digests, [12] * 5)

    def test_effect_report_requires_full_mode_exact_inputs_and_one_consumption(self):
        config = {'stage_report_sha256': 'a' * 64, 'stage_plan_sha256': 'b' * 64,
                  'full_wire_sha256': 'c' * 64, 'expected_genesis': 'genesis'}
        report = {'schema': 'part5-v3-local-execute-v1', 'passed': True, 'application_effect': True,
                  'effect_count': 1, 'request_consumed': True, 'proof_mode': 'Full',
                  'stage_report_sha256': 'a' * 64, 'stage_plan_sha256': 'b' * 64,
                  'wire_sha256': 'c' * 64, 'genesis': 'genesis', 'program': 'program',
                  'finalized_slot': 10, 'account_sha256': ['d' * 64] * 5}
        m.check_effect_report(report, config, {'program': 'program'})
        for field, value in [('effect_count', 2), ('request_consumed', False), ('proof_mode', 'Anchor'),
                             ('wire_sha256', 'e' * 64), ('finalized_slot', 0), ('account_sha256', [])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.check_effect_report(dict(report, **{field: value}), config, {'program': 'program'})

    def test_run_rechecks_finalized_bytes_and_retains_effect_on_sigint_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, control = root / 'execute', root / 'control'
            c = bytearray(381); c[:8] = b'DYNCONF3'
            r = bytearray(2249); r[:8] = b'DYNREQ03'; r[183] = 1; r[8:40] = bytes([4]) * 32
            q = bytearray(2090); q[:8] = b'DYNQUE03'; q[8:40] = bytes([4]) * 32
            data = [bytes(c), b'issuer', b'head', bytes(r), bytes(q)]
            hashes = [m.base.sha(raw) for raw in data]
            stage_root = root / 'stage'; stage_root.mkdir(mode=0o700)
            for name, raw in zip(m.ACCOUNT_NAMES, data):
                fd = os.open(stage_root / (name + '.bin'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'wb') as stream: stream.write(raw)
            r[183] = 2; q[40:42] = (1).to_bytes(2, 'big'); q[42:74] = bytes([9]) * 32
            post = [bytes(c), b'updated issuer', b'updated head', bytes(r), bytes(q)]
            loaded = {name: name for name in m.IDENTITY_FIELDS}
            original = {'program': 'program', 'elf': '/elf', 'elf_sha256': 'elf_sha256',
                        'validator': '/validator', 'build_plan': '/build', 'build_plan_sha256': 'a' * 64}
            config = {'runner': '/runner', 'runner_sha256': 'a' * 64, 'ledger': '/ledger',
                      'prior_stage_status_sha256': 'a' * 64, 'stage_root': str(stage_root),
                      'stage_report_sha256': 'b' * 64, 'stage_plan_sha256': 'c' * 64,
                      'full_wire': '/wire', 'full_wire_sha256': 'd' * 64,
                      'context': '/context', 'context_sha256': 'e' * 64, 'expected_genesis': 'genesis'}
            staged = {name: name for name in m.ACCOUNT_NAMES}
            staged.update(config=m.base.b58(bytes([4]) * 32), request=m.base.b58(bytes([9]) * 32))
            staged.update(finalized_slot=5, account_sha256=hashes)
            report = {'schema': 'part5-v3-local-execute-v1', 'passed': True, 'application_effect': True,
                      'effect_count': 1, 'request_consumed': True, 'proof_mode': 'Full',
                      'stage_report_sha256': 'b' * 64, 'stage_plan_sha256': 'c' * 64,
                      'wire_sha256': 'd' * 64, 'genesis': 'genesis', 'program': 'program',
                      'finalized_slot': 6, 'account_sha256': [m.base.sha(raw) for raw in post],
                      'loaded_program': {'elf_match': True, 'elf_sha256': 'elf_sha256'}}
            class Proc:
                def __init__(self, code): self.returncode = code
                def poll(self): return self.returncode
                def wait(self, timeout=None): return self.returncode
                def send_signal(self, sig): self.returncode = -signal.SIGINT
            spawns = []
            def spawn(argv, **kwargs):
                spawns.append(argv)
                self.assertFalse(kwargs['start_new_session'])
                if len(spawns) == 1: return Proc(None)
                m.base.write_new(output / 'execute-report.json', report)
                for name, raw in zip(m.ACCOUNT_NAMES, post):
                    fd = os.open(output / (name + '.bin'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(fd, 'wb') as stream: stream.write(raw)
                return Proc(0)
            with patch.object(m, 'admit', return_value=(original, {'loaded_program': loaded}, staged,
                                                       b'elf', list(map(len, data)), output, control)), \
                 patch.object(m.stage, 'resume_argv', return_value=['/validator']), \
                 patch.object(m.base, 'ports_free'), patch.object(m.base, 'LocalRpc'), \
                 patch.object(m.base, 'wait_loaded', return_value=loaded), \
                 patch.object(m, 'finalized_accounts', side_effect=[(5, data), (6, post)]) as accounts, \
                 patch.object(m.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(m, 'pinned_json', return_value={'source_manifest': {}}), \
                 patch.object(m.base.prep, 'check_manifest'), \
                 patch.dict(os.environ, {'P5_V3_EXEC_SUPERVISOR': 'local-ledger-review-and-execute'}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.run(config, 'f' * 64), 1)
            self.assertEqual(len(spawns), 2)
            self.assertEqual(accounts.call_count, 2)
            status = json.loads((control / 'status.json').read_bytes())
            self.assertTrue(status['effect_verified'])
            self.assertTrue(status['application_effect'])
            self.assertEqual(status['status'], 'failed')
            self.assertTrue(status['ledger_reuse_requires_review'])
            self.assertEqual(status['validator_cleanup']['exit_code'], -2)
            self.assertEqual((control / 'status.json').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
