import importlib.util
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = __import__('pathlib').Path(__file__).with_name(
    'queue_v3_local_ambiguous_restart.py')
SPEC = importlib.util.spec_from_file_location('queue_v3_local_ambiguous_restart', MODULE_PATH)
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class AmbiguousRestartTests(unittest.TestCase):
    def test_receipt_requires_one_pinned_accepted_submission_and_signature(self):
        signature = m.proxy.encode_base58(bytes(range(64)))
        receipt = {
            'schema': m.PROXY_RECEIPT_SCHEMA,
            'status': 'response_dropped',
            'target_wire_sha256': 'a' * 64,
            'transaction_sha256': 'b' * 64,
            'signature': signature,
            'matching_submissions': 1,
            'duplicate_matching_submissions': 0,
            'duplicate_rejected': False,
            'forward_attempted': 1,
            'forwarded': 1,
            'response_dropped': True,
        }
        self.assertEqual(m.validate_proxy_receipt(receipt, 'a' * 64), receipt)
        for changed in (
            dict(receipt, status='outcome_unknown'),
            dict(receipt, matching_submissions=2, duplicate_matching_submissions=1,
                 duplicate_rejected=True),
            dict(receipt, target_wire_sha256='c' * 64),
            dict(receipt, signature='not-a-signature'),
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                m.validate_proxy_receipt(changed, 'a' * 64)

    def test_only_the_specific_nonzero_send_transport_failure_is_expected(self):
        receipt = {
            'schema': m.PROXY_RECEIPT_SCHEMA,
            'status': 'response_dropped',
            'target_wire_sha256': 'a' * 64,
            'transaction_sha256': 'b' * 64,
            'signature': m.proxy.encode_base58(bytes(range(64))),
            'matching_submissions': 1,
            'duplicate_matching_submissions': 0,
            'duplicate_rejected': False,
            'forward_attempted': 1,
            'forwarded': 1,
            'response_dropped': True,
        }
        self.assertTrue(m.expected_transport_failure(
            1, b'RPC sendTransaction transport failed', receipt, 'a' * 64))
        for code, stderr in ((0, b''), (1, b'assertion failed'),
                             (1, b'RPC getLatestBlockhash transport failed')):
            with self.subTest(code=code, stderr=stderr), self.assertRaises(ValueError):
                m.expected_transport_failure(code, stderr, receipt, 'a' * 64)

    def test_reconciliation_accepts_only_exact_single_consume_and_queue_append(self):
        before, after, context = self._account_fixture()
        pre_submit = after[:3] + [before[3], before[4]]
        self.assertTrue(m._pre_submit_matches_stage_transition(before, pre_submit, context))
        digests = m.reconcile_final_accounts(before, after, context, pre_submit)
        self.assertEqual(len(digests), 5)
        changed_pre = list(pre_submit)
        changed_pre[1] = changed_pre[1][:-1] + bytes([changed_pre[1][-1] ^ 1])
        with self.assertRaises(ValueError):
            m._pre_submit_matches_stage_transition(before, changed_pre, context)
        for index, offset in ((0, 100), (1, 180), (2, 110), (3, 100), (4, 80)):
            changed = list(after)
            raw = bytearray(changed[index])
            raw[offset] ^= 1
            changed[index] = bytes(raw)
            with self.subTest(index=index, offset=offset), self.assertRaises(ValueError):
                m.reconcile_final_accounts(before, changed, context)

    def test_missing_direct_prepositive_snapshot_is_a_hard_failure(self):
        result = m.final_status({
            'proxy_receipt_verified': True,
            'expected_transport_failure': True,
            'restart_identity_verified': True,
            'signature_finalized_success': True,
            'five_account_reconciliation_verified': True,
            'prepositive_snapshot_saved_by_runner': False,
            'cleanup_verified': True,
        })
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['heldout_acceptance'])

    def test_finality_reconciliation_uses_mock_rpc_and_exact_signature(self):
        signature = m.proxy.encode_base58(bytes(range(64)))
        replies = [
            {'value': [{'confirmationStatus': 'confirmed', 'err': None, 'slot': 20}]},
            {'value': [{'confirmationStatus': 'finalized', 'err': None, 'slot': 21}]},
            {'slot': 21, 'meta': {'err': None}, 'transaction': {'signatures': [signature]}},
        ]
        calls = []

        def rpc(method, params):
            calls.append((method, params))
            return replies.pop(0)

        with patch.object(m.time, 'sleep'):
            slot, signature_sha = m._wait_finalized_signature(
                rpc, signature, m.time.monotonic() + 1)
        self.assertEqual(slot, 21)
        self.assertEqual(signature_sha, sha(signature.encode()))
        self.assertEqual([name for name, _ in calls], [
            'getSignatureStatuses', 'getSignatureStatuses', 'getTransaction'])

    def test_supervisor_deadline_stays_inside_outer_limit(self):
        self.assertGreater(m.SUPERVISOR_BUDGET_SECONDS, 0)
        self.assertLess(m.SUPERVISOR_BUDGET_SECONDS, 180)

    def test_pre_submit_snapshot_requires_all_pins_and_private_role_files(self):
        before, after, context = self._account_fixture()
        snapshots = after[:3] + [before[3], before[4]]
        staged = {name: f'address-{name}' for name in m.ACCOUNT_NAMES}
        config = {
            'stage_report_sha256': 'a' * 64,
            'stage_plan_sha256': 'b' * 64,
            'full_wire_sha256': 'c' * 64,
            'expected_program': 'program-key',
            'expected_genesis': 'genesis-hash',
            'expected_elf_sha256': 'd' * 64,
        }
        report = {
            'schema': m.PREPOSITIVE_SCHEMA,
            'training_only': True,
            'application_effect': False,
            'request_consumed': False,
            'finalized_slot': 44,
            'stage_report_sha256': config['stage_report_sha256'],
            'stage_plan_sha256': config['stage_plan_sha256'],
            'wire_sha256': config['full_wire_sha256'],
            'program': config['expected_program'],
            'genesis': config['expected_genesis'],
            'loaded_program': {'elf_match': True, 'elf_sha256': config['expected_elf_sha256']},
            'addresses': staged,
            'account_sha256': [sha(raw) for raw in snapshots],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for name, raw in zip(m.ACCOUNT_NAMES, snapshots):
                path = output / f'pre-submit-{name}.bin'
                path.write_bytes(raw)
                path.chmod(0o600)
            report_path = output / 'pre-submit-report.json'
            report_path.write_text(json.dumps(report))
            report_path.chmod(0o600)
            actual, loaded, report_sha = m._load_pre_submit_snapshot(
                output, [len(raw) for raw in before], 40, config, staged)
            self.assertEqual(actual, report)
            self.assertEqual(loaded, snapshots)
            self.assertEqual(len(report_sha), 64)

            broken = dict(config, full_wire_sha256='e' * 64)
            with self.assertRaises(ValueError):
                m._load_pre_submit_snapshot(output, [len(raw) for raw in before], 40,
                                            broken, staged)

    def test_saved_final_account_bytes_are_private_and_bound_to_reconciled_state(self):
        _, after, _ = self._account_fixture()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            hashes, paths = m._persist_final_account_bytes(output, after)
            self.assertEqual(hashes, [sha(raw) for raw in after])
            self.assertEqual(paths, [str(output / f'final-{name}.bin')
                                     for name in m.ACCOUNT_NAMES])
            for name in m.ACCOUNT_NAMES:
                info = (output / f'final-{name}.bin').stat()
                self.assertEqual(info.st_mode & 0o777, 0o600)
                self.assertEqual(info.st_nlink, 1)
            self.assertEqual(m._verify_saved_final_account_bytes(output, after),
                             (hashes, paths))

            changed = output / 'final-queue.bin'
            raw = bytearray(changed.read_bytes())
            raw[-1] ^= 1
            changed.write_bytes(raw)
            changed.chmod(0o600)
            with self.assertRaises(ValueError):
                m._verify_saved_final_account_bytes(output, after)

    def _account_fixture(self):
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[332:364] = bytes(range(1, 33))
        config[364:372] = (3).to_bytes(8, 'big')
        config[372:380] = (4).to_bytes(8, 'big')
        issuer = bytearray(374)
        issuer[:8] = b'DYNISS03'
        issuer[8:40] = bytes([1]) * 32
        issuer[40:72] = bytes([2]) * 32
        issuer[140:172] = bytes([3]) * 32
        issuer[172] = 1
        issuer[173:181] = (8).to_bytes(8, 'big')
        issuer[181:213] = bytes([4]) * 32
        issuer[213:221] = (1000).to_bytes(8, 'big', signed=True)
        issuer[221:229] = (1200).to_bytes(8, 'big', signed=True)
        issuer[229:261] = config[332:364]
        issuer[261:269] = (3).to_bytes(8, 'big')
        issuer[269:277] = (8).to_bytes(8, 'big')
        issuer[277:309] = bytes([4]) * 32
        issuer[309:317] = (1).to_bytes(8, 'big')
        issuer[317:349] = bytes([5]) * 32
        issuer[349:357] = (4).to_bytes(8, 'big')
        issuer[357] = 1
        issuer[358:366] = (6).to_bytes(8, 'big')
        issuer[366:374] = (6).to_bytes(8, 'big')
        head = bytearray(280)
        head[:8] = b'DYNHEAD3'
        head[8:40] = issuer[8:40]
        head[40:72] = bytes([6]) * 32
        head[72:104] = bytes([7]) * 32
        head[104:112] = (9).to_bytes(8, 'big')
        head[112:144] = bytes([8]) * 32
        head[144:176] = bytes([9]) * 32
        head[176:208] = config[332:364]
        head[208:216] = (3).to_bytes(8, 'big')
        head[216:224] = (8).to_bytes(8, 'big')
        head[224:256] = bytes([4]) * 32
        head[256:264] = (4).to_bytes(8, 'big')
        head[264:272] = (6).to_bytes(8, 'big')
        head[272:280] = (1100).to_bytes(8, 'big', signed=True)
        request = bytearray(2249)
        request[:8] = b'DYNREQ03'
        request[8:40] = config[8:40]
        request[183] = 1
        queue = bytearray(2090)
        queue[:8] = b'DYNQUE03'
        queue[8:40] = config[8:40]
        before = [bytes(config), bytes(issuer), bytes(head), bytes(request), bytes(queue)]
        context = {
            'root': bytes(config[332:364]),
            'request': bytes([10]) * 32,
            'observed_at': 1201,
            'head_committed_at': 1202,
        }
        after = m.expected_reconciled_accounts(before, context)
        return before, after, context


if __name__ == '__main__':
    unittest.main()
