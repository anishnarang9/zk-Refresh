"""Synthetic evidence consistency only; these tests do not execute a validator."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from tools.part5 import heldout_queue_capacity_evidence as tool


def _fixture(root):
    identities = dict.fromkeys(tool.IDENTITIES, 'a' * 64)
    addresses = [f'request{i}' for i in range(64)]
    queue_hash = hashlib.sha256(b'initial-empty-queue').hexdigest()
    final_queue_hash = hashlib.sha256(b'queue-application-bytes').hexdigest()
    fills = []
    for i, address in enumerate(addresses):
        next_queue_hash = (final_queue_hash if i == 63
                           else hashlib.sha256(f'queue-state-{i}'.encode()).hexdigest())
        fills.append(dict(request_address=address, signature=f'signature{i}', slot=i + 1,
                          finalized=True, consumed=True, queue_after_addresses=addresses[:i + 1],
                          request_before_sha256=hashlib.sha256(f'request-before-{i}'.encode()).hexdigest(),
                          request_after_sha256=hashlib.sha256(f'request-after-{i}'.encode()).hexdigest(),
                          queue_before_sha256=queue_hash, queue_after_sha256=next_queue_hash))
        queue_hash = next_queue_hash
    snapshots = []
    for name in tool.checks.ACCOUNT_NAMES:
        refs = {}
        for direction in ('before', 'after'):
            path = root / f'{name}-{direction}.bin'
            raw = (name + '-application-bytes').encode()
            path.write_bytes(raw)
            refs[direction] = {'path': path.name, 'sha256': hashlib.sha256(raw).hexdigest()}
        snapshots.append(dict(name=name, **refs))
    report = dict(schema=tool.SCHEMA, identities=identities, fill_history=fills,
                  before_queue_addresses=addresses[:], after_queue_addresses=addresses[:],
                  rejected_request=dict(request_address='request65', signature='signature65', slot=65,
                                        finalized=True, consumed=False,
                                        rpc_error={'InstructionError': [1, {'Custom': 708}]}),
                  preconditions=dict(status_active=True, issuer_active=True, head_bound=True,
                                     request_live=True, full_wire_valid=True, observed_at=100,
                                     expires_at=400, now=200, request_deadline=300),
                  snapshots=snapshots,
                  owner=dict(wall_limit_seconds=180, rss_limit_bytes=1024, storage_limit_bytes=1024,
                             wall_seconds=10, peak_owned_rss_bytes=100, storage_growth_bytes=100,
                             ownership_known=True, cleanup_complete=True, remaining_owned_processes=0))
    return report, copy.deepcopy(identities)


class CapacityEvidenceTests(unittest.TestCase):
    def test_success_calls_shared_pure_checks_and_returns_path_free_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report, identities = _fixture(root)
            with patch.object(tool.checks, 'check_finalized_fill_history', wraps=tool.checks.check_finalized_fill_history) as fills, \
                    patch.object(tool.checks, 'check_full_queue', wraps=tool.checks.check_full_queue) as queue, \
                    patch.object(tool.checks, 'check_execute_error', wraps=tool.checks.check_execute_error) as error, \
                    patch.object(tool.checks, 'check_application_accounts_unchanged', wraps=tool.checks.check_application_accounts_unchanged) as unchanged:
                result = tool.validate_report(report, root, identities)
            for check in (fills, queue, error, unchanged):
                check.assert_called_once()
            self.assertTrue(result['report_consistent'])
            self.assertFalse(result['loaded_run_established'])
            self.assertFalse(result['heldout_acceptance_established'])
            self.assertIn('no loaded execution', result['scope'])
            output = json.dumps(result)
            for value in (temporary, 'request65', 'signature65', 'config-before.bin', 'a' * 64):
                self.assertNotIn(value, output)

    def test_fail_closed_mutations(self):
        mutations = [lambda r: r.update(extra=True),
                     lambda r: r['identities'].update(freeze_sha256='b'*64),
                     lambda r: r['fill_history'].pop(),
                     lambda r: r['fill_history'][1].update(request_address='request0'),
                     lambda r: r['fill_history'][1].update(signature='signature0'),
                     lambda r: r['fill_history'][1].update(slot=True),
                     lambda r: r['fill_history'][2].update(slot=1),
                     lambda r: r['fill_history'][0].update(finalized=False),
                     lambda r: r['fill_history'][0].update(consumed=False),
                     lambda r: r['fill_history'][0].update(success=True),
                     lambda r: r['fill_history'][0].update(request_after_sha256=r['fill_history'][0]['request_before_sha256']),
                     lambda r: r['fill_history'][0].update(queue_after_sha256=r['fill_history'][0]['queue_before_sha256']),
                     lambda r: r['fill_history'][1].update(queue_before_sha256='f'*64),
                     lambda r: r['fill_history'][0].update(request_before_sha256='F'*64),
                     lambda r: r['fill_history'][63].update(queue_after_sha256='f'*64),
                     lambda r: r['fill_history'][1]['queue_after_addresses'].reverse(),
                     lambda r: r['before_queue_addresses'].pop(),
                     lambda r: r['after_queue_addresses'].reverse(),
                     lambda r: r['rejected_request'].update(request_address='request0'),
                     lambda r: r['rejected_request'].update(finalized=False),
                     lambda r: r['rejected_request'].update(consumed=True),
                     lambda r: r['rejected_request'].update(slot=1),
                     lambda r: r['rejected_request'].update(rpc_error={'InstructionError': [0, {'Custom': 708}]}),
                     lambda r: r['rejected_request'].update(rpc_error={'InstructionError': [True, {'Custom': 708}]}),
                     lambda r: r['rejected_request'].update(rpc_error={'InstructionError': [1, {'Custom': 708.0}]}),
                     lambda r: r['rejected_request'].update(rpc_error={'InstructionError': [1, {'Custom': 705}]}),
                     lambda r: r['preconditions'].update(status_active=False),
                     lambda r: r['preconditions'].update(issuer_active=False),
                     lambda r: r['preconditions'].update(head_bound=False),
                     lambda r: r['preconditions'].update(full_wire_valid=False),
                     lambda r: r['preconditions'].update(request_live=False),
                     lambda r: r['preconditions'].update(now=400),
                     lambda r: r['preconditions'].update(expires_at=401),
                     lambda r: r['preconditions'].update(request_deadline=200),
                     lambda r: r['snapshots'].reverse(),
                     lambda r: r['snapshots'][0]['before'].update(path='../escape'),
                     lambda r: r['snapshots'][0]['before'].update(sha256='f'*64),
                     lambda r: r['owner'].update(cleanup_complete=False),
                     lambda r: r['owner'].update(ownership_known=False),
                     lambda r: r['owner'].update(remaining_owned_processes=1),
                     lambda r: r['owner'].update(wall_limit_seconds=0),
                     lambda r: r['owner'].update(wall_limit_seconds=True),
                     lambda r: r['owner'].update(wall_seconds=float('inf')),
                     lambda r: r['owner'].update(peak_owned_rss_bytes=1025),
                     lambda r: r['owner'].update(storage_growth_bytes=1025)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report, identities = _fixture(root)
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    changed = copy.deepcopy(report)
                    mutate(changed)
                    with self.assertRaises(ValueError):
                        tool.validate_report(changed, root, identities)

    def test_snapshot_bytes_rehashed_tamper_symlink_and_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for kind in ('changed', 'symlink', 'oversize', 'missing'):
                with self.subTest(kind=kind):
                    report, identities = _fixture(root)
                    reference = report['snapshots'][0]['after']
                    path = root / reference['path']
                    if kind == 'changed':
                        path.write_bytes(b'changed')
                        reference['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                    elif kind == 'symlink':
                        path.unlink()
                        path.symlink_to(root / 'config-before.bin')
                    elif kind == 'oversize':
                        path.write_bytes(b'x' * (tool.MAX_ACCOUNT_BYTES + 1))
                    else:
                        path.unlink()
                    with self.assertRaises(ValueError):
                        tool.validate_report(report, root, identities)
                    if path.is_symlink():
                        path.unlink()

    def test_fifo_snapshot_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report, identities = _fixture(root)
            fifo = root / report['snapshots'][0]['before']['path']
            fifo.unlink()
            os.mkfifo(fifo)
            report_path = root / 'report.json'
            report_path.write_text(json.dumps(report))
            script = (
                'import json,sys\n'
                'from tools.part5 import heldout_queue_capacity_evidence as t\n'
                'try:\n'
                ' t.verify_file(sys.argv[1],sys.argv[2],json.loads(sys.argv[3]))\n'
                'except ValueError:\n'
                ' sys.exit(0)\n'
                'sys.exit(1)\n'
            )
            result = subprocess.run([sys.executable, '-c', script, str(report_path), str(root),
                                     json.dumps(identities)], capture_output=True, text=True,
                                    timeout=3, cwd=Path(tool.__file__).resolve().parents[2])
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_fifo_report_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _, identities = _fixture(root)
            fifo = root / 'report-fifo'
            os.mkfifo(fifo)
            script = (
                'import json,sys\n'
                'from tools.part5 import heldout_queue_capacity_evidence as t\n'
                'try:\n'
                ' t.verify_file(sys.argv[1],sys.argv[2],json.loads(sys.argv[3]))\n'
                'except ValueError:\n'
                ' sys.exit(0)\n'
                'sys.exit(1)\n'
            )
            result = subprocess.run([sys.executable, '-c', script, str(fifo), str(root),
                                     json.dumps(identities)], capture_output=True, text=True,
                                    timeout=3, cwd=Path(tool.__file__).resolve().parents[2])
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_reopens_all_ten_refs_and_detects_mid_validation_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report, identities = _fixture(root)
            original = tool._snapshot
            with patch.object(tool, '_snapshot', wraps=original) as read:
                tool.validate_report(report, root, identities)
            self.assertEqual(read.call_count, 20)
            for read_number in (11, 20):
                with self.subTest(read_number=read_number):
                    report, identities = _fixture(root)
                    calls = 0
                    def mutate_on_reopen(reference, directory):
                        nonlocal calls
                        calls += 1
                        if calls == read_number:
                            (directory / reference['path']).write_bytes(b'changed after initial checks')
                        return original(reference, directory)
                    with patch.object(tool, '_snapshot', side_effect=mutate_on_reopen):
                        with self.assertRaises(ValueError):
                            tool.validate_report(report, root, identities)

    def test_strict_json_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report, identities = _fixture(root)
            path = root / 'report.json'
            path.write_text(json.dumps(report))
            self.assertTrue(tool.verify_file(path, root, identities)['report_consistent'])
            for raw in ('{"schema":1,"schema":2}', '{"schema":NaN}'):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    tool.verify_file(path, root, identities)

    def test_report_path_must_be_canonical_and_nonsymlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report, identities = _fixture(root)
            path = root / 'report.json'
            path.write_text(json.dumps(report))
            link = root / 'link'
            link.symlink_to(root, target_is_directory=True)
            for source in (Path('report.json'), link / 'report.json'):
                with self.subTest(source=source), self.assertRaises(ValueError):
                    tool.verify_file(source, root, identities)


if __name__ == '__main__':
    unittest.main()
