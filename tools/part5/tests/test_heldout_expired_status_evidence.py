"""Synthetic report checks only; no RPC, proof, or process execution."""
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import heldout_expired_status_evidence as evidence


class ExpiredStatusEvidenceTests(unittest.TestCase):
    def test_integer_measurements_must_be_finite_for_float_conversion(self):
        with self.assertRaises(ValueError):
            evidence._number(10 ** 400)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        snapshots = []
        for name in ('config', 'issuer', 'head', 'request', 'queue'):
            row = {'name': name}
            for phase in ('before', 'after'):
                path = self.root / (name + '-' + phase)
                raw = (name + '-application-account').encode()
                path.write_bytes(raw)
                row[phase] = {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}
            snapshots.append(row)
        self.report = {
            'schema': evidence.SCHEMA,
            'identities': {key: 'a' * 64 for key in evidence.IDENTITY_ROLES},
            'clock': {'observed_at': 1000, 'expires_at': 1020, 'now': 1020, 'rpc_finalized': True},
            'preconditions': {key: True for key in ('status_active', 'issuer_active', 'head_bound',
                                                   'request_live', 'full_wire_valid')},
            'transaction': {'signature': '2' * 88, 'slot': 42, 'finalized': True,
                            'error': {'InstructionError': [1, {'Custom': 705}]}},
            'snapshots': snapshots,
            'limits': {'owner_wall_seconds': 60, 'rss_bytes': 1024, 'storage_growth_bytes': 2048,
                       'clock_wait_seconds': 30},
            'measured': {'owner_wall_seconds': 25.123456789, 'clock_wait_seconds': 20,
                         'peak_owned_rss_bytes': 512, 'storage_growth_bytes': 1024},
            'cleanup': {'remaining_owned_processes': 0, 'status_unknown': False,
                        'runner_reaped': True, 'validator_reaped': True, 'censored': False,
                        'stop_reason': None, 'runner_error_type': None},
            'application_effect': False}
        self.report['source_refs'] = {}
        for role in ('full_proof', 'full_wire'):
            path = self.root / role
            raw = (role + '-synthetic-protected-artifact').encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            self.report['source_refs'][role] = {'path': str(path), 'sha256': digest}
            self.report['identities'][role] = digest
        self.expected_identities = copy.deepcopy(self.report['identities'])

    def rejected(self, report):
        with self.assertRaises(ValueError):
            evidence.validate_report(report, self.expected_identities)

    def test_full_source_refs_are_pinned_bounded_and_rechecked(self):
        for role in ('full_proof', 'full_wire'):
            for mutation in ('missing', 'changed', 'symlink', 'oversize', 'digest-drift'):
                report = copy.deepcopy(self.report)
                with self.subTest(role=role, mutation=mutation):
                    ref = report['source_refs'][role]
                    if mutation == 'missing':
                        del report['source_refs'][role]
                    elif mutation == 'digest-drift':
                        ref['sha256'] = 'b' * 64
                    elif mutation == 'changed':
                        changed = self.root / (role + '-changed')
                        changed.write_bytes(b'changed')
                        ref['path'] = str(changed)
                    elif mutation == 'symlink':
                        link = self.root / (role + '-link')
                        link.symlink_to(ref['path'])
                        ref['path'] = str(link)
                    else:
                        changed = self.root / (role + '-oversize')
                        changed.write_bytes(b'x' * (evidence.MAX_SOURCE_BYTES + 1))
                        ref['path'] = str(changed)
                    self.rejected(report)
        original = evidence._snapshot
        calls = 0
        def mutate_source(ref, cap=None):
            nonlocal calls
            calls += 1
            if calls == 3:
                Path(self.report['source_refs']['full_wire']['path']).write_bytes(b'changed after initial read')
            return original(ref, cap)
        with patch.object(evidence, '_snapshot', side_effect=mutate_source):
            self.rejected(self.report)

    def test_strict_report_file(self):
        path = self.root / 'report.json'
        path.write_text(json.dumps(self.report))
        facts = evidence.verify_file(path, self.expected_identities)
        self.assertEqual(facts['custom_error'], 705)
        for raw in ('{"schema":1,"schema":2}', '{"schema":NaN}',
                    '{"schema":Infinity}', '{"schema":1e999}', ''):
            path.write_text(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.verify_file(path, self.expected_identities)
        path.write_bytes(b'x' * (evidence.MAX_REPORT_BYTES + 1))
        with self.assertRaises(ValueError):
            evidence.verify_file(path, self.expected_identities)
        link = self.root / 'report-link.json'
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            evidence.verify_file(link, self.expected_identities)

    def test_fifo_report_rejected_promptly(self):
        path = self.root / 'report-fifo'
        os.mkfifo(path)
        code = (
            'import sys\n'
            'from tools.part5 import heldout_expired_status_evidence as e\n'
            'try:\n'
            '    e.verify_file(sys.argv[1], {})\n'
            'except ValueError:\n'
            '    sys.exit(0)\n'
            'sys.exit(1)\n'
        )
        result = subprocess.run([sys.executable, '-B', '-c', code, str(path)],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')

    def test_success_path_free_and_no_acceptance_claim(self):
        facts = evidence.validate_report(self.report, self.expected_identities)
        raw = json.dumps(facts)
        self.assertNotIn(str(self.root), raw)
        self.assertNotIn('signature', raw)
        self.assertFalse(facts['loaded_run_established'])
        self.assertFalse(facts['heldout_acceptance_established'])
        self.assertEqual(facts['application_account_count'], 5)
        self.assertEqual(facts['measured']['owner_wall_seconds'], 25.123456789)

    def test_snapshot_ref_hash_and_bytes(self):
        for mutation in ('unknown', 'missing', 'bad-hash', 'wrong-hash', 'changed', 'symlink', 'parent-symlink', 'directory'):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(self.report)
                ref = report['snapshots'][0]['after']
                if mutation == 'unknown':
                    ref['extra'] = True
                elif mutation == 'missing':
                    ref['path'] += '-missing'
                elif mutation == 'bad-hash':
                    ref['sha256'] = 'B' * 64
                elif mutation == 'wrong-hash':
                    ref['sha256'] = 'a' * 64
                elif mutation == 'changed':
                    path = self.root / 'changed'
                    path.write_bytes(b'other')
                    ref.update(path=str(path), sha256=hashlib.sha256(b'other').hexdigest())
                elif mutation == 'symlink':
                    link = self.root / 'link'
                    link.symlink_to(ref['path'])
                    ref['path'] = str(link)
                elif mutation == 'parent-symlink':
                    link = self.root / 'parent-link'
                    link.symlink_to(self.root, target_is_directory=True)
                    ref['path'] = str(link / Path(ref['path']).name)
                else:
                    ref['path'] = str(self.root)
                self.rejected(report)
        report = copy.deepcopy(self.report)
        report['snapshots'].reverse()
        self.rejected(report)
        with patch.object(evidence, 'MAX_SNAPSHOT_BYTES', 1):
            self.rejected(self.report)

    def test_ref_changes_during_validation(self):
        original = evidence._snapshot
        calls = 0
        def changing(ref, cap=None):
            nonlocal calls
            calls += 1
            if calls == 13:
                Path(ref['path']).write_bytes(b'changed during validation')
            return original(ref, cap)
        with patch.object(evidence, '_snapshot', side_effect=changing):
            self.rejected(self.report)

    def test_expiry_boundaries(self):
        for observed, expiry, now, accepted in (
                (1000, 1020, 1019, False), (1000, 1020, 1020, True),
                (1000, 1300, 1300, True), (1000, 1020, 1301, False),
                (1000, 1301, 1301, False), (1000, 1000, 1000, False),
                (True, 1020, 1020, False)):
            report = copy.deepcopy(self.report)
            report['clock'].update(observed_at=observed, expires_at=expiry, now=now)
            with self.subTest(observed=observed, expiry=expiry, now=now):
                if accepted:
                    evidence.validate_report(report, self.expected_identities)
                else:
                    self.rejected(report)

    def test_unknown_fields_and_preconditions(self):
        for field in ('clock', 'preconditions', 'transaction', 'identities', 'limits', 'measured', 'cleanup', 'source_refs'):
            report = copy.deepcopy(self.report)
            report[field]['unknown'] = True
            self.rejected(report)
        report = copy.deepcopy(self.report)
        report['unknown'] = True
        self.rejected(report)
        for key in self.report['preconditions']:
            report = copy.deepcopy(self.report)
            report['preconditions'][key] = False
            self.rejected(report)
        for key in evidence.IDENTITY_ROLES:
            report = copy.deepcopy(self.report)
            report['identities'][key] = 'private-path'
            self.rejected(report)

    def test_external_identity_pins_are_required_and_exact(self):
        for role in evidence.IDENTITY_ROLES:
            changed = copy.deepcopy(self.report)
            changed['identities'][role] = 'b' * 64
            self.rejected(changed)
        for mutation in ('missing', 'unknown', 'bad-hash'):
            pins = copy.deepcopy(self.expected_identities)
            if mutation == 'missing':
                del pins['genesis']
            elif mutation == 'unknown':
                pins['extra'] = 'a' * 64
            else:
                pins['genesis'] = 'private-path'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.validate_report(self.report, pins)
        for key in ('peak_owned_rss_bytes', 'storage_growth_bytes'):
            for value in (-1, True, 0.5, float('inf'), float('nan')):
                changed = copy.deepcopy(self.report)
                changed['measured'][key] = value
                self.rejected(changed)

    def test_exact_error_and_finalization(self):
        for error in ({'InstructionError': [0, {'Custom': 705}]},
                      {'InstructionError': [1, {'Custom': 708}]},
                      {'InstructionError': [True, {'Custom': 705}]},
                      {'InstructionError': [1, {'Custom': 705.0}]},
                      {'InstructionError': [1, {'Custom': 705}], 'extra': 1}):
            report = copy.deepcopy(self.report)
            report['transaction']['error'] = error
            self.rejected(report)
        for field, key in (('transaction', 'finalized'), ('clock', 'rpc_finalized')):
            report = copy.deepcopy(self.report)
            report[field][key] = False
            self.rejected(report)

    def test_cleanup_and_bounds(self):
        for key in self.report['cleanup']:
            report = copy.deepcopy(self.report)
            original = report['cleanup'][key]
            report['cleanup'][key] = 1 if key == 'remaining_owned_processes' else (not original if type(original) is bool else 'failure')
            self.rejected(report)
        for key in self.report['limits']:
            for value in (0, -1, True, float('inf'), float('nan')):
                report = copy.deepcopy(self.report)
                report['limits'][key] = value
                self.rejected(report)
        for key in self.report['measured']:
            report = copy.deepcopy(self.report)
            limit_key = 'rss_bytes' if key == 'peak_owned_rss_bytes' else key
            report['measured'][key] = report['limits'][limit_key] + 1
            self.rejected(report)
        report = copy.deepcopy(self.report)
        report['limits']['clock_wait_seconds'] = 61
        self.rejected(report)


if __name__ == '__main__':
    unittest.main()
