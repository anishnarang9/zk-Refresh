"""Synthetic binding checks; never open campaign evidence."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import bind_v3_campaign_completion as binder


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.args = {}
        self.docs = {
            'matrix_manifest': {'campaign_id': 'training-011'},
            'clock_report': {'passed': True, 'slot_count': 60, 'tolerance_seconds': 5.0},
            'economics_report': {'input_manifest_sha256': self.digest({'sessions': []})},
            'reconciliation_report': {},
            'total_summary': {'matched_pairs': 20, 'expected_pairs': 20, 'matrix_grid_complete': True},
        }
        for key, doc in self.docs.items():
            self.args[key] = self.write(key + '.json', doc)
        self.sequence = self.write('sequence-receipt.json', {})
        self.write('economics-input-manifest.json', {'sessions': []})
        self.args['output'] = self.root / 'qualification.json'
        self.validated = {'output_root': self.root, 'campaign_id': 'training-011', 'manifest_sha256': 'a' * 64}
        reconciliation = {'economics_report_sha256': binder._read(self.args['economics_report'])[1]}
        self.write('reconciliation_report.json', reconciliation)
        mocks = [
            patch.object(binder.matrix, 'validate_manifest', return_value=self.validated),
            patch.object(binder.costs, 'verify_completed_matrix', return_value=self.digest({})),
            patch.object(binder.matrix, 'plan_slots', return_value=[{}] * 60),
            patch.object(binder.matrix, 'economics_input_manifest', return_value={'sessions': []}),
            patch.object(binder.clock, 'audit', return_value=self.docs['clock_report']),
            patch.object(binder.economics, 'aggregate', return_value={}),
            patch.object(binder.costs, 'reconcile', return_value={}),
            patch.object(binder.total, 'summarize', return_value=self.docs['total_summary']),
            patch.object(binder, 'REGISTERED_MANIFEST_PATH', self.args['matrix_manifest']),
            patch.object(binder, 'REGISTERED_MANIFEST_RAW_SHA256', self.digest(self.docs['matrix_manifest'])),
            patch.object(binder, 'REGISTERED_MANIFEST_CANONICAL_SHA256', 'a' * 64),
            patch.object(binder, 'REGISTERED_OUTPUT_ROOT', self.root),
        ]
        self.mocks = [mock.start() for mock in mocks]
        for mock in mocks:
            self.addCleanup(mock.stop)

    @staticmethod
    def raw(doc):
        return (json.dumps(doc) + '\n').encode()

    def digest(self, doc):
        return hashlib.sha256(self.raw(doc)).hexdigest()

    def write(self, name, doc):
        path = self.root / name
        path.write_bytes(self.raw(doc))
        return path

    def test_success_path_free_pins_and_exclusive(self):
        receipt = binder.bind(**self.args)
        self.assertEqual(receipt['matched_pairs'], 20)
        self.assertNotIn(str(self.root), json.dumps(receipt))
        self.assertEqual(receipt['source_sha256']['matrix_manifest'], self.digest(self.docs['matrix_manifest']))
        self.assertEqual(self.args['output'].stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            binder.bind(**self.args)

    def test_rejects_incomplete_matrix(self):
        self.mocks[1].side_effect = ValueError('incomplete')
        with self.assertRaises(ValueError):
            binder.bind(**self.args)
        self.assertFalse(self.args['output'].exists())

    def test_rejects_unregistered_matrix_identity(self):
        with patch.object(binder, 'REGISTERED_MANIFEST_RAW_SHA256', 'f' * 64):
            with self.assertRaisesRegex(ValueError, 'registered Training-011 manifest'):
                binder.bind(**self.args)
        with patch.object(binder, 'REGISTERED_MANIFEST_PATH', self.root / 'other.json'):
            with self.assertRaisesRegex(ValueError, 'registered Training-011 manifest'):
                binder.bind(**self.args)
        with patch.object(binder, 'REGISTERED_OUTPUT_ROOT', self.root / 'other-root'):
            with self.assertRaisesRegex(ValueError, 'registered Training-011 campaign'):
                binder.bind(**self.args)
        self.assertFalse(self.args['output'].exists())

    def test_rejects_duplicate_or_nonfinite_report_values(self):
        path = self.args['clock_report']
        for raw in (b'{"passed":true,"passed":true}\n',
                    b'{"tolerance_seconds":NaN}\n'):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    binder.bind(**self.args)
        self.assertFalse(self.args['output'].exists())

    def test_report_mismatch(self):
        for key in ('clock_report', 'economics_report', 'reconciliation_report', 'total_summary'):
            with self.subTest(key=key):
                path = self.args[key]
                raw = path.read_bytes()
                path.write_text('{}')
                with self.assertRaises((ValueError, TypeError)):
                    binder.bind(**self.args)
                path.write_bytes(raw)
        self.assertFalse(self.args['output'].exists())

    def test_requires_twenty_matched_pairs(self):
        report = dict(self.docs['total_summary'], matched_pairs=19)
        self.mocks[7].return_value = report
        self.write('total_summary.json', report)
        with self.assertRaises(ValueError):
            binder.bind(**self.args)
        self.assertFalse(self.args['output'].exists())

    def test_rejects_incorrect_economics_input_manifest(self):
        self.write('economics-input-manifest.json', {'sessions': ['different']})
        with self.assertRaises(ValueError):
            binder.bind(**self.args)
        self.assertFalse(self.args['output'].exists())

    def test_rejects_failed_clock(self):
        report = dict(self.docs['clock_report'], passed=False)
        self.write('clock_report.json', report)
        self.mocks[4].return_value = report
        with self.assertRaises(ValueError):
            binder.bind(**self.args)

    def test_clock_tolerance_enforced_by_real_audit(self):
        # Exercise the actual audit's tolerance gate before it reads a manifest.
        self.mocks[4].side_effect = lambda path, tolerance: binder.clock._tolerance(tolerance)
        for tolerance in (6, -1, float('nan'), True):
            self.write('clock_report.json', dict(self.docs['clock_report'], tolerance_seconds=tolerance))
            with self.assertRaises(ValueError):
                binder.bind(**self.args)

    def test_rejects_stale_source(self):
        calls = 0
        def verify(validated):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.args['matrix_manifest'].write_text('{"changed":true}')
            return self.digest({})
        self.mocks[1].side_effect = verify
        with self.assertRaises(ValueError):
            binder.bind(**self.args)
        self.assertFalse(self.args['output'].exists())

    def test_rejects_symlinks_and_relative_outputs(self):
        for output in (Path('relative.json'), self.root / 'link.json'):
            if output.is_absolute():
                output.symlink_to(self.sequence)
            with self.assertRaises(ValueError):
                binder.bind(**dict(self.args, output=output))
        source = self.args['matrix_manifest']
        source.unlink()
        source.symlink_to(self.sequence)
        with self.assertRaises(ValueError):
            binder.bind(**self.args)

    def test_no_profitability_gate(self):
        self.docs['total_summary']['profitable'] = False
        self.write('total_summary.json', self.docs['total_summary'])
        self.assertTrue(binder.bind(**self.args)['qualified'])

    def test_argument_errors_do_not_echo_private_argv(self):
        with self.assertRaises(SystemExit) as error:
            binder.main(['--private=/secret/private/path'])
        self.assertNotIn('/secret', str(error.exception))


if __name__ == '__main__':
    unittest.main()
