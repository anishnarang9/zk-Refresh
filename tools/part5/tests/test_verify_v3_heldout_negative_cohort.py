"""Synthetic prospective cohort consistency checks, without loaded execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import verify_v3_heldout_negative_cohort as tool
from tools.part5.tests.test_heldout_queue_capacity_evidence import _fixture as capacity_fixture
from tools.part5.tests import test_heldout_expired_status_evidence as expired_fixtures


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cohort(root):
    capacity_dir = root / 'capacity'
    capacity_dir.mkdir()
    queue, expected_queue = capacity_fixture(capacity_dir)
    source = expired_fixtures.ExpiredStatusEvidenceTests('test_success_path_free_and_no_acceptance_claim')
    source.setUp()
    try:
        stale = copy.deepcopy(source.report)
        for row in stale['snapshots']:
            for phase in ('before', 'after'):
                original = Path(row[phase]['path'])
                path = root / original.name
                path.write_bytes(original.read_bytes())
                row[phase]['path'] = str(path)
        for ref in stale['source_refs'].values():
            original = Path(ref['path'])
            path = root / original.name
            path.write_bytes(original.read_bytes())
            ref['path'] = str(path)
    finally:
        source.doCleanups()
    def entry(name, report, **extra):
        path = root / name
        path.write_text(json.dumps(report))
        return dict(path=str(path), sha256=_sha(path), expected_identities=copy.deepcopy(report['identities']), **extra)
    def stale_entry(index):
        report = copy.deepcopy(stale)
        for role in ('stage', 'clone'):
            report['identities'][role] = hashlib.sha256(f'{role}-{index}'.encode()).hexdigest()
        return entry(f'expired-{index}.json', report, variant=index)
    return dict(schema=tool.SCHEMA, common_identities=dict.fromkeys(tool.COMMON, 'a' * 64),
                expired_status_reports=[stale_entry(i) for i in range(8)],
                queue_capacity_reports=[entry('capacity.json', queue, evidence_dir=str(capacity_dir))])


class NegativeCohortTests(unittest.TestCase):
    def test_real_child_integration_and_path_free_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = _cohort(root)
            path = root / 'manifest.json'
            path.write_text(json.dumps(manifest))
            with patch.object(tool.expired, 'validate_report', wraps=tool.expired.validate_report) as stale, \
                    patch.object(tool.capacity, 'validate_report', wraps=tool.capacity.validate_report) as queue:
                result = tool.verify_file(path, _sha(path))
            self.assertEqual(stale.call_count, 8)
            self.assertEqual(queue.call_count, 1)
            self.assertEqual(result['expired_status_report_count'], 8)
            self.assertEqual(result['shared_queue_capacity_report_count'], 1)
            self.assertFalse(result['loaded_run_established'])
            self.assertFalse(result['heldout_acceptance_established'])
            self.assertNotIn(temporary, json.dumps(result))
            self.assertNotIn('path', json.dumps(result))

    def test_shape_order_cardinality_identity_and_digest_mutations(self):
        mutations = [lambda m: m.update(extra=True),
                     lambda m: m['expired_status_reports'].pop(),
                     lambda m: m['expired_status_reports'].reverse(),
                     lambda m: m['expired_status_reports'][0].update(variant=True),
                     lambda m: m['expired_status_reports'][1].update(variant=0),
                     lambda m: m['queue_capacity_reports'].clear(),
                     lambda m: m['queue_capacity_reports'].append(copy.deepcopy(m['queue_capacity_reports'][0])),
                     lambda m: m['expired_status_reports'][0].update(extra=True),
                     lambda m: m['expired_status_reports'][0].update(sha256='b' * 64),
                     lambda m: m['expired_status_reports'][1].update(path=m['expired_status_reports'][0]['path']),
                     lambda m: m['expired_status_reports'][0]['expected_identities'].update(genesis='b' * 64),
                     lambda m: m['queue_capacity_reports'][0]['expected_identities'].update(elf_sha256='b' * 64),
                     lambda m: m['common_identities'].update(freeze_sha256='b' * 64),
                     lambda m: m['queue_capacity_reports'][0].update(evidence_dir='/missing/nonexistent')]
        with tempfile.TemporaryDirectory() as temporary:
            manifest = _cohort(Path(temporary).resolve())
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    changed = copy.deepcopy(manifest)
                    mutate(changed)
                    with self.assertRaises(ValueError):
                        tool.validate_manifest(changed)

    def test_child_failure_and_mutation_during_later_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = _cohort(root)
            with patch.object(tool.expired, 'validate_report', side_effect=ValueError('synthetic child failure')):
                with self.assertRaises(ValueError):
                    tool.validate_manifest(manifest)
            original = tool.capacity.validate_report
            for kind in ('report', 'snapshot', 'source-ref'):
                manifest = _cohort_reusable(root)
                def mutate_then_validate(*args):
                    facts = original(*args)
                    first = manifest['expired_status_reports'][0]
                    document = json.loads(Path(first['path']).read_bytes())
                    path = (Path(first['path']) if kind == 'report' else
                            Path(document['snapshots'][0]['before']['path']) if kind == 'snapshot' else
                            Path(document['source_refs']['full_wire']['path']))
                    path.write_bytes(path.read_bytes() + b'changed')
                    return facts
                with self.subTest(kind=kind), patch.object(tool.capacity, 'validate_report', side_effect=mutate_then_validate):
                    with self.assertRaises(ValueError):
                        tool.validate_manifest(manifest)

    def test_copied_report_bytes_and_reused_case_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for kind in ('same-bytes', 'same-case-identity'):
                manifest = _cohort_reusable(root)
                first, second = manifest['expired_status_reports'][:2]
                original = Path(first['path']).read_bytes()
                if kind == 'same-bytes':
                    Path(second['path']).write_bytes(original)
                else:
                    report = json.loads(Path(second['path']).read_bytes())
                    report['identities'] = copy.deepcopy(first['expected_identities'])
                    report['transaction']['slot'] += 1
                    Path(second['path']).write_text(json.dumps(report))
                second['expected_identities'] = copy.deepcopy(first['expected_identities'])
                second['sha256'] = _sha(Path(second['path']))
                with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'distinct bytes and per-case'):
                    tool.validate_manifest(manifest)

    def test_child_validates_pinned_document_despite_path_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = _cohort(Path(temporary).resolve())
            original = tool.expired.validate_report
            def swap_during_validation(report, expected):
                entry = next(row for row in manifest['expired_status_reports']
                             if row['expected_identities'] == expected)
                path = Path(entry['path'])
                pinned = path.read_bytes()
                self.assertEqual(report, json.loads(pinned))
                replacement = copy.deepcopy(report)
                replacement['clock']['now'] = 0  # Invalid B must never be read by child.
                path.write_text(json.dumps(replacement))
                try:
                    return original(report, expected)
                finally:
                    path.write_bytes(pinned)
            with patch.object(tool.expired, 'validate_report', side_effect=swap_during_validation), \
                    patch.object(tool.expired, 'verify_file', side_effect=AssertionError('must not reread')), \
                    patch.object(tool.capacity, 'verify_file', side_effect=AssertionError('must not reread')):
                self.assertTrue(tool.validate_manifest(manifest)['report_consistent'])

    def test_manifest_byte_pin_duplicate_keys_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = _cohort(root)
            path = root / 'manifest.json'
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                tool.verify_file(path, '0' * 64)
            link = root / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                tool.verify_file(link, _sha(path))
            path.write_text('{"schema":1,"schema":2}')
            with self.assertRaises(ValueError):
                tool.verify_file(path, _sha(path))
            path.write_text(json.dumps(manifest))
            original = tool.capacity.validate_report
            def mutate_manifest(*args):
                facts = original(*args)
                path.write_bytes(path.read_bytes() + b' ')
                return facts
            with patch.object(tool.capacity, 'validate_report', side_effect=mutate_manifest):
                with self.assertRaises(ValueError):
                    tool.verify_file(path, _sha(path))


def _cohort_reusable(root):
    # Every mutation scenario uses a fresh source tree.
    directory = Path(tempfile.mkdtemp(dir=root))
    return _cohort(directory)


if __name__ == '__main__':
    unittest.main()
