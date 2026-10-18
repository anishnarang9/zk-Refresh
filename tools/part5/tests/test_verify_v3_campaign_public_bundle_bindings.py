import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.part5 import verify_v3_campaign_public_projection as projection
from tools.part5 import verify_v3_campaign_public_receipts as receipts
from tools.part5.tests.test_verify_v3_campaign_public_projection import (
    _public_bundle, _read_json, _write_json, _rehash_public,
)
from tools.part5.tests.test_verify_v3_campaign_public_receipts import _bundle, _sha, _json_bytes

try:
    from tools.part5 import verify_v3_campaign_public_bundle_bindings as tool
except ImportError:
    tool = None


def _paired(root):
    plan_root = _public_bundle(root)
    receipt_root = _bundle(root / 'receipts')
    plan = _read_json(plan_root / 'matrix-plan.json')
    for slot in plan['slots']:
        slot['slot_identity_sha256'] = f'{slot["sequence"]:064x}'
    _write_json(plan_root / 'matrix-plan.json', plan)
    _rehash_public(_read_json(plan_root / 'index.json'), plan_root, 'matrix_plan')
    index = _read_json(receipt_root / 'index.json')
    sequence = _read_json(receipt_root / 'sequence-receipt.json')
    index['matrix_manifest_canonical_sha256'] = plan['matrix_manifest_canonical_sha256']
    sequence['manifest_sha256'] = plan['matrix_manifest_canonical_sha256']
    _save_sequence(receipt_root, index, sequence)
    (root / 'private-manifest.json').unlink()
    (root / 'private-plan.json').unlink()
    return plan_root, receipt_root


def _save_sequence(root, index, sequence):
    raw = _json_bytes(sequence)
    (root / 'sequence-receipt.json').write_bytes(raw)
    index['sequence_receipt']['sha256'] = _sha(raw)
    (root / 'index.json').write_bytes(_json_bytes(index))


class PublicBundleBindingTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(tool, 'cross-bundle verifier is required')

    def test_verifies_sixty_bindings_and_calls_independent_verifiers_first(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, chain = _paired(Path(temporary).resolve())
            with mock.patch.object(projection, 'verify_bundle', wraps=projection.verify_bundle) as p, \
                    mock.patch.object(receipts, 'verify_bundle', wraps=receipts.verify_bundle) as r:
                result = tool.verify_bundles(plan, chain)
            p.assert_called_once_with(plan)
            r.assert_called_once_with(chain)
            self.assertEqual(result['status'], 'verified')
            self.assertEqual(result['slot_count'], 60)
            self.assertEqual(result['campaign_id'], 'training-010')
            self.assertIn('cross-binding only', result['scope'])
            self.assertIn('not independently verified', result['scope'])

    def test_rejects_plan_identity_tampering_even_after_rehash(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, chain = _paired(Path(temporary).resolve())
            doc = _read_json(plan / 'matrix-plan.json')
            doc['slots'][59]['slot_identity_sha256'] = 'f' * 64
            _write_json(plan / 'matrix-plan.json', doc)
            _rehash_public(_read_json(plan / 'index.json'), plan, 'matrix_plan')
            projection.verify_bundle(plan)
            receipts.verify_bundle(chain)
            with self.assertRaisesRegex(ValueError, 'slot 60.*slot_identity_sha256'):
                tool.verify_bundles(plan, chain)

    def test_rejects_receipt_identity_tampering_after_rehashing_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, chain = _paired(Path(temporary).resolve())
            index = _read_json(chain / 'index.json')
            sequence = _read_json(chain / 'sequence-receipt.json')
            path = chain / 'slot-receipts/slot-0060.json'
            slot = _read_json(path)
            slot['slot_identity_sha256'] = 'f' * 64
            raw = _json_bytes(slot)
            path.write_bytes(raw)
            digest = _sha(raw)
            index['slot_receipts'][-1]['sha256'] = digest
            sequence['sequence'][-1]['slot_identity_sha256'] = 'f' * 64
            sequence['sequence'][-1]['slot_receipt_sha256'] = digest
            sequence['final_slot_receipt_sha256'] = digest
            _save_sequence(chain, index, sequence)
            receipts.verify_bundle(chain)
            with self.assertRaisesRegex(ValueError, 'slot 60.*slot_identity_sha256'):
                tool.verify_bundles(plan, chain)

    def test_rejects_individually_valid_different_campaign_or_manifest(self):
        for field, value in [('campaign_id', 'training-011'),
                             ('matrix_manifest_canonical_sha256', 'e' * 64)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                plan, chain = _paired(Path(temporary).resolve())
                index = _read_json(chain / 'index.json')
                sequence = _read_json(chain / 'sequence-receipt.json')
                index[field] = value
                sequence['campaign_id' if field == 'campaign_id' else 'manifest_sha256'] = value
                _save_sequence(chain, index, sequence)
                receipts.verify_bundle(chain)
                with self.assertRaisesRegex(ValueError, field):
                    tool.verify_bundles(plan, chain)

    def test_rejects_missing_unknown_fields_and_dimension_order_changes(self):
        mutations = [lambda slot: slot.pop('slot_identity_sha256'),
                     lambda slot: slot.update(extra=True),
                     lambda slot: slot.update(target_count=1),
                     lambda slot: slot.update(registered_order_position=2),
                     lambda slot: slot.update(sequence=2)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                plan, chain = _paired(Path(temporary).resolve())
                doc = _read_json(plan / 'matrix-plan.json')
                mutate(doc['slots'][0])
                _write_json(plan / 'matrix-plan.json', doc)
                _rehash_public(_read_json(plan / 'index.json'), plan, 'matrix_plan')
                with self.assertRaises(ValueError):
                    tool.verify_bundles(plan, chain)

    def test_rejects_symlink_parent_receipt_root_and_fixed_file_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            plan, chain = _paired(root)
            link = root / 'alias'
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                tool.verify_bundles(plan, link / 'receipts')
            path = plan / 'matrix-plan.json'
            raw = path.read_bytes()
            path.unlink()
            target = root / 'external.json'
            target.write_bytes(raw)
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                tool.verify_bundles(plan, chain)

    def test_rejects_file_change_between_independent_and_cross_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, chain = _paired(Path(temporary).resolve())
            original = receipts.verify_bundle
            def change_after_verify(root):
                result = original(root)
                path = plan / 'matrix-plan.json'
                path.write_bytes(path.read_bytes() + b' ')
                return result
            with mock.patch.object(receipts, 'verify_bundle', side_effect=change_after_verify):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    tool.verify_bundles(plan, chain)

    def test_standalone_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, chain = _paired(Path(temporary).resolve())
            result = subprocess.run([sys.executable, str(Path(tool.__file__)),
                                     str(plan), str(chain)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['slot_count'], 60)


if __name__ == '__main__':
    unittest.main()
