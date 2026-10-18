import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.part5 import export_v3_campaign_public_projection as exporter
from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5.tests.test_export_v3_campaign_public_projection import synthetic_inputs

try:
    from tools.part5 import verify_v3_campaign_public_projection as verifier
except ImportError:
    verifier = None


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _public_bundle(root, campaign_id='training-010'):
    manifest, validated, plan = synthetic_inputs(campaign_id)
    manifest['limits']['1']['anchor']['runtime_seconds'] = 2400
    validated['limits'] = manifest['limits']
    validated['manifest_sha256'] = hashlib.sha256(
        matrix.canonical_json(manifest)).hexdigest()
    plan['manifest_sha256'] = validated['manifest_sha256']
    for slot in plan['slots']:
        slot['limits'] = manifest['limits'][str(slot['target_count'])][slot['mode']]
    manifest_path = root / 'private-manifest.json'
    plan_path = root / 'private-plan.json'
    manifest_path.write_bytes((json.dumps(manifest, sort_keys=True) + '\n').encode())
    plan_path.write_bytes((json.dumps(plan, sort_keys=True) + '\n').encode())
    output = root / 'projection'
    with mock.patch.object(exporter.matrix, 'validate_manifest', return_value=validated), \
            mock.patch.object(exporter.matrix, 'plan_slots', return_value=plan['slots']):
        exporter.export_public_projection(manifest_path, plan_path, output)
    return output


def _read_json(path):
    return json.loads(path.read_bytes())


def _write_json(path, value):
    path.write_bytes(_canonical(value))


def _rehash_public(index, root, kind):
    name = 'matrix-manifest.json' if kind == 'matrix_manifest' else 'matrix-plan.json'
    index['public_files'][kind]['sha256'] = _sha((root / name).read_bytes())
    _write_json(root / 'index.json', index)


class PublicCampaignProjectionVerificationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(verifier, 'public projection verifier module is required')

    def test_verifies_exported_path_free_manifest_and_registered_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())

            result = verifier.verify_bundle(root)

            self.assertEqual(result['status'], 'verified')
            self.assertEqual(result['campaign_id'], 'training-010')
            self.assertEqual(result['slot_count'], 60)
            self.assertTrue(result['canonical_manifest_digest_consistent'])
            self.assertEqual(result['scope'], verifier.SCOPE)
            text = ''.join(path.read_text(encoding='utf-8')
                           for path in root.iterdir() if path.is_file())
            for private in ('/Users/', 'alice', 'SECRET', 'TOKEN', 'outer_argv',
                            'clone_argv', 'output_root', 'owner', 'paths'):
                self.assertNotIn(private, text)

    def test_rejects_extra_entries_and_symlink_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            (root / 'extra.json').write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'unexpected projection entries'):
                verifier.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            plan = root / 'matrix-plan.json'
            target = root / 'matrix-manifest.json'
            plan.unlink()
            plan.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'regular non-symlink'):
                verifier.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            root = root.parent / 'projection-link'
            root.symlink_to(root.parent / 'projection')
            with self.assertRaisesRegex(ValueError, 'real directory'):
                verifier.verify_bundle(root)

    def test_rejects_byte_tampering_and_unknown_index_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            path = root / 'matrix-plan.json'
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'byte hash mismatch'):
                verifier.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            index_path = root / 'index.json'
            index = _read_json(index_path)
            index['local_path'] = '/Users/private'
            _write_json(index_path, index)
            with self.assertRaisesRegex(ValueError, 'unknown index fields'):
                verifier.verify_bundle(root)

    def test_rejects_unknown_projection_fields_even_when_hashes_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            index = _read_json(root / 'index.json')
            document = _read_json(root / 'matrix-manifest.json')
            document['local_path'] = '/Users/private'
            _write_json(root / 'matrix-manifest.json', document)
            _rehash_public(index, root, 'matrix_manifest')
            with self.assertRaisesRegex(ValueError, 'unknown public manifest fields'):
                verifier.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            index = _read_json(root / 'index.json')
            document = _read_json(root / 'matrix-plan.json')
            document['slots'][0]['owner'] = 'private-owner'
            _write_json(root / 'matrix-plan.json', document)
            _rehash_public(index, root, 'matrix_plan')
            with self.assertRaisesRegex(ValueError, 'unknown plan slot fields'):
                verifier.verify_bundle(root)

    def test_rejects_manifest_digest_mismatch_and_bad_tool_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            index = _read_json(root / 'index.json')
            manifest = _read_json(root / 'matrix-manifest.json')
            manifest['matrix_manifest_canonical_sha256'] = 'e' * 64
            _write_json(root / 'matrix-manifest.json', manifest)
            _rehash_public(index, root, 'matrix_manifest')
            with self.assertRaisesRegex(ValueError, 'canonical manifest digest'):
                verifier.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            index = _read_json(root / 'index.json')
            manifest = _read_json(root / 'matrix-manifest.json')
            manifest['tool_pins']['unexpected_tool'] = {'sha256': 'f' * 64}
            _write_json(root / 'matrix-manifest.json', manifest)
            _rehash_public(index, root, 'matrix_manifest')
            with self.assertRaisesRegex(ValueError, 'tool pin allowlist'):
                verifier.verify_bundle(root)

    def test_rejects_grid_or_limit_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            index = _read_json(root / 'index.json')
            plan = _read_json(root / 'matrix-plan.json')
            plan['slots'][0]['target_count'] = 1
            _write_json(root / 'matrix-plan.json', plan)
            _rehash_public(index, root, 'matrix_plan')
            with self.assertRaisesRegex(ValueError, 'registered grid'):
                verifier.verify_bundle(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            index = _read_json(root / 'index.json')
            manifest = _read_json(root / 'matrix-manifest.json')
            manifest['limits']['1']['anchor']['runtime_seconds'] = 1
            _write_json(root / 'matrix-manifest.json', manifest)
            _rehash_public(index, root, 'matrix_manifest')
            with self.assertRaisesRegex(ValueError, 'Anchor k=1'):
                verifier.verify_bundle(root)

    def test_training011_uses_its_registered_tool_pin_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve(), 'training-011')
            result = verifier.verify_bundle(root)
            self.assertEqual(result['campaign_id'], 'training-011')
            self.assertEqual(result['slot_count'], 60)

    def test_cli_prints_narrow_verification_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _public_bundle(Path(temporary).resolve())
            script = Path(verifier.__file__).resolve()
            result = subprocess.run([sys.executable, '-B', str(script), str(root)],
                                    capture_output=True, text=True, check=False)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(verifier.SCOPE, result.stdout)
            self.assertIn('raw private manifest', result.stdout)


if __name__ == '__main__':
    unittest.main()
