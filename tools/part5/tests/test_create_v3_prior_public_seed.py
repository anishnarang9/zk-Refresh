import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization

from tools.part5 import create_v3_prior_public_seed as tool
from tools.part5 import freeze_v3_campaign_cohort as freeze


class PriorPublicSeedTests(unittest.TestCase):
    def _layout(self, temporary):
        root = (Path(temporary) / 'repo').resolve()
        part5 = root / 'artifacts/dynark/part5'
        part5.mkdir(parents=True)
        return root, part5

    def test_creates_public_rsa_seed_parsed_by_prior_key_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, part5 = self._layout(temporary)
            output = part5 / 'synthetic-prior-rsa-public-seed.pem'
            with mock.patch.object(tool, 'PART5', part5), \
                    mock.patch.object(freeze, 'ROOT', root), \
                    mock.patch.object(freeze, 'PART5', part5):
                hashes = tool.create_seed(output)
                fingerprints, sources = freeze.prior_keys()

            raw = output.read_bytes()
            public = serialization.load_pem_public_key(raw)
            self.assertEqual(public.key_size, 2048)
            self.assertEqual(raw.count(b'-----BEGIN '), 1)
            self.assertIn(b'-----BEGIN PUBLIC KEY-----', raw)
            self.assertNotIn(b'PRIVATE KEY', raw)
            self.assertEqual(hashes['public_key_sha256'], fingerprints[0])
            self.assertEqual(hashes['pem_sha256'], sources[0]['sha256'])
            self.assertEqual([path.name for path in part5.iterdir()], [output.name])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_rejects_existing_and_symlink_outputs_without_replacing_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, part5 = self._layout(temporary)
            existing = part5 / 'existing.pem'
            existing.write_bytes(b'keep me')
            with mock.patch.object(tool, 'PART5', part5):
                with self.assertRaises(ValueError):
                    tool.create_seed(existing)
                link = part5 / 'link.pem'
                link.symlink_to(existing)
                with self.assertRaises(ValueError):
                    tool.create_seed(link)
            self.assertEqual(existing.read_bytes(), b'keep me')
            self.assertEqual(sorted(path.name for path in part5.iterdir()),
                             ['existing.pem', 'link.pem'])

    def test_rejects_outside_nested_and_non_pem_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, part5 = self._layout(temporary)
            nested = part5 / 'nested'
            nested.mkdir()
            with mock.patch.object(tool, 'PART5', part5):
                for target in (Path(temporary) / 'outside.pem',
                               nested / 'inside.pem', part5 / 'seed.der'):
                    with self.subTest(target=target), self.assertRaises(ValueError):
                        tool.create_seed(target)
            self.assertEqual(list(part5.iterdir()), [nested])

    def test_cli_prints_hashes_without_path_or_pem_contents(self):
        from contextlib import redirect_stdout
        from io import StringIO
        import sys

        with tempfile.TemporaryDirectory() as temporary:
            _, part5 = self._layout(temporary)
            output = part5 / 'synthetic-prior-rsa-public-seed.pem'
            captured = StringIO()
            with mock.patch.object(tool, 'PART5', part5), \
                    mock.patch.object(sys, 'argv', ['create_v3_prior_public_seed',
                                                    '--output', str(output)]), \
                    redirect_stdout(captured):
                tool.main()
            report = json.loads(captured.getvalue())
            self.assertEqual(set(report), {'pem_sha256', 'public_key_sha256'})
            for digest in report.values():
                self.assertRegex(digest, r'^[0-9a-f]{64}$')
            self.assertNotIn(str(output), captured.getvalue())
            self.assertNotIn('BEGIN PUBLIC KEY', captured.getvalue())

    def test_help_identifies_synthetic_control_not_prior_credential(self):
        import subprocess
        import sys

        script = Path(tool.__file__).resolve()
        result = subprocess.run([sys.executable, '-B', str(script), '--help'],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('synthetic prior-key control', result.stdout)
        self.assertIn('not a prior credential', result.stdout)


if __name__ == '__main__':
    unittest.main()
