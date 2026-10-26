import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import generate_v3_heldout_keys as tool


class HeldoutKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.freeze = self.root / 'freeze.json'
        self.output = self.root / 'cohort'
        self.boundary = dict(schema=tool.FREEZE_SCHEMA, frozen_at_unix_ns=100,
            issuance_tool_sha256=tool.file_sha(tool.ISSUANCE_TOOL),
            key_generation_tool_sha256=tool.file_sha(Path(tool.__file__)),
            identities={name: 'a' * 64 for name in tool.IDENTITY_ROLES},
            forbidden_public_key_sha256=['f' * 64])

    def save(self):
        self.freeze.write_text(json.dumps(self.boundary))
        self.freeze.chmod(0o600)
        return hashlib.sha256(self.freeze.read_bytes()).hexdigest()

    def key(self, index):
        key = mock.Mock(spec=rsa.RSAPrivateKey)
        key.key_size = 2048
        key.public_key.return_value.public_numbers.return_value.e = 65537
        key.public_key.return_value.public_numbers.return_value.n = (1 << 2047) + index
        key.public_key.return_value.public_bytes.return_value = b'public-' + str(index).encode()
        key.private_bytes.return_value = b'PRIVATE TEST KEY ' + str(index).encode()
        return key

    def generate(self, keys=None, expected=None):
        digest = self.save()
        with mock.patch.object(tool, '_ignored', return_value=True), \
             mock.patch.object(tool.time, 'time_ns', side_effect=range(200, 500)), \
             mock.patch.object(tool, '_new_key', side_effect=keys or [self.key(i) for i in range(12)]) as gen:
            receipt = tool.generate(self.freeze, expected or digest, self.output)
        return receipt, gen

    def test_fresh_generation_has_four_issuers_eight_holders_and_scrubbed_receipt(self):
        receipt, gen = self.generate()
        self.assertEqual(gen.call_count, 12)
        self.assertEqual(receipt['counts'], {'issuers': 4, 'holders': 8})
        self.assertEqual(len(set(row['public_key_sha256'] for row in receipt['keys'])), 12)
        self.assertGreater(receipt['generation_started_unix_ns'], 100)
        self.assertGreater(receipt['generation_completed_unix_ns'], receipt['generation_started_unix_ns'])
        self.assertEqual(receipt['freeze_receipt_sha256'], tool.file_sha(self.freeze))
        self.assertEqual(receipt['identities'], self.boundary['identities'])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(list(self.output.glob('issuer-*.pem'))), 4)
        self.assertEqual(len(list(self.output.glob('holder-*.pem'))), 8)
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        raw = json.dumps(receipt)
        for forbidden in ('PRIVATE TEST KEY', str(self.root), '.pem'):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(json.loads((self.output / 'key-generation-receipt.json').read_text()), receipt)

    def test_freeze_failures_precede_any_key_generation(self):
        changes = [('schema', 'wrong'), ('frozen_at_unix_ns', 300),
                   ('frozen_at_unix_ns', True), ('issuance_tool_sha256', '0' * 64),
                   ('key_generation_tool_sha256', '0' * 64), ('identities', {}),
                   ('forbidden_public_key_sha256', []), ('extra', 'field')]
        for name, value in changes:
            original = dict(self.boundary)
            self.boundary[name] = value
            with self.subTest(name=name), mock.patch.object(tool, '_new_key') as gen, \
                 self.assertRaises(ValueError):
                self.generate()
            gen.assert_not_called()
            self.assertFalse(self.output.exists())
            self.boundary = original

    def test_exact_freeze_digest_and_duplicate_json_fields_rejected(self):
        with self.assertRaises(ValueError):
            self.generate(expected='0' * 64)
        self.freeze.write_text('{"schema":1,"schema":2}')
        with mock.patch.object(tool, '_new_key') as gen, self.assertRaises(ValueError):
            tool.generate(self.freeze, tool.file_sha(self.freeze), self.output)
        gen.assert_not_called()

    def test_duplicate_reused_and_nonprofile_keys_never_publish(self):
        reused = hashlib.sha256(b'public-0').hexdigest()
        for kind in ('duplicate', 'reused', 'bits', 'exponent'):
            keys = [self.key(i) for i in range(12)]
            if kind == 'duplicate':
                keys[-1] = keys[0]
            elif kind == 'reused':
                self.boundary['forbidden_public_key_sha256'] = [reused]
            elif kind == 'bits':
                keys[0].key_size = 1024
            else:
                keys[0].public_key.return_value.public_numbers.return_value.e = 3
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.generate(keys)
            self.assertFalse(self.output.exists())
            self.boundary['forbidden_public_key_sha256'] = ['f' * 64]

    def test_private_and_fresh_ignored_output_boundaries(self):
        digest = self.save()
        with mock.patch.object(tool, '_new_key') as gen:
            self.freeze.chmod(0o644)
            with self.assertRaises(ValueError):
                tool.generate(self.freeze, digest, self.output)
            self.freeze.chmod(0o600)
            with mock.patch.object(tool, '_ignored', return_value=False), self.assertRaises(ValueError):
                tool.generate(self.freeze, digest, self.output)
            self.output.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                tool.generate(self.freeze, digest, self.output)
            gen.assert_not_called()

    def test_symlink_and_hardlinked_freeze_reject_before_generation(self):
        digest = self.save()
        alias = self.root / 'alias.json'
        for kind in ('symlink', 'hardlink'):
            if kind == 'symlink':
                alias.symlink_to(self.freeze)
            else:
                os.link(self.freeze, alias)
            with self.subTest(kind=kind), mock.patch.object(tool, '_new_key') as gen, \
                 self.assertRaises((ValueError, OSError)):
                tool.generate(alias, digest, self.output)
            gen.assert_not_called()
            alias.unlink()

    def test_partial_write_failure_removes_only_own_new_output(self):
        real_write = tool.issuance._write
        calls = 0
        def fail_second(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('mock write failure')
            return real_write(*args)
        with mock.patch.object(tool.issuance, '_write', side_effect=fail_second), self.assertRaises(OSError):
            self.generate()
        self.assertFalse(self.output.exists())
        self.assertTrue(self.freeze.exists())

    def test_key_backend_profile_and_cli_are_scrubbed(self):
        with mock.patch.object(tool.rsa, 'generate_private_key', return_value='mock-key') as gen:
            self.assertEqual(tool._new_key(), 'mock-key')
        gen.assert_called_once_with(public_exponent=65537, key_size=2048)
        receipt, _ = self.generate()
        argv = ['generator', '--freeze', str(self.freeze), '--freeze-sha256', tool.file_sha(self.freeze),
                '--output', str(self.output)]
        stdout = io.StringIO()
        with mock.patch.object(tool.sys, 'argv', argv), \
             mock.patch.object(tool, 'generate', return_value=receipt), contextlib.redirect_stdout(stdout):
            tool.main()
        self.assertEqual(json.loads(stdout.getvalue()), receipt)
        self.assertNotIn(str(self.root), stdout.getvalue())
        with mock.patch.object(tool.sys, 'argv', argv), \
             mock.patch.object(tool, 'generate', side_effect=OSError('secret ' + str(self.root))), \
             self.assertRaises(SystemExit) as failure:
            tool.main()
        self.assertEqual(str(failure.exception), 'heldout key generation rejected')


if __name__ == '__main__':
    unittest.main()
