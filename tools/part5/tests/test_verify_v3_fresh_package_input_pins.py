"""Synthetic record verification only; no compiler, witness, setup, or proof jobs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import verify_v3_fresh_package_input_pins as tool


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _record():
    return dict(schema=tool.SCHEMA, source_commit='a' * 40,
                toolchain=dict(circom_version='2.2.3', node_version='v22.14.0',
                               rustc_version='1.90.0', cargo_version='1.90.0',
                               circom_binary_sha256='b' * 64),
                semantic_hashes=dict(tool.SEMANTIC_HASHES), census=dict(tool.CENSUS),
                ordered_public_inputs=list(tool.PUBLIC_INPUTS),
                reviewed_suite=dict(report_sha256='c' * 64, total_count=52,
                                    accepted_count=18, rejected_count=34), public_repo_files=[])


def _write(root, record):
    path = root / 'pins.json'
    raw = json.dumps(record, sort_keys=True).encode()
    path.write_bytes(raw)
    return path, _sha(raw)


class FreshInputPinsTests(unittest.TestCase):
    def test_success_empty_and_current_public_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            record = _record()
            path, digest = _write(root, record)
            result = tool.verify_file(path, digest, repo_root=root)
            self.assertTrue(result['input_record_consistent'])
            self.assertFalse(result['clean_checkout_reproduction_established'])
            self.assertFalse(result['setup_or_proofs_executed'])
            self.assertNotIn(temporary, json.dumps(result))
            source = root / 'circuits/credential-v3-bounded/credential.circom'
            source.parent.mkdir(parents=True)
            source.write_bytes(b'pragma circom 2.2.3;')
            record['public_repo_files'] = [{'path': str(source.relative_to(root)), 'sha256': _sha(source.read_bytes())}]
            path, digest = _write(root, record)
            self.assertEqual(tool.verify_file(path, digest, repo_root=root)['public_source_file_count'], 1)
            source.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'source digest'):
                tool.verify_file(path, digest, repo_root=root)

    def test_strict_schema_and_counts_after_rehash(self):
        mutations = [lambda r: r.update(private_path='/PRIVATE/SECRET'),
                     lambda r: r.update(schema='v1'),
                     lambda r: r.update(source_commit='A' * 40),
                     lambda r: r.update(source_commit='/Users/private'),
                     lambda r: r['toolchain'].update(node_version='/usr/bin/node'),
                     lambda r: r['toolchain'].update(rustc_version=True),
                     lambda r: r['toolchain'].update(circom_binary_sha256='A' * 64),
                     lambda r: r['toolchain'].update(secret='private-key'),
                     lambda r: r['semantic_hashes'].update(r1cs_sha256='d' * 64),
                     lambda r: r['semantic_hashes'].update(profile_sha256='d' * 64),
                     lambda r: r['census'].update(constraints=True),
                     lambda r: r['census'].update(matrix_entries=1),
                     lambda r: r['ordered_public_inputs'].reverse(),
                     lambda r: r['reviewed_suite'].update(total_count=51),
                     lambda r: r['reviewed_suite'].update(accepted_count=19),
                     lambda r: r['reviewed_suite'].update(rejected_count=True),
                     lambda r: r['reviewed_suite'].update(report_sha256='not-a-hash'),
                     lambda r: r['reviewed_suite'].update(witness_path='/private/witness'),
                     lambda r: r.update(public_repo_files={})]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    record = _record()
                    mutate(record)
                    path, digest = _write(root, record)
                    with self.assertRaises(ValueError):
                        tool.verify_file(path, digest, repo_root=root)

    def test_external_hash_strict_json_caps_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path, digest = _write(root, _record())
            with self.assertRaisesRegex(ValueError, 'byte digest'):
                tool.verify_file(path, '0' * 64, repo_root=root)
            link = root / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                tool.verify_file(link, digest, repo_root=root)
            for raw in (b'{"schema":1,"schema":2}', b'{"schema":NaN}', b'{"schema":1e999}'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    tool.verify_file(path, _sha(raw), repo_root=root)
            path.write_bytes(b'x' * (tool.MAX_RECORD_BYTES + 1))
            with self.assertRaises(ValueError):
                tool.verify_file(path, _sha(path.read_bytes()), repo_root=root)

    def test_private_traversal_duplicate_and_mismatched_source_refs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ('../secret.rs', '/private/key.rs', 'artifacts/witness.wtns',
                         'circuits/credential-v3-bounded/private.json', '.git/config',
                         'tools/part5/../secret.py'):
                record = _record()
                record['public_repo_files'] = [{'path': name, 'sha256': 'a' * 64}]
                path, digest = _write(root, record)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    tool.verify_file(path, digest, repo_root=root)
            record = _record()
            record['public_repo_files'] = [{'path': 'circuits/credential-v3-bounded/profile.json', 'sha256': 'a' * 64}]
            path, digest = _write(root, record)
            with self.assertRaisesRegex(ValueError, 'profile reference'):
                tool.verify_file(path, digest, repo_root=root)
            source = root / 'tools/part5/public.py'
            source.parent.mkdir(parents=True)
            source.write_bytes(b'public')
            ref = {'path': 'tools/part5/public.py', 'sha256': _sha(b'public')}
            record['public_repo_files'] = [ref, copy.deepcopy(ref)]
            path, digest = _write(root, record)
            with self.assertRaisesRegex(ValueError, 'sorted and distinct'):
                tool.verify_file(path, digest, repo_root=root)

    def test_rechecks_record_and_source_mutations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'tools/part5/public.py'
            source.parent.mkdir(parents=True)
            source.write_bytes(b'public')
            record = _record()
            record['public_repo_files'] = [{'path': 'tools/part5/public.py', 'sha256': _sha(b'public')}]
            original = tool._read
            for mutate_record in (True, False):
                source.write_bytes(b'public')
                path, digest = _write(root, record)
                calls = 0
                def change_after_first_source_read(current, cap):
                    nonlocal calls
                    raw = original(current, cap)
                    calls += 1
                    if calls == 2:
                        target = path if mutate_record else source
                        target.write_bytes(target.read_bytes() + b' ')
                    return raw
                with self.subTest(record=mutate_record), patch.object(tool, '_read', side_effect=change_after_first_source_read):
                    with self.assertRaises(ValueError):
                        tool.verify_file(path, digest, repo_root=root)

    def test_fifo_never_blocks_and_cli_redacts_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            result = subprocess.run([sys.executable, tool.__file__, str(fifo), '--expected-raw-sha256', 'a' * 64],
                                    cwd=tool.REPO, capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(temporary, result.stderr)
            path, digest = _write(root, {**_record(), 'SECRET': '/private/TOKEN'})
            result = subprocess.run([sys.executable, tool.__file__, str(path), '--expected-raw-sha256', digest],
                                    cwd=tool.REPO, capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            for private in (temporary, 'SECRET', 'TOKEN'):
                self.assertNotIn(private, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
