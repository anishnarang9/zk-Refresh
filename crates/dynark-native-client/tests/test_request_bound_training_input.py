"""Small training-input tests; no WTNS, setup, proof or validator execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import prepare_v3_request_fixture as bridge
from tools.part5.tests.test_v3_rust_request_join import development_config

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / 'crates/dynark-native-client/tests/support/prepare_v3_request_bound_training.py'
EXPORTER = ROOT / 'program/target/debug/examples/export_v3_request_fixture'


def load_helper():
    spec = importlib.util.spec_from_file_location('request_bound_training', HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RequestBoundTrainingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name).resolve()
        cls.root.chmod(0o700)
        cls.source = cls.root / 'source'
        cls.source.mkdir(mode=0o700)
        fixture = bridge.prepare(cls.source)
        cls.der = fixture['credential_der'].read_bytes()
        cls.modulus = fixture['issuer_modulus']
        cls.membership = bridge.build_membership(cls.der, cls.modulus)
        cls.config = development_config(cls.membership['active_root'], cls.membership['policy_hash'])
        cls.parameters = dict(program_id='14' * 32, genesis=cls.config[104:136].hex(),
                              creator='15' * 32, nonce='16' * 32, recipient='17' * 32,
                              request_type=1, deadline=1792109040, now=1792108800,
                              payload='00010203',
                              exporter_sha256=hashlib.sha256(EXPORTER.read_bytes()).hexdigest())
        for name, data in [('issuer-modulus.bin', cls.modulus.to_bytes(256, 'big')),
                           ('membership.json', json.dumps(cls.membership).encode()),
                           ('config.bin', cls.config),
                           ('parameters.json', json.dumps(cls.parameters).encode())]:
            cls.put(name, data)

    @classmethod
    def put(cls, name, data):
        path = cls.source / name
        path.write_bytes(data)
        path.chmod(0o600)

    def output(self):
        path = Path(tempfile.mkdtemp(dir=self.root))
        path.chmod(0o700)
        return path

    def prepare(self, output=None):
        return self.helper.prepare(self.source, output or self.output(), EXPORTER)

    def test_exact_rust_request_worker_and_witness_input_outputs(self):
        out = self.output()
        stdout, stderr = io.StringIO(), io.StringIO()
        worker = self.helper.load_worker()
        with (contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr),
              patch.object(self.helper, 'load_worker', return_value=worker),
              patch.object(worker, 'build', wraps=worker.build) as build):
            receipt = self.prepare(out)
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ('', ''))
        expected = {'request.bin', 'summary.bin', 'input.json', 'public.json',
                    'input-coordinates.bin', 'internal-coordinate.bin', 'training-receipt.json'}
        self.assertEqual({p.name for p in out.iterdir()}, expected)
        for path in out.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        q1 = (out / 'request.bin').read_bytes()
        build.assert_called_once_with(q1)
        self.assertEqual(len(q1), 1918)
        self.assertEqual(q1[4:956], self.der)
        inputs = json.loads((out / 'input.json').read_bytes())
        publics = json.loads((out / 'public.json').read_bytes())
        self.assertEqual(publics, [inputs[k] for k in
                                  ('root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash')])
        self.assertEqual(int(inputs['actionHash']), int.from_bytes(q1[1212:1244], 'big'))
        self.assertEqual(len((out / 'summary.bin').read_bytes()), 459)
        self.assertEqual(len((out / 'input-coordinates.bin').read_bytes()), 3004)
        self.assertEqual(len((out / 'internal-coordinate.bin').read_bytes()), 4)
        self.assertFalse(receipt['proof_created'])
        self.assertFalse(receipt['live_state_authenticated'])
        self.assertEqual(receipt['exporter_sha256'], self.parameters['exporter_sha256'])
        for name in ('request.bin', 'input.json', 'public.json'):
            self.assertEqual(receipt['artifact_sha256'][name],
                             hashlib.sha256((out / name).read_bytes()).hexdigest())
        self.assertNotIn('source', json.dumps(receipt))
        self.assertNotIn('PRIVATE KEY', json.dumps(receipt))
        self.assertFalse((out / 'output.wtns').exists())

    def test_source_bounds_modes_and_hardlinks_reject_before_exporter(self):
        originals = {name: (self.source / name).read_bytes() for name in
                     ('credential.der', 'holder.pem', 'issuer-modulus.bin', 'config.bin',
                      'membership.json', 'parameters.json')}
        for name, data in originals.items():
            path = self.source / name
            try:
                for invalid in (b'', data + b'x' * 16385):
                    self.put(name, invalid)
                    out = self.output()
                    with (self.subTest(name=name, case='bounds'),
                          patch.object(bridge, 'finalize_v3p1') as finalize,
                          self.assertRaises(ValueError)):
                        self.prepare(out)
                    finalize.assert_not_called()
                    self.assertEqual(list(out.iterdir()), [])
                self.put(name, data)
                path.chmod(0o640)
                with (self.subTest(name=name, case='mode'),
                      patch.object(bridge, 'finalize_v3p1') as finalize,
                      self.assertRaises(ValueError)):
                    self.prepare()
                finalize.assert_not_called()
                path.chmod(0o600)
                alias = self.root / 'hardlink'
                os.link(path, alias)
                try:
                    with (self.subTest(name=name, case='hardlink'),
                          patch.object(bridge, 'finalize_v3p1') as finalize,
                          self.assertRaises(ValueError)):
                        self.prepare()
                    finalize.assert_not_called()
                finally:
                    alias.unlink()
            finally:
                self.put(name, data)

    def test_private_directories_required(self):
        self.source.chmod(0o750)
        try:
            with self.assertRaises(ValueError):
                self.prepare()
        finally:
            self.source.chmod(0o700)
        out = self.output()
        out.chmod(0o755)
        with self.assertRaises(ValueError):
            self.prepare(out)
        out.chmod(0o700)
        link = self.root / 'source-link'
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.helper.prepare(link, self.output(), EXPORTER)

    def test_malformed_parameters_and_duplicate_keys_reject_before_exporter(self):
        cases = [dict(self.parameters, request_type=True),
                 dict(self.parameters, request_type=65536),
                 dict(self.parameters, now=1 << 63),
                 dict(self.parameters, deadline='1792109040'),
                 dict(self.parameters, program_id='ab' * 31),
                 dict(self.parameters, payload='x1'),
                 dict(self.parameters, payload='00' * 1025),
                 dict(self.parameters, unknown=1)]
        encoded = [json.dumps(case).encode() for case in cases]
        encoded.append(json.dumps(self.parameters).encode()[:-1] + b',"now":1}')
        try:
            for data in encoded:
                self.put('parameters.json', data)
                with (self.subTest(case=encoded.index(data)),
                      patch.object(bridge, 'finalize_v3p1') as finalize,
                      self.assertRaises(ValueError)):
                    self.prepare()
                finalize.assert_not_called()
        finally:
            self.put('parameters.json', json.dumps(self.parameters).encode())

    def test_cli_failure_is_silent(self):
        result = subprocess.run([os.sys.executable, str(HELPER), str(self.source)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))

    def test_explicit_genesis_and_exporter_pin_required(self):
        try:
            for key in ('genesis', 'program_id', 'exporter_sha256', 'nonce', 'now'):
                changed = dict(self.parameters)
                del changed[key]
                self.put('parameters.json', json.dumps(changed).encode())
                out = self.output()
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    self.prepare(out)
                self.assertEqual(list(out.iterdir()), [])
            for key in ('genesis', 'exporter_sha256'):
                changed = dict(self.parameters)
                changed[key] = 'ff' * 32
                self.put('parameters.json', json.dumps(changed).encode())
                with self.subTest(changed=key), self.assertRaises(ValueError):
                    self.prepare()
        finally:
            self.put('parameters.json', json.dumps(self.parameters).encode())

    def test_private_modes_links_and_nonempty_output_fail_closed(self):
        key = self.source / 'holder.pem'
        key.chmod(0o644)
        try:
            with self.assertRaises(ValueError):
                self.prepare()
        finally:
            key.chmod(0o600)
        original = key.read_bytes()
        key.unlink()
        key.symlink_to(self.source / 'credential.der')
        try:
            with self.assertRaises(ValueError):
                self.prepare()
        finally:
            key.unlink()
            self.put('holder.pem', original)
        out = self.output()
        (out / 'already').write_bytes(b'x')
        with self.assertRaises(ValueError):
            self.prepare(out)
        self.assertEqual({p.name for p in out.iterdir()}, {'already'})

    def test_persisted_membership_substitution_rejected(self):
        changed = dict(self.membership)
        changed['active_root'] += 1
        self.put('membership.json', json.dumps(changed).encode())
        out = self.output()
        try:
            with self.assertRaises(ValueError):
                self.prepare(out)
            self.assertEqual(list(out.iterdir()), [])
        finally:
            self.put('membership.json', json.dumps(self.membership).encode())

    def test_worker_public_substitution_rejected_before_outputs(self):
        worker = self.helper.load_worker()
        original = worker.build
        def changed(request):
            response = bytearray(original(request))
            response[463] ^= 1
            return bytes(response)
        worker.build = changed
        out = self.output()
        with patch.object(self.helper, 'load_worker', return_value=worker):
            with self.assertRaises(ValueError):
                self.prepare(out)
        self.assertEqual(list(out.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
