import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HELPER = Path(__file__).parent / 'support/prepare_v2_context.py'
spec = importlib.util.spec_from_file_location('prepare_v2_context', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class ContextTests(unittest.TestCase):
    def test_prepare_admits_fresh_certificate_and_signs_exact_action(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            private, public = base / 'private', base / 'public.json'
            context = helper.prepare(private, public)
            self.assertEqual(context['schema'], 'dynark-part5-v2-public-context-v1')
            self.assertEqual(context['synthetic_only'], True)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            self.assertEqual(set(context), {'schema', 'synthetic_only', 'circuit_id', 'package_id',
                'semantic_schema', 'profile_id', 'issuer_hash', 'root', 'not_before', 'not_after'})
            for item in private.iterdir():
                self.assertEqual(item.stat().st_mode & 0o777, 0o600)
            action = base / 'action.be'
            action.write_bytes((98765).to_bytes(32, 'big'))
            output = helper.sign(private, public, hashlib.sha256(public.read_bytes()).hexdigest(),
                action, hashlib.sha256(action.read_bytes()).hexdigest())
            inputs = json.loads(output.read_bytes())
            self.assertEqual(inputs['actionHash'], '98765')
            self.assertEqual(inputs['issuerHash'], context['issuer_hash'])
            self.assertEqual(inputs['root'], context['root'])
            self.assertEqual(len(inputs['tbs']), 656)
            self.assertEqual(len(inputs['holderSignature']), 17)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_context_and_action_substitution_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            private, public = base / 'private', base / 'public.json'
            helper.prepare(private, public)
            public_pin = hashlib.sha256(public.read_bytes()).hexdigest()
            action = base / 'action.be'
            action.write_bytes((1).to_bytes(32, 'big'))
            pin = hashlib.sha256(action.read_bytes()).hexdigest()
            action.write_bytes((2).to_bytes(32, 'big'))
            with self.assertRaises(ValueError):
                helper.sign(private, public, public_pin, action, pin)
            with self.assertRaises(ValueError):
                helper.sign(private, public, '00' * 32, action,
                    hashlib.sha256(action.read_bytes()).hexdigest())
            self.assertFalse((private / 'request-input.json').exists())

    def test_private_key_permission_or_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            private, public = base / 'private', base / 'public.json'
            helper.prepare(private, public)
            public_pin = hashlib.sha256(public.read_bytes()).hexdigest()
            key = private / 'holder.synthetic.pem'
            key.chmod(0o644)
            action = base / 'action.be'
            action.write_bytes((1).to_bytes(32, 'big'))
            with self.assertRaises(ValueError):
                helper.sign(private, public, public_pin, action,
                    hashlib.sha256(action.read_bytes()).hexdigest())
            key.chmod(0o600)
            copy = private / 'key-copy.pem'
            key.rename(copy)
            key.symlink_to(copy)
            with self.assertRaises(ValueError):
                helper.sign(private, public, public_pin, action,
                    hashlib.sha256(action.read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
