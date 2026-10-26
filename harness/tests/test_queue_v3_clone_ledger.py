import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


source = Path(__file__).with_name('queue_v3_clone_ledger.py')
spec = importlib.util.spec_from_file_location('v3_clone', source)
clone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clone)


class LedgerInventoryTest(unittest.TestCase):
    def test_owner_only_internal_link_and_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary).resolve() / 'ledger'
            ledger.mkdir(mode=0o700)
            file = ledger / 'genesis.bin'
            descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(b'genesis')
            (ledger / 'current').symlink_to('genesis.bin')
            original = clone.inventory(ledger)
            self.assertEqual(len(original), 2)
            file.write_bytes(b'changed')
            self.assertNotEqual(original, clone.inventory(ledger))
            (ledger / 'outside').symlink_to('../outside')
            with self.assertRaises(ValueError):
                clone.inventory(ledger)


if __name__ == '__main__':
    unittest.main()
