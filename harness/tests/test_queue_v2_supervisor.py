import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('queue_supervisor',Path(__file__).with_name('queue_v2_supervisor.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ContractTests(unittest.TestCase):
    def test_prepare_refuses_existing_ledger_and_execute_requires_existing_genesis(self):
        with tempfile.TemporaryDirectory() as d:
            ledger=Path(d)/'ledger'
            m.check_ledger('prepare',ledger)
            with self.assertRaises(ValueError):m.check_ledger('execute',ledger)
            ledger.mkdir()
            with self.assertRaises(ValueError):m.check_ledger('prepare',ledger)
            (ledger/'genesis.bin').write_bytes(b'local')
            m.check_ledger('execute',ledger)
    def test_reset_only_in_initial_prepare_and_genesis_load_not_repeated_on_restart(self):
        with tempfile.TemporaryDirectory() as d:
            ledger=Path(d)/'ledger';a=m.validator_argv('/validator',ledger,'/reviewed.so','prepare')
            self.assertIn('--reset',a);self.assertIn('--bpf-program',a)
            ledger.mkdir();(ledger/'genesis.bin').write_bytes(b'local')
            a=m.validator_argv('/validator',ledger,'/reviewed.so','execute')
            self.assertNotIn('--reset',a);self.assertNotIn('--bpf-program',a)
    def test_builder_uses_offline_locked_separate_output_and_installed_tools(self):
        a=m.build_argv('/builder','/new/elf')
        self.assertIn('--offline',a);self.assertIn('--skip-tools-install',a);self.assertEqual(a[-2:],['--','--locked'])
        self.assertEqual(a[a.index('--sbf-out-dir')+1],'/new/elf')
        self.assertEqual(a[a.index('--manifest-path')+1],str(m.REPO/'program/Cargo.toml'))
    def test_stack_warnings_in_either_stream_fail_build_admission(self):
        self.assertFalse(m.stack_diagnostic('Finished release build',''))
        for text in ['Stack offset of 8192 exceeded max offset of 4096', 'stack frame size exceeds limit']:
            self.assertTrue(m.stack_diagnostic(text,''))
            self.assertTrue(m.stack_diagnostic('',text))
    def test_output_rejects_legacy_paths_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)/'allowed';base.mkdir();outside=Path(d)/'outside';outside.mkdir();(base/'escape').symlink_to(outside,target_is_directory=True)
            m.under(base/'good',base)
            for p in [outside/'x',base/'escape'/'x',Path('relative')]:
                with self.assertRaises(ValueError):m.under(p,base)
if __name__=='__main__':unittest.main()
