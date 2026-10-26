import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('diagnostic',Path(__file__).with_name('queue_v2_replay_diagnostic.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class DiagnosticContract(unittest.TestCase):
    def test_only_observational_rpc_methods(self):
        for method in ('getGenesisHash','getSlot','getMultipleAccounts'):
            self.assertEqual(m.rpc_item(1,method,[])['method'],method)
        for method in ('sendTransaction','requestAirdrop','simulateTransaction'):
            with self.assertRaises(ValueError):m.rpc_item(1,method,[])
    def test_inventory_rejects_symlinks_and_accounts_for_all_regular_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'genesis.bin').write_bytes(b'abc');(p/'validator.log').symlink_to('genesis.bin')
            records,total=m.inventory(p)
            self.assertEqual(total,3);self.assertEqual(set(records),{'genesis.bin'})
            (p/'escape').symlink_to('/tmp')
            with self.assertRaises(ValueError):m.inventory(p)
    def test_restart_arguments_cannot_reset_or_reload(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'genesis.bin').write_bytes(b'x')
            argv=m.s.validator_argv('/validator',p,'/unused','execute')
            for forbidden in ('--reset','--bpf-program','--mint','--clone','--url'):
                self.assertNotIn(forbidden,argv)
    def test_account_hashes_require_expected_owner_and_bytes(self):
        import base64,hashlib
        target={'owner':'program','sha256':hashlib.sha256(b'abc').hexdigest(),'length':3}
        v={'data':[base64.b64encode(b'abc').decode(),'base64'],'owner':'program','executable':False,'lamports':1}
        self.assertTrue(m.account_record(v,target)['matches_expected'])
        v['owner']='other';self.assertFalse(m.account_record(v,target)['matches_expected'])
        self.assertEqual(m.account_record(None,target),{'present':False})
if __name__=='__main__':unittest.main()
