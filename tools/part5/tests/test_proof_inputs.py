import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
TARGET=ROOT/'tools/part5/prepare_proof_inputs_v1.py'
spec=importlib.util.spec_from_file_location('proof_inputs_v1',TARGET)
p=importlib.util.module_from_spec(spec)
if TARGET.exists():spec.loader.exec_module(p)

class ProofInputTests(unittest.TestCase):
    def inputs(self):
        self.assertTrue(TARGET.exists(),'proof input preparer missing')
        value={name:'1' for name in p.PUBLIC_NAMES}
        value.update(layout='0',slot='1')
        for name,n in p.ARRAYS:value[name]=['0']*n
        return value

    def test_exact_input_map_rejects_ambiguous_eliminated_or_missing_symbols(self):
        self.assertTrue(TARGET.exists(),'proof input preparer missing')
        names=p.required_symbols()
        lines=[f'{i},{i},573,{name}\n' for i,name in enumerate(names,1)]
        mapped=p.map_from_lines(lines)
        self.assertEqual(len(mapped),751)
        for bad in [lines[:-1],lines+[lines[0]],['1,-1,573,main.root\n']+lines[1:],
                    ['1,784796,573,main.root\n']+lines[1:],['1,2,573,main.root\n']+lines[1:]]:
            with self.assertRaises(ValueError):p.map_from_lines(bad)

    def test_canonical_scalars_exact_keys_and_shape(self):
        inputs=self.inputs()
        self.assertEqual(len(p.flatten_inputs(inputs)),751)
        for value in [1,'01','-1',str(p.FR)]:
            bad=dict(inputs,root=value)
            with self.assertRaises(ValueError):p.flatten_inputs(bad)
        with self.assertRaises(ValueError):p.flatten_inputs(dict(inputs,extra='0'))
        bad=dict(inputs,tbs=['0']*671)
        with self.assertRaises(ValueError):p.flatten_inputs(bad)

    def test_wtns_input_link_checks_all_coordinates_without_claiming_relation(self):
        inputs=self.inputs();flat=p.flatten_inputs(inputs)
        mapping={name:i for i,name in enumerate(p.required_symbols(),1)}
        values=[1]+[flat[name] for name in p.required_symbols()]+[0]*48
        count=len(values)
        header=b'wtns'+(2).to_bytes(4,'little')+(2).to_bytes(4,'little')+(1).to_bytes(4,'little')+(40).to_bytes(8,'little')+(32).to_bytes(4,'little')+p.FR.to_bytes(32,'little')+count.to_bytes(4,'little')+(2).to_bytes(4,'little')+(32*count).to_bytes(8,'little')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'toy.wtns'
            path.write_bytes(header+b''.join(v.to_bytes(32,'little') for v in values))
            p.verify_wtns_input_link(path,flat,mapping,expected_count=count)
            changed=dict(flat);changed['main.actionHash']+=1
            with self.assertRaises(ValueError):p.verify_wtns_input_link(path,changed,mapping,expected_count=count)
            path.write_bytes(path.read_bytes()+b'\x00')
            with self.assertRaises(ValueError):p.verify_wtns_input_link(path,flat,mapping,expected_count=count)

if __name__=='__main__':unittest.main()
