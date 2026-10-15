"""Lightweight binary-format and canonical serialization regression checks."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

from tools.part5 import corpus
from tools.part5.credential_profile import FR

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT/'tools/part5/witness_check.py'
spec = importlib.util.spec_from_file_location('v3_witness_check',CHECKER)
q = importlib.util.module_from_spec(spec)
if CHECKER.exists(): spec.loader.exec_module(q)

class QualificationTests(unittest.TestCase):
    def test_canonical_json_roundtrip_preserves_large_fields(self):
        self.assertTrue(hasattr(corpus,'canonical_strings'),'canonical scalar serialization missing')
        inputs = {'root':FR-1,'small':7,'array':[0,1 << 200]}
        encoded = corpus.canonical_strings(inputs)
        self.assertEqual(json.loads(json.dumps(encoded)),{'root':str(FR-1),'small':'7','array':['0',str(1 << 200)]})
        for invalid in (-1,FR,True,0.1,'1'):
            with self.assertRaises(ValueError): corpus.canonical_strings({'field':invalid})

    def test_private_corpus_files_are_strings_and_mode_600(self):
        self.assertTrue(hasattr(corpus,'write_corpus'),'protected corpus writer missing')
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'private'
            corpus.write_corpus(output,[dict(name='sample',expect='accept',family='test',inputs={'root':FR-1})])
            self.assertEqual(json.loads((output/'sample.input.json').read_text()),{'root':str(FR-1)})
            self.assertEqual(output.stat().st_mode & 0o777,0o700)
            for file in output.iterdir(): self.assertEqual(file.stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError): corpus.write_corpus(output,[])

    @staticmethod
    def sectioned(magic,version,sections):
        return magic+struct.pack('<II',version,len(sections))+b''.join(struct.pack('<IQ',kind,len(data))+data for kind,data in sections)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.r1cs = Path(self.directory.name)/'toy.r1cs'
        self.wtns = Path(self.directory.name)/'toy.wtns'
        self.values = [1,9,2,3,4,5,6,3]
        self.public = self.values[1:7]
        header = struct.pack('<I',32)+FR.to_bytes(32,'little')+struct.pack('<IIIIQI',8,0,6,1,8,1)
        term = lambda index: struct.pack('<II',1,index)+(1).to_bytes(32,'little')
        self.r1cs.write_bytes(self.sectioned(b'r1cs',1,[(1,header),(2,term(7)+term(7)+term(1))]))
        self.write_witness()

    def write_witness(self):
        header = struct.pack('<I',32)+FR.to_bytes(32,'little')+struct.pack('<I',len(self.values))
        self.wtns.write_bytes(self.sectioned(b'wtns',2,[(1,header),(2,b''.join(x.to_bytes(32,'little') for x in self.values))]))

    def test_complete_six_field_satisfaction(self):
        self.assertTrue(CHECKER.exists(),'six-field witness checker missing')
        report=q.check_witness(self.r1cs,self.wtns,self.public)
        self.assertTrue(report['satisfied'])
        self.assertEqual(report['constraints_checked'],1)

    def test_wrong_policy_public_unsatisfied_and_noncanonical(self):
        self.assertTrue(CHECKER.exists(),'six-field witness checker missing')
        for statement in (self.public[:5],self.public[:5]+[7]):
            with self.assertRaisesRegex(ValueError,'public statement'):
                q.check_witness(self.r1cs,self.wtns,statement)
        for at,value in ((7,4),(7,FR),(0,0)):
            saved=self.values[:]
            self.values[at]=value
            self.write_witness()
            with self.assertRaises(ValueError): q.check_witness(self.r1cs,self.wtns,self.public)
            self.values=saved

    def test_trailing_bytes_rejected(self):
        self.assertTrue(CHECKER.exists(),'six-field witness checker missing')
        self.wtns.write_bytes(self.wtns.read_bytes()+b'\x00')
        with self.assertRaises(ValueError): q.check_witness(self.r1cs,self.wtns,self.public)

if __name__=='__main__': unittest.main()
