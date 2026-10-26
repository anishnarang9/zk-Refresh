import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from harness.tests import queue_v3_capacity_runtime as runtime


def encoded_signed_execute():
    key=Ed25519PrivateKey.generate()
    public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    keys=[public,bytes([2])*32,bytes([3])*32,
          runtime.execute.base.key('ComputeBudget111111111111111111111111111111')]
    data=b'\x51\x07'+bytes(448)
    message=bytes([1,0,2,4])+b''.join(keys)+bytes(32)+bytes([2])
    message+=bytes([3,0,5,2])+int(1400000).to_bytes(4,'little')
    size=len(data)
    message+=bytes([2,1,1,(size&127)|128,size>>7])+data
    signature=key.sign(message)
    return bytes([1])+signature+message,runtime.execute.base.b58(signature),runtime.execute.base.b58(keys[2]),data,[(runtime.execute.base.b58(keys[1]),False,True)]


class CapacityRuntimeTests(unittest.TestCase):
    def test_signed_execute_is_verified_and_exactly_bound(self):
        raw,signature,program,data,accounts=encoded_signed_execute()
        self.assertEqual(runtime.signed_transaction(raw,signature,program,data,accounts),data)
        with self.assertRaises(ValueError):
            runtime.signed_transaction(raw,signature,program,data[:-1],accounts)
        with self.assertRaises(ValueError):
            runtime.signed_transaction(raw,signature,program,data,[(accounts[0][0],False,False)])
        modified=bytearray(raw)
        modified[-1]^=1
        with self.assertRaises(Exception):
            runtime.signed_transaction(bytes(modified),signature,program,data,accounts)

    def test_short_vector_rejects_truncation_and_noncanonical_encoding(self):
        for raw in (b'\x80',b'\x80\x00',b'\xff\xff\xff'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                runtime.short(raw,0)

    def test_queue_rejects_duplicate_entries_and_nonzero_unused_bytes(self):
        config=runtime.execute.base.b58(bytes([7])*32)
        raw=bytearray(b'DYNQUE03'+bytes([7])*32+bytes(2050))
        self.assertEqual(runtime.queue(bytes(raw),config),[])
        raw[40:42]=(2).to_bytes(2,'big')
        raw[42:74]=raw[74:106]=bytes([8])*32
        with self.assertRaisesRegex(ValueError,'distinct'):
            runtime.queue(bytes(raw),config)
        raw[40:42]=bytes(2)
        with self.assertRaisesRegex(ValueError,'canonical'):
            runtime.queue(bytes(raw),config)


if __name__=='__main__':
    unittest.main()
