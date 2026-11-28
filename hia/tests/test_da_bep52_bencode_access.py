"""Actual frozen offline bencode value access and same-loan range projection."""
from collections import Counter
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_bep52_bencode_prefix import (
    CAP, ROOT, WORK, array, mapping, original_capture, rows, string,
)

SOURCE = ROOT / "hia/src/data_availability/bep52_bencode_access.hepta"
WITNESS = ROOT / "hia/tests/rust_da_bep52_bencode_access_reference.rs"
OUT = bytes([0x93]) * 39
NUMBER = (1 << 63) - 1


def frame(root, key, mode):
    return root + key + struct.pack(">IB", len(root), mode)


def matrix():
    # One fixed dictionary independently pins encoded selected ranges.
    root = b"d1:ai3e1:b4:notee"
    yield frame(root,b"",0), 0, (4,0,17,2)
    yield frame(root,b"a",1), 0, (2,4,7,0)
    yield frame(root,b"b",2), 0, (1,10,16,0)
    yield frame(root,b"a",3), 0, (2,4,7,3)
    yield frame(root,b"z",1), 0, (0,0,0,0)
    yield frame(root,b"z",2), 44, None
    yield frame(root,b"z",3), 44, None
    yield frame(root,b"b",3), 41, None
    yield frame(b"i9e",b"",4), 0, (2,0,3,9)
    yield frame(b"4:note",b"",5), 0, (1,2,6,0)
    yield frame(b"0:",b"",5), 0, (1,2,2,0)
    yield frame(b"li1e0:e",b"",6), 0, (3,0,7,2)
    yield frame(b"de",b"",0), 0, (4,0,2,0)
    yield frame(b"le",b"",6), 0, (3,0,2,0)
    for x, kind in ((b"0:",1),(b"i1e",2),(b"le",3),(b"de",4)):
        for mode in range(7):
            k = b"item" if mode in (1,2,3) else b""
            status = (0 if kind==4 else 40, 0 if kind==4 else 40,
                      44 if kind==4 else 40, 44 if kind==4 else 40,
                      0 if kind==2 else 41, 0 if kind==1 else 42, 0 if kind==3 else 43)[mode]
            yield frame(x,k,mode),status,None
    for n in (0,1,999,(1<<32)+2,NUMBER):
        scalar = b"i"+str(n).encode()+b"e"
        yield frame(scalar+b"inert",b"",4),0,(2,0,len(scalar),n)
        node = mapping([(b"",scalar)])
        yield frame(node,b"",3),0,(2,3,3+len(scalar),n)
    for n in (-1,-999,-(1<<63)):
        scalar = b"i"+str(n).encode()+b"e"
        yield frame(scalar,b"",4),41,None
        node = mapping([(b"v",scalar)])
        yield frame(node,b"v",3),41,None
        yield frame(node,b"v",2),0,(2,4,4+len(scalar),0)
    for i in range(24):
        k = bytes([64+i])
        w = bytes([128+i])
        samples = [(b"",b"0:"),(k,b"l0:i2ee"),(k+b"q",b"de"),(w,b"i7e")]
        x = mapping(samples)
        yield frame(x+b"extra",b"",0),0,(4,0,len(x),4)
        offset = 1
        for key,val in samples:
            a = offset + len(string(key))
            b = a + len(val)
            kind = {b"0":1,b"i":2,b"l":3,b"d":4}[val[:1]]
            yield frame(x,key,1),0,(kind,a,b,0)
            yield frame(x,key,2),0,(kind,a,b,0)
            offset = b
        yield frame(x,k+b"z",1),0,(0,0,0,0)
        yield frame(x,k+b"z",2),44,None
    for n in (1,7,126,127):
        x = array([b"le"]*n)
        yield frame(x,b"",6),0,(3,0,len(x),n)
    for root, status, _ in rows():
        if status:
            # A wrong accessor/empty key must not hide the parser's first error.
            yield frame(root,b"",3),status,None
    k = b"a"*99999
    x = mapping([(b"",b"0:"),(k,b"0:")])
    yield frame(x,k,1),0,(1,len(x)-3,len(x)-1,0)
    x = b"i7e"+b"x"*(CAP-8)
    yield frame(x,b"",4),0,(2,0,3,7)


class DaBep52BencodeAccess(unittest.TestCase):
    def test_actual_frozen_value_accessors_and_borrowed_ranges_both_stock(self):
        cases = list(matrix())
        with tempfile.TemporaryDirectory(prefix="trnm-pure-bencode-access-") as tmp:
            original, proof = original_capture(Path(tmp), [x[0] for x in cases], WITNESS)
        expectation = []
        pos = 0
        for wire, wanted, recorded in cases:
            actual = original[pos]
            pos += 1
            self.assertEqual(actual, wanted, (wire[:60],len(wire)))
            result = b""
            if not actual:
                result = original[pos:pos+32]
                kind, a, b, value = struct.unpack(">QQQQ",result)
                if recorded is not None:
                    self.assertEqual((kind,a,b,value),recorded)
                self.assertLessEqual(a,b)
                self.assertLessEqual(b,int.from_bytes(wire[-5:-1],"big"))
                pos += 32
            expectation.append((wire,OUT,WORK,actual,result,81))
        self.assertEqual(pos,len(original))
        self.assertEqual({x[3] for x in expectation},{0,*range(20,34),*range(40,45)})
        print(json.dumps(dict(proof, status_counts=Counter(x[3] for x in expectation)),
                         sort_keys=True),flush=True)
        valid = frame(b"0:",b"",5)
        controls = [(valid,OUT[:31],WORK,102,b"",0),
                    (valid,OUT,WORK[:80],102,b"",0),
                    (b"",OUT,WORK,100,b"",0),
                    (b"0:"+struct.pack(">IB",3,5),OUT,WORK,100,b"",0),
                    (frame(b"0:",b"not-a-key-mode",5),OUT,WORK,100,b"",0),
                    (frame(b"0:",b"",7),OUT,WORK,100,b"",0),
                    (valid,OUT[:32],WORK[:81],0,struct.pack(">QQQQ",1,2,2,0),81)]
        for backend in ("direct","selfhost"):
            fixture_max = CAP + (backend == "selfhost")
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend, max_input_extent=fixture_max) as n:
                group = expectation+controls
                if backend == "selfhost":
                    group += [(b"i7e"+b"x"*(CAP-7)+struct.pack(">IB",CAP-4,4),OUT,WORK,100,b"",0)]
                small = [x for x in group if len(x[0])<40000]
                large = [x for x in group if len(x[0])>=40000]
                batches = [small[i:i+16] for i in range(0,len(small),16)] + [[x] for x in large]
                for batch in batches:
                    result = n.call_many([("f0",list(x[:3])) for x in batch],timeout=60)
                    for (wire,out,work,status,raw,privacy), got in zip(batch,result,strict=True):
                        self.assertEqual(got.require_returned().value,status,(backend,wire[:60],len(wire)))
                        self.assertEqual(got.arguments[0],wire)
                        self.assertEqual(got.arguments[1],raw+out[len(raw):])
                        self.assertEqual(got.arguments[2][privacy:],work[privacy:])
                print(json.dumps(dict(backend=backend,native_elf=n.artifact_sha256,
                                      original_matches=len(cases),abi_controls=len(group)-len(cases)),
                                 sort_keys=True),flush=True)
