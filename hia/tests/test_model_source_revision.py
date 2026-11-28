"""Original pure typed source revision over generated local values only."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_policy_value import ROOT, original

SOURCE=ROOT/"hia/src/model/source_revision.hepta"
REFERENCE=Path(__file__).with_name("rust_model_source_revision_reference.rs")
WORK=28672


class ModelSourceRevisionTests(unittest.TestCase):
    def test_original_immutable_source_revision_two_stock(self):
        with tempfile.TemporaryDirectory(prefix="trnm-model-source-revision-") as directory:
            raw=original(Path(directory),REFERENCE)
        rows=[]
        while raw:
            code,n=struct.unpack_from("<II",raw)
            f,h=raw[8:8+n],raw[8+n:40+n]
            self.assertEqual((len(f),len(h)),(n,32))
            rows.append((code,f,h if code==0 else b""))
            raw=raw[40+n:]
        self.assertEqual([c for c,_,_ in rows],[0,0,0,1,1,2,3,4,4,4,5,6,3,3,5,0])
        self.assertEqual(rows[0][2],rows[1][2])
        self.assertNotEqual(rows[0][2],rows[2][2])
        self.assertEqual(len(rows[-1][1]),134168)
        f=rows[0][1]
        o,w=b"T"*39,b"W"*(WORK+7)
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                SOURCE,byte_exports=("f0",),backend=backend,
            ) as native:
                cases=rows+[(100,f[:-1],b""),(100,f+b"x",b""),(100,b"MSR2"+f[4:],b"")]
                for code,packet,result in cases:
                    got=native.call("f0",[packet,o,w]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(code,[packet,result+o[len(result):]]))
                    self.assertEqual(got.arguments[2][WORK:],w[WORK:])
                for output,work in ((o[:31],w),(o,w[:WORK-1])):
                    args=[f,output,work]
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(102,args))
