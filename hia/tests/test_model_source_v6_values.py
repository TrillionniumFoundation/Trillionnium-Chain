"""Detached V6 math values; original locked Rust and two native emitters."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_policy_value import ROOT,original

SOURCE=ROOT/"hia/src/model/source_v6_values.hepta"
REFERENCE=Path(__file__).with_name("rust_model_source_v6_values_reference.rs")
WORK=2208


class ModelSourceV6ValuesTests(unittest.TestCase):
    def test_original_detached_allocation_root_and_release_identity_both_native(self):
        with tempfile.TemporaryDirectory(prefix="trnm-source-v6-values-") as directory:
            raw=original(Path(directory),REFERENCE)
        rows=[]
        while raw:
            s,n=struct.unpack_from("<II",raw)
            f,h=raw[8:8+n],raw[8+n:40+n]
            self.assertEqual((len(f),len(h)),(n,32))
            rows.append((s,f,h if s==0 else b""))
            raw=raw[40+n:]
        self.assertEqual([s for s,_,_ in rows],[1]+[0]*7+[1]+[0]*7)
        self.assertEqual(rows[1][2],bytes(32))
        self.assertEqual(rows[2][2],rows[3][2])
        self.assertEqual(rows[4][2],rows[5][2])
        self.assertNotEqual(rows[6][2],rows[7][2]) # sibling-local sorting, not whole-set sorting
        self.assertEqual(len({h for _,_,h in rows[9:]}),7)
        f=rows[2][1]
        release=rows[9][1]
        invalid=[f[:-1],f+b"x",release[:-1],b"AV62"+f[4:]]
        o,w=b"Q"*39,b"S"*(WORK+7)
        for b in ("direct","selfhost"):
            with self.subTest(backend=b),NativeModule(
                SOURCE,byte_exports=("f0",),backend=b,
            ) as native:
                for status,packet,value in rows+[(100,f,b"") for f in invalid]:
                    got=native.call("f0",[packet,o,w]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(status,[packet,value+o[len(value):]]))
                    self.assertEqual(got.arguments[2][WORK:],w[WORK:])
                    if status:
                        self.assertEqual(got.arguments[2],w)
                for out,work in ((o[:31],w),(o,w[:WORK-1])):
                    args=[f,out,work]
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(102,args))
