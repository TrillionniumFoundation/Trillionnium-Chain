"""Frozen original model task roots, inert generated tokens and two native emitters."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_policy_value import ROOT, original

SOURCE=ROOT/"hia/src/model/tasks_root.hepta"
REFERENCE=Path(__file__).with_name("rust_model_tasks_root_reference.rs")
WORK=49152


class ModelTasksRootTests(unittest.TestCase):
    def test_original_immutable_model_task_roots_both_native(self):
        with tempfile.TemporaryDirectory(prefix="trnm-model-tasks-root-") as directory:
            raw=original(Path(directory),REFERENCE)
        rows=[]
        while raw:
            status,n=struct.unpack_from("<II",raw)
            f,h=raw[8:8+n],raw[8+n:40+n]
            self.assertEqual((len(f),len(h)),(n,32))
            rows.append((status,f,h if status==0 else b""))
            raw=raw[40+n:]
        self.assertEqual([s for s,_,_ in rows],[0,0,0,0,0,7,1,2,3,4,5,6,8,7,9,8,0])
        self.assertEqual(len({h for s,_,h in rows if s==0}),6)
        f=rows[0][1]
        self.assertGreater(len(rows[2][1]),40000)
        o,w=b"Q"*39,b"S"*(WORK+7)
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                SOURCE,byte_exports=("f0",),backend=backend,
            ) as native:
                cases=rows+[(100,f[:-65],b""),(100,f+b"x",b""),(100,b"MSR2"+f[4:],b"")]
                for status,packet,h in cases:
                    got=native.call("f0",[packet,o,w]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(status,[packet,h+o[len(h):]]))
                    self.assertEqual(got.arguments[2][WORK:],w[WORK:])
                for out,work in ((o[:31],w),(o,w[:WORK-1])):
                    args=[f,out,work]
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(102,args))
