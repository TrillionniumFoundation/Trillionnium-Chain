"""Actual original retained archive Borsh records, without store side effects."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, original

SOURCE = ROOT / "hia/src/task_kernel/archive_retained_plan.hepta"
REFERENCE = Path(__file__).with_name("rust_task_archive_retained_plan_reference.rs")


class TaskArchiveRetainedPlanTests(unittest.TestCase):
    def test_original_full_retained_rows_and_failures_two_native(self):
        with tempfile.TemporaryDirectory(prefix="m10-archive-retained-") as temp:
            raw = execute([original(Path(temp), REFERENCE)]).stdout
        rows = []
        while raw:
            status, frame_len, n = struct.unpack_from("<III",raw)
            end = 12+frame_len
            frame, value = raw[12:end], raw[end:end+n]
            self.assertEqual((len(frame),len(value)),(frame_len,n))
            rows.append((status,frame,value))
            raw=raw[end+n:]
        self.assertEqual([c for c,_,_ in rows], [0,0,0,0,0,1,18,19,0,1])
        f=rows[1][1]
        self.assertEqual(rows[0][2],struct.pack("<I",0))
        self.assertEqual(len(rows[1][2]),6100)
        self.assertEqual(rows[1][2],rows[2][2])
        self.assertEqual(struct.unpack_from("<I",rows[3][2])[0],3)
        self.assertEqual(struct.unpack_from("<I",rows[4][2])[0],3)
        self.assertNotEqual(rows[3][2],rows[4][2])
        self.assertEqual(rows[8][2],struct.pack("<I",0))
        o,w=b"A"*6112,b"K"*1504
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                SOURCE,byte_exports=("f0",),backend=backend,
            ) as native:
                tests=rows+[(100,f[:-1],b""),(100,f+b"\0",b"")]
                calls=[("f0",[data,o,w]) for _,data,_ in tests]
                for item,(status,data,value) in zip(native.call_many(calls),tests,strict=True):
                    got=item.require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(status,[data,value+o[len(value):]]))
                    self.assertEqual(got.arguments[2][1496:],w[1496:])
                for out,scratch in ((o[:6099],w),(o,w[:1495])):
                    args=[f,out,scratch]
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(102,args))
