"""Exact pure Borsh path construction on authentic local original archive batches."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, original

SOURCE = ROOT / "hia/src/task_kernel/archive_path.hepta"
REFERENCE = Path(__file__).with_name("rust_task_archive_path_reference.rs")


class TaskArchivePathTests(unittest.TestCase):
    def test_public_original_paths_and_validation_priority_both_native(self):
        with tempfile.TemporaryDirectory(prefix="m10-task-archive-path-") as directory:
            raw = execute([original(Path(directory), REFERENCE)]).stdout
        rows = []
        while raw:
            status, in_len, out_len = struct.unpack_from("<III", raw)
            end = 12+in_len
            frame, out = raw[12:end], raw[end:end+out_len]
            self.assertEqual((len(frame),len(out)),(in_len,out_len))
            rows.append((status, frame, out))
            raw = raw[end+out_len:]
        self.assertEqual([status for status,_,_ in rows],
                         [0,19]+[0]*2+[19]+[0]*3+[19]+[0]*5+[19,13,2,22]+[0]*8+[19])
        self.assertEqual(set(len(out) for s,_,out in rows if not s), {42,74,106,138})
        self.assertEqual(struct.unpack_from("<II", rows[7][2],34), (2,2))
        odd = [out for s,_,out in rows if not s and struct.unpack_from("<II",out,34)==(4,3)]
        self.assertEqual(len(odd),2)
        self.assertNotEqual(odd[0],odd[1])
        first=rows[0][1]
        rows.extend([(100,first[:-33],b""),(100,b"",b"")])
        o, w = b"A"*145, b"K"*1872
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                calls=[("f0",[f,o,w]) for _,f,_ in rows]
                for item,(status,frame,expect) in zip(native.call_many(calls),rows,strict=True):
                    got=item.require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(status,[frame,expect+o[len(expect):]]))
                    self.assertEqual(got.arguments[2][1864:],w[1864:])
                for out,scratch in ((o[:137],w),(o,w[:1863])):
                    args=[first,out,scratch]
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(102,args))
