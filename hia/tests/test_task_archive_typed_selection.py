"""One native call for canonical Borsh admission, selection and record output."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, original
from hia.tests.test_task_archive_selection import REFERENCE

SOURCE = ROOT / "hia/src/task_kernel/archive_typed_selection.hepta"


class TaskArchiveTypedSelectionTests(unittest.TestCase):
    def test_original_typed_policy_facts_holds_and_selected_borsh(self):
        with tempfile.TemporaryDirectory(prefix="m10-archive-typed-plan-") as directory:
            raw = execute([original(Path(directory), REFERENCE), "typed"]).stdout
        rows = []
        while raw:
            status, n = struct.unpack_from("<II", raw)
            start = n+8
            vector, = struct.unpack_from("<Q", raw, start+168)
            stop = start+176+vector
            self.assertGreaterEqual(len(raw), stop)
            rows.append((status, raw[8:start], raw[start:stop]))
            raw = raw[stop:]
        self.assertEqual([c for c, *_ in rows],
                         [0,0,19,1,0,0,18,18,0,0,20,18,2,20,0,
                          22,1,22,200,1,15,1,0])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                            backend=backend) as native:
                calls = [[raw, b"A"*6284, b"B"*1504] for _, raw, _ in rows]
                for row, args, item in zip(rows, calls, native.call_many([("f0", a) for a in calls]), strict=True):
                    status, raw, projection = row
                    got = item.require_returned()
                    expected = projection + args[1][len(projection):] if status == 0 else args[1]
                    self.assertEqual((got.value, got.arguments[:2]), (status,[raw,expected]))
                    self.assertEqual(got.arguments[2][1496:], args[2][1496:])
                valid = rows[1][1]
                for raw, output, work, code in [(valid[:-1],6276,1496,100),(valid+b"\0",6276,1496,100),
                                                (valid,6275,1496,102),(valid,6276,1495,102)]:
                    args = [raw, b"X"*output, b"Y"*work]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (code,args[:2]))
                    if code == 102: self.assertEqual(got.arguments[2], args[2])
