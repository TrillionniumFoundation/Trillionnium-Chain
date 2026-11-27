"""Original planner status and ordered index projection after typed admission."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, original

SOURCE = ROOT / "hia/src/task_kernel/archive_selection.hepta"
REFERENCE = ROOT / "hia/tests/rust_task_archive_selection_reference.rs"


class TaskArchiveSelectionTests(unittest.TestCase):
    def test_exact_source_public_plan_projection(self):
        with tempfile.TemporaryDirectory(prefix="m10-archive-plan-") as directory:
            raw = execute([original(Path(directory), REFERENCE)]).stdout
        rows = []
        while raw:
            status, length = struct.unpack_from("<II", raw)
            self.assertGreaterEqual(len(raw), 176 + length)
            rows.append((status, raw[8:8+length], raw[8+length:176+length]))
            raw = raw[176+length:]
        self.assertEqual([code for code, _, _ in rows],
                         [0,0,19,1,0,0,18,18,0,0,20,18,2,20,0])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                            backend=backend) as native:
                inputs = [[payload, b"A"*181, b"B"*225] for _, payload, _ in rows]
                answers = native.call_many([("f0", args) for args in inputs])
                for (code, raw, projection), args, result in zip(rows, inputs, answers, strict=True):
                    result = result.require_returned()
                    expected = projection+args[1][168:] if code == 0 else args[1]
                    self.assertEqual((result.value, result.arguments[:2]), (code, [raw,expected]))
                    self.assertEqual(result.arguments[2][216:], args[2][216:])
                for args, code in [([rows[1][1][:-1],bytes(168),bytes(216)],100),
                                   ([rows[1][1]+b"\0",bytes(168),bytes(216)],100),
                                   ([rows[1][1],bytes(167),bytes(216)],102),
                                   ([rows[1][1],bytes(168),bytes(215)],102)]:
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (code,args))
