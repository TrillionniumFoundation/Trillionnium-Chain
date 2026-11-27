"""Pinned native variable batches against the unchanged public Rust verifier."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, original

SOURCE = ROOT / "hia/src/task_kernel/archive_variable_batch.hepta"
REFERENCE = ROOT / "hia/tests/rust_task_archive_variable_batch_reference.rs"


class TaskArchiveVariableBatchTests(unittest.TestCase):
    def test_actual_ordered_distinct_records_sums_and_merkle(self):
        with tempfile.TemporaryDirectory(prefix="m10-archive-variable-") as directory:
            raw = execute([original(Path(directory), REFERENCE)]).stdout
        rows = []
        while raw:
            status, n = struct.unpack_from("<II", raw)
            self.assertGreaterEqual(len(raw), 8+n)
            packet = raw[8:8+n]
            rows.append((status, packet))
            raw = raw[8+n:]
        self.assertEqual([status for status, _ in rows],
                         [0, 0, 0, 0, 0, 0, 2, 22, 2, 2, 15, 15, 200,
                          20, 20, 1, 13, 13, 13, 13, 13])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                            backend=backend) as native:
                args = [[body, b"Y"*17, b"Z"*1728] for _, body in rows]
                results = native.call_many([("f0", row) for row in args])
                for (status, _), call, item in zip(rows, args, results, strict=True):
                    got = item.require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (status, call[:2]))
                    self.assertEqual(got.arguments[2][1720:], call[2][1720:])
                valid = rows[4][1]
                p, s = struct.unpack_from("<2Q", valid)
                at = 16+p+s
                too_many = valid[:at] + struct.pack("<I", 9) + valid[at+4:]
                empty = valid[:at] + bytes(4)
                for packet, n, code in [(valid[:-1],1720,100),(valid+b"\0",1720,100),
                                        (too_many,1720,100),(empty,1720,100),(valid,1719,102)]:
                    inputs = [packet, b"Y"*17, b"Z"*n]
                    got = native.call("f0", inputs).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (code, inputs[:2]))
                    if packet in (too_many, empty, valid):
                        self.assertEqual(got.arguments[2], inputs[2])
