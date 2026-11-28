"""Measure the typed original receipt, then retain it through one native entry."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/typed_record_evidence.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_record_evidence_reference.rs"


class SqliteTypedRecordEvidenceTests(unittest.TestCase):
    def test_typed_json_binds_actual_original_retention(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-typed-evidence-") as directory:
            data = execute([original_adapter(Path(directory), ADAPTER), "--typed"]).stdout
        records = []
        while data:
            n, = struct.unpack_from("<Q", data)
            self.assertLessEqual(160, n)
            self.assertLessEqual(n, 672)
            body = data[8:8+n]
            status, *after = struct.unpack_from("<10Q", data, 8+n)
            records.append((body, status, after))
            data = data[88+n:]
        self.assertEqual(len(records), 44)
        self.assertEqual({struct.unpack_from("<Q", request)[0] for request, _, _ in records}, set(range(1, 13)))
        self.assertEqual(sum(status == 13 for _, status, _ in records), 10)
        self.assertEqual(sum(after[8] == 0 for _, _, after in records), 10)
        for first in range(0, len(records), 22):
            rows = records[first:first+22]
            for i, width in ((0, 511), (1, 511), (2, 512), (3, 512)):
                old_total, = struct.unpack_from("<Q", rows[i][0], 120)
                self.assertEqual(rows[i][2][3] - old_total, width)
            for i in (4, 5, 7, 10, 12):
                self.assertEqual(rows[i][1], 13)

        good = [[body, b"\x91"*81, b"\x9b"*17] for body, _, _ in records]
        normal = good[0][0]
        head = normal[:160]
        bad = [(head[:-1], 72, 100), (head+b"x"*513, 72, 100), (normal, 71, 102),
               (head+b"\xed\xa0\x80", 72, 100)]
        def replace(word, value):
            return normal[:8*word] + struct.pack("<Q", value) + normal[8*word+8:]
        for word, value in ((0, 0), (0, 13), (1, 0), (3, 1), (5, 2), (6, 1 << 32),
                            (12, 8), (13, 1025), (14, 257), (15, 655361), (16, 2), (18, 1), (19, 13)):
            bad.append((replace(word, value), 72, 100))
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                replies = native.call_many([("f0", args) for args in good])
                for args, (_, status, after), result in zip(good, records, replies, strict=True):
                    self.assertEqual((result.require_returned().value, result.arguments),
                        (status, [args[0], struct.pack("<9Q", *after)+args[1][72:], args[2]]))
                for raw, length, status in bad:
                    args = [raw, b"\xa5"*length, b"\x9b"*17]
                    result = native.call("f0", args).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, args))
