"""Actual original SQLite retained bytes plus native evidence diagnostics."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/retained_lifecycle_json.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_record_evidence_reference.rs"


class SqliteRetainedLifecycleJsonTests(unittest.TestCase):
    def test_original_retained_json_and_no_bytes_on_pressure(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-retained-json-") as directory:
            data = execute([original_adapter(Path(directory), ADAPTER), "--retained-json"]).stdout
        records = []
        while data:
            n, = struct.unpack_from("<Q", data)
            self.assertLessEqual(160, n)
            self.assertLessEqual(n, 672)
            body = data[8:8+n]
            status, *after = struct.unpack_from("<10Q", data, 8+n)
            end = 88+n
            expected = struct.pack("<9Q", *after)
            if status == 0:
                size, = struct.unpack_from("<Q", data, end)
                chunk = data[end+8:end+8+size]
                self.assertEqual(len(chunk), size)
                self.assertGreater(size, 0)
                self.assertLessEqual(size, 512)
                old_total, = struct.unpack_from("<Q", body, 120)
                self.assertEqual(after[3]-old_total, size)
                expected += data[end:end+8+size]
                end += 8+size
            else:
                self.assertEqual(status, 13)
            records.append((body, status, expected))
            data = data[end:]
        self.assertEqual(len(records), 44)
        self.assertEqual(sum(status == 13 for _, status, _ in records), 10)
        self.assertEqual(sum(len(written) == 592 for _, _, written in records), 4)
        self.assertEqual({struct.unpack_from("<Q", body)[0] for body, _, _ in records}, set(range(1, 13)))
        fixture = records[0][0]
        def field(index, v):
            return fixture[:8*index] + struct.pack("<Q", v) + fixture[8*index+8:]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as n:
                good = []
                for body, status, written in records:
                    for pad in (0, 521):
                        good.append(([body, b"\xa5"*(len(written)+pad), b"\x88"*15], status, written))
                replies = n.call_many([("f0", args) for args, _, _ in good])
                for (args, status, written), result in zip(good, replies, strict=True):
                    self.assertEqual((result.require_returned().value, result.arguments),
                        (status, [args[0], written+args[1][len(written):], args[2]]))
                bad = [(body, len(written)-1, 102) for body, _, written in records]
                bad += [(fixture[:159], 900, 100), (fixture[:160]+b"x"*513, 900, 100),
                        (fixture[:160]+b"\xed\xa0\x80", 900, 100),
                        (field(0, 13), 900, 100), (field(1, 999), 900, 100),
                        (field(13, 1025), 900, 100), (field(19, 13), 900, 100)]
                replies = n.call_many([("f0", [body, b"\x7c"*length, b"\x44"*17])
                                       for body, length, _ in bad])
                for (body, length, status), result in zip(bad, replies, strict=True):
                    self.assertEqual((result.require_returned().value, result.arguments),
                        (status, [body, b"\x7c"*length, b"\x44"*17]))
