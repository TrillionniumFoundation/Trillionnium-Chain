"""Exact native size of the original compact SQLite lifecycle receipt."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/lifecycle_json_size.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_lifecycle_json_size_reference.rs"


class SqliteLifecycleJsonSizeTests(unittest.TestCase):
    def test_original_compact_receipt_size(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-lifecycle-size-") as directory:
            data = execute([original_adapter(Path(directory), ADAPTER)]).stdout
        records = []
        while data:
            family, n, expected = struct.unpack_from("<3Q", data)
            raw = data[24:128+n]
            self.assertEqual(len(raw), 104+n)
            records.append((family, raw, expected))
            data = data[128+n:]
        self.assertEqual(len(records), 39)
        self.assertEqual({struct.unpack_from("<Q", raw)[0] for family, raw, _ in records if family == 0},
                         set(range(1, 13)))
        self.assertEqual([expected for family, _, expected in records if family == 2], [511, 512, 513])
        self.assertEqual({struct.unpack_from("<Q", raw, 96)[0] for family, raw, _ in records if family == 1},
                         set(range(8)))
        valid = [[raw, b"\x6c"*17, b"\xef"*11] for _, raw, _ in records]
        head = valid[0][0][:104]
        bad = [(head[:-1], 8, 100), (head+b"x"*513, 8, 100), (head, 7, 102)]
        for tail in (b"\x80", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82"):
            bad.append((head+tail, 8, 100))
        for i, v in ((0, 0), (0, 13), (3, 1), (4, 1), (5, 2), (6, 1 << 32),
                     (7, 1 << 32), (8, 1 << 32), (11, 1), (12, 8)):
            bad.append((head[:i*8] + struct.pack("<Q", v) + head[i*8+8:], 8, 100))
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                for a, row, reply in zip(valid, records, native.call_many([("f0", a) for a in valid]), strict=True):
                    reply.require_returned()
                    self.assertEqual((reply.value, reply.arguments),
                                     (0, [a[0], struct.pack("<Q", row[2])+a[1][8:], a[2]]))
                for raw, length, status in bad:
                    a = [raw, b"\x9b"*length, b"\xe1"*11]
                    result = native.call("f0", a).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, a))
