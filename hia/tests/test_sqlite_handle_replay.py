"""Exact bounded Rust reserve_handle/opened parity, no underlying VFS callback."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/handle_replay.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_handle_reference.rs"


class SqliteHandleReplayTests(unittest.TestCase):
    def test_original_pending_handle_and_log_admission(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-handle-replay-") as directory:
            original = original_adapter(Path(directory), ADAPTER)
            oracle = execute([original]).stdout
        self.assertEqual(len(oracle), 28 * 160)
        rows = list(struct.iter_unpack("<20Q", oracle))
        self.assertEqual(rows[:11], rows[11:22])  # exact V1 and V2 in the short sequences
        self.assertEqual([r[10] for r in rows[:11]], [0, 0, 0, 0, 0, 13, 0, 10, 10, 10, 10])
        self.assertEqual([r[19] for r in rows[:11]], [1, 1, 2, 2, 1, 0, 2, 0, 0, 0, 0])
        self.assertEqual((rows[4][2:5], rows[4][11:14]), ((1, 30, 31), (1, 31, 32)))
        self.assertEqual((rows[6][8:10], rows[6][10], rows[6][17:20]), ((2, 13), 0, (2, 13, 2)))
        self.assertEqual([r[5] for r in rows[22:27]], [1016, 1017, 1017, 1017, 1017])
        self.assertEqual([r[14] for r in rows[22:27]], [1017, 1017, 1018, 1017, 1018])
        self.assertEqual([r[17:20] for r in rows[23:]], [(1, 13, 0), (1, 13, 2),
                                                       (1, 13, 0), (1, 13, 2), (4, 13, 2)])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as mod:
                args = [[struct.pack("<10Q", *r[:10]), b"\xab"*79, b"\x88"*9] for r in rows]
                for row, a, observed in zip(rows, args, mod.call_many([("f0", a) for a in args]), strict=True):
                    result = observed.require_returned()
                    self.assertEqual(result.value, row[10])
                    self.assertEqual(result.arguments, [a[0], struct.pack("<9Q", *row[11:]) + a[1][72:], a[2]])
                valid = args[0][0]
                bad = []
                for index, value in ((0, 2), (1, 2), (2, 33), (3, 33), (2, 1), (4, 97),
                                     (4, 65), (5, 1018), (8, 5), (9, 13)):
                    bad.append(valid[:8*index] + struct.pack("<Q", value) + valid[8*index+8:])
                cases = [(valid[:-1], 72, 100), (valid + b"\0", 72, 100), (valid, 71, 102)]
                cases += [(row, 72, 100) for row in bad]
                for request, width, status in cases:
                    a = [request, b"\xc7"*width, b"\xc8"*9]
                    result = mod.call("f0", a).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, a))
