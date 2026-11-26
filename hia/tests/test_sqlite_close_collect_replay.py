"""Replay exact Rust ledger observations after a successful underlying close."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/close_collect_replay.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_close_collect_reference.rs"


class SqliteCloseCollectReplayTests(unittest.TestCase):
    def test_original_close_and_root_wide_refund(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-close-collect-") as directory:
            original = original_adapter(Path(directory), ADAPTER)
            serialized = execute([original]).stdout
        self.assertEqual(len(serialized), 16 * 344)
        records = list(struct.iter_unpack("<43Q", serialized))
        for policy in range(2):
            rows = records[policy * 8:(policy + 1) * 8]
            first, last, shm, peer, reserved, pending, full, third = rows
            self.assertEqual([x[30:33:2] for x in (first, last)], [(1, 3), (0, 2)])
            self.assertGreater(first[33], last[33])
            self.assertEqual((shm[32], shm[37], peer[32]), (3, 1, 1))
            self.assertEqual((reserved[3] & 8, reserved[32] & 1, pending[36]), (8, 1, 1))
            self.assertEqual((full[2], full[31]), (255, 256))
            self.assertEqual((third[0], third[30], third[32]), (2, 1, 3))

        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                args = [[struct.pack("<30Q", *x[:30]), b"\x6c" * 111, b"\xe1" * 9] for x in records]
                observed = native.call_many([("f0", a) for a in args])
                for original, a, result in zip(records, args, observed, strict=True):
                    result.require_returned()
                    self.assertEqual((result.value, result.arguments),
                                     (0, [a[0], struct.pack("<13Q", *original[30:]) + a[1][104:], a[2]]))
                body = args[0][0]
                bad = []
                for index, value in (
                    (0, 3), (0, 2), (1, 1), (1, 97), (2, 256), (3, 16), (3, 2),
                    (4, 0), (4, 33), (5, 32), (6, 33), (7, (1 << 24) + 1), (8, 4098), (9, 0),
                    (22, 1), (29, 1),
                ):
                    bad.append(body[:index*8] + struct.pack("<Q", value) + body[(index+1)*8:])
                cases = [(body[:-1], 104, 100), (body + b"\0", 104, 100), (body, 103, 102)]
                cases.extend((row, 104, 100) for row in bad)
                for request, n, status in cases:
                    a = [request, b"\x9b" * n, b"\xe1" * 9]
                    result = native.call("f0", a).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, a))
