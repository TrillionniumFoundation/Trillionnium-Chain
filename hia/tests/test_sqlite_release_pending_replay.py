"""Original pending cancellation and logical reclaim; no live file is accessed."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/release_pending_replay.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_release_pending_reference.rs"


class SqlitePendingReleaseReplayTests(unittest.TestCase):
    def test_original_cancellation_actions_and_deferred_refund(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-release-pending-") as directory:
            original = original_adapter(Path(directory), ADAPTER)
            stream = execute([original]).stdout
        self.assertEqual(len(stream), 12 * 360)
        rows = list(struct.iter_unpack("<45Q", stream))
        for policy in range(2):
            original = rows[policy * 6:(policy + 1) * 6]
            self.assertEqual([r[30] for r in original], [1, 1, 2, 1, 2, 2])
            self.assertEqual([r[44] for r in original], [r[30] for r in original])
            self.assertEqual([r[31] for r in original], [1, 0, 0, 0, 0, 0])
            self.assertEqual([r[33] for r in original], [3, 2, 1, 1, 1, 0])
            self.assertEqual([r[36] for r in original], [0, 0, 1, 0, 0, 0])
            self.assertEqual([r[37] for r in original], [0] * 6)
            self.assertEqual([r[38] for r in original], [0, 0, 0, 1, 0, 0])
            self.assertEqual(original[4][35] & 8, 8)
            self.assertGreater(original[0][34], original[1][34])
            self.assertEqual(original[-1][34], 0)

        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                args = [[struct.pack("<31Q", *r[:31]), b"\xbd"*123, b"\xcf"*8] for r in rows]
                results = native.call_many([("f0", a) for a in args])
                for row, a, reply in zip(rows, args, results, strict=True):
                    verdict = reply.require_returned()
                    self.assertEqual((verdict.value, verdict.arguments),
                                     (0, [a[0], struct.pack("<14Q", *row[31:]) + a[1][112:], a[2]]))
                raw = args[0][0]
                malformed = []
                for i, value in ((0, 3), (0, 2), (1, 97), (2, 256), (3, 8),
                                 (5, 33), (7, (1 << 24) + 1), (30, 0), (30, 3)):
                    malformed.append(raw[:i*8] + struct.pack("<Q", value) + raw[(i+1)*8:])
                no_pending = list(rows[0][:31])
                no_pending[1] -= 1
                no_pending[5] = 0
                malformed.append(struct.pack("<31Q", *no_pending))
                cases = [(raw[:-1], 112, 100), (raw + b"\0", 112, 100), (raw, 111, 102)]
                cases += [(r, 112, 100) for r in malformed]
                for packet, width, status in cases:
                    a = [packet, b"\xab"*width, b"\xfe"*8]
                    result = native.call("f0", a).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, a))
