"""Original logical SHM reference admission, release and deferred collection."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/shm_replay.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_shm_reference.rs"


class SqliteShmReplayTests(unittest.TestCase):
    def test_original_shm_pressure_and_global_collection(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-shm-replay-") as directory:
            original = original_adapter(Path(directory), ADAPTER)
            recorded = execute([original]).stdout
        self.assertEqual(len(recorded), 28 * 432)
        rows = list(struct.iter_unpack("<54Q", recorded))
        for policy in range(2):
            cases = rows[policy * 14:(policy + 1) * 14]
            self.assertEqual((cases[0][6], cases[0][43], cases[0][53]), (31, 32, 1))
            self.assertEqual((cases[1][35], cases[1][50:54]), (13, (1, 2, 13, 0)))
            self.assertEqual((cases[3][35], cases[3][51:54]), (0, (1, 14, 1)))
            self.assertEqual((cases[5][6], cases[5][43], cases[5][53]), (0, 0, 2))
            self.assertEqual((cases[6][38], cases[6][39]), (0, 0))
            self.assertEqual((cases[7][36], cases[7][38], cases[7][43]), (1, 3, 0))
            self.assertEqual((cases[9][2], cases[9][37], cases[10][37]), (255, 256, 256))
            self.assertEqual([r[31] for r in cases[-3:]], [1023, 1024, 1024])
            self.assertEqual([r[49] for r in cases[-3:]], [1024, 1024, 1024])
            self.assertEqual([r[35] for r in cases[-3:]], [0, 13, 0])
            self.assertEqual([r[43] for r in cases[-3:]], [32, 32, 31])
            self.assertEqual(cases[-2][51:54], (2, 13, 0))
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                args = [[struct.pack("<35Q", *r[:35]), b"\xb3"*155, b"\xc4"*11] for r in rows]
                results = native.call_many([("f0", a) for a in args])
                for row, a, reply in zip(rows, args, results, strict=True):
                    verdict = reply.require_returned()
                    self.assertEqual((verdict.value, verdict.arguments),
                                     (row[35], [a[0], struct.pack("<18Q", *row[36:]) + a[1][144:], a[2]]))
                raw = args[0][0]
                cases = [(raw[:-1], 144, 100), (raw+b"\0", 144, 100), (raw, 143, 102)]
                for index, value in ((0, 3), (0, 1), (1, 1), (2, 257), (3, 8),
                                     (6, 33), (30, 0), (30, 3), (31, 1024), (31, 1025), (33, 2), (34, 13)):
                    cases.append((raw[:index*8] + struct.pack("<Q", value) + raw[index*8+8:], 144, 100))
                for packet, width, status in cases:
                    a = [packet, b"\xab"*width, b"\xce"*9]
                    result = native.call("f0", a).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, a))
