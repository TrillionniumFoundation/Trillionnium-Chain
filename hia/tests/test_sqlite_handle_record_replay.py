"""Actual original pending/actual handle mutation and global collection even when recording fails."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/handle_record_replay.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_handle_record_replay_reference.rs"


class SqliteHandleRecordReplayTests(unittest.TestCase):
    def test_original_mutation_and_refund_when_evidence_is_full(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-handle-record-") as directory:
            data = execute([original_adapter(Path(directory), ADAPTER)]).stdout
        cases = []
        while data:
            family, extent = struct.unpack_from("<2Q", data)
            body = data[16:16+extent]
            outer, *after = struct.unpack_from("<16Q", data, 16+extent)
            end = 144+extent
            written = struct.pack("<15Q", *after)
            if after[13] == 0:
                size, = struct.unpack_from("<Q", data, end)
                self.assertLessEqual(size, 512)
                written += data[end:end+8+size]
                end += 8+size
            cases.append((family, body, outer, after, written))
            data = data[end:]
        self.assertEqual(len(cases), 14)
        for i in (0, 7):
            self.assertEqual([case[0] for case in cases[i:i+7]], list(range(7)))
            full, sticky, dropped, main, add, close, zero = cases[i:i+7]
            self.assertEqual((full[2], full[3][9], full[3][10], full[3][13]), (13, 2, 0, 13))
            self.assertEqual((sticky[3][6], sticky[3][7]), (2, 14))
            self.assertEqual((dropped[2], dropped[3][9], dropped[3][11], dropped[3][13]), (0, 0, 2, 13))
            self.assertEqual((main[2], main[3][11], main[3][13], main[3][14]), (0, 3, 13, 1))
            self.assertGreater(main[3][12], dropped[3][12])
            self.assertEqual([case[3][9] for case in (add, close, zero)], [2, 1, 0])
        fixture = cases[4][1]
        def replace(i, v):
            return fixture[:i*8] + struct.pack("<Q", v) + fixture[i*8+8:]
        malformed = [fixture[:391], fixture[:392]+b"x"*513, fixture[:392]+b"\xc0\x80"]
        malformed += [replace(i, v) for i,v in ((0,1),(1,0),(2,0),(3,8),(4,0),(5,0),
                    (6,1),(7,2),(8,2),(9,0),(10,0),(11,2),(12,7),(20,3),(21,1),(24,0),(25,32))]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as n:
                positive = [([raw, b"\x82"*(len(written)+pad), b"\x77"*9], outer, written)
                    for _, raw, outer, _, written in cases for pad in (0, 519)]
                results = n.call_many([("f0", args) for args, _, _ in positive])
                for (args, outer, written), result in zip(positive, results, strict=True):
                    self.assertEqual((result.require_returned().value, result.arguments),
                        (outer, [args[0],written+args[1][len(written):],args[2]]))
                invalid = [(raw,800,100) for raw in malformed] + [
                    (raw,len(written)-1,102) for _,raw,_,_,written in cases]
                results = n.call_many([("f0",[raw,b"\x54"*size,b"\x13"*11]) for raw,size,_ in invalid])
                for (raw,size,status),result in zip(invalid,results,strict=True):
                    self.assertEqual((result.require_returned().value, result.arguments),
                        (status,[raw,b"\x54"*size,b"\x13"*11]))
