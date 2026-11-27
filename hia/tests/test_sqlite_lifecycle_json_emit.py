"""Compare complete native compact JSON to locked Rust serde receipts."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/lifecycle_json_emit.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_lifecycle_json_size_reference.rs"


class SqliteLifecycleJsonEmitTests(unittest.TestCase):
    def test_original_compact_receipt_bytes(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-lifecycle-emit-") as directory:
            data = execute([original_adapter(Path(directory), ADAPTER), "--bytes"]).stdout
        cases = []
        while data:
            family, tail_n, json_n = struct.unpack_from("<3Q", data)
            end = 128 + tail_n
            receipt = data[end:end+json_n]
            self.assertEqual((len(data[24:end]), len(receipt)), (104+tail_n, json_n))
            cases.append((family, data[24:end], receipt))
            data = data[end+json_n:]
        self.assertEqual(len(cases), 39)
        self.assertEqual([len(body) for family, _, body in cases if family == 2], [511, 512, 513])
        for family, _, receipt in cases:
            typed = json.loads(receipt)
            self.assertEqual(list(typed), [
                "sequence", "action", "generation", "basename", "device", "inode",
                "linked", "handles", "pending_opens", "shm_references", "high_water_bytes",
                "actual_last_bytes", *(["requested_endpoint"] if "requested_endpoint" in typed else []),
            ])
            self.assertIn(typed["linked"], (True, False))
            if family == 1:
                self.assertIn(b"\\u0000", receipt)
                self.assertIn(b"\\b\\t\\n", receipt)
                self.assertIn(b'/\\"\\\\', receipt)
                self.assertIn("é中😀\u2028\u2029".encode(), receipt)

        inputs = [[raw, b"\x61"*(8+len(receipt)+(i % 2)*11), b"\x72"*17]
                  for i, (_, raw, receipt) in enumerate(cases)]
        head = inputs[0][0][:104]
        bad = [(head[:-1], 1200, 100), (head+b"x"*513, 4000, 100)]
        def replace(index, value):
            return head[:8*index] + struct.pack("<Q", value) + head[8*index+8:]
        bad.extend((replace(i, v), 1200, 100) for i, v in [
            (0, 0), (0, 13), (3, 1), (4, 1), (5, 2), (6, 1 << 32),
            (7, 1 << 32), (8, 1 << 32), (11, 1), (12, 8),
        ])
        bad.extend((head+tail, 1200, 100) for tail in [
            b"\x80", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82",
        ])
        bad.extend((raw, 7+len(receipt), 102) for _, raw, receipt in cases if len(receipt) >= 511)
        bad.append((inputs[0][0], 0, 102))
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                for args, (_, _, receipt), got in zip(inputs, cases, native.call_many([("f0", a) for a in inputs]),
                                                    strict=True):
                    exact = struct.pack("<Q", len(receipt)) + receipt
                    self.assertEqual((got.require_returned().value, got.arguments),
                                     (0, [args[0], exact+args[1][len(exact):], args[2]]))
                for raw, extent, status in bad:
                    args = [raw, b"\x91"*extent, b"\x92"*17]
                    result = native.call("f0", args).require_returned()
                    self.assertEqual((result.value, result.arguments), (status, args))
