"""Differential of exact original compact JSON evidence retention, not serialization authority."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/record_evidence.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_record_evidence_reference.rs"


class SqliteRecordEvidenceTests(unittest.TestCase):
    def test_actual_original_measured_json_and_independent_vector_limits(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-record-evidence-") as directory:
            original = original_adapter(Path(directory), ADAPTER)
            serialized = execute([original]).stdout
        self.assertEqual(len(serialized), 28 * 160)
        rows = list(struct.iter_unpack("<20Q", serialized))
        for policy in range(2):
            records = rows[policy * 14:(policy + 1) * 14]
            self.assertEqual([r[1] for r in records[:6]], [511, 511, 512, 512, 513, 513])
            self.assertEqual([r[10] for r in records[:6]], [0, 0, 0, 0, 13, 13])
            self.assertEqual([r[11:13] for r in records[6:12]],
                             [(1024, 0), (1024, 0), (1024, 1), (1, 256), (1, 256), (2, 256)])
            self.assertEqual([r[10] for r in records[6:12]], [0, 13, 0, 0, 13, 0])
            self.assertEqual([r[15] for r in records[6:12]], [1, 0, 0, 1, 0, 0])
            self.assertEqual([r[17:20] for r in records[-2:]], [(2, 14, 0), (2, 14, 1)])
            for row in records:
                self.assertEqual(row[13], row[11] + row[12])
                self.assertEqual(row[14] - row[5], row[1] if row[19] else 0)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as module:
                args = [[struct.pack("<10Q", *r[:10]), b"\xdb"*81, b"\xc7"*8] for r in rows]
                observed = module.call_many([("f0", a) for a in args])
                for row, a, native in zip(rows, args, observed, strict=True):
                    result = native.require_returned()
                    self.assertEqual((result.value, result.arguments),
                                     (row[10], [a[0], struct.pack("<9Q", *row[11:]) + a[1][72:], a[2]]))
                packet = args[0][0]
                rejects = [(packet[:-1], 72, 100), (packet+b"\0", 72, 100), (packet, 71, 102)]
                for i, value in ((0, 0), (0, 3), (1, 0), (1, 4097), (2, 1025), (3, 257),
                                 (4, 2), (5, 513), (6, 2), (8, 1), (9, 13)):
                    option = packet[:i*8] + struct.pack("<Q", value) + packet[(i+1)*8:]
                    rejects.append((option, 72, 100))
                for raw, width, code in rejects:
                    a = [raw, b"\xeb"*width, b"\xed"*8]
                    result = module.call("f0", a).require_returned()
                    self.assertEqual((result.value, result.arguments), (code, a))
