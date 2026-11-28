"""Complete singleton typed batch verification against the original public API."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, original

SOURCE = ROOT / "hia/src/task_kernel/archive_singleton_batch.hepta"
REFERENCE = ROOT / "hia/tests/rust_task_archive_singleton_batch_reference.rs"


class TaskArchiveSingletonBatchTests(unittest.TestCase):
    def test_original_full_singleton_batch_and_charge_precedence(self):
        with tempfile.TemporaryDirectory(prefix="m10-archive-singleton-") as directory:
            raw = execute([original(Path(directory), REFERENCE)]).stdout
        records = []
        while raw:
            status, n = struct.unpack_from("<II", raw)
            self.assertGreaterEqual(len(raw), n+8)
            records.append((status, raw[8:n+8]))
            raw = raw[n+8:]
        self.assertEqual([status for status, _ in records],
                         [0, 0, 15, 20, 20, 20, 20, 22, 1, 13, 22, 200,
                          13, 13, 13, 13, 1, 1, 15, 13, 13, 13, 13, 13])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                            backend=backend) as module:
                arguments = [[raw, b"o"*39, b"x"*1369] for _, raw in records]
                results = module.call_many([("f0", args) for args in arguments])
                for (status, _), args, item in zip(records, arguments, results, strict=True):
                    reply = item.require_returned()
                    self.assertEqual((reply.value, reply.arguments[:2]), (status, args[:2]))
                    self.assertEqual(reply.arguments[2][1360:], args[2][1360:])
                valid = records[0][1]
                a, b = struct.unpack_from("<2Q", valid)
                cursor = 16+a+b
                multi = valid[:cursor] + struct.pack("<I", 2) + valid[cursor+4:]
                for packet, size, code in [(valid[:-1],1360,100),(valid+b"\0",1360,100),
                                           (multi,1360,100),(valid,1359,102)]:
                    args = [packet, b"o"*39, b"x"*size]
                    got = module.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (code, args))
