"""Finite logical original existing-slot binding replay, with no live VFS."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_sqlite_reservation_replay import original_adapter

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/sqlite_io_boundary/observed_bind_replay.hepta"
ADAPTER = ROOT / "hia/tests/rust_sqlite_observed_bind_reference.rs"


class SqliteObservedBindReplayTests(unittest.TestCase):
    def test_original_pre_io_observation_and_bound_reply_precedence(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m15-observed-bind-") as directory:
            original = original_adapter(Path(directory), ADAPTER)
            serialized = execute([original]).stdout
        self.assertEqual(len(serialized), 24 * 320)
        records = list(struct.iter_unpack("<40Q", serialized))
        # Exact genuine original initial Some(0), sticky conventional bind
        # still succeeding, linked/cap/alias/replacement precedence and margin.
        self.assertTrue(any(x[25] == 0 and x[38] == 2 and x[39] == 0 for x in records))
        self.assertTrue(any(x[16] and x[1] == 0 and x[25] == 0 for x in records))
        self.assertEqual([x[25] for x in records[-3:]], [0, 13, 0])
        self.assertEqual([x[13] for x in records[-3:]], [1016, 1017, 1017])
        self.assertEqual([x[38] for x in records[-3:]], [2, 0, 1])
        self.assertEqual(records[-2][35:37], (6, 13))
        self.assertTrue(any(x[16] == 1 and x[25] == 13 and x[35:37] == (1,10) for x in records))
        self.assertTrue(any(x[25] == 10 and x[1] == 1 for x in records))
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                args = [[struct.pack("<25Q", *x[:25]), b"\x6c"*121, bytes(10)] for x in records]
                observed = native.call_many([("f0", a) for a in args])
                for real, a, result in zip(records,args,observed,strict=True):
                    self.assertEqual(result.require_returned().value, real[25])
                    self.assertEqual(result.arguments, [a[0], struct.pack("<14Q", *real[26:]) + a[1][112:], a[2]])
                body = args[0][0]
                poisoned = []
                for field,value in [(0,2),(1,2),(2,8),(5,1<<25),(8,4),(13,1018),(16,8),(17,11),(20,2)]:
                    poisoned.append(body[:field*8] + struct.pack("<Q",value) + body[field*8+8:])
                for request, n, result in [(body[:-1],112,100),(body+b"\0",112,100),(body,111,102),
                                            *[(p,112,100) for p in poisoned]]:
                    a = [request, b"\x9b"*n, bytes(5)]
                    got = native.call("f0",a).require_returned()
                    self.assertEqual((got.value,got.arguments), (result,a))
