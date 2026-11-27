"""Genuine original public read-only planner versus native sealed Borsh bytes."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute
from hia.tests.test_task_archive_hash import ROOT, original
from hia.tests.test_task_archive_selection import REFERENCE

SOURCE = ROOT / "hia/src/task_kernel/archive_sealed_plan.hepta"


class TaskArchiveSealedPlanTests(unittest.TestCase):
    def test_original_public_planner_complete_batch_and_seal_borsh(self):
        with tempfile.TemporaryDirectory(prefix="m10-archive-sealed-plan-") as directory:
            raw = execute([original(Path(directory), REFERENCE), "sealed"]).stdout
        rows = []
        while raw:
            status, n = struct.unpack_from("<II", raw)
            start = n + 8
            count, = struct.unpack_from("<Q", raw, start)
            end = start + 8 + count
            self.assertGreaterEqual(len(raw), end)
            rows.append((status, raw[8:start], raw[start:end]))
            raw = raw[end:]
        self.assertEqual(len(rows), 31)
        for i, (status, inp, batch) in enumerate(rows[:8], 1):
            self.assertEqual(status, 0)
            policy_n, = struct.unpack_from("<Q", inp)
            self.assertEqual(struct.unpack_from("<I", batch, 8 + policy_n - 40 + 220)[0], i)
        self.assertEqual(len(rows[7][2]), 6914)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                            backend=backend) as native:
                calls = [[inp, b"A"*6922, b"B"*1832] for _, inp, _ in rows]
                for idx, ((status, inp, out), args, item) in enumerate(
                        zip(rows, calls, native.call_many([("f0", a) for a in calls]), strict=True)):
                    with self.subTest(case=idx):
                        got = item.require_returned()
                        expected = out + args[1][len(out):] if status == 0 else args[1]
                        self.assertEqual((got.value, got.arguments[:2]), (status, [inp, expected]))
                        self.assertEqual(got.arguments[2][1824:], args[2][1824:])
                valid = rows[0][1]
                for inp, out, work, code in [(valid[:-1],6914,1824,100),(valid+b"\0",6914,1824,100),
                                             (valid,6913,1824,102),(valid,6914,1823,102)]:
                    args = [inp, b"X"*out, b"Y"*work]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (code,args[:2]))
                    if code == 102:
                        self.assertEqual(got.arguments[2], args[2])
