"""Private typed original nested Optimizer canonical JSON differential."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_model_artifact import ROOT, original

SOURCE = ROOT / "hia/src/model/cell_state_optimizer.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_state_optimizer_reference.rs")
WORK = 73728


class CellStateOptimizerTests(unittest.TestCase):
    def test_original_full_size_nested_optimizer_and_both_native(self):
        with tempfile.TemporaryDirectory(prefix="trnm-cell-state-optimizer-") as tmp:
            raw = original(Path(tmp), REFERENCE)
        cases = []
        while raw:
            frame_len, n = struct.unpack_from("<II", raw)
            frame, wire = raw[8:8+frame_len], raw[8+frame_len:8+frame_len+n]
            self.assertEqual(len(wire), n)
            cases.append((frame, struct.pack("<Q", n) + wire))
            raw = raw[8+frame_len+n:]
        self.assertEqual(len(cases), 4)
        self.assertEqual(len({wire for _, wire in cases}), 4)
        self.assertEqual(len(cases[-1][0]), 26304)
        self.assertLess(len(cases[-1][1]), WORK)
        self.assertGreater(len(cases[-1][1]), 73000)
        frame, expected = cases[0]
        invalid = [b"CSV1" + frame[4:], frame[:-1], frame + b"x",
                   frame[:8] + struct.pack("<Q", 257) + frame[16:]]
        sentinel, work = b"Z" * (WORK + 3), b"W" * (WORK + 3)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                inputs = [(f, w, 0) for f, w in cases] + [(f, b"", 1) for f in invalid]
                args = [("f0", [f, sentinel, work]) for f, _, _ in inputs]
                for call, (f, w, status) in zip(native.call_many(args), inputs, strict=True):
                    got = call.require_returned()
                    self.assertEqual(got.value, status)
                    self.assertEqual(got.arguments[:2], [f, w + sentinel[len(w):]])
                    self.assertEqual(got.arguments[2][WORK:], work[WORK:])
                    if status:
                        self.assertEqual(got.arguments[2], work)
                for out, scratch in ((sentinel[:len(expected)-1], work), (sentinel, work[:WORK-1])):
                    got = native.call("f0", [frame, out, scratch]).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (102, [frame, out]))
