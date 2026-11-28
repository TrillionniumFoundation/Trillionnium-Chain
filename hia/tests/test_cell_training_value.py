"""Immutable original Cell Training and TrainableMask canonical numeric values."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_model_artifact import ROOT, original

SOURCE = ROOT / "hia/src/model/cell_training_value.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_training_value_reference.rs")
WORK = 18944


class CellTrainingValueTests(unittest.TestCase):
    def test_original_training_and_mask_two_native_emitters(self):
        with tempfile.TemporaryDirectory(prefix="trnm-cell-training-value-") as directory:
            raw = original(Path(directory), REFERENCE)
        cases = []
        while raw:
            frame_len, n = struct.unpack_from("<II", raw)
            f, w = raw[8:8+frame_len], raw[8+frame_len:8+frame_len+n]
            self.assertEqual(len(w), n)
            cases.append((f, struct.pack("<Q", n)+w))
            raw = raw[8+frame_len+n:]
        self.assertEqual(len(cases), 7)
        self.assertEqual([len(f) for f, _ in cases], [3092]*3+[3132]*4)
        self.assertEqual(len(set(w for _, w in cases)), 7)
        self.assertGreater(len(cases[4][1]), 18600)
        self.assertLess(len(cases[4][1]), WORK)
        frame, expect = cases[3]
        bad = [frame[:-1], frame+b"x", b"CTm1"+frame[4:],
               frame[:48]+b"\x02"+frame[49:], frame[:-1]+b"\xff"]
        output, work = b"Z"*(WORK+3), b"W"*(WORK+3)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                expected = cases + [(f,b"") for f in bad]
                trials = [("f0",[f,output,work]) for f,_ in expected]
                for call, (f,w) in zip(native.call_many(trials), expected, strict=True):
                    got = call.require_returned()
                    self.assertEqual((got.value, got.arguments[:2]),
                                     (int(not w),[f,w+output[len(w):]]))
                    self.assertEqual(got.arguments[2][WORK:], work[WORK:])
                    if not w:
                        self.assertEqual(got.arguments[2], work)
                for o,s in ((output[:len(expect)-1],work),(output, work[:WORK-1])):
                    got = native.call("f0",[frame,o,s]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(102,[frame,o]))
