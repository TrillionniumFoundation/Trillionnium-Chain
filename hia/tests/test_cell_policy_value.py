"""Exact private Policy canonical serialization; never authorizes any action."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_model_artifact import ROOT, original

SOURCE = ROOT / "hia/src/model/cell_policy_value.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_policy_value_reference.rs")
WORK = 24576


class CellPolicyValueTests(unittest.TestCase):
    def test_original_cell_policy_immutable_both_native(self):
        with tempfile.TemporaryDirectory(prefix="trnm-cell-policy-value-") as directory:
            raw = original(Path(directory), REFERENCE)
        cases = []
        while raw:
            frame_len, n = struct.unpack_from("<II", raw)
            f, w = raw[8:8+frame_len], raw[8+frame_len:8+frame_len+n]
            self.assertEqual(len(w), n)
            cases.append((f, struct.pack("<Q", n)+w if n else b""))
            raw = raw[8+frame_len+n:]
        self.assertEqual([bool(w) for _, w in cases], [True]*5+[False])
        self.assertEqual(len(cases[2][0]), 329)
        self.assertEqual(len(cases[4][0]), 4033)
        self.assertGreater(len(cases[4][1]), 23000)
        self.assertLess(len(cases[4][1]), WORK)
        self.assertNotEqual(cases[0][1], cases[1][1])
        frame, expect = cases[3]

        def u64_at(index, value):
            return frame[:index] + struct.pack("<Q", value) + frame[index+8:]

        bad = [frame[:-1], frame+b"x", u64_at(16,5), u64_at(24,65),
               u64_at(32,2), u64_at(40,2), u64_at(48,129),
               frame[:72]+b"\x04"+frame[73:], frame[:76]+b"\x02"+frame[77:],
               frame[:-1]+b"\x02"]
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
