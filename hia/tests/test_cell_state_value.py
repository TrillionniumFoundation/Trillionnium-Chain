"""Private typed CellState projection only, from the unchanged original public serializer."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_model_artifact import ROOT, original

SOURCE = ROOT / "hia/src/model/cell_state_value.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_state_value_reference.rs")


class CellStateValueTests(unittest.TestCase):
    def test_original_cell_state_canonical_json_and_both_native(self):
        with tempfile.TemporaryDirectory(prefix="trnm-cell-state-value-") as tmp:
            raw = original(Path(tmp), REFERENCE)
        rows = []
        while raw:
            spans = struct.unpack_from("<6Q", raw, 8)
            frame_len = 88 + sum(spans[:5]) + 8 * spans[5]
            size = struct.unpack_from("<Q", raw, frame_len)[0]
            wire = raw[frame_len + 8:frame_len + 8 + size]
            self.assertEqual(len(wire), size)
            rows.append((raw[:frame_len], struct.pack("<Q", size) + wire if size else b""))
            raw = raw[frame_len + 8 + size:]
        self.assertEqual([bool(w) for _, w in rows], [True] * 5 + [False])
        self.assertEqual(len(rows[4][0]), 1624)
        first, expect = rows[0]
        wrong = [(first[:-1], b""), (first + b"X", b""),
                 (b"CSV2" + first[4:], b""), (first[:48] + struct.pack("<Q", 33) + first[56:], b"")]
        full_out, full_work = b"Z"*8714, b"W"*8714
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                cases = rows + wrong
                calls = [("f0", [data, full_out, full_work]) for data, _ in cases]
                for call, (data, expected) in zip(native.call_many(calls), cases, strict=True):
                    got = call.require_returned()
                    self.assertEqual(got.value, int(not expected))
                    self.assertEqual(got.arguments[:2], [data, expected + full_out[len(expected):]])
                    self.assertEqual(got.arguments[2][8704:], full_work[8704:])
                    if not expected:
                        self.assertEqual(got.arguments[2], full_work)
                for out, work in ((full_out[:len(expect)-1], full_work), (full_out, full_work[:8703])):
                    args = [first, out, work]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (102, args[:2]))
