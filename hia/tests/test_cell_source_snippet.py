"""Canonical serialization of inert original SourceSnippet objects and ordered lists."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_model_artifact import ROOT, original

SOURCE = ROOT / "hia/src/model/cell_source_snippet.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_source_snippet_reference.rs")
WORK = 419328


class CellSourceSnippetTests(unittest.TestCase):
    def test_original_source_snippet_object_and_ordered_batch_both_native(self):
        with tempfile.TemporaryDirectory(prefix="trnm-cell-source-snippet-") as tmp:
            raw = original(Path(tmp), REFERENCE)
        cases = []
        while raw:
            frame_len, n = struct.unpack_from("<II", raw)
            frame, wire = raw[8:8+frame_len], raw[8+frame_len:8+frame_len+n]
            self.assertEqual(len(wire), n)
            cases.append((frame, struct.pack("<Q", n) + wire if n else b""))
            raw = raw[8+frame_len+n:]
        self.assertEqual([bool(wire) for _, wire in cases], [True]*6 + [False, True])
        self.assertEqual(cases[3][1], struct.pack("<Q", 2) + b"[]")
        self.assertNotEqual(cases[4][1], cases[5][1])
        self.assertEqual(len(cases[7][0]), 69904)
        self.assertGreater(len(cases[7][1]), 417792)
        self.assertLess(len(cases[7][1]), WORK)
        frame, expected = cases[0]
        invalid = [frame[:-1], frame+b"x", frame[:8]+struct.pack("<Q",0)+frame[16:],
                   frame[:40]+struct.pack("<Q",256)+frame[48:],
                   frame[:16]+struct.pack("<Q",8193)+frame[24:],
                   cases[3][0][:8]+struct.pack("<Q",9)]
        out, work = b"Z"*(WORK+3), b"W"*(WORK+3)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for packet, wire in cases + [(f, b"") for f in invalid]:
                    result = native.call("f0", [packet, out, work]).require_returned()
                    self.assertEqual((result.value, result.arguments[:2]),
                                     (int(not wire), [packet, wire+out[len(wire):]]))
                    self.assertEqual(result.arguments[2][WORK:], work[WORK:])
                    if not wire:
                        self.assertEqual(result.arguments[2], work)
                for o, w in ((out[:len(expected)-1], work), (out, work[:WORK-1])):
                    result = native.call("f0", [frame,o,w]).require_returned()
                    self.assertEqual((result.value, result.arguments[:2]), (102,[frame,o]))
