"""Frozen original checkpoint header typed selection, no checkpoint bytes."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE = ROOT / "hia/src/checkpoint/tile_tensor_header.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_tensor_header_reference.rs")
WITNESS = b"""
pub(super) fn tensor_header_witness(raw:&[u8],payload:u64)->MaterialResult<([u64;2],usize)> {
    let mut callback=|_: MaterialProgress| Ok(());
    let o=Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    tensor_header(raw,payload,&o)
}
"""
TARGET = "model.layers.0.self_attn.q_proj.weight"
N = 576 * 576 * 2
CAP = 1 << 20
WORK = 18000


def encode(row):
    return json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode()


def record(dtype, shape, start, end):
    return {"dtype": dtype, "shape": shape, "data_offsets": [start, end]}


def frame(raw, payload):
    return b"THV1\0\0\0\0" + struct.pack("<Q", payload) + raw


class CheckpointTileTensorHeaderTests(unittest.TestCase):
    def test_original_special_tensor_sorted_admission_and_coverage_both_stock(self):
        target = record("BF16", [576, 576], 0, N)
        rows = []

        def raw(status, blob, payload=N):
            rows.append((status, frame(blob, payload)))

        def obj(status, value, payload=N):
            raw(status, encode(value), payload)

        obj(0, {TARGET: target})
        obj(0, {"z": record("U8", [1], 0, 1),
                TARGET: record("BF16", [576, 576], 1, 1 + N),
                "a": record("U32", [1], N + 1, N + 5)}, N + 5)
        obj(0, {TARGET: target, "__metadata__": {"": "a", "model": "é" * 2048}})
        raw(0, encode({TARGET: target}).replace(b'"dtype"', b'"\\u0064type"'))
        dt = {"BOOL": 1, "U8": 1, "I8": 1, "U16": 2, "I16": 2, "F16": 2,
              "BF16": 2, "U32": 4, "I32": 4, "F32": 4, "U64": 8, "I64": 8, "F64": 8}
        all_dtypes = {TARGET: target}
        pos = N
        for role, width in dt.items():
            all_dtypes[f"synthetic-{role}"] = record(role, [1] * 8, pos, pos + width)
            pos += width
        obj(0, all_dtypes, pos)
        max_rows = {TARGET: target}
        for i in range(31):
            max_rows[f"scalar-{i:02}"] = record("U8", [1], N + i, N + i + 1)
        obj(0, max_rows, N + 31)
        blob = encode({TARGET: target})
        raw(0, blob + b" " * (CAP - 16 - len(blob)))
        for malformed in (b"", b'{"x":0,}', b'{"x":{"a":1,"\\u0061":1}}',
                          b'{"x":0,"\\u0078":0}', b'{"x":1.0}',
                          blob + b"{}", b'{"x":"\xff"}'):
            raw(2, malformed)
        obj(4, {"z": 3, "": target})
        obj(5, {TARGET: target, "__metadata__": {"x": 3}})
        obj(5, {"z": 1, "__metadata__": {"x": "á" * 2049}})
        obj(5, {"__metadata__": []})
        for name in ("dtype", "shape", "data_offsets"):
            d = dict(target)
            del d[name]
            obj(6, {TARGET: d})
        for x in (None, [], {"more": 1, **target}, {**target, "dtype": 1},
                  {**target, "shape": [True]}, {**target, "shape": [-1]},
                  {**target, "data_offsets": [0]}, {**target, "data_offsets": [0, N, 5]}):
            obj(6, {TARGET: x})
        for shape in ([], [0], [(1 << 31)], [1] * 9):
            obj(7, {TARGET: {**target, "shape": shape, "dtype": "BAD"}})
        obj(8, {TARGET: {**target, "dtype": "bf16"}})
        obj(8, {TARGET: {**target, "dtype": "x" * 257}})
        obj(11, {TARGET: {**target, "shape": [(1 << 31) - 1] * 8}})
        obj(11, {TARGET: {**target, "data_offsets": [N, 0]}})
        obj(11, {TARGET: {**target, "data_offsets": [0, N - 1]}})
        obj(11, {TARGET: target}, N - 1)
        obj(9, {TARGET: {**target, "dtype": "I16"}})
        obj(9, {TARGET: {**target, "shape": [576 * 576]}})
        obj(10, {TARGET: target}, N + 1)
        obj(10, {TARGET: record("BF16", [576, 576], 1, N + 1)}, N + 1)
        obj(10, {TARGET: target, "z": record("U8", [1], N - 1, N)}, N)
        obj(10, {"a": record("I8", [1], 1, 2)}, 2)
        obj(10, {"__metadata__": {"n": "m"}}, 0)
        obj(10, {}, 0)
        obj(9, {"not-target": record("I8", [1], 0, 1)}, 1)
        obj(8, {"z": {"bad": True}, "a": record("bad", [1], 0, 1)}, 1)
        obj(6, {"é": record("bad", [1], 0, 1), "z": {"bad": True}}, 1)
        obj(7, {"a": {**target, "shape": []}, "__metadata__": {"z": 2},
                "A": {**target, "shape": [0]}})
        outside = [(0, frame(encode({TARGET: ["BF16", [576, 576], [0, N]]}), N)),
                   (0, frame(encode({TARGET: target, "x" * 129: record("I8", [1], N, N + 1)}), N + 1)),
                   (3, frame(b"[]", 0))]
        stimulus = b"".join(struct.pack("<I", len(data)) + data for _, data in rows + outside)
        with tempfile.TemporaryDirectory(prefix="checkpoint-tile-tensor-header-") as tmp:
            observed = original(Path(tmp), stimulus, reference=REFERENCE, witness=lambda _: WITNESS)
        outputs = []
        for status, lo, hi, count in struct.iter_unpack("<IQQQ", observed):
            outputs.append((status, struct.pack("<QQQ", lo, hi, count) if not status else b""))
        self.assertEqual([s for s, _ in outputs], [s for s, _ in rows + outside])
        self.assertEqual(outputs[0][1], struct.pack("<QQQ", 0, N, 1))
        self.assertEqual(outputs[1][1], struct.pack("<QQQ", 1, N + 1, 3))
        self.assertEqual(outputs[5][1], struct.pack("<QQQ", 0, N, 32))
        matrix = [(s, data, value) for (s, data), (_, value) in zip(rows, outputs[:len(rows)], strict=True)]
        matrix += [(103, data, b"") for _, data in outside]
        matrix += [(100, b"THV1", b""), (100, b"THV2" + rows[0][1][4:], b"")]
        out, work = b"O" * 29, b"W" * (WORK + 5)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for start in range(0, len(matrix), 12):
                    group = matrix[start:start + 12]
                    for (s, data, expected), call in zip(group, native.call_many(
                        [("f0", [b, out, work]) for _, b, _ in group]
                    ), strict=True):
                        got = call.require_returned()
                        self.assertEqual((got.value, got.arguments[:2]),
                                         (s, [data, expected + out[len(expected):]]))
                        self.assertEqual(got.arguments[2][WORK:], work[WORK:])
                for o, w in ((out[:23], work), (out, work[:WORK-1])):
                    args = [rows[0][1], o, w]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (102, args))
