"""Four frozen original activation representations on the same pinned raw loan."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_activation_composed import REFERENCE, WITNESS
from hia.tests.test_checkpoint_tile_activation_raw import activation, packet
from hia.tests.test_checkpoint_tile_activation_runtime_sequence import ROOT_FIELDS, runtime_array
from hia.tests.test_checkpoint_tile_activation_typed import encode
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE = ROOT / "hia/src/checkpoint/tile_activation_root_sequence.hepta"


def positional(row):
    return [copy.deepcopy(row[key]) for key in ROOT_FIELDS]


class CheckpointTileActivationRootSequenceTests(unittest.TestCase):
    def test_frozen_original_four_representation_forms(self):
        one = json.loads(activation(1))
        rows = []

        def raw(status, data, *, bad_pin=False, pin=b"\x03" * 32):
            rows.append((status, packet(data, bad_pin) + pin))

        def emit(status, value, **kw):
            raw(status, encode(value), **kw)

        for tokens in (1, 64):
            value = json.loads(activation(tokens))
            rt = runtime_array(value)
            for shape in (value, rt, positional(value), positional(rt)):
                emit(0, shape)
        p = positional(one)
        p[7] = "0123456789abcdef" * 288
        p[10]["torch"] = "😀"
        p[10]["numpy"] = "é" * 64
        emit(0, p)
        raw(0, encode(p).replace(b'"torch"', b'"\\u0074orch"').replace(b',', b', \r\n'))
        for index in range(13):
            missing = positional(one)
            del missing[index]
            emit(3, missing)
        emit(3, positional(one) + [None])
        emit(3, [])
        for index, bad in ((0, False), (1, 0), (2, None), (3, []),
                           (3, [1, 1, 576, 0]), (4, [True]), (5, [-1]),
                           (6, "positions"), (7, True), (8, []),
                           (10, None), (10, [False]), (11, []), (12, 5)):
            invalid = positional(one)
            invalid[index] = bad
            emit(3, invalid)
        extra = positional(one) + [None]
        raw(2, encode(extra)[:-5] + b"1.0]")
        raw(2, encode(positional(one)) + b"[]")
        raw(2, encode(positional(one))[:-1] + b",]")
        malformed = encode(positional(one)).replace(b'"device":"cpu"', b'"device":"cpu","\\u0064evice":"cpu"')
        raw(2, malformed)
        raw(1, malformed, bad_pin=True)
        raw(1, encode(positional(one)), bad_pin=True)
        for changes, status in (
            ({0: "wrong", 1: "also wrong"}, 4),
            ({1: "wrong", 2: "also wrong"}, 5),
            ({2: "wrong", 3: [1, 0, 576]}, 4),
            ({3: [1, 0, 576], 8: "bad hash"}, 6),
            ({4: [49152], 8: "bad hash"}, 7),
            ({8: "bad hash", 10: {**one["runtime"], "device": "gpu"}}, 5),
            ({7: "bad bits", 10: {**one["runtime"], "device": "gpu"}}, 8),
            ({7: "00" * 2303 + "0A"}, 9),
        ):
            b = positional(one)
            for i, v in changes.items():
                b[i] = v
            emit(status, b)
        emit(4, positional(one), pin=b"\x05" * 32)
        stimulus = b"".join(struct.pack("<I", len(data)) + data for _, data in rows)
        with tempfile.TemporaryDirectory(prefix="checkpoint-activation-root-sequence-") as tmp:
            response = original(Path(tmp), stimulus, reference=REFERENCE, witness=lambda _: WITNESS)
        expect = []
        while response:
            status, n = struct.unpack_from("<II", response)
            body = response[8:8 + n]
            self.assertEqual(len(body), n)
            expect.append((status, body))
            response = response[8 + n:]
        self.assertEqual([s for s, _ in expect], [s for s, _ in rows])
        self.assertEqual(expect[:4], [expect[0]] * 4)
        self.assertEqual(expect[4:8], [expect[4]] * 4)
        self.assertEqual(expect[8], expect[9])
        self.assertEqual(expect[8][1][8:], bytes.fromhex(p[7]))
        native_rows = [(s, p, o) for (s, p), (_, o) in zip(rows, expect, strict=True)]
        # Explicitly outside bounded grammar, not claimed original refusals.
        long_string = positional(one)
        long_string[0] = "x" * 257
        outside = (b"[[[0]]]", b'[{"x":{"y":0}}]', encode([0] * 65), encode(long_string))
        native_rows += [(103, packet(data) + b"\x03" * 32, b"") for data in outside]
        native_rows.append((100, b"TAR1", b""))
        work = b"W" * 315007
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for start in range(0, len(native_rows), 7):
                    batch = native_rows[start:start + 7]
                    outs = [b"O" * (len(p) + 7) for _, _, p in batch]
                    calls = [("f0", [p, dst, work]) for (_, p, _), dst in zip(batch, outs, strict=True)]
                    for (status, data, body), sent, call in zip(
                        batch, outs, native.call_many(calls), strict=True
                    ):
                        got = call.require_returned()
                        self.assertEqual((got.value, got.arguments[:2]),
                                         (status, [data, body + sent[len(body):]]))
                        self.assertEqual(got.arguments[2][315000:], work[315000:])
                for out, scratch in ((b"O" * 2311, work), (b"O", work[:314999])):
                    args = [rows[2][1], out, scratch]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (102, args[:2]))
