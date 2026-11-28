"""Frozen full activation on original positional nested Runtime JSON."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_activation_composed import REFERENCE, WITNESS
from hia.tests.test_checkpoint_tile_activation_raw import activation, packet
from hia.tests.test_checkpoint_tile_activation_typed import encode
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE = ROOT / "hia/src/checkpoint/tile_activation_runtime_sequence.hepta"
FIELDS = ("device", "python", "torch", "transformers", "safetensors", "numpy", "threads",
          "base_only", "training", "local_files_only", "trust_remote_code", "forward_calls",
          "hook_calls", "parameter_count", "storage_dtype", "material_manifest_sha256")
ROOT_FIELDS = ("schema", "checkpoint_sha256", "dtype", "shape", "token_ids", "attention_mask",
               "positions", "hidden_hex", "producer_script_sha256", "prompt_utf8_sha256",
               "runtime", "activation_origin", "scope")


def runtime_array(row):
    value = copy.deepcopy(row)
    value["runtime"] = [row["runtime"][key] for key in FIELDS]
    return value


class CheckpointTileActivationRuntimeSequenceTests(unittest.TestCase):
    def test_frozen_original_positional_runtime_and_named_parity(self):
        one = json.loads(activation(1))
        many = json.loads(activation(64))
        rows = []

        def raw(status, value, *, bad_pin=False, pin=b"\x03" * 32):
            rows.append((status, packet(value, bad_pin) + pin))

        def row(status, value, **kw):
            raw(status, encode(value), **kw)

        for value in (one, many):
            row(0, value)
            row(0, runtime_array(value))
        raw(0, encode(runtime_array(one)).replace(b'"runtime"', b'"\\u0072untime"'))
        changed = runtime_array(one)
        changed["runtime"][1] = "é" * 64
        changed["runtime"][2] = "😀"
        changed["hidden_hex"] = "0123456789abcdef" * 288
        row(0, changed)
        row(1, changed, bad_pin=True)
        raw(2, b'{"runtime":[],"\\u0072untime":[]}')
        raw(2, encode(changed).replace(b'"cpu"', b"1.0", 1))
        for index in range(16):
            less = runtime_array(one)
            del less["runtime"][index]
            row(3, less)
        extra = runtime_array(one)
        extra["runtime"].append("unrecognized")
        row(3, extra)
        row(3, {**one, "runtime": []})
        for i, value in ((0, False), (3, None), (6, "2"), (6, -1), (7, 1),
                         (9, "true"), (11, False), (15, 0)):
            bad = runtime_array(one)
            bad["runtime"][i] = value
            row(3, bad)
        swapped = runtime_array(one)
        swapped["runtime"][6], swapped["runtime"][7] = swapped["runtime"][7], swapped["runtime"][6]
        row(3, swapped)
        row(4, {**changed, "schema": "invalid"}, pin=b"\x04" * 32)
        row(4, changed, pin=b"\x04" * 32)
        row(5, {**changed, "checkpoint_sha256": "A0" * 32})
        row(6, {**changed, "shape": [1, 0, 576], "prompt_utf8_sha256": "wrong"})
        row(7, {**changed, "positions": [1], "prompt_utf8_sha256": "wrong"})
        bad_hash = copy.deepcopy(changed)
        bad_hash["runtime"][15] = "not a SHA"
        bad_hash["runtime"][0] = "not cpu"
        row(5, bad_hash)
        for i, value in ((0, "other"), (1, ""), (5, "é" * 65), (6, 0), (7, False),
                         (8, True), (9, False), (10, True), (11, 0), (12, 2),
                         (13, 0), (14, "bf16")):
            bad = copy.deepcopy(changed)
            bad["runtime"][i] = value
            bad["hidden_hex"] = "first runtime error wins"
            row(8, bad)
        row(9, {**changed, "hidden_hex": "01"})
        row(9, {**changed, "hidden_hex": "0a0B" * 1152})
        # Frozen Rust also accepts both positional struct levels, but lexical
        # TAR1 intentionally lacks top-level arrays of nested arrays/objects.
        root_sequence = [runtime_array(one)[key] for key in ROOT_FIELDS]
        root_private = packet(encode(root_sequence)) + b"\x03" * 32
        stimulus = b"".join(struct.pack("<I", len(data)) + data
                            for data in [p for _, p in rows] + [root_private])
        with tempfile.TemporaryDirectory(prefix="checkpoint-activation-runtime-sequence-") as tmp:
            response = original(Path(tmp), stimulus, reference=REFERENCE, witness=lambda _: WITNESS)
        expect = []
        while response:
            status, n = struct.unpack_from("<II", response)
            body = response[8:8 + n]
            self.assertEqual(len(body), n)
            expect.append((status, body))
            response = response[8 + n:]
        self.assertEqual(expect.pop(), expect[0])
        self.assertEqual([s for s, _ in expect], [s for s, _ in rows])
        self.assertEqual(expect[0], expect[1])
        self.assertEqual(expect[2], expect[3])
        self.assertEqual(expect[0], expect[4])
        self.assertEqual(expect[5][1][8:], bytes.fromhex(changed["hidden_hex"]))
        native_rows = [(s, p, o) for (s, p), (_, o) in zip(rows, expect, strict=True)]
        native_rows += [(103, root_private, b""), (100, b"TAR1", b"")]
        work = b"W" * 315007
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for start in range(0, len(native_rows), 8):
                    batch = native_rows[start:start + 8]
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
                    args = [rows[1][1], out, scratch]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (102, args[:2]))
