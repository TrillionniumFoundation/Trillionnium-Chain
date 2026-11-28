"""Full original private activation oracle over inert bounded named object bytes."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_activation_raw import activation, packet
from hia.tests.test_checkpoint_tile_activation_typed import encode
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE = ROOT / "hia/src/checkpoint/tile_activation_composed.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_activation_composed_reference.rs")
WITNESS = b"""
pub(super) fn composed_activation_witness(raw:&[u8],expected:[u8;32],checkpoint:[u8;32])
    -> MaterialResult<(usize,Vec<u8>)> {
    let mut callback=|_: MaterialProgress| Ok(());
    let o=Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    let ctx=PinnedTileContextV1 {
        network:[1;32],parameters:[2;32],checkpoint_sha256:checkpoint,
        checkpoint_bytes:10,activation_sha256:expected,model:[7;32],input:[8;32],
    };
    activation(raw,&ctx,&o)
}
"""


class CheckpointTileActivationComposedTests(unittest.TestCase):
    def test_full_frozen_original_same_raw_on_both_stock(self):
        fixture = json.loads(activation(1))
        rows = []

        def wire(code, raw, *, checkpoint=b"\x03" * 32, incorrect=False):
            rows.append((code, packet(raw, incorrect) + checkpoint))

        def change(code, root=None, runtime=None, **kwargs):
            v = copy.deepcopy(fixture)
            v.update(root or {})
            v["runtime"].update(runtime or {})
            wire(code, encode(v), **kwargs)

        wire(0, activation(1))
        wire(0, activation(64))
        wire(0, encode(fixture, sort_keys=True))
        wire(0, activation(1).replace(b'"schema"', b'"\\u0073chema"'))
        # Nonzero data includes negative zero, nonfinite payload bits and ordinary
        # finite lanes; original this stage returns bytes, not matrix admission.
        first_bytes = bytes.fromhex("000000800100807f0000803f")
        change(0, {"hidden_hex": first_bytes.hex() + "00" * (2304-len(first_bytes)),
                   "token_ids": [49151]})
        change(0, {"producer_script_sha256": "00" * 32}, {"python": "é" * 64})
        wire(1, b'{ "x":0,"x":1 }', incorrect=True)
        wire(1, activation(1), incorrect=True)
        wire(2, b'{ "x":0,"x":1 }')
        wire(2, b'{"t":1.2}')
        wire(3, b'{"schema":"missing other fields"}')
        change(3, {"shape": [1, 1]})
        change(3, {"shape": [1, 1, -1]})
        change(3, {"schema": "wrong", "token_ids": [True]})
        change(4, {"schema": "wrong", "checkpoint_sha256": "NOT_HEX"})
        change(5, {"checkpoint_sha256": "NOT_HEX", "dtype": "wrong"})
        change(4, {"dtype": "wrong", "shape": [0, 1, 1]})
        change(4, {"scope": "wrong"})
        change(4, {"activation_origin": "wrong"})
        change(4, {}, checkpoint=b"\x04" * 32)
        change(4, {"checkpoint_sha256": "00" * 32}, checkpoint=b"\x01" * 32)
        change(5, {"checkpoint_sha256": "aB" * 32})
        change(6, {"shape": [1, 0, 576], "producer_script_sha256": "wrong"})
        change(6, {"shape": [1, 65, 576]})
        change(6, {"shape": [1, 1, 575]})
        change(6, {"shape": [2, 1, 576]})
        change(7, {"token_ids": [49152], "prompt_utf8_sha256": "wrong"})
        change(7, {"token_ids": []})
        change(7, {"attention_mask": [0]})
        change(7, {"positions": [1]})
        change(5, {"producer_script_sha256": "ZZ"}, {"device": "wrong"})
        change(5, {"prompt_utf8_sha256": "A0" * 32})
        change(5, {}, {"material_manifest_sha256": ""})
        for k, v in (("device", "gpu"), ("storage_dtype", "bf16"), ("threads", 1),
                     ("base_only", False), ("training", True), ("local_files_only", False),
                     ("trust_remote_code", True), ("forward_calls", 0), ("hook_calls", 2),
                     ("parameter_count", 0), ("python", "é" * 65), ("numpy", "")):
            change(8, {"hidden_hex": "wrong"}, {k: v})
        change(9, {"hidden_hex": "00"})
        change(9, {"hidden_hex": "00" * 2303 + "0A"})
        change(9, {"hidden_hex": "00" * 2303 + "é"})
        stimulus = b"".join(struct.pack("<I", len(data)) + data for _, data in rows)
        with tempfile.TemporaryDirectory(prefix="checkpoint-activation-composed-") as temp:
            observed = original(Path(temp), stimulus, reference=REFERENCE, witness=lambda _: WITNESS)
        expected = []
        while observed:
            st, n = struct.unpack_from("<II", observed)
            out = observed[8:8 + n]
            self.assertEqual(len(out), n)
            expected.append((st, out))
            observed = observed[8 + n:]
        self.assertEqual([s for s, _ in expected], [s for s, _ in rows])
        self.assertEqual(expected[0], expected[2])
        self.assertEqual(expected[0], expected[3])
        self.assertEqual(expected[4][1][8:20], first_bytes)
        self.assertEqual(len(expected[1][1]), 147464)
        stored = list(fixture["runtime"].values())
        seq = copy.deepcopy(fixture)
        seq["runtime"] = stored
        private = [(100, b"TAR1", b""),
                   (103, packet(encode(seq)) + b"\x03" * 32, b""),
                   (103, packet(encode({**fixture, "schema": "a"*257})) + b"\x03" * 32, b"")]
        native_rows = [(st, data, out) for (st, data), (_, out) in
                       zip(rows, expected, strict=True)] + private
        w = b"W" * 315007
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for start in range(0, len(native_rows), 8):
                    batch = native_rows[start:start + 8]
                    outs = [b"O" * (len(p) + 7) for _, _, p in batch]
                    calls = [("f0", [data, out, w]) for (_, data, _), out in
                             zip(batch, outs, strict=True)]
                    for (status, data, out), sent, call in zip(
                        batch, outs, native.call_many(calls), strict=True):
                        got = call.require_returned()
                        self.assertEqual((got.value, got.arguments[:2]),
                                         (status, [data, out + sent[len(out):]]))
                        self.assertEqual(got.arguments[2][315000:], w[315000:])
                for out, scratch in ((b"O" * 2311, w), (b"O", w[:314999])):
                    args = [rows[0][1], out, scratch]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (102, args[:2]))
