"""Read from the same held TAR1 bytes, comparing the actual original serde types."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_activation_raw import activation, packet
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE = ROOT / "hia/src/checkpoint/tile_activation_typed.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_activation_typed_reference.rs")
WITNESS = b"""
pub(super) fn typed_activation_witness(raw:&[u8],expected:[u8;32]) -> MaterialResult<Vec<u8>> {
    let mut callback=|_: MaterialProgress| Ok(());
    let o=Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    require(sha_observed(raw,MaterialPhase::ActivationHash,&o)?==expected,"ACTIVATION_PIN")?;
    let a: Activation=serde_json::from_value(parse_observed(
        raw,MAX_ACTIVATION_BYTES,MaterialPhase::ActivationJson,&o
    )?).map_err(|_|"ACTIVATION_FIELDS")?;
    let mut out=Vec::new();
    fn word(out:&mut Vec<u8>, word:u64){ out.extend(word.to_le_bytes()); }
    fn text(out:&mut Vec<u8>, s:&str){ word(out,s.len() as u64); out.extend(s.bytes()); }
    fn array(out:&mut Vec<u8>, a:&[u64]){
        word(out,a.len() as u64); for n in a {word(out,*n);}
    }
    for s in [&a.schema,&a.checkpoint_sha256,&a.dtype] { text(&mut out,s); }
    for a in [&a.shape[..],&a.token_ids,&a.attention_mask,&a.positions] { array(&mut out,a); }
    for s in [&a.hidden_hex,&a.producer_script_sha256,&a.prompt_utf8_sha256,
              &a.activation_origin,&a.scope] { text(&mut out,s); }
    let r=a.runtime;
    for s in [&r.device,&r.python,&r.torch,&r.transformers,&r.safetensors,&r.numpy] { text(&mut out,s); }
    word(&mut out,r.threads);
    for f in [r.base_only,r.training,r.local_files_only,r.trust_remote_code] {
        word(&mut out,u64::from(f));
    }
    for n in [r.forward_calls,r.hook_calls,r.parameter_count] { word(&mut out,n); }
    text(&mut out,&r.storage_dtype);
    text(&mut out,&r.material_manifest_sha256);
    Ok(out)
}
"""


def encode(obj, **kwargs):
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"), **kwargs).encode()


class CheckpointTileActivationTypedTests(unittest.TestCase):
    def test_frozen_original_same_blob_typed_projection_both_stock(self):
        fixture = json.loads(activation(1))
        controls = [(0, activation(1)), (0, activation(64)),
                    (0, encode(fixture, sort_keys=True))]
        controls.append((0, activation(1).replace(b'"schema"', b'"\\u0073chema"')))
        altered = copy.deepcopy(fixture)
        altered.update(schema="not an activation profile", hidden_hex="\x00é😀", shape=[0, 999, 42],
                       attention_mask=[], token_ids=[0, (1 << 64) - 1], positions=[999])
        altered["runtime"].update(threads=(1 << 64) - 1, training=True, base_only=False,
                                  device="inert", torch="é\r\x00😀")
        controls.append((0, encode(altered)))
        escaped = copy.deepcopy(fixture)
        escaped["activation_origin"] = "a" * 256
        controls.append((0, encode(escaped)))

        def edit(group, key, value, *, remove=False):
            x = copy.deepcopy(fixture)
            owner = x if group == "root" else x["runtime"]
            if remove:
                del owner[key]
            else:
                owner[key] = value
            controls.append((3, encode(x)))

        for key in fixture:
            edit("root", key, None, remove=True)
        for key in fixture["runtime"]:
            edit("runtime", key, None, remove=True)
        edit("root", "stray", 0)
        edit("runtime", "stray", 0)
        edit("root", "dtype", False)
        edit("root", "hidden_hex", [])
        edit("root", "shape", [1, 1])
        edit("root", "shape", [1, 1, 576, 0])
        edit("root", "shape", [-1, 4, 5])
        edit("root", "token_ids", ["0"])
        edit("root", "token_ids", [-1])
        edit("root", "attention_mask", [True])
        edit("root", "positions", None)
        edit("root", "runtime", {})
        edit("runtime", "threads", -1)
        edit("runtime", "base_only", 1)
        edit("runtime", "training", None)
        edit("runtime", "torch", 91)
        controls.append((3, b"{}"))
        controls += [(2, b'{"unknown":1.0}'), (2, b'{"a":0,"\\u0061":1}'),
                     (2, b'{"runtime":{"x":1,"\\u0078":2}}')]
        rows = [(status, packet(raw)) for status, raw in controls]
        rows += [(1, packet(activation(1), True)), (1, packet(b'{"bad":', True))]
        sequence = copy.deepcopy(fixture)
        sequence["runtime"] = list(sequence["runtime"].values())
        outside_sequence = packet(encode(sequence))
        stimulus = b"".join(struct.pack("<I", len(data)) + data
                            for data in [v for _, v in rows] + [outside_sequence])
        with tempfile.TemporaryDirectory(prefix="checkpoint-activation-typed-") as temp:
            oracle = original(Path(temp), stimulus, reference=REFERENCE, witness=lambda _: WITNESS)
        expected = []
        while oracle:
            status, extent = struct.unpack_from("<II", oracle)
            value = oracle[8:8 + extent]
            self.assertEqual(len(value), extent)
            expected.append((status, value))
            oracle = oracle[8 + extent:]
        # Original derives also admit Runtime in declaration-order sequence form.
        # The bounded native envelope is deliberately object-only at both levels.
        self.assertEqual(expected.pop(), expected[0])
        self.assertEqual([s for s, _ in expected], [s for s, _ in rows])
        self.assertEqual(expected[0], expected[2])
        self.assertEqual(expected[0], expected[3])
        self.assertGreater(len(expected[1][1]), 294912)

        too_long = copy.deepcopy(fixture)
        too_long["schema"] = "x" * 257
        native_rows = [(st, v, projection) for (st, v), (_, projection) in zip(rows, expected, strict=True)]
        native_rows += [(100, b"TAR1", b""), (103, packet(encode(too_long)), b""),
                        (103, outside_sequence, b"")]
        w = b"W" * 315007
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                # Bound the aggregate runner envelope: individual loans stay exact.
                for start in range(0, len(native_rows), 8):
                    batch = native_rows[start:start + 8]
                    outs = [b"O" * (len(p) + 7) for _, _, p in batch]
                    for (status, data, projection), out, call in zip(batch, outs, native.call_many(
                        [("f0", [data, out, w]) for (_, data, _), out in zip(batch, outs, strict=True)]
                    ), strict=True):
                        got = call.require_returned()
                        self.assertEqual((got.value, got.arguments[:2]),
                                         (status, [data, projection + out[len(projection):]]))
                        self.assertEqual(got.arguments[2][315000:], w[315000:])
                for out, scratch in ((b"O" * (len(expected[0][1]) - 1), w), (b"O", w[:314999])):
                    args = [rows[0][1], out, scratch]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (102, args[:2]))
