"""Frozen original same-byte activation pin and strict raw JSON prelude."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_activation_profile import FIELDS
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE = ROOT / "hia/src/checkpoint/tile_activation_raw.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_activation_raw_reference.rs")
WITNESS = b"""
pub(super) fn raw_activation_witness(raw:&[u8],expected:[u8;32],mode:u8)
    -> MaterialResult<usize> {
    let mut callback=|_: MaterialProgress| Ok(());
    let o=Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    if mode != 0 {
        let ctx=PinnedTileContextV1 {
           network:[1;32],parameters:[2;32],checkpoint_sha256:[3;32],
           checkpoint_bytes:10,activation_sha256:expected,model:[7;32],input:[8;32],
        };
        let (count, hidden)=activation(raw,&ctx,&o)?;
        assert_eq!(hidden,vec![0;count*WIDTH*4]);
        return Ok(count);
    }
    require(sha_observed(raw,MaterialPhase::ActivationHash,&o)?==expected,"ACTIVATION_PIN")?;
    parse_observed(raw,MAX_ACTIVATION_BYTES,MaterialPhase::ActivationJson,&o)?;
    Ok(0)
}
"""


def packet(raw, bad_pin=False):
    digest = hashlib.sha256(raw).digest()
    if bad_pin:
        digest = bytes([digest[0] ^ 1]) + digest[1:]
    return b"TAR1\0\0\0\0" + digest + raw


def activation(tokens):
    f = [v.decode() for v in FIELDS]
    # Reordered unique keys, real closed original nested runtime and typed arrays.
    return json.dumps({
        "runtime": {
            "device": f[8], "python": f[10], "torch": f[11] + "😀",
            "transformers": f[12], "safetensors": f[13], "numpy": f[14],
            "threads": 2, "base_only": True, "training": False, "local_files_only": True,
            "trust_remote_code": False, "forward_calls": 1, "hook_calls": 1,
            "parameter_count": 134515008, "storage_dtype": f[9],
            "material_manifest_sha256": f[7],
        },
        "schema": f[0], "checkpoint_sha256": f[1], "dtype": f[2],
        "shape": [1, tokens, 576], "token_ids": list(range(tokens)),
        "attention_mask": [1] * tokens, "positions": list(range(tokens)),
        "hidden_hex": "00" * (tokens * 2304), "producer_script_sha256": f[5],
        "prompt_utf8_sha256": f[6], "activation_origin": f[3], "scope": f[4],
    }, ensure_ascii=True, separators=(",", ":")).encode()


class CheckpointTileActivationRawTests(unittest.TestCase):
    def test_frozen_original_same_blob_pin_strict_json_both_stock(self):
        good = [
            b"{}", b'{"x":{},"y":{},"a":[]}', b'{"z":1,"a":2,"b":3}',
            b'{"p":{"s":true,"t":false,"v":null},"q":{"s":null}}',
            b'{"":[1,2,-1,false,true,null,"ab\\b\\f\\r\\n\\t\\/"]}',
            b'{"s":18446744073709551615,"t":-9223372036854775808}',
            b'{"\\u0000":0,"\\uD83D\\uDE00":2,"\\u00E9":3}',
            '{"𝄞":1,"é":"á","a":"😅"}'.encode(),
            b' \r\n\t{ "\\u0078" : 0 } \r\n\t ',
            b'{"x":"\x7f"}', b'{"' + b"k" * 128 + b'":1}',
            b'{' + b','.join(b'"k%d":0' % i for i in range(32)) + b'}',
            b'{"x":[' + b','.join([b'0'] * 64) + b']}',
        ]
        bad = [
            b"", b'{"x":0,"x":1}', b'{"a":0,"b":1,"\\u0061":2}',
            '{"𝄞":1,"\\uD834\\uDD1E":2}'.encode(),
            b'{"top":{"same":0,"middle":1,"same":2}}',
            b'{"":{"":"","\\u0000":0,"":1}}', b'{"x":0}{}',
            b'{"x":-0}', b'{"x":00}', b'{"x":1.0}', b'{"x":1e0}',
            b'{"x":- 3}', b'{"x":[1,3.0]}', b'{"x":18446744073709551616}',
            b'{"x":-9223372036854775809}', b'{"x":-18446744073709551615}',
            b'{"x":truex}', b'{"x":1,}', b'{"x":[1,]}', b'{"x",1}',
            b'{"x":"\\uD800"}', b'{"x":"\\uDE00"}', b'{"x":"\\q"}',
            b'{"x":"\xff"}', b'{"x":"\xc0\x80"}', b'{"x":"\x00"}',
            b'{"x":"truncated', b'{"x":{"a":null', b'{"x":', b'{"x":[1,',
        ]
        rows = [(0, 0, packet(v)) for v in good]
        rows += [(2, 0, packet(v)) for v in bad]
        rows += [(1, 0, packet(b'{"x":0,"x":1}', True)),
                 (1, 0, packet(b'', True))]
        one, max_tokens = activation(1), activation(64)
        rows += [(0, 1, packet(one)), (0, 64, packet(max_tokens)),
                 (1, 1, packet(one, True))]
        stimulus = b"".join(struct.pack("<IB", len(data) + 1, mode) + data
                            for _, mode, data in rows)
        with tempfile.TemporaryDirectory(prefix="checkpoint-activation-raw-") as temp:
            oracle = original(Path(temp), stimulus, reference=REFERENCE, witness=lambda _: WITNESS)
        self.assertEqual(list(struct.unpack(f"<{len(rows)}I", oracle)), [x[0] for x in rows])
        private = [
            (100, b"TAR1"), (100, b"TAR2" + packet(b"{}")[4:]),
            (103, packet(b"[]")), (103, packet(b'{"a":{"b":{"c":0}}}')),
            (103, packet(b'{"a":[[0]]}')), (103, packet(b'{"' + b"k" * 129 + b'":1}')),
            (103, packet(b'{"x":[' + b','.join([b'0'] * 65) + b']}')),
            (103, packet(b'{' + b','.join(b'"k%d":0' % i for i in range(33)) + b'}')),
        ]
        o, w = b"UNTOUCHED", b"W" * 9927
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                cases = [(s, data) for s, _, data in rows] + private
                calls = [("f0", [data, o, w]) for _, data in cases]
                for (status, data), call in zip(cases, native.call_many(calls), strict=True):
                    result = call.require_returned()
                    self.assertEqual((result.value, result.arguments[:2]), (status, [data, o]))
                    self.assertEqual(result.arguments[2][9920:], w[9920:])
                short = [packet(b"{}"), o, w[:9919]]
                got = native.call("f0", short).require_returned()
                self.assertEqual((got.value, got.arguments), (102, short))
