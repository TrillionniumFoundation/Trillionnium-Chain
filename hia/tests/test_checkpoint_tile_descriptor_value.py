"""Compare a typed inert descriptor with the frozen original serializer."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE = ROOT / "hia/src/checkpoint/tile_descriptor_value.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_descriptor_value_reference.rs")
ORIGINAL_FRAGMENT_SHA256 = "24fa4fb63601bb09b169f27ead69c2febc16d1d48e9186811ff34ecd81774a8c"
FIELDS = (
    ("a_nonzero", "u"),
    ("a_sha256", "s"),
    ("activation_clip", "i"),
    ("activation_clipped", "u"),
    ("activation_scale_power", "b"),
    ("activation_sha256", "s"),
    ("activation_width", "u"),
    ("b_nonzero", "u"),
    ("b_sha256", "s"),
    ("chain_authority", "false"),
    ("checkpoint_bytes", "u"),
    ("checkpoint_sha256", "s"),
    ("dense_base_product_multiplications", "u"),
    ("full_forward_verified", "false"),
    ("genuine_demand_verified", "false"),
    ("hardness_accepted", "false"),
    ("header_bytes", "u"),
    ("header_sha256", "s"),
    ("input", "s"),
    ("input_coordinates", "pair"),
    ("marginal_contribution_accepted", "false"),
    ("matrix_task", "s"),
    ("model", "s"),
    ("network", "s"),
    ("output_coordinates", "pair"),
    ("padded_token_columns", "u"),
    ("parameters", "s"),
    ("policy", "s"),
    ("real_token_columns", "u"),
    ("schema", "s"),
    ("sparse_b_base_product_multiplications", "u"),
    ("tensor", "s"),
    ("tensor_count", "u"),
    ("tensor_dtype", "s"),
    ("tensor_offsets", "pair"),
    ("tensor_shape", "pair"),
    ("weight_clip", "i"),
    ("weight_clipped", "u"),
    ("weight_scale_power", "b"),
)

def witness(frozen):
    start = b"struct DescriptorWriter"
    end = b"fn sha(bytes"
    assert frozen.count(start) == frozen.count(end) == 1
    chunk = frozen[frozen.index(start):frozen.index(end)]
    assert hashlib.sha256(chunk).hexdigest() == ORIGINAL_FRAGMENT_SHA256
    return b"""
pub(super) fn tile_descriptor_value_witness(d:&TileMaterialDescriptorV1) -> MaterialResult<Vec<u8>> {
    let mut callback=|_: MaterialProgress| Ok(());
    let o=&Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    canonical_descriptor_observed(d,o)
}
"""

def packet(values):
    parts = [b"TDV1"+bytes(4)]
    for key, kind in FIELDS:
        v = values[key]
        if kind == "s":
            raw = v.encode("ascii")
            parts.extend([struct.pack("<Q",len(raw)),raw])
        elif kind == "pair":
            parts.append(struct.pack("<QQ",*v))
        elif kind == "i":
            parts.append(struct.pack("<q",v))
        elif kind != "false":
            parts.append(struct.pack("<Q",v))
    return b"".join(parts)

class CheckpointTileDescriptorValueTests(unittest.TestCase):
    def test_frozen_original_compact_json_bytes_both_stock(self):
        cases = []
        for k in range(7):
            values = {}
            for i,(key,kind) in enumerate(FIELDS):
                if kind == "s":
                    s = ["", f"synthetic-{i}", "s\x00\t\n\r\b\f\x1e\x7f\\/\\\"", "\x00"*256,
                         "".join(chr(c) for c in range(128)), "a"*255+"\n", f"opaque-not-a-proof-{i}"]
                    values[key] = s[k]
                elif kind == "false":
                    values[key] = False
                elif kind == "pair":
                    values[key] = [0,(1<<64)-1] if k%2==0 else [i*10,i]
                elif kind == "i":
                    values[key] = [0,-1,-(1<<63),(1<<63)-1,-32767,128,-128][k]
                elif kind == "b":
                    values[key] = [0,1,255,251,10,100,9][k]
                else:
                    values[key] = [0,i,(1<<64)-1,(1<<63),9,10,18446744073709551610][k]
            cases.append((values,packet(values)))
        stimulus=b"".join(struct.pack("<Q",len(raw))+raw for _,raw in cases)
        with tempfile.TemporaryDirectory(prefix="checkpoint-tile-descriptor-value-") as temp:
            original_output=original(Path(temp),stimulus,reference=REFERENCE,witness=witness)
        expected = []
        offset=0
        for values,raw in cases:
            n=struct.unpack_from("<Q",original_output,offset)[0]
            framed=original_output[offset:offset+n+8]
            offset+=n+8
            decoded=json.loads(framed[8:])
            self.assertEqual(decoded,values)
            self.assertEqual(list(decoded),[k for k,_ in FIELDS])
            expected.append(framed)
        self.assertEqual(offset,len(original_output))
        self.assertGreater(len(expected[3]),20000)
        values,valid=cases[0]
        bad_ascii=bytearray(cases[1][1])
        bad_ascii[24]=0xff
        long=packet({**values,"schema":"s"*257})
        wrong_u8=packet({**values,"activation_scale_power":256})
        shape=[b"TDV1",b"BAD!"+valid[4:],valid[:-1],valid+b"X",
               b"X"*4097,bad_ascii,long,wrong_u8]
        output,work=b"O"*32800,b"W"*32789
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as native:
                tests=[(raw,0,body) for (_,raw),body in zip(cases,expected,strict=True)]
                tests += [(bytes(raw),100,b"") for raw in shape]
                for i in range(0,len(tests),2):
                    group=tests[i:i+2]
                    batch=[("f0",[raw,output,work]) for raw,_,_ in group]
                    for (raw,status,body),reply in zip(group,native.call_many(batch),strict=True):
                        got=reply.require_returned()
                        self.assertEqual((got.value,got.arguments[:2]),(status,[raw,body+output[len(body):]]))
                        self.assertEqual(got.arguments[2][32776:],work[32776:])
                for o,w in ((output[:len(expected[0])-1],work),(output,work[:32775])):
                    got=native.call("f0",[valid,o,w]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(102,[valid,o]))
