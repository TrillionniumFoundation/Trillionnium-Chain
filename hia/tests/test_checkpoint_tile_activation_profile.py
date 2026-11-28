"""Frozen original activation metadata predicates on inert held typed strings."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE=ROOT/"hia/src/checkpoint/tile_activation_profile.hepta"
REFERENCE=Path(__file__).with_name("rust_checkpoint_tile_activation_profile_reference.rs")
WORK=384

WITNESS=b"""
pub(super) fn activation_profile_witness(
    expected: [u8;32], n: &[u64], f: &[&str],
) -> MaterialResult<(usize,Vec<u8>)> {
    let fixture=serde_json::json!({
       "schema":f[0],"checkpoint_sha256":f[1],"dtype":f[2],"activation_origin":f[3],"scope":f[4],
       "producer_script_sha256":f[5],"prompt_utf8_sha256":f[6],
       "shape":[1,1,576],"token_ids":[0],"attention_mask":[1],"positions":[0],
       "hidden_hex":"00".repeat(2304),
       "runtime":{
          "material_manifest_sha256":f[7],"device":f[8],"storage_dtype":f[9],
          "python":f[10],"torch":f[11],"transformers":f[12],"safetensors":f[13],"numpy":f[14],
          "threads":n[0],"forward_calls":n[1],"hook_calls":n[2],"parameter_count":n[3],
          "base_only":n[4]&1!=0,"training":n[4]&2!=0,"local_files_only":n[4]&4!=0,
          "trust_remote_code":n[4]&8!=0
       }
    });
    let raw=serde_json::to_vec(&fixture).unwrap();
    let context=PinnedTileContextV1 {
        network:[1;32],parameters:[2;32],checkpoint_sha256:expected,
        checkpoint_bytes:10, activation_sha256:sha(&raw),model:[7;32],input:[8;32],
    };
    let mut callback=|_: MaterialProgress| Ok(());
    let observed=Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    activation(&raw,&context,&observed)
}
"""

FIELDS=[b"checkpoint-qproj-postnorm-activation-v1",b"03"*32,b"F32LE",
        b"actual-layer0-q_proj-prehook-post-RMSNorm",
        b"observed CPU base-model hook; no independent full-forward proof or source authority",
        b"04"*32,b"05"*32,b"06"*32,b"cpu",b"float32",
        b"fixture-python",b"fixture-torch",b"fixture-transformers",b"fixture-safetensors",b"fixture-numpy"]
NUMS=[2,1,1,134515008,5]


def packet(text=None, numbers=None, expected=b"\x03"*32):
    text=FIELDS if text is None else text
    numbers=NUMS if numbers is None else numbers
    return (b"TAP1\0\0\0\0"+expected+struct.pack("<5Q",*numbers)
            +struct.pack("<15Q",*map(len,text))+b"".join(text))


class CheckpointTileActivationProfileTests(unittest.TestCase):
    def test_original_frozen_typed_profile_and_static_fields_both_native(self):
        rows=[]
        def row(status, changes=None, nums=None, expected=b"\x03"*32):
            fields=FIELDS.copy()
            for i,new in (changes or {}).items():
                fields[i]=new
            numbers=NUMS.copy()
            for i,new in (nums or {}).items():
                numbers[i]=new
            rows.append((status,packet(fields,numbers,expected)))
        row(0)
        row(0,{5:b"00"*32,6:b"00"*32,7:b"00"*32,10:"é".encode()*64})
        row(1,{0:b"wrong",1:b"F"})
        row(2,{1:b"F"*64,2:b"wrong"})
        row(2,{1:b"ab"*31+b"aF"},expected=b"\0"*32)
        row(1,{1:b"07"*32,5:b"F"})
        row(1,expected=b"\x07"*32)
        for i in (2,3,4):
            row(1,{i:b"wrong",5:b"F"})
        for i in (5,6,7):
            row(2,{i:b"00"*31+b"0F",8:b"wrong"})
            row(2,{i:b""})
        for i in (8,9):
            row(3,{i:b"wrong"})
        for i in range(10,15):
            row(3,{i:b""})
            row(3,{i:b"x"*129})
        for i in range(4):
            row(3,nums={i:NUMS[i]+1})
        for flag in (1,2,4,8):
            row(3,nums={4:NUMS[4]^flag})
        stimulus=b"".join(struct.pack("<I",len(f))+f for _,f in rows)
        with tempfile.TemporaryDirectory(prefix="trnm-checkpoint-act-profile-") as tmp:
            raw=original(Path(tmp),stimulus,reference=REFERENCE,witness=lambda _:WITNESS)
        self.assertEqual([x for x, in struct.iter_unpack("<I",raw)],[s for s,_ in rows])
        f=rows[0][1]
        bad=[f[:-1],f+b"X",b"TAP2"+f[4:],f[:72]+struct.pack("<Q",16)+f[80:],
             packet([*FIELDS[:-1],b"x"*257]),packet([*FIELDS[:-1],b"\xff"])]
        o,w=b"unchanged",b"K"*(WORK+7)
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                SOURCE,byte_exports=("f0",),backend=backend,
            ) as native:
                cases=rows+[(100,x) for x in bad]
                calls=[("f0",[f,o,w]) for _,f in cases]
                for (status,f),call in zip(cases,native.call_many(calls),strict=True):
                    g=call.require_returned()
                    self.assertEqual((g.value,g.arguments[:2]),(status,[f,o]))
                    self.assertEqual(g.arguments[2][WORK:],w[WORK:])
                args=[f,o,w[:WORK-1]]
                g=native.call("f0",args).require_returned()
                self.assertEqual((g.value,g.arguments),(102,args))
