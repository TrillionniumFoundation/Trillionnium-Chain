"""Bounded post-JSON activation value differential, not original pin/provenance."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE=ROOT/"hia/src/checkpoint/tile_activation_value.hepta"
REFERENCE=Path(__file__).with_name("rust_checkpoint_tile_activation_value_reference.rs")

# Compiled with the original entire unchanged module. Surrounding fields are
# inert oracle prerequisites only; no actual observed runtime or material.
WITNESS=b"""
pub(super) fn activation_value_witness(
    shape: [u64;3], ids: Vec<u64>, mask: Vec<u64>, pos: Vec<u64>, hidden: &str,
) -> MaterialResult<(usize, Vec<u8>)> {
    let fixture = serde_json::json!({
        "schema":"checkpoint-qproj-postnorm-activation-v1", "checkpoint_sha256":hex::encode([3;32]),
        "dtype":"F32LE", "shape":shape, "token_ids":ids, "attention_mask":mask, "positions":pos,
        "hidden_hex":hidden, "producer_script_sha256":hex::encode([4;32]),
        "prompt_utf8_sha256":hex::encode([5;32]), "activation_origin":ORIGIN, "scope":SCOPE,
        "runtime":{
            "device":"cpu", "python":"synthetic", "torch":"synthetic", "transformers":"synthetic",
            "safetensors":"synthetic", "numpy":"synthetic", "threads":2, "base_only":true,
            "training":false, "local_files_only":true, "trust_remote_code":false,
            "forward_calls":1, "hook_calls":1, "parameter_count":134515008,
            "storage_dtype":"float32", "material_manifest_sha256":hex::encode([6;32])
        }
    });
    let raw=serde_json::to_vec(&fixture).unwrap();
    let context=PinnedTileContextV1 {
        network:[1;32], parameters:[2;32], checkpoint_sha256:[3;32], checkpoint_bytes:10,
        activation_sha256:sha(&raw), model:[7;32], input:[8;32],
    };
    let mut callback=|_: MaterialProgress| Ok(());
    let observed=Rc::new(RefCell::new(Observer {
        callback:&mut callback, first_error:None, checkpoint_bytes_read:0,
    }));
    activation(&raw,&context,&observed)
}
"""


def frame(n, shape=None, ids=None, mask=None, pos=None, hidden=None):
    shape=(1,n,576) if shape is None else shape
    ids=[0]+[49151]*(n-1) if ids is None else ids
    mask=[1]*n if mask is None else mask
    pos=list(range(n)) if pos is None else pos
    if hidden is None:
        # Inert bit patterns, including nonfinite bits: this layer decodes
        # without granting numeric validity. Assembly checks all exponents.
        hidden=b"00000000000000c0ffff7f7f010080ff"*144*n
    result=b"TAV1\0\0\0\0"+struct.pack("<7Q",*shape,len(ids),len(mask),len(pos),len(hidden))
    for a in (ids,mask,pos):
        result+=struct.pack(f"<{len(a)}Q",*a)
    return result+hidden


class CheckpointTileActivationValueTests(unittest.TestCase):
    def test_original_private_activation_shape_tokens_and_hex_two_stock(self):
        f1,f2,f64=(frame(n) for n in (1,2,64))
        cases=[f1,f2,f64,
               frame(1,shape=(2,1,576),ids=[49152],hidden=b"F"),
               frame(1,shape=(1,1,575)),
               frame(1,shape=(1,0,576)),frame(1,shape=(1,65,576)),
               frame(1,ids=[]),frame(1,ids=[49152],hidden=b"F"),frame(2,mask=[1,0]),
               frame(2,pos=[1,0]),frame(2,pos=[0]),frame(1,hidden=b"0"*4607),
               frame(1,hidden=b"0"*4607+b"F"),frame(1,hidden=b"0"*4606+"λ".encode())]
        stimulus=b"".join(struct.pack("<I",len(f))+f for f in cases)
        with tempfile.TemporaryDirectory(prefix="trnm-checkpoint-tile-act-") as tmp:
            oracle=original(Path(tmp),stimulus,reference=REFERENCE,witness=lambda _:WITNESS)
        rows=[]
        while oracle:
            s,n=struct.unpack_from("<II",oracle)
            self.assertGreaterEqual(len(oracle),8+n)
            rows.append((s,oracle[8:8+n]))
            oracle=oracle[8+n:]
        self.assertEqual([s for s,_ in rows],[0,0,0]+[1]*4+[2]*5+[3]*3)
        self.assertEqual([len(v) for _,v in rows[:3]],[2312,4616,147464])
        self.assertEqual(len(f64),296512)
        self.assertEqual(rows[0][1][8:24],bytes.fromhex("00000000000000c0ffff7f7f010080ff"))
        invalid=[f1[:-1],f1+b"!",b"TAV2"+f1[4:],
                 f1[:32]+struct.pack("<Q",65)+f1[40:]]
        o,w=b"X"*147472,b"unused"
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,byte_exports=("f0",),backend=backend,
            ) as native:
                tests=list(zip(cases,rows,strict=True))+[(f,(100,b"")) for f in invalid]
                for f,(status,value) in tests:
                    g=native.call("f0",[f,o,w]).require_returned()
                    self.assertEqual((g.value,g.arguments),(status,[f,value+o[len(value):],w]))
                args=[f1,o[:2311],w]
                g=native.call("f0",args).require_returned()
                self.assertEqual((g.value,g.arguments),(102,args))
