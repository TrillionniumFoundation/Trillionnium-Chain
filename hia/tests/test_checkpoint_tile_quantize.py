"""Exact original integer BF16/F32LE quantization without material construction."""
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_policy_value import ROOT, ORIGINAL, CARGO_LOCK
from hia.tests.test_settlement_schema_read import execute

LEGACY = ROOT/"trillionnium"
MATERIAL = LEGACY/"crates/trnm-mvcc-fee/src/checkpoint_tile_material_v1.rs"
MATERIAL_SHA = "6643eb9536eacbc2a29a463ca76ded72d8c06669f889cbd750499be473db1720"
SOURCE = ROOT/"hia/src/checkpoint/tile_quantize.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_quantize_reference.rs")
# The source prefix is retained verbatim. Only this test forwarding function is appended.
WITNESS = b"""
pub(super) fn quantize_witness(bits: u32, profile: u8) -> MaterialResult<(i64, bool)> {
    match profile {
        1 => quantize(bits, 7, 14, 32767),
        2 => quantize(bits, 23, 4, 128),
        _ => unreachable!(),
    }
}
"""


def original(directory, stimulus, *, reference=REFERENCE, witness=None):
    git = ['git','-C',ROOT]
    if execute([*git,'rev-parse','HEAD:trillionnium']).stdout.decode().strip() != ORIGINAL:
        raise ValueError("Wrong frozen Rust tree")
    execute([*git,'diff','--quiet','HEAD','--','trillionnium'])
    original_source = MATERIAL.read_bytes()
    if (hashlib.sha256(original_source).hexdigest()!=MATERIAL_SHA
            or hashlib.sha256((LEGACY/'Cargo.lock').read_bytes()).hexdigest()!=CARGO_LOCK):
        raise ValueError("Original quantization source or lock differs")
    requested = os.environ.get("TRNM_HIA_RUSTC","rustc")
    channel = tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = execute([requested,"--version"]).stdout
    sysroot = Path(execute([requested,"--print","sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc,cargo = sysroot/"bin/rustc",sysroot/"bin/cargo"
    if version.decode().split()[1] != channel or execute([rustc,"--version"]).stdout != version:
        raise ValueError("Wrong original toolchain")
    target=directory/"target"
    env={**os.environ,"RUSTC":str(rustc),"CARGO_BUILD_JOBS":"1",
         "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0"}
    log=execute([cargo,"build","--locked","--offline","--no-default-features","--lib",
                 "-p","trnm-mvcc-fee","--manifest-path",LEGACY/"Cargo.toml",
                 "--target-dir",target,"--message-format=json"],env=env,timeout=360).stdout
    events=[json.loads(line) for line in log.splitlines()]
    if events[-1] != {"reason":"build-finished","success":True}:
        raise ValueError("Locked original build not observed")
    sources={
        "serde":None,"serde_json":None,"sha2":None,"hex":None,
        "trnm_crypto_primitives":LEGACY/"crates/trnm-crypto-primitives/Cargo.toml",
        "trnm_protocol":LEGACY/"crates/trnm-protocol/Cargo.toml",
    }
    versions={"serde":"1.0.229","serde_json":"1.0.149","sha2":"0.10.9","hex":"0.4.3"}
    extern=[]
    for name, manifest in sources.items():
        [event]=[x for x in events if x.get("reason")=="compiler-artifact"
                 and x["target"]["name"]==name and "lib" in x["target"]["kind"]
                 and (name not in versions or x["package_id"].endswith("@"+versions[name]))
                 and (name!="serde" or "derive" in x["features"])]
        if event["fresh"] or (manifest and Path(event["manifest_path"])!=manifest):
            raise ValueError(f"Wrong locked original dependency: {name}")
        [lib]=[Path(p) for p in event["filenames"] if p.endswith(".rlib")]
        if not lib.is_relative_to(target):
            raise ValueError("Original library outside private target")
        extern+=["--extern",f"{name}={lib}"]
    frozen=directory/"frozen_tile_material.rs"
    appended=WITNESS if witness is None else witness(original_source)
    frozen.write_bytes(original_source+appended)
    adapter=directory/"quantize_reference.rs"
    adapter.write_bytes(reference.read_bytes())
    exe=directory/"quantize_reference"
    execute([rustc,"--edition=2021",adapter,"-L",f"dependency={target/'debug/deps'}",
             *extern,"-o",exe],env=env,timeout=90)
    if frozen.read_bytes()!=original_source+appended or MATERIAL.read_bytes()!=original_source:
        raise ValueError("Frozen original source changed")
    return execute([exe],input=stimulus).stdout


def packet(mode, values):
    return (b"TQ16\0\0\0\0" if mode==1 else b"TQ32\0\0\0\0")+(
        struct.pack("<Q",len(values))+struct.pack(f"<{len(values)}{'H' if mode==1 else 'I'}",*values))


class CheckpointTileQuantizeTests(unittest.TestCase):
    def test_frozen_original_exhaustive_bf16_and_f32_boundaries_two_stock(self):
        bf16=list(range(1<<16))
        # Two signs, all exponents with exact mantissa edges, and fixed random bits.
        f32=[(s<<31)|(e<<23)|m for s in (0,1) for e in range(256)
             for m in (0,1,(1<<22)-1,1<<22,(1<<23)-1)]
        rng=random.Random(0x51554e54)
        f32 += [rng.getrandbits(32) for _ in range(1024)]
        # Exact half-step ties and one representable float on either side.
        for k in [0,1,2,3,126,127,128,129]:
            for s in (1,-1):
                b=struct.unpack("<I",struct.pack("<f",s*(k+0.5)/16))[0]
                f32.extend((b-1,b,b+1))
        stimulus=b"".join(struct.pack("<BI",m,v) for m,values in ((1,bf16),(2,f32)) for v in values)
        with tempfile.TemporaryDirectory(prefix="trnm-checkpoint-tile-quant-") as temp:
            actual=original(Path(temp),stimulus)
        self.assertEqual(len(actual),16*(len(bf16)+len(f32)))
        got_bf16=actual[:16*len(bf16)]
        self.assertEqual(struct.unpack_from("<qQ",got_bf16,16*0x3f80),(16384,0))
        self.assertEqual(struct.unpack_from("<qQ",got_bf16,16*0x4000),(32767,1))
        self.assertEqual(struct.unpack_from("<qQ",got_bf16,16*0x7f80),(0,2))
        self.assertEqual(sum(code==2 for _,code in struct.iter_unpack("<qQ",got_bf16)),256)
        f=packet(1,[0x3f80])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                SOURCE,byte_exports=("f0",),backend=backend,
            ) as native:
                pos=0
                for mode,values in ((1,bf16),(2,f32)):
                    for at in range(0,len(values),4096):
                        block=values[at:at+4096]
                        raw=packet(mode,block)
                        cut=pos+16*len(block)
                        result=actual[pos:cut]
                        pos=cut
                        out=b"Y"*(len(result)+9)
                        g=native.call("f0",[raw,out,b"W"]).require_returned()
                        self.assertEqual((g.value,g.arguments),(0,[raw,result+b"Y"*9,b"W"]))
                self.assertEqual(pos,len(actual))
                for raw,out,st in ((f[:-1],17,100),(f+b"x",17,100),
                                   (packet(1,[]),17,100),(packet(1,[0]*4097),16,100),
                                   (b"TQ64"+f[4:],17,100),(f,15,102)):
                    args=[raw,b"Y"*out,b"W"]
                    g=native.call("f0",args).require_returned()
                    self.assertEqual((g.value,g.arguments),(st,args))
