"""Locked original Hepta handoff value hashing and exact dual native CBOR bytes."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute

ROOT=Path(__file__).resolve().parents[2]
RUST=ROOT/"trillionnium"
SOURCE=ROOT/"hia/src/research_protocol/hepta_artifact_value.hepta"
ADAPTER=Path(__file__).with_name("rust_research_hepta_artifact_value_reference.rs")
OUT,WORK,FRAME=520,1792,456
DOMAIN=b"trnm-hepta-artifact-admission-v1"


def locked_original(tmp, adapter=ADAPTER):
    git=["git","-C",ROOT]
    if execute([*git,"rev-parse","HEAD:trillionnium"]).stdout.strip()!=b"563bb7e471b3db278d50feceb3cbac7de4ab281a":
        raise ValueError("Wrong immutable original workspace")
    execute([*git,"diff","--quiet","HEAD","--","trillionnium"])
    requested=os.environ.get("TRNM_HIA_RUSTC","rustc")
    pin=tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version=execute([requested,"--version"]).stdout
    sysroot=Path(execute([requested,"--print","sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc,cargo=sysroot/"bin/rustc",sysroot/"bin/cargo"
    if version.decode().split()[1]!=pin or execute([rustc,"--version"]).stdout!=version:
        raise ValueError("Wrong original compiler")
    target=tmp/"target"
    package=RUST/"crates/trnm-research-protocol"
    env={**os.environ,"RUSTC":str(rustc),"CARGO_BUILD_JOBS":"1",
         "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0"}
    run=execute([cargo,"build","--locked","--offline","--lib","-p","trnm-research-protocol",
                 "--manifest-path",RUST/"Cargo.toml","--target-dir",target,"--message-format=json"],
                env=env,timeout=240)
    events=[json.loads(line) for line in run.stdout.splitlines()]
    [artifact]=[a for a in events if a.get("reason")=="compiler-artifact"
                and a["target"]["name"]=="trnm_research_protocol" and "lib" in a["target"]["kind"]]
    if (events[-1]!={"reason":"build-finished","success":True} or artifact["fresh"]
            or artifact["features"] or Path(artifact["manifest_path"])!=package/"Cargo.toml"
            or Path(artifact["target"]["src_path"])!=package/"src/lib.rs"):
        raise ValueError("Wrong original library provenance")
    [rlib]=[p for p in artifact["filenames"] if p.endswith(".rlib")]
    if not Path(rlib).is_relative_to(target):
        raise ValueError("Wrong Cargo artifact path")
    program=tmp/"hepta-artifact-value-original"
    execute([rustc,"--edition=2021","-Dwarnings",adapter,"-L",f"dependency={target/'debug/deps'}",
             "--extern",f"trnm_research_protocol={rlib}","-o",program],env=env,timeout=60)
    return execute([program]).stdout


class HeptaArtifactValueTests(unittest.TestCase):
    def test_exact_public_original_bytes_and_digest_with_both_native_emitters(self):
        with tempfile.TemporaryDirectory(prefix="trnm-hepta-artifact-value-") as folder:
            raw=locked_original(Path(folder))
        rows=[]
        while raw:
            n=struct.unpack_from("<Q",raw,FRAME+32)[0]
            end=FRAME+40+n
            cbor=raw[FRAME+40:end]
            self.assertEqual((cbor[:2],len(cbor)),(b"\x92\x01",n))
            original=raw[FRAME:FRAME+32]
            self.assertEqual(original,sha256(b"TRNM_RESEARCH_PROTOCOL_HASH_V1\0"+
                len(DOMAIN).to_bytes(4,"big")+DOMAIN+n.to_bytes(8,"big")+cbor).digest())
            rows.append((raw[:FRAME],raw[FRAME:end]))
            raw=raw[end:]
        self.assertEqual(len(rows),9)
        self.assertEqual(len(rows[6][1]),520)
        self.assertEqual(len(set(out[:32] for _,out in rows)),9)
        self.assertEqual(rows[0][1][40+172],246) # None
        self.assertEqual(rows[1][1][40+172:40+174],b"\x58\x20") # Some
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native:
                out,work=b"O"*(OUT+8),b"W"*(WORK+8)
                pairs=[("f0",[inp,out,work]) for inp,_ in rows]
                for result,(inp,expected) in zip(native.call_many(pairs),rows,strict=True):
                    got=result.require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(0,[inp,expected+out[len(expected):]]))
                    self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                inp=rows[0][0]
                cases=[([inp[:-1],out,work],100),([inp+b"x",out,work],100),
                       ([b"BAD!"+inp[4:],out,work],100),([inp[:4]+b"\x02"+inp[5:],out,work],100),
                       ([inp[:5]+b"\x01"+inp[6:],out,work],100),
                       ([inp,out[:OUT-1],work],102),([inp,out,work[:WORK-1]],102)]
                for args,code in cases:
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(code,args))
