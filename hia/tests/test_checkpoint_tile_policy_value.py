"""Exact public maintenance-only immutable checkpoint policy value, no execution."""
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/checkpoint/tile_policy_value.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_policy_value_reference.rs")
LEGACY = ROOT / "trillionnium"
ORIGINAL = "563bb7e471b3db278d50feceb3cbac7de4ab281a"
CARGO_LOCK = "86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e"


def original(directory):
    git = ['git','-C',ROOT]
    if execute([*git,'rev-parse','HEAD:trillionnium']).stdout.decode().strip() != ORIGINAL:
        raise ValueError("Wrong frozen Rust workspace")
    execute([*git,'diff','--quiet','HEAD','--','trillionnium'])
    if hashlib.sha256((LEGACY/'Cargo.lock').read_bytes()).hexdigest() != CARGO_LOCK:
        raise ValueError("Wrong frozen Cargo graph")
    requested = os.environ.get("TRNM_HIA_RUSTC","rustc")
    channel = tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = execute([requested,"--version"]).stdout
    sysroot = Path(execute([requested,"--print","sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc,cargo = sysroot/"bin/rustc",sysroot/"bin/cargo"
    if version.decode().split()[1] != channel or execute([rustc,"--version"]).stdout != version:
        raise ValueError("Wrong original toolchain")
    target = directory/"target"
    manifest = LEGACY/"crates/trnm-mvcc-fee/Cargo.toml"
    env = {**os.environ,"RUSTC":str(rustc),"CARGO_BUILD_JOBS":"1",
           "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0"}
    log = execute([cargo,"build","--locked","--offline","--no-default-features","--lib",
                   "-p","trnm-mvcc-fee","--manifest-path",LEGACY/"Cargo.toml",
                   "--target-dir",target,"--message-format=json"],env=env,timeout=360).stdout
    events = [json.loads(line) for line in log.splitlines()]
    if events[-1] != {"reason":"build-finished","success":True}:
        raise ValueError("Native oracle did not build")
    [m] = [e for e in events if e.get("reason") == "compiler-artifact"
           and e["target"]["name"] == "trnm_mvcc_fee" and "lib" in e["target"]["kind"]]
    if (m["fresh"] or m["features"] or Path(m["manifest_path"]) != manifest
            or Path(m["target"]["src_path"]) != manifest.parent/"src/lib.rs"):
        raise ValueError("Original linked package differs")
    [lib] = [Path(p) for p in m["filenames"] if p.endswith(".rlib")]
    if not lib.is_relative_to(target):
        raise ValueError("Original library escaped private target")
    exe=directory/"tile-policy-value-original"
    execute([rustc,"--edition=2021",REFERENCE,"-L",f"dependency={target/'debug/deps'}",
             "--extern",f"trnm_mvcc_fee={lib}","-o",exe],env=env,timeout=90)
    return execute([exe]).stdout


class CheckpointTilePolicyValueTests(unittest.TestCase):
    def test_original_context_free_maintenance_policy_value_and_id_two_native(self):
        with tempfile.TemporaryDirectory(prefix="checkpoint-tile-policy-value-") as temp:
            raw=original(Path(temp))
        rows=[]
        while raw:
            status,n=struct.unpack_from("<II",raw)
            frame,digest,wire=raw[8:590],raw[590:622],raw[622:622+n]
            self.assertEqual(len(wire),n)
            rows.append((status,frame,struct.pack("<Q",n)+digest+wire if n else b""))
            raw=raw[622+n:]
        self.assertEqual([c for c,_,_ in rows],[0,0,0,0,1,2,3,4,4,2,3,1])
        self.assertEqual(len({v for c,_,v in rows if not c}),4)
        f,expected=rows[0][1:]
        guards=[f[:-1],f+b"x",b"TPV2"+f[4:],
                f[:24]+struct.pack("<Q",128)+f[32:]]
        o,w=b"A"*1200,b"W"*4104
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                SOURCE,byte_exports=("f0",),backend=backend,
            ) as native:
                cases=rows+[(100,x,b"") for x in guards]
                calls=[("f0",[data,o,w]) for _,data,_ in cases]
                for call,(s,data,value) in zip(native.call_many(calls),cases,strict=True):
                    got=call.require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(s,[data,value+o[len(value):]]))
                    self.assertEqual(got.arguments[2][4096:],w[4096:])
                    if s:
                        self.assertEqual(got.arguments[2],w)
                for out,work in ((o[:len(expected)-1],w),(o,w[:4095])):
                    got=native.call("f0",[f,out,work]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(102,[f,out]))
