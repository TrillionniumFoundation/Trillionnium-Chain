"""Public original RootRecovery V3 policy and bootstrap checkpoint value parity."""
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

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/"hia/src/release_bundle/root_recovery_checkpoint_v3.hepta"
REFERENCE = ROOT/"hia/tests/rust_root_recovery_checkpoint_reference.rs"
BASE = ROOT/"trillionnium"
PINS = {
    "Cargo.lock": "86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e",
    "crates/trnm-release-bundle/Cargo.toml": "5fde65e85f21d1325b1868004e63f115ec8f48e966495dab6e3fbf9f79205e5e",
    "crates/trnm-release-bundle/src/lib.rs": "e41410d1151ad6edf17cfa20cf2a592baf9fc23225b78d6596c838fa9445b5ce",
    "crates/trnm-release-bundle/src/root_recovery_v3.rs": "06caa4741b9289c20d4f7cfc7377ad16b64cb10f7ca98fc10fdd0424631b6438",
    "crates/trnm-crypto-primitives/Cargo.toml": "5ab0c24b08430a326f58c9ce3aa4a85eef538c4b11b2cb08287e5201b41892de",
    "crates/trnm-crypto-primitives/src/lib.rs": "83fe52804bfbc593e2768c3a88764b532539deb8c9e866ee7305286491e16115",
    "crates/trnm-crypto-primitives/src/pq_root_v3.rs": "59fd7fb334161fd869237cfe35765747a6b9f675f070e3e617a24d11de2fe2c7",
}


def original(directory):
    for name,digest in PINS.items():
        if sha256((BASE/name).read_bytes()).hexdigest()!=digest:
            raise ValueError(f"Original RootRecovery value source differs: {name}")
    requested = os.environ.get("TRNM_HIA_RUSTC","rustc")
    channel = tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = execute([requested,"--version"]).stdout
    sysroot = Path(execute([requested,"--print","sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc,cargo = sysroot/"bin/rustc",sysroot/"bin/cargo"
    if version.decode().split()[1]!=channel or execute([rustc,"--version"]).stdout!=version:
        raise ValueError("Pinned original Rust toolchain required")
    target = directory/"target"
    env = {**os.environ,"RUSTC":str(rustc),"CARGO_BUILD_JOBS":"2"}
    raw = execute([cargo,"build","--locked","--offline","--manifest-path",BASE/"Cargo.toml",
                   "--target-dir",target,"-p","trnm-release-bundle","--features","pq-root-v3",
                   "--message-format=json"],env=env,timeout=180).stdout
    values = [json.loads(x) for x in raw.splitlines()]
    extern = []
    for name in ("trnm_release_bundle","trnm_crypto_primitives"):
        [event] = [r for r in values if r.get("reason")=="compiler-artifact"
                   and r["target"]["name"]==name and "lib" in r["target"]["kind"]]
        if Path(event["manifest_path"])!=BASE/"crates"/name.replace("_","-")/"Cargo.toml":
            raise ValueError("Wrong original value crate")
        [rlib] = [x for x in event["filenames"] if x.endswith(".rlib")]
        extern.extend(["--extern",f"{name}={rlib}"])
    exe = directory/"original-root-values"
    execute([rustc,"--edition=2021",REFERENCE,"-L",f"dependency={target/'debug/deps'}",
             *extern,"-o",exe],env=env,timeout=40)
    return execute([exe]).stdout


class RootRecoveryCheckpointTests(unittest.TestCase):
    def test_actual_original_policy_roster_admission_and_bootstrap_checkpoint(self):
        with tempfile.TemporaryDirectory(prefix="m15-root-recovery-values-") as temp:
            ref = original(Path(temp))
        rows = []
        while ref:
            status,n = struct.unpack_from("<II",ref)
            size = 0 if status else 128
            rows.append((ref[8:n+8],status,ref[n+8:n+8+size]))
            ref = ref[n+8+size:]
        self.assertEqual([s for _,s,_ in rows],[0,0,0,2,2,2,1,3,1,1,4,5,6,6,8,4,2,5,0,0,2,0,0])
        self.assertEqual(rows[0][2][:64],rows[1][2][:64])
        self.assertNotEqual(rows[0][2][64:],rows[1][2][64:])
        self.assertNotEqual(rows[0][2][:64],rows[2][2][:64])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as native:
                args = [[inp,b"X"*136,b"Y"*132264] for inp,_,_ in rows]
                for (inp,status,result),call,arg in zip(rows,native.call_many([("f0",a) for a in args]),
                                                          args,strict=True):
                    got=call.require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),(status,[inp,result+arg[1][len(result):]]))
                    self.assertEqual(got.arguments[2][132256:],arg[2][132256:])
                for out,work in ((127,132256),(128,132255)):
                    a=[rows[0][0],b"X"*out,b"Y"*work]
                    got=native.call("f0",a).require_returned()
                    self.assertEqual((got.value,got.arguments),(102,a))
