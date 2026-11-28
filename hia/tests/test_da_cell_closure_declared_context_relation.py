"""Pure TCD1 declared relation, actual frozen Rust and both stock emitters."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cell_closure_declared_context_relation.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_closure_declared_context_relation_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/closure.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
LIMIT = 1024**2
WORK = 13944
DOMAIN = b"trnm.cell-dependency-closure.v1\0"


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (ORIGINAL, MANIFEST, LOCK, REFERENCE, CRATE / "src/cell/manifest.rs")
    before = tuple(sha(p.read_bytes()) for p in paths)
    rust_version = subprocess.run([rustc, "--version"], env=env, check=True, capture_output=True,
                                  text=True, timeout=10).stdout
    if not rust_version.startswith("rustc 1.95.0 (59807616e "):
        raise ValueError("expected original locked Rust 1.95.0")
    comp = subprocess.run([cargo, "build", "--locked", "--offline", "--manifest-path",
                           str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-data-availability",
                           "--lib", "--target-dir", str(target), "--message-format=json"],
                          env=env, check=True, capture_output=True, text=True, timeout=180)
    records = [v for v in map(json.loads, comp.stdout.splitlines())
               if v.get("reason") == "compiler-artifact"
               and v["target"]["name"] == "trnm_data_availability" and v["target"]["kind"] == ["lib"]]
    if len(records) != 1 or records[0]["features"] != ["default"]:
        raise ValueError("expected one actual unchanged original default-feature DA library")
    library, = (Path(x) for x in records[0]["filenames"] if x.endswith(".rlib"))
    library_sha = sha(library.read_bytes())
    exe = directory / "original-closure-context-relation"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    observed = subprocess.run([str(exe)], env=env, check=True, capture_output=True, timeout=25)
    if (not observed.stdout or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original closure context evidence")
    rows = []
    raw = observed.stdout
    cursor = 0
    while cursor < len(raw):
        length = struct.unpack_from("<I", raw, cursor)[0]
        pos = cursor+4
        end = pos+length
        if not (264 <= length <= LIMIT and end < len(raw)):
            raise ValueError("invalid original fixture extent")
        rows.append((raw[pos:end],raw[end]))
        cursor = end+1
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "manifest_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    return rows


def change(raw, at, value):
    return raw[:at]+value+raw[at+len(value):]


class CellClosureDeclaredContextRelation(unittest.TestCase):
    def test_actual_locked_original_declared_closure_relation_both_stock(self):
        with tempfile.TemporaryDirectory(prefix="trnm-closure-context-locked-") as tmp:
            rows=original_rows(Path(tmp))
        self.assertEqual(set(s for _,s in rows),{0,60,61,62,63,64})
        self.assertEqual([s for _,s in rows[-2:]],[0,64])
        raw=rows[0][0]
        tail=len(raw)-4-int.from_bytes(raw[-4:],"big")
        self.assertEqual(hashlib.sha256(DOMAIN+raw[:tail]).digest(),raw[tail+8:tail+40])
        invalid=(
            (b"",100),(raw[:-1],100),(change(raw,tail,b"BAD!"),100),
            (change(raw,len(raw)-4,b"\xff"*4),100),
            (change(raw,tail+96,bytes(2)),100),
            (change(raw,tail+260,b"\xff"),100),
            (change(raw,len(raw)-5,b"\x07"),100),
            (change(raw,0,b"BAD!"),3),
        )
        out,work=b"O"*19,b"W"*(WORK+11)
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),16):
                    sub=rows[at:at+16]
                    got=module.call_many([("f0",[value,out,work]) for value,_ in sub])
                    for (sent,status),result in zip(sub,got,strict=True):
                        self.assertEqual((result.status,result.value),("returned",status),at)
                        self.assertEqual(result.arguments[:2],[sent,out])
                        self.assertEqual(result.arguments[2][WORK:],work[WORK:])
                for value,status in invalid:
                    result=module.call("f0",[value,out,work])
                    self.assertEqual((result.status,result.value),("returned",status))
                    self.assertEqual(result.arguments[:2],[value,out])
                    self.assertEqual(result.arguments[2][WORK:],work[WORK:])
                short=module.call("f0",[raw,out,work[:WORK-1]])
                self.assertEqual((short.status,short.value),("returned",102))
                exact=module.call("f0",[rows[-2][0],b"",work[:WORK]])
                self.assertEqual((exact.status,exact.value),("returned",0))
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(invalid)+2,
                                  "original_status_counts":dict(Counter(s for _,s in rows))},
                                 sort_keys=True),flush=True)
