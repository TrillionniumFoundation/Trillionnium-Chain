"""Exact original immutable object/alias/declared capacity subrelation."""
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
SOURCE = ROOT / "hia/src/data_availability/cell_version_retention_object_relation.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_version_retention_object_relation_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/version_retention.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
LIMIT = 1024**2
WORK = 4104


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (ORIGINAL, MANIFEST, LOCK, REFERENCE, CRATE / "src/cell/retention.rs")
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
    exe = directory / "original-version-retention-objects"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    observed = subprocess.run([str(exe)], env=env, check=True, capture_output=True, timeout=25)
    if (not observed.stdout or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original version object evidence")
    rows = []
    raw = observed.stdout
    cursor = 0
    while cursor < len(raw):
        length = struct.unpack_from("<I", raw, cursor)[0]
        pos = cursor+4
        end = pos+length
        if not (132 <= length <= LIMIT and end < len(raw)):
            raise ValueError("invalid original fixture extent")
        rows.append((raw[pos:end],raw[end]))
        cursor = end+1
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "retention_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    return rows


def change(data, offset, value):
    return data[:offset]+value+data[offset+len(value):]


class CellVersionRetentionObjectRelation(unittest.TestCase):
    def test_actual_locked_original_ordered_objects_and_declared_capacity_both_stock(self):
        with tempfile.TemporaryDirectory(prefix="trnm-retention-object-locked-") as tmp:
            rows = original_rows(Path(tmp))
        self.assertEqual(set(status for _,status in rows),{0,*range(20,28)})
        biggest = max((row for row,s in rows if s==0),key=len)
        self.assertEqual(struct.unpack_from(">HH",biggest,128),(512,512))
        self.assertEqual(int.from_bytes(biggest[40:48],"big"),512*4096)
        high = [(d,s) for d,s in rows if len(d)>=len(biggest)]
        self.assertEqual([s for _,s in high],[0,27])
        good=rows[0][0]
        n=int.from_bytes(good[132:136],"big")
        flag=136+n+88
        outer=(b"",good[:131],b"X"+good[1:],good[:-1],good+b"X",
               change(good,132,bytes([255])*4),change(good,flag,b"\x02"))
        out,work=b"O"*23,b"W"*(WORK+7)
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as mod:
                for at in range(0,len(rows),4):
                    sub=rows[at:at+4]
                    got=mod.call_many([("f0",[raw,out,work]) for raw,_ in sub])
                    for (raw,status), result in zip(sub,got,strict=True):
                        self.assertEqual((result.status,result.value),("returned",status),at)
                        self.assertEqual(result.arguments[:2],[raw,out])
                        self.assertEqual(result.arguments[2][WORK:],work[WORK:])
                for raw in outer:
                    r=mod.call("f0",[raw,out,work])
                    self.assertEqual((r.status,r.value),("returned",100))
                    self.assertEqual(r.arguments[:2],[raw,out])
                    self.assertEqual(r.arguments[2][WORK:],work[WORK:])
                short=mod.call("f0",[good,b"",work[:WORK-1]])
                self.assertEqual((short.status,short.value,short.arguments),("returned",102,[good,b"",work[:WORK-1]]))
                exact=mod.call("f0",[biggest,b"",work[:WORK]])
                self.assertEqual((exact.status,exact.value),("returned",0))
                print(json.dumps({"backend":backend,"artifact_sha256":mod.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(outer)+2,
                                  "original_status_counts":dict(Counter(s for _,s in rows))},
                                  sort_keys=True),flush=True)
