"""Actual locked M09 CPS1 immutable value; no scheduler, store, or authority."""
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cell_periodic_snapshot_policy.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_periodic_snapshot_policy_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/snapshot_schedule.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
TAG = b"CPS1"
DOMAIN = b"trnm.cell-periodic-snapshot-policy.v1\0"
WORK = 1398
OUT = 184
I64 = (1 << 63) - 1
U64 = (1 << 64) - 1


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory, rows):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (ORIGINAL, MANIFEST, LOCK, REFERENCE)
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
    exe = directory / "original-cps1-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<H", len(row))+row for row in rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != 185 * len(rows) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original CPS1 value evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    output = []
    for i in range(0, len(observed.stdout), 185):
        status, *body = observed.stdout[i:i+185]
        record = bytes(body)
        if status and any(record):
            raise ValueError("nonzero original CPS1 rejection padding")
        output.append((status, record if not status else b""))
    return output


def frame(first=7, spacing=12, count=17, digests=None):
    values = tuple(bytes([i])*32 for i in (1, 2, 3, 4)) if digests is None else digests
    return TAG + b"".join(values) + struct.pack(">QQI", first, spacing, count)


def corpus():
    baseline = frame()
    records = [(b"", 100), (baseline[:-1], 100), (baseline+b"Y", 100),
               (b"CPS2"+baseline[4:], 100), (baseline, 0)]
    for index in range(4):
        at = 4+32*index
        records += [(baseline[:at]+bytes(32)+baseline[at+32:], 101),
                    (baseline[:at]+bytes(31)+b"\x01"+baseline[at+32:], 0),
                    (baseline[:at]+b"\x01"+bytes(31)+baseline[at+32:], 0)]
    # Every identity byte must remain in the commitment transcript.
    records += [(baseline[:i]+bytes([baseline[i]^0x80])+baseline[i+1:], 0)
                for i in range(4, 132)]
    for first, spacing, count, status in (
        (0, 0, 0, 102), (1, 0, 1, 102), (1, 1, 0, 102), (1, 1, 128, 102),
        (1, 1, (1<<32)-1, 102), (I64+1, 0, 128, 102), (I64, U64, 1, 0),
        (I64+1, U64, 1, 103), (U64, 1, 1, 103), (I64-1, 1, 2, 0),
        (I64, 1, 2, 103), (I64-1, 2, 2, 103), (1, U64, 2, 103),
        (1, U64, 3, 103), (1, U64//2, 3, 103), (1, 1, 127, 0),
    ):
        records.append((frame(first, spacing, count), status))
    for count in (2, 3, 63, 127):
        for first in (1, 15, (1 << 31)+7, 1 << 62):
            ceiling = (I64-first)//(count-1)
            records.extend((frame(first, w, count), status)
                           for w, status in ((ceiling-1, 0), (ceiling, 0), (ceiling+1, 103)))
    rng = random.Random(0x43505331)
    for _ in range(30):
        first, count = rng.randrange(1,I64), rng.randrange(2,128)
        edge = (I64-first)//(count-1)
        digests = tuple(rng.randbytes(32) for _ in range(4))
        records += [(frame(first, rng.randrange(1,edge+1), count, digests), 0),
                    (frame(first, edge+1, count, digests), 103)]
    return records


class CellPeriodicSnapshotPolicyValue(unittest.TestCase):
    def test_real_original_cps1_encode_decode_and_both_stock_emitters(self):
        cases = corpus()
        rows = [x for x, _ in cases]
        with tempfile.TemporaryDirectory(prefix="trnm-cps1-locked-original-") as tmp:
            expected = original_rows(Path(tmp), rows)
        self.assertEqual([code for code, _ in expected], [code for _, code in cases])
        for (status, result), (raw, _) in zip(expected,cases,strict=True):
            self.assertEqual(result, raw + hashlib.sha256(DOMAIN+raw).digest() if status==0 else b"")
        good = frame()
        invalid = frame(0, 17, 4)
        out, work = b"O"*(OUT+9), b"S"*(WORK+13)
        controls = (
            (good, out[:OUT-1], work, 104), (good, out, work[:WORK-1], 104),
            (good, b"", b"", 104), (invalid, b"", b"", 102), (b"\0", b"", b"", 100),
        )
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),16):
                    sub = rows[at:at+16]
                    actual = module.call_many([("f0",[row,out,work]) for row in sub])
                    for raw, got, (status, output) in zip(sub,actual,expected[at:at+16],strict=True):
                        self.assertEqual((got.status,got.value), ("returned",status))
                        self.assertEqual(got.arguments[:2], [raw,output+out[len(output):]])
                        scratch = got.arguments[2]
                        self.assertEqual(scratch if status else scratch[WORK:],work if status else work[WORK:])
                        if status==0:
                            self.assertEqual(scratch[1208:WORK],DOMAIN+raw)
                for raw, output, scratch, status in controls:
                    got = module.call("f0",[raw,output,scratch])
                    self.assertEqual((got.status,got.value),("returned",status))
                    self.assertEqual(got.arguments,[raw,output,scratch])
                result = module.call("f0",[good,out[:OUT],work[:WORK]])
                self.assertEqual((result.status,result.value),("returned",0))
                self.assertEqual(result.arguments[1],good+hashlib.sha256(DOMAIN+good).digest())
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(controls)+1},
                                 sort_keys=True),flush=True)
