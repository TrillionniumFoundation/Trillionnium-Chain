"""Actual locked TCX1 immutable wire and identity; no retrieval or cache."""
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_cell_manifest import (
    MAX_CELL, MAX_CHUNK, MAX_ROWS, cases as manifest_cases, wire as manifest_wire,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cell_chunk_delta_value.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_chunk_delta_value_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/delta.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
DOMAIN = b"trnm.cell-chunk-delta.v1\0"
WORK = 1240
LIMIT = 44 + 1024**2 + MAX_ROWS*4
NEW = (1 << 32) - 1


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory, rows):
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
    exe = directory / "original-cell-chunk-delta-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I", len(row))+row for row in rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != 33 * len(rows) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original TCX1 value evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "manifest_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    output = []
    for i in range(0, len(observed.stdout), 33):
        status, *body = observed.stdout[i:i+33]
        record = bytes(body)
        if status and any(record):
            raise ValueError("nonzero original TCX1 rejection padding")
        output.append((status, record if not status else b""))
    return output


def frame(manifest, vector=(0, NEW), base=bytes(range(32)), *, length=None, count=None):
    return (b"TCX1" + base + struct.pack(">I", len(manifest) if length is None else length)
            + manifest + struct.pack(">I", len(vector) if count is None else count)
            + b"".join(struct.pack(">I", x) for x in vector))


def corpus():
    base = manifest_wire(b"Cell-1", opaque=True)
    nominal = frame(base)
    manifest_panel = manifest_cases()
    result = [(nominal, 0), (frame(base, (MAX_ROWS-1, MAX_ROWS-1)), 0)]
    for row,status in manifest_panel:
        count = int.from_bytes(row[209+row[4]:213+row[4]],"big") if status == 0 else 0
        result.append((frame(row, (NEW,)*count),status))
    result += [(b"",20), (nominal[:43],20), (b"T"* (LIMIT+1),20)]
    result += [(b"TCK1"+nominal[4:],21), (b"TCK1"+bytes(32)+nominal[36:],21),
               (frame(base,base=bytes(32),length=NEW),22),
               (frame(base,length=NEW),23), (frame(base,length=len(nominal)),23),
               (frame(b"",()),2), (frame(b"BOOM",(),count=NEW),3),
               (frame(base,count=NEW),24), (frame(base,count=0),24),
               (frame(base,(MAX_ROWS,)),24), (nominal+b"x",24), (nominal[:-1],24),
               (frame(base,(MAX_ROWS,0)),25), (frame(base,(0,NEW-1)),25),
               (nominal.ljust(MAX_EXTENT,b"\0"),24)]
    # Ordered indices, every base byte, and actual maximum original row count.
    result += [(frame(base,base=nominal[4:i]+bytes([nominal[i]^0x80])+nominal[i+1:36]),0)
               for i in range(4,36)]
    large = manifest_wire(b"A"*64,MAX_CELL-1,MAX_CHUNK)
    result += [(frame(large,(0,)*(MAX_ROWS-1)+(NEW,)),0),
               (frame(large,(0,)*(MAX_ROWS-1)+(MAX_ROWS,)),25)]
    rng = random.Random(0x54435831)
    for i in range(40):
        count = 1+i%10
        manifest = manifest_wire(f"Cell-{i}".encode(), size=16384*count-i%1024, opaque=True)
        vector = tuple(NEW if rng.randrange(3)==0 else rng.randrange(MAX_ROWS) for _ in range(count))
        result.append((frame(manifest,vector,rng.randbytes(32)),0))
    return result


class CellChunkDeltaValue(unittest.TestCase):
    def test_actual_locked_original_canonical_tcx1_and_identity_both_stock(self):
        panel = corpus()
        rows = [raw for raw, _ in panel]
        with tempfile.TemporaryDirectory(prefix="trnm-tcx1-value-locked-") as tmp:
            expected = original_rows(Path(tmp), rows)
        self.assertEqual([s for s,_ in expected], [s for _,s in panel])
        for raw,(status,digest) in zip(rows,expected,strict=True):
            if status == 0:
                self.assertEqual(digest,hashlib.sha256(DOMAIN+raw).digest())
        output,work = b"X"*47,b"W"*(WORK+13)
        for backend in ("selfhost", "direct"):
            extent = LIMIT + 1 if backend == "selfhost" else MAX_EXTENT
            comparable = [(raw, value) for raw, value in zip(rows, expected, strict=True)
                          if len(raw) <= extent]
            outside = [(raw, value) for raw, value in zip(rows, expected, strict=True)
                       if len(raw) > extent]
            self.assertEqual([value[0] for _, value in outside], [] if backend == "selfhost" else [20])
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                    backend=backend, max_input_extent=extent) as module:
                for raw, _ in outside:
                    # The fixed Direct fixture extent is not widened for an
                    # original rejection beyond even the outer wire limit.
                    with self.assertRaisesRegex(ValueError, "within the fixture extent"):
                        module.call("f0", [raw, output, work])
                for at in range(0, len(comparable), 4):
                    sub = comparable[at:at+4]
                    calls = module.call_many([("f0", [raw, output, work]) for raw, _ in sub])
                    for (raw, (status, digest)), got in zip(sub, calls, strict=True):
                        self.assertEqual((got.status,got.value),("returned",status))
                        self.assertEqual(got.arguments[0],raw)
                        self.assertEqual(got.arguments[1],digest+output[32:] if not status else output)
                        if status:
                            self.assertEqual(got.arguments[2],work)
                        else:
                            self.assertEqual(got.arguments[2][1208:1233],DOMAIN)
                            self.assertEqual(got.arguments[2][1240:],work[1240:])
                controls = [(rows[0],output[:31],work,102),(rows[0],output,work[:WORK-1],102),
                            (b"",b"",b"",20)]
                for raw,dst,scratch,status in controls:
                    got = module.call("f0",[raw,dst,scratch])
                    self.assertEqual((got.status,got.value),("returned",status))
                    self.assertEqual(got.arguments,[raw,dst,scratch])
                got = module.call("f0",[rows[0],output[:32],work[:WORK]])
                self.assertEqual((got.status,got.value,got.arguments[1]),("returned",0,expected[0][1]))
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(comparable),"abi_controls":len(controls)+1,"outside_fixture_extent":len(outside)},
                                 sort_keys=True),flush=True)
