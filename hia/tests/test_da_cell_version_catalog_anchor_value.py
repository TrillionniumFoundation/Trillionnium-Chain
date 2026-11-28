"""Actual immutable original CVA3 oracle and both pinned emitters."""
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
SOURCE = ROOT / "hia/src/data_availability/cell_version_catalog_anchor_value.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_version_catalog_anchor_value_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/version_retention.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
TAG = b"CVA3"
LENGTH = 84
DIGEST = bytes(range(32))


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory, rows):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (ORIGINAL, MANIFEST, LOCK, REFERENCE, CRATE / "src/cell/version_retention/codec.rs")
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
    exe = directory / "original-cva3-anchor-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I", len(row))+row for row in rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != 85 * len(rows) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original CVA3 value evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "codec_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    output = []
    for i in range(0, len(observed.stdout), 85):
        status, *body = observed.stdout[i:i+85]
        record = bytes(body)
        if status and any(record):
            raise ValueError("nonzero original CVA3 rejection padding")
        output.append((status, record if not status else b""))
    return output


def frame(generation, digest=DIGEST):
    return TAG + generation.to_bytes(8,"big") + digest


def corpus():
    valid = frame(0)
    wrong = b"CVA2"+valid[4:]
    panel = [(frame(i),0) for i in range(385)]
    panel += [(valid[:i],20) for i in range(len(valid))]
    panel += [(wrong[:i],20 if i<4 else 21) for i in range(len(wrong)+1)]
    panel += [(frame(i),22) for i in (385,386,511,65535,1<<32,1<<63,(1<<64)-1)]
    panel += [(frame(n,bytes(32)),22) for n in (0,255,256,384,385)]
    panel += [(valid+tail,22) for tail in (b"\0",b"x",valid,b"x"*4096)]
    panel += [(wrong+b"x",21),(b"BAD!",21)]
    for i in range(32):
        only = bytearray(32)
        only[i] = 1 << (i % 8)
        panel.append((frame(384,bytes(only)),0))
    return panel


class CellVersionCatalogAnchorValue(unittest.TestCase):
    def test_actual_locked_original_cva3_wire_and_getters_both_stock(self):
        panel = corpus()
        rows = [raw for raw,_ in panel]
        with tempfile.TemporaryDirectory(prefix="trnm-cva3-locked-") as tmp:
            expected = original_rows(Path(tmp), rows)
        self.assertEqual([status for status,_ in expected],[status for _,status in panel])
        for raw,(status,want) in zip(rows,expected,strict=True):
            if not status:
                self.assertEqual(want,raw[4:12][::-1]+raw[12:44]+raw)
        output = b"X"*(LENGTH+13)
        work = b"W"*23
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),24):
                    sub = rows[at:at+24]
                    calls = module.call_many([("f0",[raw,output,work]) for raw in sub])
                    for raw,got,(status,body) in zip(sub,calls,expected[at:at+24],strict=True):
                        self.assertEqual((got.status,got.value),("returned",status))
                        self.assertEqual(got.arguments,[raw,body+output[LENGTH:] if not status else output,work])
                checks = ((rows[0],b"",102),(rows[0],output[:LENGTH-1],102),(b"",b"",20),
                          (b"NOPE",b"",21),(frame(385),b"",22))
                for raw,dst,status in checks:
                    got = module.call("f0",[raw,dst,work])
                    self.assertEqual((got.status,got.value),("returned",status))
                    self.assertEqual(got.arguments,[raw,dst,work])
                exact = module.call("f0",[rows[384],output[:LENGTH],b""])
                self.assertEqual((exact.status,exact.value,exact.arguments[1]),
                                 ("returned",0,expected[384][1]))
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(checks)+1,
                                  "status_counts":dict(Counter(status for status,_ in expected))},
                                 sort_keys=True),flush=True)
