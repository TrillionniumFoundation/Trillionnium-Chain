"""Actual locked M09 immutable retention commitment; no store or authority."""
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
from hia.tests.test_cell_manifest import cases as manifest_cases, wire as manifest_wire

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cell_retention_contract_value.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_retention_contract_value_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/retention.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
TAG = b"NCRC0001"
DOMAIN = b"trnm.cell-retention-contract.v1\0"
MANIFEST_DOMAIN = b"trnm.cell-manifest.v1\0"
WORK = 1457
U64 = (1 << 64) - 1


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
    exe = directory / "original-cell-retention-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I", len(row))+row for row in rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != 65 * len(rows) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original retention contract value evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "manifest_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    output = []
    for i in range(0, len(observed.stdout), 65):
        status, *body = observed.stdout[i:i+65]
        record = bytes(body)
        if status and any(record):
            raise ValueError("nonzero original TCM1 rejection padding")
        output.append((status, record if not status else b""))
    return output


def frame(manifest, successor=None, terms=(1, 2, 3)):
    ids = bytes(range(96))
    tail = b"\0" if successor is None else b"\1" + b"".join(successor)
    return TAG + ids + struct.pack(">QQQ", *terms) + tail + manifest


def preimage(frame, manifest_id):
    present = frame[128] == 1
    return DOMAIN + frame[8:104] + manifest_id + frame[104:129+64*present]


def corpus():
    baseline = manifest_wire(b"Cell-1", opaque=True)
    successor = (b"S"*32, b"O"*32)
    left, right = frame(baseline), frame(baseline, successor)
    panel = [(left, 0), (right, 0)]
    # Every field/byte of both forms binds. The neutral value boundary does
    # not issue, reserve, or reinterpret these terms as an active contract.
    for index in range(8, 193):
        if index != 128:
            panel.append((right[:index] + bytes([right[index]^0x80]) + right[index+1:], 0))
    for i in range(3):
        for value in (0, 1, 255, 1<<32, 1<<63, U64):
            terms = list((1, 2, 3))
            terms[i] = value
            panel.append((frame(baseline, terms=terms), 0))
    for raw, status in manifest_cases():
        panel.append((frame(raw, successor), status))
    rng = random.Random(0x4E435243)
    for i in range(20):
        manifest = manifest_wire(f"Cell-{i}".encode(), size=rng.randrange(1, 32768), opaque=True)
        optional = (rng.randbytes(32),rng.randbytes(32)) if i%2 else None
        panel.append((frame(manifest, optional, tuple(rng.getrandbits(64) for _ in range(3))), 0))
    return panel


class CellRetentionContractValue(unittest.TestCase):
    def test_actual_locked_original_derived_manifest_and_retention_commitment_both_stock(self):
        panel = corpus()
        rows = [raw for raw, _ in panel]
        with tempfile.TemporaryDirectory(prefix="trnm-retention-value-locked-") as tmp:
            expected = original_rows(Path(tmp), rows)
        self.assertEqual([s for s, _ in expected], [s for _, s in panel])
        for raw, (status, observed) in zip(rows, expected, strict=True):
            if status==0:
                manifest_at = 193 if raw[128] else 129
                manifest_id = hashlib.sha256(MANIFEST_DOMAIN+raw[manifest_at:]).digest()
                self.assertEqual(observed, manifest_id+hashlib.sha256(preimage(raw,manifest_id)).digest())
        self.assertEqual(len({result[32:] for _,result in expected[1:186]}),185)
        good = rows[1]
        short_form = rows[0]
        out, work = b"O"*51, b"S"*(WORK+13)
        controls = (
            (b"",out,work,100), (good[:128],out,work,100), (good[:192],out,work,100),
            (b"X"+good[1:],out,work,100),
            (good[:128]+b"\x02"+good[129:],out,work,100),
            (short_form[:129],b"",b"",2), (good,out[:31],work,102),
            (good,out,work[:WORK-1],102),
        )
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),8):
                    sub = rows[at:at+8]
                    calls = module.call_many([("f0",[raw,out,work]) for raw in sub])
                    for raw, got, (status,result) in zip(sub,calls,expected[at:at+8],strict=True):
                        self.assertEqual((got.status,got.value),("returned",status))
                        self.assertEqual(got.arguments[0],raw)
                        self.assertEqual(got.arguments[1],result[32:]+out[32:] if not status else out)
                        scratch = got.arguments[2]
                        if status:
                            self.assertEqual(scratch,work)
                        else:
                            exact = preimage(raw,result[:32])
                            self.assertEqual(scratch[1208:1208+len(exact)],exact)
                            self.assertEqual(scratch[1208+len(exact):],work[1208+len(exact):])
                for raw, dst, scratch, status in controls:
                    got = module.call("f0",[raw,dst,scratch])
                    self.assertEqual((got.status,got.value),("returned",status))
                    self.assertEqual(got.arguments,[raw,dst,scratch])
                bound = module.call("f0",[good,out[:32],work[:WORK]])
                self.assertEqual((bound.status,bound.value,bound.arguments[1]),("returned",0,expected[1][1][32:]))
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(controls)+1},
                                 sort_keys=True),flush=True)
