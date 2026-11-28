"""Actual locked M13 value digest; no agreement verification or issuance."""
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/cutover_agreement_digest.hepta"
REFERENCE = ROOT / "hia/tests/rust_state_import_cutover_agreement_digest_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-state-import"
ORIGINAL = CRATE / "src/lib.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
TAG = b"NCAD0001"
DOMAIN = b"trnm.migration.cutover-agreement-record.v0"
WIDTHS = (32, 32, 32, 8, 8, 32)
WORK = 1456


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
                           str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-state-import",
                           "--lib", "--target-dir", str(target), "--message-format=json"],
                          env=env, check=True, capture_output=True, text=True, timeout=180)
    records = [v for v in map(json.loads, comp.stdout.splitlines())
               if v.get("reason") == "compiler-artifact"
               and v["target"]["name"] == "trnm_state_import" and v["target"]["kind"] == ["lib"]]
    if len(records) != 1 or records[0]["features"] != []:
        raise ValueError("expected one actual unchanged original State Import library")
    library, = (Path(x) for x in records[0]["filenames"] if x.endswith(".rlib"))
    library_sha = sha(library.read_bytes())
    exe = directory / "original-cutover-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_state_import={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != 32 * len(rows) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original cutover metadata evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    return [observed.stdout[i:i+32] for i in range(0, len(observed.stdout), 32)]


def framed(row):
    assert len(row) == 184 and row.startswith(TAG)
    parts, pos = [DOMAIN], len(TAG)
    for width in WIDTHS:
        parts.append(row[pos:pos+width])
        pos += width
    assert pos == 152
    return b"".join(len(field).to_bytes(8, "big")+field for field in parts)


def corpus():
    exact = TAG + bytes(range(176))
    rows = [exact, TAG + bytes(176), TAG + b"\xff"*176]
    rows += [exact[:i]+bytes([exact[i] ^ 0x80])+exact[i+1:] for i in range(8,184)]
    for i in (104, 112):
        rows += [exact[:i]+v.to_bytes(8,"big")+exact[i+8:]
                 for v in (0, 1, (1<<32)-1, 1<<32, (1<<63)-1, 1<<63, (1<<64)-1)]
    rng = random.Random(0x4D3133434144)
    rows.extend(TAG + rng.randbytes(176) for _ in range(112))
    return rows


class StateImportCutoverAgreementDigest(unittest.TestCase):
    def test_actual_locked_value_only_and_both_stock_emitters(self):
        rows = corpus()
        with tempfile.TemporaryDirectory(prefix="trnm-cutover-digest-original-") as tmp:
            expected = original_rows(Path(tmp), rows)
        self.assertEqual(expected, [hashlib.sha256(framed(row)).digest() for row in rows])
        # Every one-byte binding input differs; none of the self-digest bytes binds.
        self.assertEqual(len(set(expected[:3+144])), 3+144)
        self.assertEqual(expected[3+144:3+176], [expected[0]]*32)
        good, out, work = rows[0], b"O"*43, b"A"*(WORK+19)
        guards = [(b"", out, work, 100), (good[:-1], out, work, 100),
                  (good+b"B", out, work, 100), (b"B"+good[1:], out, work, 100),
                  (good, out[:31], work, 102), (good, out, work[:WORK-1], 102),
                  (good, out[:31], work[:WORK-1], 102), (b"", b"", b"", 100)]
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                             backend=backend) as native:
                for pos in range(0, len(rows), 16):
                    chunk = rows[pos:pos+16]
                    calls = native.call_many([("f0", [row, out, work]) for row in chunk])
                    for row, reply, digest in zip(chunk, calls, expected[pos:pos+16], strict=True):
                        self.assertEqual((reply.status, reply.value), ("returned", 0))
                        self.assertEqual(reply.arguments[:2], [row, digest+out[32:]])
                        self.assertEqual(reply.arguments[2][1208:1450], framed(row))
                        self.assertEqual(reply.arguments[2][1450:], work[1450:])
                for row, output, scratch, status in guards:
                    got = native.call("f0", [row, output, scratch])
                    self.assertEqual((got.status, got.value), ("returned", status))
                    self.assertEqual(got.arguments, [row, output, scratch])
                min_result = native.call("f0", [good, out[:32], work[:WORK]])
                self.assertEqual((min_result.status, min_result.value), ("returned", 0))
                self.assertEqual(min_result.arguments[1], expected[0])
                print(json.dumps({"backend": backend, "artifact_sha256": native.artifact_sha256,
                                  "original_compared": len(rows), "abi_controls": len(guards)+1},
                                 sort_keys=True), flush=True)
