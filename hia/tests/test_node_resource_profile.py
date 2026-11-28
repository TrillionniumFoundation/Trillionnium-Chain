"""Differential against the real legacy Node's pure public local resource profile metadata."""
import hashlib
import json
import os
from pathlib import Path
import random
from dataclasses import dataclass, replace
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/node/resource_profile.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-pon-node/src/resource_owner_v1.rs"
REFERENCE = ROOT / "hia/tests/rust_node_resource_profile_reference.rs"
CARGO = ROOT / "trillionnium/crates/trnm-pon-node/Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
MAX = 1 << 60
U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
SCRATCH = 132256
DOMAIN = b"pon-local-resource-owner-v1"
ERRORS = {
    "RESOURCE_OWNER_ID": 32, "RESOURCE_OWNER_UNITS": 33,
    "RESOURCE_OWNER_GRANT": 34, "RESOURCE_OWNER_SLOTS": 35,
    "RESOURCE_OWNER_OVERSHOOT_REQUIRED": 36,
}


@dataclass(frozen=True)
class Inputs:
    owner: bytes = bytes(range(32))
    grants: tuple[int, ...] = (1, 11, 101, 1001, 10001, 100001)
    ops: tuple[int, ...] = (29, 123, 512)
    inflight: tuple[int, ...] = (1, 2, 16)
    overshoot: tuple[int, ...] = (101, 0)

    def frame(self):
        return (b"NRPF0001" + self.owner
                + struct.pack("<6Q6I2Q", *self.grants, *self.ops, *self.inflight, *self.overshoot))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rust_reference(directory, frames, *, target=None):
    if target is None:
        target = directory / "node-original-target"
    cargo, rustc = os.environ.get("CARGO", "cargo"), os.environ.get("RUSTC", "rustc")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2",
           "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_INCREMENTAL": "0"}
    source_paths = (ORIGINAL, LOCK, REFERENCE, CARGO)
    before = tuple(map(sha, source_paths))
    rust_version = subprocess.run([rustc, "--version"], env=env, check=True, capture_output=True,
                                  text=True, timeout=10).stdout
    if not rust_version.startswith("rustc 1.95.0 (59807616e "):
        raise ValueError("expected locked Rust 1.95.0 original Node oracle")
    build = subprocess.run(
        [cargo, "build", "--locked", "--offline", "--manifest-path",
         str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-pon-node", "--lib",
         "--target-dir", str(target), "--message-format=json"],
        env=env, check=True, capture_output=True, text=True, timeout=300,
    )
    events = [json.loads(line) for line in build.stdout.splitlines()]
    records = [event for event in events
                if event.get("reason") == "compiler-artifact"
                and event["target"]["name"] == "trnm_pon_node"
                and event["target"]["kind"] == ["lib"]]
    if len(records) != 1 or records[0]["features"] != ["default"]:
        raise ValueError("expected one actual default-feature original Node library")
    library, = (Path(path) for path in records[0]["filenames"] if path.endswith(".rlib"))
    serde, = (Path(path) for event in events
              if event.get("reason") == "compiler-artifact"
              and event.get("target", {}).get("name") == "serde_json"
              and event.get("target", {}).get("kind") == ["lib"]
              for path in event["filenames"] if path.endswith(".rlib"))
    exe = directory / "original-resource-profile"
    subprocess.run(
        [rustc, "--edition=2021", "-O", str(REFERENCE), "--extern",
         f"trnm_pon_node={library}", "--extern", f"serde_json={serde}", "-L", f"dependency={target / 'debug/deps'}",
         "-o", str(exe)], check=True, capture_output=True, env=env, timeout=30,
    )
    wire = "".join(value.hex() + "\n" for value in frames)
    result = subprocess.run([str(exe)], input=wire, check=True, capture_output=True,
                            text=True, env=env, timeout=15)
    if before != tuple(map(sha, source_paths)):
        raise ValueError("original resource profile input changed during comparison")
    output = []
    for line in result.stdout.splitlines():
        status, value = line.split(" ", 1)
        if status == "OK":
            digest, raw = map(bytes.fromhex, value.split(" "))
            if len(digest) != 32 or hashlib.sha256(DOMAIN+raw).digest() != digest:
                raise ValueError("original JSON and typed resource profile ID disagree")
            output.append((0, digest, raw))
        elif status == "ERR":
            output.append((ERRORS[value], b"", b""))
        else:
            raise ValueError("unexpected original resource profile result")
    if len(output) != len(frames) or result.stderr:
        raise ValueError("incomplete original resource profile reference")
    print(json.dumps({"original_sha256": before[0], "locked_cargo_sha256": before[1],
                      "actual_original_library_sha256": sha(library),
                      "original_serde_library_sha256": sha(serde), "original_manifest_sha256": before[3],
                      "actual_oracle_sha256": sha(exe), "oracle_stdout_sha256":
                          hashlib.sha256(result.stdout.encode()).hexdigest(),
                      "oracle_rows": len(output)}, sort_keys=True), flush=True)
    return output


def with_item(values, index, value):
    return values[:index] + (value,) + values[index + 1:]


def corpus():
    sample = Inputs()
    cases = [(sample, 0), (replace(sample, owner=b"\xff"*32), 0),
             (replace(sample, owner=b"\x00"*31+b"\x01"), 0),
             (replace(sample, owner=b"\x00"*32), 32),
             (replace(sample, grants=(MAX,)*6, ops=(1, 1, 1022),
                      inflight=(1, 1, 1), overshoot=(MAX, MAX)), 0),
             (replace(sample, overshoot=(0, 0)), 36),
             (replace(sample, overshoot=(0, MAX+1)), 33),
             (replace(sample, overshoot=(MAX+1, 0)), 33),
             (replace(sample, overshoot=(1, MAX)), 0),
             (replace(sample, ops=(1, 1, 1023), inflight=(1, 1, 1)), 35),
             (replace(sample, ops=(U32, 2, 3), inflight=(1, 1, 1)), 35),
             # Lane 1/2 ordering, actual u32 checked overflow before ensuing lane,
             # yet the final 1024 cap is considered only after all lane checks.
             (replace(sample, ops=(U32, 1, 3), inflight=(1, 1, 1),
                      grants=(1, 1, 1, 1, MAX+1, 1)), 35),
             (replace(sample, ops=(1024, 1, 1), inflight=(1, 1, 1),
                      grants=(1, 1, 1, 1, 0, 1)), 34),
             (replace(sample, grants=(1, 0, MAX+1, 1, 1, 1), overshoot=(0, 0)), 34),
             (replace(sample, grants=(0, U64, 1, 1, 1, 1), inflight=(0, 1, 1)), 33),
             (replace(sample, owner=b"\0"*32, grants=(U64,)*6, inflight=(0, 0, 0)), 32)]
    for i in range(6):
        for v, code in ((0, 34), (MAX, 0), (MAX+1, 33), (U64, 33), (9, 0), (10, 0)):
            cases.append((replace(sample, grants=with_item(sample.grants, i, v)), code))
    for i in range(3):
        for v, code in ((0, 35), (1, 0), (16, 0), (17, 35), (U32, 35)):
            cases.append((replace(sample, inflight=with_item(sample.inflight, i, v)), code))
        cases.append((replace(sample, ops=with_item(sample.ops, i, 0)), 35))
    rng = random.Random(0x4E525046)
    for _ in range(26):
        v = replace(sample, owner=rng.randbytes(32), grants=tuple(rng.randint(1, MAX) for _ in range(6)),
                    ops=tuple(rng.randint(16, 339) for _ in range(3)),
                    inflight=tuple(rng.randint(1, 16) for _ in range(3)),
                    overshoot=(rng.randint(1, MAX), rng.randint(0, MAX)))
        cases.extend(((v, 0), (replace(v, inflight=with_item(v.inflight, rng.randrange(3), 17)), 35)))
    return cases


class NodeResourceProfile(unittest.TestCase):
    def test_actual_locked_original_resource_metadata_and_both_stock_emitters(self):
        records = corpus()
        frames = [value.frame() for value, _ in records]
        with tempfile.TemporaryDirectory(prefix="trnm-original-resource-profile-") as raw:
            expected = rust_reference(Path(raw), frames)
        self.assertEqual([code for code, _, _ in expected], [code for _, code in records])
        self.assertEqual({code for code, _, _ in expected}, {0, *ERRORS.values()})
        valid, invalid = frames[0], frames[3]
        out, arena = b"D"*45, b"S"*(SCRATCH+19)
        controls = (
            (valid[:-1], out, arena, 1), (valid+b"x", out, arena, 1),
            (b"X"+valid[1:], out, arena, 1), (valid, out[:31], arena, 2),
            (valid, out, arena[:SCRATCH-1], 3),
            (invalid, out[:31], arena[:SCRATCH-1], 32),
        )
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                             backend=backend) as native:
                for i in range(0, len(frames), 8):
                    batch, wants = frames[i:i+8], expected[i:i+8]
                    actual = native.call_many([("f0", [value, out, arena]) for value in batch])
                    for got, value, (status, digest, raw) in zip(actual, batch, wants, strict=True):
                        self.assertEqual((got.status, got.value), ("returned", status))
                        self.assertEqual(got.arguments[0], value)
                        self.assertEqual(got.arguments[1], digest+out[len(digest):])
                        scratch = got.arguments[2]
                        if status:
                            self.assertEqual(scratch, arena)
                        else:
                            prefix = DOMAIN+raw
                            self.assertEqual(scratch[:len(prefix)], prefix)
                            self.assertEqual(scratch[len(prefix):131136], arena[len(prefix):131136])
                            self.assertEqual(scratch[SCRATCH:], arena[SCRATCH:])
                for value, output, work, status in controls:
                    got = native.call("f0", [value, output, work])
                    self.assertEqual((got.status, got.value), ("returned", status))
                    self.assertEqual(got.arguments, [value, output, work])
                print(json.dumps({"backend": backend, "artifact_sha256": native.artifact_sha256,
                                  "original_compared": len(expected), "abi_canaries": len(controls)},
                                 sort_keys=True), flush=True)
