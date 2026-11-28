"""Differential against the real legacy Node's pure public ASERT target."""
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
SOURCE = ROOT / "hia/src/consensus/asert_target.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs"
REFERENCE = ROOT / "hia/tests/rust_consensus_asert_target_reference.rs"
VECTORS = ROOT / "formal/pon-nakamoto-v1/vectors/quantum-daa-asert-bchn-v1.json"
LOCK = ROOT / "trillionnium/Cargo.lock"
U64 = (1 << 64) - 1
U256 = (1 << 256) - 1
SCRATCH = 768
ERRORS = {"SCHEDULE_ASERT_PARAMETERS": 32, "SCHEDULE_ASERT_I128_RANGE": 33}


def frame(anchor, limit, time, intervals, spacing, half_life):
    return (b"NASA0001" + anchor.to_bytes(32, "big") + limit.to_bytes(32, "big")
            + time.to_bytes(16, "little", signed=True)
            + struct.pack("<QQQ", intervals, spacing, half_life))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rust_reference(directory, frames, *, target=None):
    if target is None:
        target = directory / "node-original-target"
    cargo, rustc = os.environ.get("CARGO", "cargo"), os.environ.get("RUSTC", "rustc")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2",
           "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_INCREMENTAL": "0"}
    before = (sha(ORIGINAL), sha(LOCK), sha(REFERENCE))
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
    exe = directory / "original-asert-target"
    subprocess.run(
        [rustc, "--edition=2021", "-O", str(REFERENCE), "--extern",
         f"trnm_pon_node={library}", "-L", f"dependency={target / 'debug/deps'}",
         "-o", str(exe)], check=True, capture_output=True, env=env, timeout=30,
    )
    wire = "".join(value.hex() + "\n" for value in frames)
    result = subprocess.run([str(exe)], input=wire, check=True, capture_output=True,
                            text=True, env=env, timeout=15)
    if before != (sha(ORIGINAL), sha(LOCK), sha(REFERENCE)):
        raise ValueError("original ASERT input changed during comparison")
    output = []
    for line in result.stdout.splitlines():
        status, value = line.split(" ", 1)
        if status == "OK":
            data = bytes.fromhex(value)
            if len(data) != 32:
                raise ValueError("wrong original target width")
            output.append((0, data))
        elif status == "ERR":
            output.append((ERRORS[value], b""))
        else:
            raise ValueError("unexpected original ASERT result")
    if len(output) != len(frames) or result.stderr:
        raise ValueError("incomplete original ASERT reference")
    print(json.dumps({"original_sha256": before[0], "locked_cargo_sha256": before[1],
                      "actual_original_library_sha256": sha(library),
                      "actual_oracle_sha256": sha(exe), "oracle_stdout_sha256":
                          hashlib.sha256(result.stdout.encode()).hexdigest(),
                      "oracle_rows": len(output)}, sort_keys=True), flush=True)
    return output


def corpus():
    doc = json.loads(VECTORS.read_text())
    limit = int(doc["pow_limit_hex"], 16)
    frames = [
        frame(int(row["anchor_target_hex"], 16), limit, row["time_delta"], row["intervals"],
              doc["spacing"], doc["half_life"]) for row in doc["vectors"]
    ]
    vector_results = [(0, bytes.fromhex(row["expected_target_hex"])) for row in doc["vectors"]]
    a = (1 << 244) + 137
    for d in (-(495*65536+1), -495*65536, -495*65536+1,
              -131073, -131072, -131071, -65537, -65536, -65535, -32768, -1,
              0, 1, 65535, 65536, 65537, 16*65536-1, 16*65536,
              272*65536-1, 272*65536, 272*65536+1):
        frames.append(frame(a, U256, d+1, 1, 1, 65536))
    frames.extend(frame(a, U256, sign*U64, 1, 1, divisor)
                  for sign in (-1, 1) for divisor in (1, 65535, 65536, U64))
    # The signed scaled product admits exactly -2^127, not one below it.
    frames.extend(frame(a, U256, d, 1 << 55, 1 << 56, U64) for d in (-1, 0, 1))
    params = (a, U256, 10, 3, 10, 160)
    for index, value in ((0, 0), (1, 0), (1, a - 1), (2, -(U64+1)), (2, U64+1),
                         (2, -(1 << 127)), (2, (1 << 127)-1), (3, 0), (4, 0), (5, 0)):
        item = list(params)
        item[index] = value
        frames.append(frame(*item))
    frames.extend((frame(a, U256, 0, U64, U64, 1),
                   frame(a, U256, 0, U64, 1 << 48, 1),
                   frame(0, U256, 0, U64, U64, 1),
                   frame(U256, U256, 11, 1, 10, 160)))
    randomizer = random.Random(0x4153455254)
    for _ in range(96):
        limit = randomizer.getrandbits(256) or 1
        anchor = randomizer.randrange(1, limit+1)
        if randomizer.randrange(2):
            interval, spacing, half = [randomizer.randint(1, U64) for _ in range(3)]
            delta = randomizer.randint(-U64, U64)
        else:
            interval, spacing = randomizer.randint(1, 4096), randomizer.randint(1, 86400)
            half = randomizer.randint(1, 1 << 22)
            delta = interval*spacing + randomizer.randint(-5*half, 5*half)
        frames.append(frame(anchor, limit, delta, interval, spacing, half))
    return frames, vector_results


class ConsensusAsertTargetTests(unittest.TestCase):
    def test_actual_locked_original_target_and_both_pinned_native_emitters(self):
        frames, vectors = corpus()
        with tempfile.TemporaryDirectory(prefix="trnm-asert-original-") as raw:
            expected = rust_reference(Path(raw), frames)
        self.assertEqual(expected[:len(vectors)], vectors)
        self.assertTrue({0, *ERRORS.values()} <= {code for code, _ in expected})
        canary, work = b"Z" * 49, b"S" * (SCRATCH + 23)
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                             backend=backend) as native:
                actual = native.call_many([("f0", [value, canary, work]) for value in frames])
                for got, value, (status, output) in zip(actual, frames, expected, strict=True):
                    self.assertEqual((got.status, got.value), ("returned", status))
                    self.assertEqual(got.arguments[0], value)
                    self.assertEqual(got.arguments[1], output + canary[len(output):])
                    self.assertEqual(got.arguments[2][SCRATCH:], work[SCRATCH:])
                valid = frames[0]
                for value, output, scratch, want, clean_scratch in (
                    (valid[:-1], canary, work, 1, True),
                    (valid+b"x", canary, work, 1, True),
                    (b"R"+valid[1:], canary, work, 1, True),
                    (valid, canary, work[:SCRATCH-1], 3, True),
                    (valid, canary[:31], work, 2, False),
                    (frame(0, U256, 0, U64, U64, 1), canary[:31], work, 32, False),
                    (frame(1, U256, 0, U64, U64, 1), canary[:31], work, 33, False),
                ):
                    got = native.call("f0", [value, output, scratch])
                    self.assertEqual((got.status, got.value), ("returned", want))
                    self.assertEqual(got.arguments[:2], [value, output])
                    if clean_scratch:
                        self.assertEqual(got.arguments[2], scratch)
                    else:
                        self.assertEqual(got.arguments[2][SCRATCH:], scratch[SCRATCH:])
                print(json.dumps({"backend": backend, "artifact_sha256": native.artifact_sha256,
                                  "original_compared": len(actual), "abi_canaries": 7},
                                 sort_keys=True), flush=True)
