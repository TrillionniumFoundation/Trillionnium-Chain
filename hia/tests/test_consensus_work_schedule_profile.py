"""Differential against the real legacy Node's pure public research work-schedule profile metadata."""
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
SOURCE = ROOT / "hia/src/consensus/work_schedule_profile.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs"
REFERENCE = ROOT / "hia/tests/rust_consensus_work_schedule_profile_reference.rs"
PROTOCOL = ROOT / "trillionnium/crates/trnm-protocol/src/pon_wire.rs"
CARGO = ROOT / "trillionnium/crates/trnm-pon-node/Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
U64 = (1 << 64) - 1
U256 = (1 << 256) - 1
SCRATCH = 132256
ERRORS = {"SCHEDULE_PARAMETERS": 32}


@dataclass(frozen=True)
class Inputs:
    network: bytes = bytes(range(32))
    parameters: bytes = b"P" * 32
    genesis: bytes = b"G" * 32
    target: int = 1 << 239
    limit: int = 1 << 240
    genesis_time: int = 10
    interval: int = 16
    spacing: int = 600
    skew: int = 120
    wire: int = 1
    anchor: tuple | None = None

    def frame(self):
        return (b"NWSP0001" + self.network + self.parameters + self.genesis
                + self.target.to_bytes(32, "big") + self.limit.to_bytes(32, "big")
                + struct.pack("<QQQQBB", self.genesis_time, self.interval, self.spacing,
                              self.skew, self.wire, int(self.anchor is not None))
                + (struct.pack("<QQ", *self.anchor) if self.anchor is not None else b""))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rust_reference(directory, frames, *, target=None):
    if target is None:
        target = directory / "node-original-target"
    cargo, rustc = os.environ.get("CARGO", "cargo"), os.environ.get("RUSTC", "rustc")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2",
           "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_INCREMENTAL": "0"}
    source_paths = (ORIGINAL, LOCK, REFERENCE, PROTOCOL, CARGO)
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
    exe = directory / "original-work-schedule-profile"
    subprocess.run(
        [rustc, "--edition=2021", "-O", str(REFERENCE), "--extern",
         f"trnm_pon_node={library}", "-L", f"dependency={target / 'debug/deps'}",
         "-o", str(exe)], check=True, capture_output=True, env=env, timeout=30,
    )
    wire = "".join(value.hex() + "\n" for value in frames)
    result = subprocess.run([str(exe)], input=wire, check=True, capture_output=True,
                            text=True, env=env, timeout=15)
    if before != tuple(map(sha, source_paths)):
        raise ValueError("original schedule profile input changed during comparison")
    output = []
    for line in result.stdout.splitlines():
        status, value = line.split(" ", 1)
        if status == "OK":
            data = bytes.fromhex(value)
            if len(data) != 32:
                raise ValueError("wrong original profile ID width")
            output.append((0, data))
        elif status == "ERR":
            output.append((ERRORS[value], b""))
        else:
            raise ValueError("unexpected original schedule profile result")
    if len(output) != len(frames) or result.stderr:
        raise ValueError("incomplete original schedule profile reference")
    print(json.dumps({"original_sha256": before[0], "locked_cargo_sha256": before[1],
                      "actual_original_library_sha256": sha(library),
                      "original_protocol_sha256": before[3], "original_manifest_sha256": before[4],
                      "actual_oracle_sha256": sha(exe), "oracle_stdout_sha256":
                          hashlib.sha256(result.stdout.encode()).hexdigest(),
                      "oracle_rows": len(output)}, sort_keys=True), flush=True)
    return output


def corpus():
    fixed = Inputs()
    anchored = replace(fixed, wire=2, anchor=(1, 1))
    records = [(fixed, 0), (anchored, 0),
               (replace(fixed, wire=2), 0), (replace(anchored, wire=1), 0)]
    # Every original encoded field independently changes the canonical ID.
    records.extend((replace(fixed, **patch), 0) for patch in (
        {"network": b"N"*32}, {"parameters": b"Q"*32}, {"genesis": b"H"*32},
        {"target": fixed.target + 1}, {"limit": fixed.limit - 1}, {"genesis_time": U64},
        {"interval": 17}, {"spacing": 601}, {"skew": U64},
    ))
    records.extend((replace(anchored, anchor=item), result) for item, result in (
        ((4095, U64), 0), ((2, 1), 0), ((1, 2), 0),
        ((0, 1), 32), ((4096, 1), 32), ((U64, 1), 32), ((1, 0), 32),
    ))
    records.extend((replace(fixed, **patch), status) for patch, status in (
        ({"target": 0}, 32), ({"limit": 0}, 32), ({"target": fixed.limit+1}, 32),
        ({"target": fixed.limit}, 0), ({"target": U256, "limit": U256-1}, 32),
        ({"target": 1, "limit": 1}, 0), ({"target": U256, "limit": U256}, 0),
        ({"target": 255, "limit": 256}, 0), ({"target": 256, "limit": 255}, 32),
        ({"interval": 15}, 32), ({"interval": 4097}, 32), ({"interval": U64}, 32),
        ({"spacing": 0}, 32), ({"spacing": U64}, 32),
    ))
    for interval in (16, 17, 4095, 4096):
        for shape in (fixed, anchored):
            edge = U64 // (4*(interval-1))
            records.extend((replace(shape, interval=interval, spacing=n), status)
                           for n, status in ((edge-1, 0), (edge, 0), (edge+1, 32),
                                             (U64//(interval-1), 32),
                                             (U64//(interval-1)+1, 32)))
    rng = random.Random(0x4E575350)
    for _ in range(32):
        limit = rng.randrange(1, U256)
        interval = rng.randrange(16, 4097)
        maximum = U64 // (4*(interval-1))
        r = replace(fixed, network=rng.randbytes(32), parameters=rng.randbytes(32),
                    genesis=rng.randbytes(32), target=rng.randrange(1, limit+1),
                    limit=limit, interval=interval, spacing=rng.randrange(1, maximum+1),
                    genesis_time=rng.getrandbits(64), skew=rng.getrandbits(64),
                    wire=rng.randrange(1, 3),
                    anchor=(rng.randrange(1,4096), rng.randrange(1,U64+1)) if rng.getrandbits(1) else None)
        records.extend(((r, 0), (replace(r, target=limit+1), 32)))
    return records


class WorkScheduleProfile(unittest.TestCase):
    def test_actual_locked_original_profile_id_and_both_stock_emitters(self):
        rows = corpus()
        frames = [value.frame() for value, _ in rows]
        with tempfile.TemporaryDirectory(prefix="trnm-original-work-profile-") as raw:
            expected = rust_reference(Path(raw), frames)
        self.assertEqual([status for status, _ in expected], [status for _, status in rows])
        self.assertEqual(len({value for _, value in expected[:13]}), 13)
        good, anchored = frames[:2]
        bad = replace(Inputs(), spacing=0).frame()
        out, arena = b"Z"*49, b"S"*(SCRATCH+17)
        controls = (
            (good[:-1], out, arena, 1), (good+b"x", out, arena, 1),
            (b"X"+good[1:], out, arena, 1), (good[:-2]+b"\x00\x00", out, arena, 1),
            (good[:-1]+b"\x01", out, arena, 1), (anchored[:-17]+b"\x00"+anchored[-16:], out, arena, 1),
            (good, out[:31], arena, 2), (good, out, arena[:SCRATCH-1], 3),
            (bad, out[:31], arena[:SCRATCH-1], 32),
        )
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                             backend=backend) as native:
                for start in range(0, len(frames), 8):
                    batch, want = frames[start:start+8], expected[start:start+8]
                    actual = native.call_many([("f0", [value, out, arena]) for value in batch])
                    for got, value, (status, output) in zip(actual, batch, want, strict=True):
                        self.assertEqual((got.status, got.value), ("returned", status))
                        self.assertEqual(got.arguments[0], value)
                        self.assertEqual(got.arguments[1], output + out[len(output):])
                        if status:
                            self.assertEqual(got.arguments[2], arena)
                        else:
                            self.assertEqual(got.arguments[2][SCRATCH:], arena[SCRATCH:])
                for value, output, scratch, status in controls:
                    got = native.call("f0", [value, output, scratch])
                    self.assertEqual((got.status, got.value), ("returned", status))
                    self.assertEqual(got.arguments, [value, output, scratch])
                print(json.dumps({"backend": backend, "artifact_sha256": native.artifact_sha256,
                                  "original_compared": len(expected), "abi_canaries": len(controls)},
                                 sort_keys=True), flush=True)
