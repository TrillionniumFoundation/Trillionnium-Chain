"""Original locked Cargo Bench versus a freestanding admitted HIA process."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import tomllib
import unittest

from hia.platform.bench.main_build import build
from hia.platform.build import new_output, sealed_executable
from hia.tests.test_bench_native import run_original_command

ROOT = Path(__file__).resolve().parents[2]
REPEAT = b"--determinism-repeats exceeds bounded maximum 1000\n"
OUTSIDE = b"Bench native candidate: invocation outside admitted no-profile scope\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build_original(output, target):
    rust_pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    for tool in ("cargo", "rustc"):
        version = subprocess.run([tool, "--version"], check=True, capture_output=True,
                                 text=True, timeout=10).stdout.split()
        if version[:2] != [tool, rust_pin]:
            raise ValueError(f"Expected {tool} {rust_pin}, got {version[:2]}")
    lock = ROOT / "trillionnium/Cargo.lock"
    original = ROOT / "trillionnium/crates/trnm-bench/src/main.rs"
    before = [digest(p.read_bytes()) for p in (lock, original)]
    command = ["cargo", "build", "--locked", "--offline", "-p", "trnm-bench",
               "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"), "--target-dir",
               str(target), "--message-format=json"]
    build_env = {}
    for name in ("PATH", "HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN",
                 "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUSTC"):
        value = os.environ.get(name)
        if value is not None:
            build_env[name] = value
    result = run_original_command(output, "original", command, build_env, 240)
    found = []
    for line in result.stdout.splitlines():
        row = json.loads(line)
        if (row.get("reason") == "compiler-artifact" and row["target"]["name"] == "trnm-bench"
                and row.get("executable") and "bin" in row["target"]["kind"]):
            found.append(Path(row["executable"]))
    if len(found) != 1 or not found[0].is_relative_to(target):
        raise ValueError("The locked original Cargo executable is missing or ambiguous")
    image = found[0].read_bytes()
    if [digest(p.read_bytes()) for p in (lock, original)] != before:
        raise ValueError("Original Bench or its lock changed while building")
    receipt = {"native_sha256": digest(image), "bytes": len(image),
               "cargo_lock_sha256": before[0], "original_main_sha256": before[1],
               "original_cargo_executable": True, "rust_pin": rust_pin}
    (output / "original-build-identity.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (output / "original.elf").write_bytes(image)
    return image


def stdout_observation(data, elapsed_ns):
    timings = re.findall(rb"(?m)^elapsed_ms=(0|[1-9][0-9]*)$", data)
    if len(timings) != 1:
        raise ValueError("Expected one actual elapsed_ms in the original output format")
    elapsed = int(timings[0])
    if elapsed > elapsed_ns // 1_000_000 + 1:
        raise ValueError("Timed interval cannot exceed outer process duration")
    # Replace only the one measurement each executable independently took.
    return elapsed, re.sub(rb"(?m)^elapsed_ms=[0-9]+$", b"elapsed_ms=<observed>", data, count=1)


class NativeBenchMain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("HIA_BENCH_MAIN_OBSERVATIONS")
        cls.root = (new_output(Path(configured)) if configured else Path(cls.enterClassContext(
            tempfile.TemporaryDirectory(prefix="trnm-bench-main-"))))
        cls.native, _ = build(cls.root / "native")
        target = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-bench-cargo-")))
        cls.original = build_original(cls.root, target)
        cls.events = []

    @classmethod
    def tearDownClass(cls):
        report = {"schema": "trnm.hia.bench-no-profile.observations.v1",
                  "actual_runs": cls.events, "profile_file_owner_qualified": False,
                  "whole_bench_native_qualified": False, "production_activation": False}
        (cls.root / "observations.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    def actual(self, label, image, args=(), *, env=None):
        current = self.root / (label + ".cwd")
        current.mkdir(mode=0o700)
        fd = sealed_executable(image, label)
        start = time.monotonic_ns()
        try:
            result = subprocess.run([b"trnm-bench", *args], executable=f"/proc/self/fd/{fd}",
                                    cwd=current, env={} if env is None else env, pass_fds=(fd,),
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=25)
        finally:
            os.close(fd)
        elapsed = time.monotonic_ns() - start
        # Capture only explicit synthetic observations; no raw inherited env.
        artifacts = sorted(str(p.relative_to(current)) for p in current.rglob("*"))
        for kind, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            (self.root / (label + "." + kind + ".raw")).write_bytes(raw)
        self.events.append({"label": label, "exit": result.returncode, "outer_wall_ns": elapsed,
                            "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr),
                            "created_paths": artifacts})
        self.assertEqual(artifacts, [])
        return result, elapsed

    def test_actual_default_20k_and_small_cli_stdout_no_file(self):
        accepted = ((), (b"--txs", b"4", b"--keys=2"), (b"--keys", b"+11", b"--txs=32"),
                    (b"--txs=0", b"--keys=0", b"--determinism-repeats=0"),
                    (b"--txs=37", b"--keys=18446744073709551615"),
                    (b"--txs=100", b"--keys=3"))
        for index, args in enumerate(accepted):
            with self.subTest(fixture=index):
                old, old_ns = self.actual(f"matched-{index}-original", self.original, args)
                new, new_ns = self.actual(f"matched-{index}-native", self.native, args)
                self.assertEqual((old.returncode, new.returncode, old.stderr, new.stderr), (0, 0, b"", b""))
                tt_old, bytes_old = stdout_observation(old.stdout, old_ns)
                tt_new, bytes_new = stdout_observation(new.stdout, new_ns)
                self.events[-2]["observed_elapsed_ms"] = tt_old
                self.events[-1]["observed_elapsed_ms"] = tt_new
                self.assertEqual(bytes_old, bytes_new)
                if index == 0:
                    self.assertIn(b"\ntxs=20000\n", bytes_new)
                    self.assertGreater(tt_new, 0)  # the default does actual scheduler work

    def test_actual_exact_repeat_error_and_invalid_exit(self):
        for index, args in enumerate(((b"--determinism-repeats", b"1001"),
                                      (b"--txs=99999", b"--determinism-repeats=18446744073709551615"))):
            old, _ = self.actual(f"over-{index}-original", self.original, args)
            new, _ = self.actual(f"over-{index}-native", self.native, args)
            self.assertEqual((old.returncode, old.stdout, old.stderr), (2, b"", REPEAT))
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", REPEAT))
        for index, args in enumerate(((b"--unknown",), (b"--txs=oops",), (b"--txs",),
                                       (b"--keys=18446744073709551616",),
                                       (b"--txs=40", b"--txs", b"4"))):
            old, _ = self.actual(f"invalid-{index}-original", self.original, args)
            new, _ = self.actual(f"invalid-{index}-native", self.native, args)
            self.assertEqual((old.returncode, old.stdout), (2, b""))
            self.assertTrue(old.stderr)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", OUTSIDE))

    def test_unsupported_original_modes_never_success_or_write_a_file(self):
        for index, args in enumerate(((b"--profile",), (b"--workload=mixed",),
                                      (b"--txs=20001",), (b"--determinism-repeats=1",))):
            result, _ = self.actual(f"outside-{index}", self.native, args)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", OUTSIDE))
        result, _ = self.actual("outside-env", self.native, (b"--txs=4",),
                                env={b"TRNM_HOT_BUCKETS": b"16"})
        self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", OUTSIDE))
