"""Original locked Cargo Bench versus a freestanding admitted HIA process."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from itertools import permutations
import hashlib
import io
import json
import os
import pty
from pathlib import Path
import re
import resource
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import unittest

from hia.platform.bench.main_build import build
from hia.platform.build import inspect_executable, new_output, sealed_executable
from hia.tests.test_bench_native import group_digest, run_original_command

ROOT = Path(__file__).resolve().parents[2]
REPEAT = b"--determinism-repeats exceeds bounded maximum 1000\n"
OUTSIDE = b"Bench native candidate: invocation outside admitted Bench scope\n"
PROFILE_ARGS = (b"--profile", b"--txs=4", b"--keys=2")
HOT_KEY = b"TRNM_HOT_BUCKETS="
# Qualification-only transport. Its own env is empty and stdin is solely the
# explicit synthetic vector. It passes array order and duplicate names across
# actual Linux execve without the mapping/coalescing of subprocess's env arg.
SYNTHETIC_EXECVE = r"""
import ctypes, os, sys
data = sys.stdin.buffer.read()
assert not data or data.endswith(b"\0")
entries = data[:-1].split(b"\0") if data else []
args = [os.fsencode(s) for s in sys.argv[2:]]
argv = (ctypes.c_char_p * (len(args) + 1))(*args, None)
envp = (ctypes.c_char_p * (len(entries) + 1))(*entries, None)
libc = ctypes.CDLL(None, use_errno=True)
libc.execve(os.fsencode(sys.argv[1]), argv, envp)
raise SystemExit("synthetic execve failed, errno " + str(ctypes.get_errno()))
"""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build_original(output, target, anchor):
    rust_pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    for tool in ("cargo", "rustc"):
        version = subprocess.run([tool, "--version"], check=True, capture_output=True,
                                 text=True, timeout=10).stdout.split()
        if version[:2] != [tool, rust_pin]:
            raise ValueError(f"Expected {tool} {rust_pin}, got {version[:2]}")
    lock = anchor / "Cargo.lock"
    original = anchor / "crates/trnm-bench/src/main.rs"
    before = [
        digest((ROOT / "trillionnium" / p.relative_to(anchor)).read_bytes())
        for p in (lock, original)
    ]
    if before != [digest(p.read_bytes()) for p in (lock, original)]:
        raise ValueError("Isolated original Cargo source differs")
    command = ["cargo", "build", "--locked", "--offline", "-p", "trnm-bench",
               "--manifest-path", str(anchor / "Cargo.toml"), "--target-dir",
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
               "original_cargo_executable": True, "rust_pin": rust_pin,
               "manifest_bound_profile_root": str(anchor / "run/bench")}
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
        copy = cls.root / "isolated-source"
        copy.mkdir(mode=0o700)
        cls.addClassCleanup(shutil.rmtree, copy)
        # Obtain the original Cargo graph and all dependency sources without
        # mutable run/target directories or transformations of the CLI.
        tracked = subprocess.check_output(["git", "archive", "--format=tar", "HEAD", "trillionnium"],
                                          cwd=ROOT, timeout=30)
        with tarfile.open(fileobj=io.BytesIO(tracked), mode="r:") as archive:
            if any(not (entry.isfile() or entry.isdir()) for entry in archive.getmembers()):
                raise ValueError("Isolated Bench source must contain only real directories and files")
            archive.extractall(copy, filter="data")
        (cls.root / "isolated-source-identity.json").write_text(json.dumps({
            "sha256": digest(tracked), "bytes": len(tracked),
            "kind": "exact-git-archive-trillionnium-subtree",
            "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                               text=True, timeout=10).strip(),
        }, indent=2) + "\n")
        cls.anchor = copy / "trillionnium"
        cls.native, cls.build = build(cls.root / "native", bind_profile_output=True)
        cls.run_path = cls.anchor / "run"
        cls.bench_path = cls.run_path / "bench"
        target = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-bench-cargo-")))
        cls.original = build_original(cls.root, target, cls.anchor)
        cls.events = []

    @classmethod
    def tearDownClass(cls):
        report = {"schema": "trnm.hia.bench-main.observations.v2",
                  "actual_runs": cls.events, "isolated_bench_profile_test_scope": True,
                  "whole_bench_native_qualified": False, "production_activation": False}
        (cls.root / "observations.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    def actual(self, label, image, args=(), *, env=None, env_entries=None, prepare=None):
        current = self.root / (label + ".cwd")
        current.mkdir(mode=0o700)
        fd = sealed_executable(image, label)
        start = time.monotonic_ns()
        start_realtime = time.time_ns()
        try:
            entry = f"/proc/self/fd/{fd}"
            if env_entries is None:
                result = subprocess.run([b"trnm-bench", *args], executable=entry,
                                        cwd=current, env={} if env is None else env, pass_fds=(fd,),
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=25,
                                        preexec_fn=prepare)
            else:
                self.assertIsNone(env)
                self.assertIsNone(prepare)
                self.assertTrue(all(b"\0" not in entry for entry in env_entries))
                result = subprocess.run([sys.executable, "-I", "-S", "-c", SYNTHETIC_EXECVE,
                                         entry, b"trnm-bench", *args],
                                        cwd=current, env={}, pass_fds=(fd,), capture_output=True, timeout=25,
                                        input=b"".join(entry + b"\0" for entry in env_entries))
        finally:
            os.close(fd)
        end_realtime = time.time_ns()
        elapsed = time.monotonic_ns() - start
        # Capture only explicit synthetic observations; no raw inherited env.
        artifacts = sorted(str(p.relative_to(current)) for p in current.rglob("*"))
        for kind, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            (self.root / (label + "." + kind + ".raw")).write_bytes(raw)
        self.events.append({"label": label, "exit": result.returncode, "outer_wall_ns": elapsed,
                            "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr),
                            "created_paths": artifacts, "realtime_start_ns": start_realtime,
                            "realtime_end_ns": end_realtime})
        self.assertEqual(artifacts, [])
        return result, elapsed

    def test_actual_default_20k_and_small_cli_stdout_no_file(self):
        accepted = ((), (b"--txs", b"4", b"--keys=2"), (b"--keys", b"+11", b"--txs=32"),
                    (b"--txs=0", b"--keys=0", b"--determinism-repeats=0"),
                    (b"--txs=37", b"--keys=18446744073709551615"),
                    (b"--txs=100", b"--keys=3"),
                    (b"--workload=classic", b"--strategy", b"original", b"--persist-profile",
                     b"--txs=6", b"--read-fanout=18446744073709551615",
                     b"--write-every=18446744073709551615"),
                    (b"--workload", b"mixed", b"--txs=37", b"--keys=0",
                     b"--read-fanout=0", b"--write-every=0"),
                    (b"--workload=mixed", b"--txs=64", b"--keys=3",
                     b"--read-fanout", b"8", b"--write-every", b"64"),
                    (b"--workload=hot-streak", b"--txs=48", b"--keys=1",
                     b"--read-fanout=8", b"--write-every=2"),
                    (b"--workload=hot-streak", b"--txs=32", b"--keys=3",
                     b"--read-fanout=8", b"--write-every=33"),
                    (b"--workload=mixed", b"--write-every=20000"),
                    (b"--workload=hot-streak", b"--write-every=20000"),
                    (b"--workload=mixed", b"--keys=1", b"--read-fanout=8"))
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
                self.assertFalse(self.run_path.exists())
                if index == 0:
                    self.assertIn(b"\ntxs=20000\n", bytes_new)
                    self.assertGreater(tt_new, 0)  # the default does actual scheduler work

    def test_ordinary_classic_footprint_desc_exact_bounded_process(self):
        mode = (b"--workload=classic", b"--strategy=footprint-desc")
        for i, (txs, keys, repeats) in enumerate(((32, 5, 1), (64, 64, 0), (0, 0, 2))):
            args = (*mode, f"--txs={txs}".encode(), f"--keys={keys}".encode(),
                    f"--determinism-repeats={repeats}".encode())
            with self.subTest(txs=txs, keys=keys, repeats=repeats):
                old, old_ns = self.actual(f"classic-footprint-{i}-original", self.original, args)
                new, new_ns = self.actual(f"classic-footprint-{i}-native", self.native, args)
                self.assertEqual((old.returncode, new.returncode, old.stderr, new.stderr), (0, 0, b"", b""))
                self.assertEqual(stdout_observation(old.stdout, old_ns)[1],
                                 stdout_observation(new.stdout, new_ns)[1])
                fields = dict(line.split(b"=", 1) for line in new.stdout.splitlines() if b"=" in line)
                self.assertEqual(fields[b"strategy"], b"FootprintDesc")
                self.assertEqual(int(fields[b"groups"]), (max(txs, 1) + max(keys, 1) - 1) // max(keys, 1))
                self.assertEqual(fields.get(b"determinism.replay_match"), b"true" if repeats else b"not-requested")
                self.assertFalse(self.run_path.exists())
        base = (*mode, b"--txs=32", b"--keys=5")
        for i, (args, env) in enumerate((
                ((*base, b"--profile"), {}), ((*base, b"--persist-profile"), {}),
                ((b"--strategy=footprint-desc", b"--txs=65", b"--keys=5"), {}),
                ((b"--strategy=footprint-desc", b"--txs=32", b"--keys=65"), {}),
                ((b"--workload=mixed", *base[1:]), {}),
                ((b"--workload=hot-streak", *base[1:]), {}),
                ((*base, b"--reader-high-water-v1"), {}), (base, {b"LANG": b"C"}))):
            with self.subTest(i=i):
                denied, _ = self.actual(f"classic-footprint-closed-{i}", self.native, args, env=env)
                self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
                self.assertFalse(self.run_path.exists())

    def test_ordinary_classic_footprint_desc_default_direct_process(self):
        strategy = (b"--strategy=footprint-desc",)
        explicit = (*strategy, b"--workload=classic", b"--txs=20000", b"--keys=2000")
        input_hash = hashlib.sha256(b"TRNM-BENCH-INPUT-V1\0")
        for j in range(20_000):
            key = j % 2_000
            input_hash.update(struct.pack("<8Q", j, 1, key, 1, 1, key, 1, 0))
        expected_groups = group_digest([range(j, j + 2_000) for j in range(0, 20_000, 2_000)])
        expected = {b"workload": b"Classic", b"strategy": b"FootprintDesc",
                    b"txs": b"20000", b"keys": b"2000", b"groups": b"10", b"grouped": b"20000",
                    b"estimated_conflict_rate": b"0.9000",
                    b"determinism.input_sha256": input_hash.hexdigest().encode(),
                    b"determinism.groups_sha256": expected_groups.hex().encode()}
        for repeats, args in enumerate((strategy, (*explicit, b"--determinism-repeats=1"))):
            comparable = []
            for owner, image in (("rust", self.original), ("native", self.native)):
                result, wall = self.actual(f"classic-footprint-default-{repeats}-{owner}", image, args)
                self.assertEqual((result.returncode, result.stderr), (0, b""))
                _, out = stdout_observation(result.stdout, wall)
                fields = dict(line.split(b"=", 1) for line in out.splitlines() if b"=" in line)
                self.assertEqual({key: fields[key] for key in expected}, expected)
                self.assertEqual(fields[b"determinism.repeats"], str(repeats).encode())
                self.assertEqual(fields[b"determinism.replay_match"], b"true" if repeats else b"not-requested")
                comparable.append(out)
                self.assertFalse(self.run_path.exists())
            self.assertEqual(*comparable)

        controls = (
            ((*explicit, b"--determinism-repeats=2"), {}),
            ((*explicit, b"--determinism-repeats=1000"), {}),
            ((*strategy, b"--txs=19999", b"--keys=2000"), {}),
            ((*strategy, b"--txs=20000", b"--keys=1999"), {}),
            ((*strategy, b"--txs=20001", b"--keys=2000"), {}),
            ((*strategy, b"--txs=20000", b"--keys=2001"), {}),
            ((*strategy, b"--workload=mixed"), {}),
            ((*strategy, b"--workload=hot-streak"), {}),
            ((*strategy, b"--reader-high-water-v1"), {}),
            ((*strategy, b"--profile"), {}),
            ((*strategy, b"--persist-profile"), {}),
            (strategy, {b"LANG": b"C"}),
        )
        for j, (args, env) in enumerate(controls):
            denied, _ = self.actual(f"classic-footprint-default-closed-{j}", self.native, args, env=env)
            self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
            self.assertFalse(self.run_path.exists())
        for owner, image in (("rust", self.original), ("native", self.native)):
            denied, _ = self.actual(f"classic-footprint-default-over-{owner}", image,
                                    (*explicit, b"--determinism-repeats=1001"))
            self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", REPEAT))
            self.assertFalse(self.run_path.exists())

    def test_actual_exact_repeat_error_and_invalid_exit(self):
        for index, args in enumerate(((b"--determinism-repeats", b"1001"),
                                      (b"--txs=99999", b"--determinism-repeats=18446744073709551615"),
                                      (b"--workload=mixed", b"--read-fanout=9",
                                       b"--determinism-repeats=1001"))):
            old, _ = self.actual(f"over-{index}-original", self.original, args)
            new, _ = self.actual(f"over-{index}-native", self.native, args)
            self.assertEqual((old.returncode, old.stdout, old.stderr), (2, b"", REPEAT))
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", REPEAT))
        for index, args in enumerate(((b"--txs=oops",), (b"--txs",),
                                       (b"--keys=18446744073709551616",),
                                       (b"--txs=40", b"--txs", b"4"), (b"--profile", b"--profile"),
                    (b"--workload=Mixed",), (b"--workload=original",), (b"--strategy=classic",),
                    (b"--persist-profile=false",), (b"--persist-profile", b"--persist-profile"),
                    (b"--read-fanout=3", b"--read-fanout", b"4"), (b"--write-every",))):
            old, _ = self.actual(f"invalid-{index}-original", self.original, args)
            new, _ = self.actual(f"invalid-{index}-native", self.native, args)
            self.assertEqual((old.returncode, old.stdout), (2, b""))
            self.assertTrue(old.stderr)
            strict = any(fragment in old.stderr for fragment in (
                b"a value is required", b"cannot be used multiple times",
                b"invalid digit found in string", b"number too large to fit in target type", b"[possible values:"))
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", old.stderr if strict else OUTSIDE))

    def test_actual_plain_cli_help_terminator_and_strict_grammar(self):
        help_cases = ((b"-h",), (b"--help",), (b"--profile", b"--help"),
                      (b"--help", b"--unknown"),
                      (b"--strategy=auto-adaptive", b"--help"),
                      (b"--strategy", b"aggressive-greedy", b"-h"),
                      (b"--txs=99999", b"--determinism-repeats=1001", b"--help"))
        for i, args in enumerate(help_cases):
            old, _ = self.actual(f"plain-help-{i}-rust", self.original, args)
            new, _ = self.actual(f"plain-help-{i}-hia", self.native, args)
            self.assertEqual((old.returncode, old.stderr, len(old.stdout)), (0, b"", 1264))
            self.assertEqual((new.returncode, new.stdout, new.stderr), (0, old.stdout, b""))
        # The duplicate category is independent of the spelling of its second
        # supplied value; missing still takes priority for a pending value.
        fields = ((b"txs", b"4"), (b"keys", b"2"), (b"determinism-repeats", b"0"),
                  (b"profile", None), (b"read-fanout", b"3"), (b"write-every", b"1"),
                  (b"workload", b"classic"), (b"persist-profile", None), (b"strategy", b"original"))
        fail = []
        for f, value in fields:
            name = b"--" + f
            if value is None:
                fail.append(((name, name, b"--help"), b"cannot be used multiple times"))
            else:
                for tail in ((), (b"--help",), (b"--profile",), (b"--",)):
                    fail.append(((name, *tail), b"a value is required"))
                fail.extend((((name, value, name + b"=known-synthetic-garbage", b"--help"),
                              b"cannot be used multiple times"),
                             ((name + b"=" + value, name), b"a value is required")))
        fail.extend((((b"--keys=4", b"--txs", b"--keys=5"), b"a value is required"),
                     ((b"--profile", b"--txs", b"--profile"), b"a value is required"),
                     ((b"--txs=2", b"--txs", b""), b"cannot be used multiple times")))
        for i, (args, expected) in enumerate(fail):
            old, _ = self.actual(f"strict-cli-{i}-rust", self.original, args)
            new, _ = self.actual(f"strict-cli-{i}-hia", self.native, args)
            self.assertEqual((old.returncode, old.stdout), (2, b""))
            self.assertIn(expected, old.stderr)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", old.stderr), args)
        for i, args in enumerate(((b"--",), (b"--txs=4", b"--keys", b"2", b"--"))):
            old, old_ns = self.actual(f"terminal-cli-{i}-rust", self.original, args)
            new, new_ns = self.actual(f"terminal-cli-{i}-hia", self.native, args)
            self.assertEqual((old.returncode, new.returncode, old.stderr, new.stderr), (0, 0, b"", b""))
            self.assertEqual(stdout_observation(old.stdout, old_ns)[1], stdout_observation(new.stdout, new_ns)[1])
        for i, args in enumerate(((b"--txs=1", b"--txs", b"-2"),
                                  (b"--txs", b"--", b"--profile"),
                                  (b"--help=true",), (b"--", b"--help"),
                                  (b"--reader-high-water-v1", b"--help"),
                                  (b"--reader-high-water-v1", b"--txs"),
                                  (b"--profile", b"--workload=mixed", b"--strategy=auto-adaptive"),
                                  (b"--profile", b"--strategy=aggressive-greedy", b"--workload=hot-streak"))):
            actual, _ = self.actual(f"plain-cli-denied-{i}", self.native, args)
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (2, b"", OUTSIDE))
        for name, args in (("help", (b"--help",)), ("missing", (b"--txs",))):
            actual, _ = self.actual(f"plain-cli-env-denied-{name}", self.native, args,
                                    env={b"HIA_BENCH_TEST_ONLY": b"synthetic-not-read"})
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_actual_free_standing_cli_diagnostic(self):
        # Full locked Bench and sealed standalone HIA processes, not parser adapters.
        suffix = (b"' found\n\nUsage: trnm-bench [OPTIONS]\n\n"
                  b"For more information, try '--help'.\n")
        help_result, _ = self.actual("free-arg-option-roster-rust", self.original, (b"--help",))
        self.assertEqual((help_result.returncode, help_result.stderr), (0, b""))
        # One genuine typo for each default Clap long flag, including auto-added help.
        tips = ((b"tx", b"txs"), (b"persist-profil", b"persist-profile"),
                (b"key", b"keys"), (b"worklod", b"workload"), (b"stratgy", b"strategy"),
                (b"read-fanut", b"read-fanout"), (b"write-evry", b"write-every"),
                (b"profil", b"profile"), (b"determinis-repeats", b"determinism-repeats"),
                (b"hel", b"help"))
        help_descriptors = re.findall(rb"(?m)^ +(?:-h, )?--([a-z-]+)(?: <([A-Z_]+)>)?$",
                                      help_result.stdout)
        self.assertEqual([arg for arg, _ in help_descriptors], [arg for _, arg in tips])
        # These ties exercise exact binary64 order, including the automatic help key.
        ties = ((b"re", b"write-every"), (b"els", b"help"), (b"etsy", b"keys"), (b"osra", b"strategy"))
        # Jaro's binary64 result for this total stripped length of 30 is
        # 0.7000000000000001, not the exact-rational 0.7.
        cutoff_above = b"txs" + b"Z" * 27
        cutoff_below = b"--txs" + b"Z" * 28
        metavar = dict(help_descriptors)
        for idx, token in enumerate((b"x", b"logfile", b"_name-12", b"MyWorkload_01-1",
                                     b"0", b"A" * 127, b"--unknown", b"--unknown-switch",
                                     b"--typo", b"--TXS", b"--404", b"--x", b"--" + b"Z" * 125,
                                     b"--not-a-bench-switch", cutoff_below)):
            exact = b"error: unexpected argument '" + token + suffix
            for owner, image in (("rust", self.original), ("hia", self.native)):
                result, _ = self.actual(f"free-arg-{idx}-{owner}", image, (token,))
                self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", exact), token)
        for idx, (typo, option) in enumerate(tips + ties + ((cutoff_above, b"txs"),)):
            args = (b"--" + typo,)
            display = (b" <" + metavar[option] + b">") if metavar[option] else b""
            exact = (b"error: unexpected argument '" + args[0] + b"' found\n\n"
                     b"  tip: a similar argument exists: '--" + option + b"'\n\n"
                     b"Usage: trnm-bench --" + option + display
                     + b"\n\nFor more information, try '--help'.\n")
            for owner, image in (("rust", self.original), ("hia", self.native)):
                result, _ = self.actual(f"free-arg-flag-tip-{idx}-{owner}", image, args)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", exact), args)
        for idx, args in enumerate(((b"A" * 128,), (b"--" + b"Z" * 126,),
                                    (b"",), (b"two words",), (b"two\nlines",), (b"bad\xff",),
                                    (b"---unknown",), (b"-x",),
                                    (b"--", b"logfile"), (b"--", b"--tx"),
                                    (b"--txs", b"--worklod"),
                                    (b"--reader-high-water-v1", b"logfile"))):
            rejected, _ = self.actual(f"free-arg-outside-{idx}", self.native, args)
            self.assertEqual((rejected.returncode, rejected.stdout, rejected.stderr), (2, b"", OUTSIDE), args)
        refused, _ = self.actual("free-arg-env-refused", self.native, (b"--unknown",),
                                 env={b"HIA_BENCH_TEST_ONLY": b"synthetic"})
        self.assertEqual((refused.returncode, refused.stdout, refused.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.bench_path.exists())

    def test_actual_unknown_long_assignment_elides_attached_value(self):
        # Clap classifies the name of an unknown standalone long option
        # before its value. Only the name reaches diagnostics or Jaro scoring.
        total_127 = (b"--unknown", b"Z" * (127 - len(b"--unknown=")))
        for idx, (option, value) in enumerate((
                (b"--unknown", b"ATTACHED_SECRETS_ARE_NOT_AN_ERROR_TOKEN"),
                (b"--unknown", b""), (b"--unknown", b"=still-attached"),
                (b"--unknown", b" --help = 'literal' "), (b"--unknown", b"~"),
                (b"--tx", b"4"), (b"--tx", b"clap-never-parses-this"),
                (b"--write-evry", b"=40"), (b"--hel", b"yes"), (b"--re", b"abc"),
                (b"--els", b"--workload"), total_127)):
            attached = option + b"=" + value
            bare, _ = self.actual(f"assign-{idx}-bare-rust", self.original, (option,))
            old, _ = self.actual(f"assign-{idx}-attached-rust", self.original, (attached,))
            new, _ = self.actual(f"assign-{idx}-attached-hia", self.native, (attached,))
            self.assertEqual((bare.returncode, bare.stdout), (2, b""))
            self.assertTrue(bare.stderr.startswith(b"error: unexpected argument '" + option + b"' found"))
            self.assertEqual((old.returncode, old.stdout, old.stderr), (2, b"", bare.stderr), attached)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", bare.stderr), attached)
        for idx, args in enumerate((
                (b"--unknown=" + b"Z" * (128 - len(b"--unknown=")),),
                (b"--unknown=x\ny",), (b"--unknown=\tfoo",), (b"--unknown=\x7f",),
                (b"--unknown=\xff",), (b"--=missing-name",), (b"--bad?=name",),
                (b"logfile=value",), (b"-x=value",), (b"---unknown=value",),
                (b"--help=value",), (b"--profile=true",), (b"--persist-profile=false",),
                (b"--reader-high-water-v1=true",),
                (b"--txs", b"--unknown=1"), (b"--", b"--unknown=1"))):
            new, _ = self.actual(f"assign-{idx}-outside", self.native, args)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", OUTSIDE), args)
        denied, _ = self.actual("assign-env-outside", self.native, (b"--tx=4",),
                                env={b"HIA_BENCH_TEST_ONLY": b"synthetic"})
        self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_actual_unknown_long_usage_after_one_completed_original_option(self):
        options = (
            (b"txs", b"TXS", b"1", b"tx"),
            (b"keys", b"KEYS", b"2", b"key"),
            (b"determinism-repeats", b"DETERMINISM_REPEATS", b"1001", b"determinis-repeats"),
            (b"profile", b"", b"", b"profil"),
            (b"read-fanout", b"READ_FANOUT", b"3", b"read-fanut"),
            (b"write-every", b"WRITE_EVERY", b"1", b"write-evry"),
            (b"workload", b"WORKLOAD", b"classic", b"worklod"),
            (b"persist-profile", b"", b"", b"persist-profil"),
            (b"strategy", b"STRATEGY", b"original", b"stratgy"))
        displays = {name: b"--" + name + (b" <" + meta + b">" if meta else b"")
                    for name, meta, _, _ in options}
        displays[b"help"] = b"--help"
        failures = [(b"--unknown", None), (b"--" + b"Z" * 125, None), (b"--hel", b"help")]
        failures.extend((b"--" + typo, name) for name, _, _, typo in options)
        count = 0
        for name, metavar, value, _ in options:
            option = b"--" + name
            prefixes = ((option + b"=" + value,), (option, value)) if metavar else ((option,),)
            for prefix in prefixes:
                for unknown, suggestion in failures:
                    args = (*prefix, unknown)
                    usage = b"Usage: trnm-bench " + displays[name]
                    if suggestion is not None and suggestion != name:
                        usage += b" " + displays[suggestion]
                    exact = b"error: unexpected argument '" + unknown + b"' found\n\n"
                    if suggestion is not None:
                        exact += b"  tip: a similar argument exists: '--" + suggestion + b"'\n\n"
                    exact += usage + b"\n\nFor more information, try '--help'.\n"
                    for owner, image in (("rust", self.original), ("hia", self.native)):
                        result, _ = self.actual(f"prior-cli-{count}-{owner}", image, args)
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                                         (2, b"", exact), args)
                    count += 1
        self.assertEqual(count, 192)
        early = (
            ((b"--txs=bad", b"--unknown"), b"invalid digit found in string"),
            ((b"--keys=2", b"--keys=3", b"--tx"), b"cannot be used multiple times"),
            ((b"--txs", b"--help", b"--unknown"), b"a value is required"),
            ((b"--workload=Mixed", b"--unknown"), b"[possible values:"))
        for idx, (args, reason) in enumerate(early):
            old, _ = self.actual(f"prior-early-{idx}-rust", self.original, args)
            new, _ = self.actual(f"prior-early-{idx}-hia", self.native, args)
            self.assertIn(reason, old.stderr)
            self.assertEqual((old.returncode, old.stdout), (2, b""))
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", old.stderr))
        args = (b"--profile", b"--help", b"--unknown")
        old, _ = self.actual("prior-early-help-rust", self.original, args)
        new, _ = self.actual("prior-early-help-hia", self.native, args)
        self.assertEqual((old.returncode, old.stderr), (0, b""))
        self.assertEqual((new.returncode, new.stdout, new.stderr), (0, old.stdout, b""))
        for idx, args in enumerate((
                (b"--profile", b"--", b"--unknown"),
                (b"--txs", b"--worklod"),
                (b"--reader-high-water-v1", b"--unknown"), (b"--profile", b"--" + b"Z"*126),
                (b"--profile", b"--unknown\xff"))):
            new, _ = self.actual(f"prior-cli-outside-{idx}", self.native, args)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", OUTSIDE), args)
        denied, _ = self.actual("prior-env-outside", self.native, (b"--profile", b"--tx"),
                                env={b"HIA_BENCH_TEST_ONLY": b"synthetic"})
        self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_actual_bounded_multi_option_unknown_tail(self):
        options = (
            ((b"--txs", b"4"), b"--txs <TXS>", b"--tx", b"--txs"),
            ((b"--keys=2",), b"--keys <KEYS>", b"--key", b"--keys"),
            ((b"--determinism-repeats=1001",), b"--determinism-repeats <DETERMINISM_REPEATS>",
             b"--determinis-repeats", b"--determinism-repeats"),
            ((b"--profile",), b"--profile", b"--profil", b"--profile"),
            ((b"--read-fanout", b"3"), b"--read-fanout <READ_FANOUT>",
             b"--read-fanut", b"--read-fanout"),
            ((b"--write-every=1",), b"--write-every <WRITE_EVERY>", b"--write-evry", b"--write-every"),
            ((b"--workload=mixed",), b"--workload <WORKLOAD>", b"--worklod", b"--workload"),
            ((b"--persist-profile",), b"--persist-profile", b"--persist-profil", b"--persist-profile"),
            ((b"--strategy", b"footprint-desc"), b"--strategy <STRATEGY>", b"--stratgy", b"--strategy"),
        )
        prefixes = list(permutations(range(len(options)), 2))
        prefixes.extend(tuple(range(length - 1, -1, -1)) for length in range(3, 10))
        prefixes.extend((tuple(range(9)), (8, 0, 7, 1, 6, 2, 5, 3, 4)))
        checked = 0
        for prefix in prefixes:
            pre = tuple(word for slot in prefix for word in options[slot][0])
            used = b" ".join(options[slot][1] for slot in prefix)
            in_option = options[prefix[0]]
            spare = next((slot for slot in range(len(options)) if slot not in prefix), None)
            tails = [(b"--ZZZZZ", b"", used), (in_option[2], in_option[3], used),
                     (b"--helpful", b"--help", used + b" --help"),
                     (b"free_tail-2", b"", b"[OPTIONS]")]
            if spare is not None:
                unused = options[spare]
                tails.append((unused[2], unused[3], used + b" " + unused[1]))
            for j, (echo, suggestion, usage) in enumerate(tails):
                tail = echo + b"=discard=this" if echo.startswith(b"--") and j % 2 else echo
                args = (*pre, tail)
                expected = b"error: unexpected argument '" + echo + b"' found\n\n"
                if suggestion:
                    expected += b"  tip: a similar argument exists: '" + suggestion + b"'\n\n"
                expected += b"Usage: trnm-bench " + usage + b"\n\nFor more information, try '--help'.\n"
                for owner, image in (("rust", self.original), ("hia", self.native)):
                    result, _ = self.actual(f"multi-cli-{checked}-{owner}", image, args)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", expected), args)
                checked += 1
        self.assertEqual(checked, 402)
        ordered = (b"--profile", b"--keys=2")
        pass_cases = (
            (*ordered, b"--" + b"Z" * 122),
            (*ordered, b"--" + b"Z" * 120 + b"=tail"),
            (*ordered, b"--ZZZZZ="),
            (*ordered, b"positional"),
            (b"--profile", b"--ZZZZZ=x"),
            (b"--profile", b"positional"),
            (*ordered, b"--txs=bad", b"--ZZZZZ"),
            (*ordered, b"--keys=3", b"--ZZZZZ"),
            (*ordered, b"--txs", b"--help", b"--ZZZZZ"),
            (b"--txs", b"4", b"--keys", b"2", b"--determinism-repeats", b"1001",
             b"--profile", b"--read-fanout", b"3", b"--write-every", b"1",
             b"--workload", b"mixed", b"--persist-profile", b"--strategy",
             b"footprint-desc", b"--ZZZZZ"),
            (*ordered, b"--help", b"--ZZZZZ"),
        )
        for j, args in enumerate(pass_cases):
            old, _ = self.actual(f"multi-bound-{j}-rust", self.original, args)
            new, _ = self.actual(f"multi-bound-{j}-hia", self.native, args)
            self.assertEqual(old.returncode, 0 if j == len(pass_cases) - 1 else 2, args)
            self.assertEqual((new.returncode, new.stdout, new.stderr),
                             (old.returncode, old.stdout, old.stderr), args)
        refuse_cases = (
            (*ordered, b"--" + b"Z" * 123),
            (*ordered, b"--" + b"Z" * 120 + b"=tails"),
            (*ordered, b"--ZZZZZ=bad\x01"), (*ordered, b"--ZZZZZ\xff"),
            (*ordered, b"--", b"--ZZZZZ"),
            (*ordered, b"--reader-high-water-v1", b"--ZZZZZ"),
        )
        for j, args in enumerate(refuse_cases):
            native, _ = self.actual(f"multi-outside-{j}", self.native, args)
            self.assertEqual((native.returncode, native.stdout, native.stderr), (2, b"", OUTSIDE), args)
        self.assertFalse(self.run_path.exists())

    def test_actual_first_unknown_precedes_bounded_suffix(self):
        # The original result for the prefix + first error is the comparison
        # anchor. All suffixes must retain it, including argv that would
        # produce different diagnostics if interpreted.
        prefixes = (
            (),
            (b"--keys=2",),
            (b"--txs", b"4", b"--profile", b"--keys=2"),
            (b"--profile", b"--keys=2", b"--txs=4", b"--workload=mixed", b"--strategy=original",
             b"--read-fanout=3", b"--write-every=1", b"--persist-profile", b"--determinism-repeats=1001"),
        )
        initial = (b"--typo", b"--tx=elided", b"--profil", b"--hel", b"--unknown=", b"ordinary_1")
        tails = (
            (b"--help",), (b"-h",), (b"--txs", b"1"), (b"--txs=1",),
            (b"--keys", b"bad"), (b"--txs",), (b"--keys=2", b"--keys=3"),
            (b"--typo", b"--again"), (b"ordinary_2",), (b"--",),
            (b"--", b"--profile"), (b"--help=not-a-request",),
            (b"--profile", b"--strategy", b"original"), (b"--txs", b"--help"),
            (b"--txs=4", b"--help"), (b"",), (b"uninterpreted-\xff",),
        )
        total = 0
        for x, prefix in enumerate(prefixes):
            for y, first in enumerate(initial):
                args = (*prefix, first)
                ref, _ = self.actual(f"first-unknown-base-{x}-{y}", self.original, args)
                token = first.split(b"=", 1)[0]
                self.assertTrue(ref.stderr.startswith(b"error: unexpected argument '" + token + b"' found\n"))
                expected = (2, b"", ref.stderr)
                self.assertEqual((ref.returncode, ref.stdout, ref.stderr), expected)
                for trail in tails:
                    candidate = (*args, *trail)
                    for owner, image in (("rust", self.original), ("hia", self.native)):
                        actual, _ = self.actual(f"first-unknown-{total}-{owner}", image, candidate)
                        self.assertEqual((actual.returncode, actual.stdout, actual.stderr), expected, candidate)
                    total += 1
        self.assertEqual(total, 408)

        extent = (b"--keys=2", b"--txs=4", b"--" + b"Z" * 122, *(b"ignored",) * 14)
        self.assertEqual(len(extent), 17)
        for i, args in enumerate((extent,
                                  (b"--keys=2", b"--txs=bad", b"--ZZZZZ", b"--help"),
                                  (b"--keys=2", b"--keys=3", b"--ZZZZZ", b"--profile"),
                                  (b"--keys=2", b"--strategy=bad", b"--ZZZZZ", b"--help"),
                                  (b"--keys=2", b"--help", b"--ZZZZZ", b"--profile"))):
            original, _ = self.actual(f"first-unknown-limit-{i}-rust", self.original, args)
            native, _ = self.actual(f"first-unknown-limit-{i}-hia", self.native, args)
            self.assertEqual(original.returncode, 0 if i == 4 else 2)
            self.assertEqual((native.returncode, native.stdout, native.stderr),
                             (original.returncode, original.stdout, original.stderr), args)

        for i, args in enumerate(((*extent, b"too-many"),
                                   (b"--keys=2", b"--txs=4", b"--" + b"Z"*123, b"--help"),
                                   (b"--unknown=invalid-value\xff", b"--help"),
                                   (b"--reader-high-water-v1", b"--ZZZZZ", b"--help"),
                                   (b"--", b"--ZZZZZ", b"--help"),
                                   (b"-x", b"--ZZZZZ", b"--help"))):
            native, _ = self.actual(f"first-unknown-outside-{i}", self.native, args)
            self.assertEqual((native.returncode, native.stdout, native.stderr), (2, b"", OUTSIDE), args)
        denied, _ = self.actual("first-unknown-env-fence", self.native, (b"--ZZZZZ", b"--help"),
                                env={b"HIA_BENCH_TEST_ONLY": b"synthetic"})
        self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_actual_plain_uint_cli_diagnostics_and_no_unbounded_echo(self):
        # Check every original unsigned field, both spellings, precedence,
        # the maximum Unix staging length, and no partial echo or file effect.
        fields = (b"--txs", b"--keys", b"--determinism-repeats", b"--read-fanout", b"--write-every")
        empty = b"cannot parse integer from empty string"
        invalid = b"invalid digit found in string"
        overflow = b"number too large to fit in target type"
        values = ((b"", empty), (b"+", invalid), (b"bad", invalid), (b"-1", invalid),
                  (b" 4", invalid), (b"12'abc", invalid),
                  (b"18446744073709551616", overflow), (b"+18446744073709551616x", overflow),
                  (b"1844674407370955161x", invalid), (b"9999999999999999999x", invalid),
                  (b"00018446744073709551616", overflow))
        cases = []
        for key in fields:
            for val, error in values:
                cases.append(((b"--profile", key + b"=" + val, b"--help"), error))
                if not val.startswith(b"-"):
                    cases.append(((b"--profile", key, val, b"--help"), error))
            cases.append(((key, b"-"), invalid))
            cases.append(((key, b"0" * 126 + b"x"), invalid))
        for i, (args, reason) in enumerate(cases):
            old, _ = self.actual(f"uint-cli-{i}-rust", self.original, args)
            new, _ = self.actual(f"uint-cli-{i}-hia", self.native, args)
            self.assertEqual((old.returncode, old.stdout), (2, b""))
            self.assertIn(reason, old.stderr)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", old.stderr), args)
        closed = ((b"--txs=\xff",), (b"--txs=bad\x01",), (b"--txs=bad\x1b[0m",),
                  (b"--write-every=\t",), (b"--read-fanout", b"0" * 127 + b"x"),
                  (b"--txs", b"-1"), (b"--reader-high-water-v1", b"--txs=bad"))
        for i, args in enumerate(closed):
            new, _ = self.actual(f"uint-cli-closed-{i}-hia", self.native, args)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", OUTSIDE))
        denied, _ = self.actual("uint-cli-env-denied", self.native, (b"--txs=bad",),
                                env={b"HIA_BENCH_TEST_ONLY": b"synthetic"})
        self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_actual_plain_enum_diagnostics_and_exact_similarity_boundary(self):
        groups = (
            (b"--workload", (b"classic", b"mixed", b"hot-streak")),
            (b"--strategy", (b"original", b"footprint-desc", b"write-first", b"write-last",
                              b"hot-bucket-interleave", b"auto-adaptive", b"aggressive-greedy")),
        )
        # o crosses 0.7 by one binary64 step, lcs is below. write-rilst
        # ties two exact f64 scores; the source value listed last must win.
        fixed = (
            (0, b"o", b"hot-streak"), (0, b"lcs", b""), (0, b"Mixed", b"mixed"),
            (0, b"CLASSIC", b""), (1, b"write-rilst", b"write-last"),
            (1, b"e", b"write-last"), (1, b"--", b""), (1, b"write", b"write-last"),
            (1, b"writ-first", b"write-first"), (1, b"auto-adaptav", b"auto-adaptive"),
        )
        cases = [(groups[k][0], value, tip) for k, value, tip in fixed]
        for flag, expected in groups:
            values = {b"", b"arbitrary invalid synthetic", b"z" * 127, b"z" * 116, b"-", b"wrong'text"}
            for name in expected:
                for at in (0, len(name) // 2, len(name) - 1):
                    values.update((name[:at] + name[at + 1:], name[:at] + name[at:at + 1].upper() + name[at + 1:],
                                   name[:at] + b"x" + name[at + 1:]))
                for at in range(0, len(name) - 1, 3):
                    values.add(name[:at] + name[at:at + 2][::-1] + name[at + 2:])
            cases.extend((flag, value, None) for value in sorted(values.difference(expected)))
        number = 0
        suggestion_count = 0
        for flag, value, tip in cases:
            arguments = []
            if len(flag) + 1 + len(value) <= 127:
                arguments.append((flag + b"=" + value,))
            if not (len(value) > 1 and value.startswith(b"-")):
                arguments.append((flag, value))
            for words in arguments:
                args = (b"--profile", *words, b"--help")
                old, _ = self.actual(f"enum-cli-{number}-rust", self.original, args)
                new, _ = self.actual(f"enum-cli-{number}-hia", self.native, args)
                number += 1
                self.assertEqual((old.returncode, old.stdout), (2, b""))
                self.assertIn(b"[possible values:", old.stderr)
                self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", old.stderr), args)
                suggestion_count += b"tip: a similar value exists:" in old.stderr
                if tip:
                    self.assertIn(b"tip: a similar value exists: '" + tip + b"'\n", old.stderr)
                elif tip == b"":
                    self.assertNotIn(b"tip:", old.stderr)
        self.assertGreater(number, 200)
        self.assertGreater(suggestion_count, 100)
        for i, (args, env) in enumerate((
                ((b"--workload=\xff",), {}), ((b"--strategy=\x1brust",), {}),
                ((b"--workload", b"x" * 128), {}), ((b"--workload", b"--misspelled"), {}),
                ((b"--reader-high-water-v1", b"--strategy=writ-first"), {}),
                ((b"--strategy=writ-first",), {b"HIA_BENCH_TEST_ONLY": b"synthetic"}),
                ((b"--workload=mixed", b"--strategy=auto-adaptive"), {}),
                ((b"--strategy=aggressive-greedy", b"--workload=mixed"), {}))):
            denied, _ = self.actual(f"enum-cli-closed-{i}", self.native, args, env=env)
            self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_plain_cli_help_refuses_native_terminal_without_emitting_help(self):
        master, slave = pty.openpty()
        fd = sealed_executable(self.native, "plain-help-terminal")
        try:
            actual = subprocess.run([b"trnm-bench", b"-h"], executable=f"/proc/self/fd/{fd}", pass_fds=(fd,),
                                    stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE, env={},
                                    cwd=self.root, timeout=25)
        finally:
            os.close(fd)
            os.close(slave)
            os.close(master)
        self.assertEqual((actual.returncode, actual.stderr), (2, OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_unsupported_original_modes_never_success_or_write_a_file(self):
        for index, args in enumerate(((b"--profile=true",), (b"--workload=mixed",),
                                      (b"--workload=hot-streak",), (b"--strategy=footprint-desc", b"--keys=1999"),
                                      (b"--txs=20001",),
                                      (b"--workload=mixed", b"--txs=32", b"--keys=2", b"--write-every=31"),
                                      (b"--workload=hot-streak", b"--txs=32", b"--keys=2", b"--write-every=31"),
                                      (b"--workload=mixed", b"--keys=1", b"--read-fanout=9"),
                                      (b"--workload=hot-streak", b"--txs=8", b"--keys=2",
                                       b"--write-every=8", b"--read-fanout=9"))):
            result, _ = self.actual(f"outside-{index}", self.native, args)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", OUTSIDE))
        result, _ = self.actual("outside-env", self.native, (b"--txs=4",),
                                env={b"TRNM_HOT_BUCKETS": b"16"})
        self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", OUTSIDE))

    def reset_profile_path(self):
        # This is the unique copy created for this test class. Never remove or
        # change an original checkout output directory.
        self.assertTrue(self.run_path.is_relative_to(self.root))
        if self.run_path.is_symlink() or self.run_path.is_file():
            self.run_path.unlink()
        elif self.run_path.is_dir():
            shutil.rmtree(self.run_path)

    def profile_comparable(self, result, wall_ns, variant):
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        elapsed, common = stdout_observation(result.stdout, wall_ns)
        fields = dict(line.split(b"=", 1) for line in result.stdout.splitlines() if b"=" in line)
        base = b"profile.report."
        epoch = int(fields[base + b"capture_started_at_epoch"])
        event = self.events[-1]
        self.assertLessEqual(event["realtime_start_ns"] // 10**9, epoch)
        self.assertLessEqual(epoch, event["realtime_end_ns"] // 10**9)
        iso = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ").encode()
        self.assertEqual(fields[base + b"capture_started_at_iso"], iso)
        for key in (b"capture_stamp", b"capture_stamp_epoch"):
            self.assertEqual(int(fields[base + key]), epoch)
        self.assertEqual(int(fields[base + b"elapsed_ms"]), elapsed)
        name = f"executor-profile-summary-{epoch}.txt"
        artifact = self.bench_path / name
        event.update(observed_elapsed_ms=elapsed, observed_realtime_epoch=epoch)
        replacements = {base + k: b"<observed>" for k in (
            b"capture_started_at_epoch", b"capture_started_at_iso", b"capture_stamp",
            b"capture_stamp_epoch", b"elapsed_ms")}
        if variant != "directory":
            self.assertEqual(fields[base + b"path"], os.fsencode(artifact))
            self.assertEqual(fields[base + b"artifact_basename"], os.fsencode(name))
            replacements[base + b"path"] = os.fsencode(self.bench_path / "executor-profile-summary-<observed>.txt")
            replacements[base + b"artifact_basename"] = b"executor-profile-summary-<observed>.txt"
        else:
            self.assertNotIn(base + b"path", fields)
            self.assertNotIn(base + b"artifact_basename", fields)
        raw_file = None
        if variant == "file":
            self.assertNotIn(base + b"persist_error", fields)
            raw_file = artifact.read_bytes()
            count = raw_file.count(b"\n")
            file_tail = (f"profile.report.output_line_count={count}\n"
                         f"profile.report.output_bytes={len(raw_file)}\n").encode()
            self.assertEqual(raw_file, result.stdout + file_tail)
            (self.root / (event["label"] + ".file.raw")).write_bytes(raw_file)
            event.update(file_path=str(artifact), file_sha256=digest(raw_file),
                         file_bytes=len(raw_file), file_lines=count)
        elif variant == "directory":
            self.assertEqual(fields[base + b"persist_error"], b"Not a directory (os error 20)")
            self.assertFalse(artifact.exists())
        elif variant == "write":
            self.assertEqual(fields[base + b"persist_error"], b"Is a directory (os error 21)")
            self.assertTrue(artifact.is_dir())
        elif variant == "candidate-file-guard":
            self.assertEqual(fields[base + b"persist_error"],
                             b"Bench profile output requires a single-link regular file")
        elif variant == "partial":
            self.assertEqual(fields[base + b"persist_error"], b"File too large (os error 27)")
            raw_file = artifact.read_bytes()
            self.assertEqual(len(raw_file), 64)
            self.assertEqual(raw_file, result.stdout[:64])
            (self.root / (event["label"] + ".file.raw")).write_bytes(raw_file)
            event.update(file_path=str(artifact), file_sha256=digest(raw_file), file_bytes=len(raw_file))
        else:
            self.fail("Unexpected scoped profile test outcome")
        def normalize(line):
            key, sep, _ = line.partition(b"=")
            return key + sep + replacements[key] if key in replacements else line
        comparable = b"\n".join(normalize(line) for line in common.split(b"\n"))
        return comparable, epoch, raw_file

    def test_profile_actual_fixed_point_same_second_replaces_and_exact_bytes(self):
        observed_twins = {}
        for kind, image in (("original", self.original), ("native", self.native)):
            self.reset_profile_path()
            # Start both small invocations just inside an epoch second. If a
            # busy runner crosses the boundary, preserve both attempts, then
            # repeat in a fresh isolated fixture; never rewrite their clocks.
            for attempt in range(3):
                self.reset_profile_path()
                now = time.time_ns()
                until = (10**9 - now % 10**9) / 10**9
                time.sleep(until + 0.020)
                one = self.profile_comparable(*self.actual(f"profile-{kind}-{attempt}-one", image,
                    (b"--profile", b"--txs=120", b"--keys=2")), "file")
                two = self.profile_comparable(*self.actual(f"profile-{kind}-{attempt}-two", image, PROFILE_ARGS), "file")
                if one[1] != two[1]:
                    continue
                self.assertGreater(len(one[2]), len(two[2]))
                self.assertEqual(len(list(self.bench_path.iterdir())), 1)
                observed_twins[kind] = (one[0], two[0])
                break
            else:
                self.fail("Could not observe an actual same-second replacement")
        self.assertEqual(observed_twins["original"], observed_twins["native"])
        self.reset_profile_path()

    def test_profile_actual_directory_and_file_errors_preserve_order(self):
        observed = {"directory": [], "write": []}
        for kind, image in (("original", self.original), ("native", self.native)):
            self.reset_profile_path()
            self.run_path.write_bytes(b"synthetic-directory-blocker")
            label = f"profile-{kind}-directory"
            report, _, _ = self.profile_comparable(*self.actual(label, image, PROFILE_ARGS), "directory")
            observed["directory"].append(report)
            self.assertEqual(self.run_path.read_bytes(), b"synthetic-directory-blocker")

            self.reset_profile_path()
            self.bench_path.mkdir(parents=True)
            now = time.time_ns() // 10**9
            seeded = [f"executor-profile-summary-{s}.txt" for s in range(now - 2, now + 6)]
            for directory in seeded:
                (self.bench_path / directory).mkdir()
            label = f"profile-{kind}-write"
            report, _, _ = self.profile_comparable(*self.actual(label, image, PROFILE_ARGS), "write")
            observed["write"].append(report)
            self.assertEqual(sorted(p.name for p in self.bench_path.iterdir()), sorted(seeded))
        for original, native in observed.values():
            self.assertEqual(original, native)
        self.reset_profile_path()

    def test_profile_path_is_confined_and_no_unbound_file_owner(self):
        self.reset_profile_path()
        quarantine = self.root / "synthetic-rejected-destination"
        quarantine.mkdir()
        marker = quarantine / "sentinel"
        marker.write_bytes(b"unchanged")
        self.run_path.symlink_to(quarantine, target_is_directory=True)
        report, _, _ = self.profile_comparable(*self.actual("profile-native-confined", self.native,
                                                             PROFILE_ARGS), "directory")
        self.assertIn(b"persist_error=Not a directory (os error 20)\n", report)
        self.assertEqual([p.name for p in quarantine.iterdir()], ["sentinel"])
        self.assertEqual(marker.read_bytes(), b"unchanged")
        self.reset_profile_path()
        unbound, _ = build(self.root / "native-unbound")
        result, _ = self.actual("profile-native-unbound", unbound, PROFILE_ARGS)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_profile_actual_short_file_and_write_errno(self):
        def restrict_file():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))
        outputs = []
        for kind, image in (("original", self.original), ("native", self.native)):
            self.reset_profile_path()
            label = f"profile-{kind}-actual-write-error"
            comparable, _, partial = self.profile_comparable(*self.actual(label, image, PROFILE_ARGS,
                                                                          prepare=restrict_file), "partial")
            outputs.append((comparable, partial))
            self.assertEqual(len(list(self.bench_path.iterdir())), 1)
        self.assertEqual(outputs[0], outputs[1])
        self.reset_profile_path()

    def test_profile_does_not_truncate_hardlinks_or_wait_on_fifo(self):
        for kind in ("hardlink", "fifo"):
            with self.subTest(kind=kind):
                self.reset_profile_path()
                self.bench_path.mkdir(parents=True)
                isolated_sentinel = self.root / "synthetic-file-guard-sentinel"
                isolated_sentinel.write_bytes(b"do not truncate")
                now = time.time_ns() // 10**9
                targets = [self.bench_path / f"executor-profile-summary-{s}.txt"
                           for s in range(now - 2, now + 6)]
                for path in targets:
                    if kind == "hardlink":
                        os.link(isolated_sentinel, path)
                    else:
                        os.mkfifo(path, mode=0o600)
                label = f"profile-native-{kind}-guard"
                report, _, _ = self.profile_comparable(*self.actual(label, self.native, PROFILE_ARGS),
                                                         "candidate-file-guard")
                self.assertIn(b"requires a single-link regular file", report)
                self.assertEqual(isolated_sentinel.read_bytes(), b"do not truncate")
                self.assertEqual(set(targets), set(self.bench_path.iterdir()))
                self.reset_profile_path()

    def test_actual_profile_with_all_workload_options_and_full_cli_extent(self):
        # Every value-bearing option uses a separate token to reach the prior
        # adapter's new 17 argv-entry boundary, including argv[0].
        mixed = (b"--profile", b"--persist-profile", b"--txs", b"33", b"--keys", b"3",
                 b"--determinism-repeats", b"0", b"--read-fanout", b"8", b"--write-every",
                 b"33", b"--workload", b"mixed", b"--strategy", b"original")
        hot = (b"--profile", b"--persist-profile", b"--txs=40", b"--keys=1",
               b"--read-fanout=8", b"--write-every=3", b"--workload=hot-streak")
        for index, args in enumerate((mixed, hot)):
            matched = []
            for tag, image in (("original", self.original), ("native", self.native)):
                self.reset_profile_path()
                label = f"profile-workload-{index}-{tag}"
                out, _, _ = self.profile_comparable(*self.actual(label, image, args), "file")
                matched.append(out)
            self.assertEqual(matched[0], matched[1])
        self.reset_profile_path()

    def test_actual_replay_cli_and_profile_against_locked_rust(self):
        admitted = (
            (b"--txs=4", b"--keys=4", b"--determinism-repeats=1"),
            (b"--txs=1", b"--determinism-repeats", b"1000"),
            (b"--txs=20", b"--keys=1", b"--workload=hot-streak", b"--determinism-repeats=5"),
            (b"--txs=20", b"--keys=2", b"--workload=mixed", b"--write-every=20",
             b"--determinism-repeats=3"),
        )
        for index, args in enumerate(admitted):
            old, old_wall = self.actual(f"replay-{index}-original", self.original, args)
            new, new_wall = self.actual(f"replay-{index}-native", self.native, args)
            self.assertEqual((old.returncode, new.returncode, old.stderr, new.stderr), (0, 0, b"", b""))
            before_ms, before = stdout_observation(old.stdout, old_wall)
            after_ms, after = stdout_observation(new.stdout, new_wall)
            self.events[-2]["observed_elapsed_ms"] = before_ms
            self.events[-1]["observed_elapsed_ms"] = after_ms
            self.assertEqual(after, before)
            self.assertIn(b"\ndeterminism.replay_match=true\n", after)
            self.assertFalse(self.run_path.exists())
        observed = []
        args = (b"--profile", b"--txs=4", b"--keys=4", b"--determinism-repeats=3")
        for kind, image in (("original", self.original), ("native", self.native)):
            self.reset_profile_path()
            row, _, _ = self.profile_comparable(*self.actual(f"replay-profile-{kind}", image, args), "file")
            self.assertIn(b"\ndeterminism.replay_match=true\n", row)
            observed.append(row)
        self.assertEqual(observed[0], observed[1])
        self.reset_profile_path()

    def test_actual_write_first_reorders_both_workload_families(self):
        for workload in (b"mixed", b"hot-streak"):
            args = (b"--workload="+workload, b"--txs=32", b"--keys=1",
                    b"--read-fanout=8", b"--write-every=3", b"--determinism-repeats=2")
            prefix = "write-first-" + workload.decode()
            observed = {}
            for strategy in (b"original", b"write-last", b"write-first"):
                flag = (b"--strategy", strategy)
                before, bt = self.actual(prefix+"-"+strategy.decode()+"-rust", self.original, (*args, *flag))
                after, at = self.actual(prefix+"-"+strategy.decode()+"-native", self.native, (*args, *flag))
                self.assertEqual((before.returncode, before.stderr, after.returncode, after.stderr), (0, b"", 0, b""))
                base_ms, base = stdout_observation(before.stdout, bt)
                after_ms, changed = stdout_observation(after.stdout, at)
                self.events[-2]["observed_elapsed_ms"] = base_ms
                self.events[-1]["observed_elapsed_ms"] = after_ms
                self.assertEqual(base, changed)
                fields = dict(row.split(b"=",1) for row in base.splitlines() if b"=" in row)
                self.assertEqual(fields[b"determinism.replay_match"], b"true")
                self.assertNotIn(b"schedule_semantics", fields)
                observed[strategy] = fields
            first = observed[b"write-first"]
            self.assertEqual(first[b"strategy"], b"WriteFirst")
            self.assertEqual([observed[k][b"groups"] for k in (b"original",b"write-first",b"write-last")],
                             [b"22", b"12", b"12"])
            self.assertEqual(len({v[b"determinism.input_sha256"] for v in observed.values()}), 1)
            self.assertEqual(len({v[b"determinism.groups_sha256"] for v in observed.values()}), 3)
            self.assertFalse(self.run_path.exists())

    def test_actual_write_first_profile_and_existing_fences(self):
        # Split/equals are both used. At this workload boundary only the
        # initial transaction writes, so old and repaired contracts agree.
        args = (b"--profile", b"--txs=32", b"--keys=7", b"--read-fanout=8",
                b"--write-every=32", b"--determinism-repeats=2", b"--workload=hot-streak",
                b"--strategy=write-first")
        paired = []
        for kind, image in (("rust", self.original), ("hia", self.native)):
            self.reset_profile_path()
            raw, _, persisted = self.profile_comparable(*self.actual("write-first-profile-"+kind,image,args), "file")
            self.assertIn(b"\nprofile.report.strategy=WriteFirst\n", raw)
            self.assertNotIn(b"schedule_semantics=", persisted)
            paired.append(raw)
        self.assertEqual(*paired)
        self.reset_profile_path()
        for idx, flags in enumerate(((b"--workload=mixed",), (b"--workload=hot-streak",),
                (b"--workload=mixed", b"--txs=32", b"--keys=7", b"--write-every=31"),
                (b"--workload=hot-streak", b"--keys=1", b"--read-fanout=9"))):
            denied, _ = self.actual(f"write-first-unsupported-{idx}", self.native,
                                     (b"--strategy=write-first", b"--profile", *flags))
            self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
        denied, _ = self.actual("write-first-env-denied", self.native,
                       (b"--strategy=write-first", b"--txs=2"), env={b"TRNM_HOT_BUCKETS":b"8"})
        self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (2, b"", OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_actual_write_last_dispatch_and_replay_against_locked_rust(self):
        fixtures = (
            # Same write footprint per transaction: stable tie order.
            (b"classic", 32, 7, 1, 1, 1),
            # Reordering is observable at the key and stride boundaries.
            (b"mixed", 32, 1, 8, 3, 3),
            (b"hot-streak", 32, 1, 8, 3, 3),
            (b"mixed", 32, 7, 8, 32, 2),
            (b"hot-streak", 32, 7, 8, 32, 2),
            (b"classic", 20000, 2000, 2, 8, 0),
        )
        for index, (workload, n, keys, fanout, stride, repeats) in enumerate(fixtures):
            args = (b"--workload=" + workload, f"--txs={n}".encode(), f"--keys={keys}".encode(),
                    f"--read-fanout={fanout}".encode(), f"--write-every={stride}".encode(),
                    f"--determinism-repeats={repeats}".encode())
            strategy = (b"--strategy", b"write-last") if index % 2 else (b"--strategy=write-last",)
            before, before_wall = self.actual(f"write-last-{index}-original", self.original, (*args, *strategy))
            after, after_wall = self.actual(f"write-last-{index}-native", self.native, (*args, *strategy))
            self.assertEqual((before.returncode, after.returncode, before.stderr, after.stderr),
                             (0, 0, b"", b""))
            before_ms, before_raw = stdout_observation(before.stdout, before_wall)
            after_ms, after_raw = stdout_observation(after.stdout, after_wall)
            self.events[-2]["observed_elapsed_ms"] = before_ms
            self.events[-1]["observed_elapsed_ms"] = after_ms
            self.assertEqual(before_raw, after_raw)
            self.assertIn(b"\nstrategy=WriteLast\n", after_raw)
            replay_state = b"true" if repeats else b"not-requested"
            self.assertIn(b"\ndeterminism.replay_match=" + replay_state + b"\n", after_raw)
            # A label-only implementation could pass on Classic. Require
            # different original/native-verified grouping for both interleaved
            # one-key workloads; compare the entire locked-Rust stdout above.
            if index in (1, 2):
                original_order, _ = self.actual(f"write-last-{index}-control", self.original, args)
                self.assertEqual((original_order.returncode, original_order.stderr), (0, b""))
                def fields(raw):
                    return dict(line.split(b"=", 1) for line in raw.splitlines() if b"=" in line)

                original_fields, write_last_fields = fields(original_order.stdout), fields(after_raw)
                self.assertEqual(original_fields[b"determinism.input_sha256"],
                                 write_last_fields[b"determinism.input_sha256"])
                self.assertNotEqual(original_fields[b"determinism.groups_sha256"],
                                    write_last_fields[b"determinism.groups_sha256"])
                self.assertEqual((original_fields[b"groups"], write_last_fields[b"groups"]), (b"22", b"12"))
            self.assertFalse(self.run_path.exists())

    def test_actual_write_last_profile_and_unchanged_refusal(self):
        for index, flags in enumerate((
                (b"--workload=mixed", b"--keys=1", b"--write-every=3"),
                (b"--workload=hot-streak", b"--keys=7", b"--write-every=32"))):
            args = (*flags, b"--strategy=write-last", b"--profile", b"--txs=32",
                    b"--read-fanout=8", b"--determinism-repeats=2")
            results = []
            for tag, image in (("original", self.original), ("native", self.native)):
                self.reset_profile_path()
                label = f"write-last-profile-{index}-{tag}"
                report, _, _ = self.profile_comparable(*self.actual(label, image, args), "file")
                self.assertIn(b"\nprofile.report.strategy=WriteLast\n", report)
                results.append(report)
            self.assertEqual(*results)
        self.reset_profile_path()
        over = (b"--profile", b"--workload=mixed", b"--strategy=write-last", b"--determinism-repeats=1001")
        for tag, image in (("original", self.original), ("native", self.native)):
            actual, _ = self.actual(f"write-last-replay-bound-{tag}", image, over)
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (2, b"", REPEAT))
            self.assertFalse(self.run_path.exists())
        for index, flags in enumerate((
                (b"--workload=mixed",), (b"--workload=hot-streak",),
                (b"--workload=mixed", b"--txs=32", b"--keys=7", b"--write-every=31"),
                (b"--workload=hot-streak", b"--txs=32", b"--keys=1", b"--read-fanout=9"),
                (b"--workload=write-last",), (b"--strategy=write-laST",),
                (b"--strategy=write-last-extra",))):
            args = (b"--profile", *flags) if flags[0].startswith(b"--strategy") else (
                b"--profile", b"--strategy=write-last", *flags)
            actual, _ = self.actual(f"write-last-refused-{index}", self.native, args)
            if index >= 4:
                original, _ = self.actual(f"write-last-refused-{index}-rust", self.original, args)
                self.assertEqual((original.returncode, original.stdout), (2, b""))
                self.assertIn(b"[possible values:", original.stderr)
                expected = original.stderr
            else:
                expected = OUTSIDE
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (2, b"", expected))
            self.assertFalse(self.run_path.exists())

    def test_actual_classic_auto_adaptive_decision_profile_and_replay(self):
        def independent_classic_decision(raw_n, raw_keys):
            n, keys = max(1, raw_n), max(1, raw_keys)
            sample = min(n, 2048)
            if n < 512:
                active, reason, streak, share = False, b"small_batch", 0.0, 0.0
            else:
                ids = [j * (n - 1) // (sample - 1) % keys for j in range(sample)]
                streak = sum(x == y for x, y in zip(ids, ids[1:])) / (sample - 1)
                share = max(Counter(ids).values()) / sample
                active = streak >= 0.22 + 0.04 and share >= 0.0075 and streak * share >= 0.01
                reason = (b"hotspot_detected" if active else b"low_hot_key_share" if share < 0.0075
                          else b"low_expected_gain" if streak * share < 0.01 else b"below_streak_budget")
            f = lambda x: f"{x:.4f}".encode()
            return {b"profile.auto." + k: v for k, v in {
                b"use_hot_bucket": b"true" if active else b"false", b"reason": reason,
                b"sample_len": str(sample).encode(), b"streak_ratio": f(streak),
                b"streak_threshold": b"0.2200", b"min_margin": b"0.0400",
                b"hot_key_share": f(share), b"min_hot_key_share": b"0.0075",
                b"expected_gain_score": f(streak * share), b"min_expected_gain_score": b"0.0100"}.items()}

        def items(raw):
            return dict(line.split(b"=", 1) for line in raw.splitlines() if b"=" in line)

        witnesses = {}
        cases = ((0, 0, 1000), (511, 1, 2), (512, 1, 2), (513, 4, 2), (2048, 4, 2),
                 (2049, 4, 2), (4095, 2, 2), (20_000, 2_000, 2))
        reason_roster = set()
        for i, (n, k, repeats) in enumerate(cases):
            args = [b"--strategy", b"auto-adaptive"] if i % 2 == 0 else [b"--strategy=auto-adaptive"]
            if i == 0:
                args += [b"--workload=classic"]
            if i != len(cases) - 1:
                args += [f"--txs={n}".encode(), f"--keys={k}".encode()]
            args += [f"--determinism-repeats={repeats}".encode()]
            expected = independent_classic_decision(n, k)
            reason_roster.add(expected[b"profile.auto.reason"])
            pair = []
            for name, image in (("rust", self.original), ("native", self.native)):
                self.reset_profile_path()
                actual, elapsed = self.actual(f"auto-classic-{i}-{name}", image, (*args, b"--profile"))
                stdout, _, raw_file = self.profile_comparable(actual, elapsed, "file")
                fields = items(stdout)
                self.assertEqual(fields[b"determinism.replay_match"], b"true")
                self.assertEqual(fields[b"determinism.repeats"], str(repeats).encode())
                self.assertEqual(fields[b"strategy"], b"AutoAdaptive")
                self.assertEqual({kk: vv for kk, vv in fields.items() if kk.startswith(b"profile.auto.")}, expected)
                self.assertEqual({kk: vv for kk, vv in items(raw_file).items() if kk.startswith(b"profile.auto.")},
                                 expected)
                pair.append(stdout)
            self.assertEqual(*pair)
            if (n, k) == (4095, 2):
                profile = items(pair[1])
                self.assertEqual(profile[b"profile.auto.use_hot_bucket"], b"true")
                witnesses["auto"] = [profile[b"determinism.input_sha256"], profile[b"determinism.groups_sha256"]]
        self.assertEqual(reason_roster, {b"small_batch", b"hotspot_detected", b"low_expected_gain", b"low_hot_key_share"})

        for strategy in (b"original", b"auto-adaptive"):
            args = (b"--strategy=" + strategy, b"--txs=4095", b"--keys=2", b"--determinism-repeats=2")
            self.reset_profile_path()
            old, old_elapsed = self.actual(f"auto-reorders-{strategy.decode()}-rust", self.original, args)
            new, new_elapsed = self.actual(f"auto-reorders-{strategy.decode()}-native", self.native, args)
            self.assertEqual((old.returncode, new.returncode, old.stderr, new.stderr), (0, 0, b"", b""))
            self.assertEqual(stdout_observation(old.stdout, old_elapsed)[1], stdout_observation(new.stdout, new_elapsed)[1])
            self.assertFalse(self.run_path.exists())
            fields = items(new.stdout)
            if strategy == b"original":
                witnesses["original"] = [fields[b"determinism.input_sha256"], fields[b"determinism.groups_sha256"]]
            else:
                self.assertEqual(witnesses["auto"], [fields[b"determinism.input_sha256"], fields[b"determinism.groups_sha256"]])
        self.assertEqual(witnesses["auto"][0], witnesses["original"][0])
        self.assertNotEqual(witnesses["auto"][1], witnesses["original"][1])
        (self.root / "auto-adaptive-classic.json").write_text(json.dumps(
            {k: [v.decode() for v in val] for k, val in witnesses.items()}, sort_keys=True) + "\n")

    def test_classic_auto_adaptive_scope_still_fails_closed(self):
        classic = (b"--strategy=auto-adaptive", b"--profile")
        controls = (
            ((*classic, b"--workload=mixed"), {}),
            ((*classic, b"--workload=hot-streak", b"--keys=1"), {}),
            ((*classic, b"--reader-high-water-v1"), {}),
            ((*classic, b"--txs=20001"), {}),
            ((b"--strategy=aggressive-greedy", b"--profile", b"--reader-high-water-v1"), {}),
            (classic, {b"TRNM_AUTO_MIN_BATCH_LEN": b"64"}),
            (classic, {b"TRNM_HOT_BUCKETS": b"17"}),
            (classic, {b"HIA_BENCH_FIXTURE_UNRELATED": b"synthetic"}),
        )
        for label, (args, env) in enumerate(controls):
            result, _ = self.actual(f"auto-classic-denied-{label}", self.native, args, env=env)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", OUTSIDE))
            self.assertFalse(self.run_path.exists())
        over = (*classic, b"--determinism-repeats=1001")
        for name, image in (("rust", self.original), ("native", self.native)):
            result, _ = self.actual(f"auto-classic-over-{name}", image, over)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"", REPEAT))
            self.assertFalse(self.run_path.exists())

    def test_actual_classic_aggressive_greedy_fast_path(self):
        strategy = b"--strategy=aggressive-greedy"
        cases = (
            ((), 20_000, 2_000, 0),
            ((b"--txs=0", b"--keys=0", b"--determinism-repeats=1000"), 1, 1, 1000),
            ((b"--txs=19", b"--keys=3", b"--determinism-repeats=2"), 19, 3, 2),
            ((b"--txs=32", b"--keys=1", b"--determinism-repeats=1"), 32, 1, 1),
            ((b"--txs=17", b"--keys=18446744073709551615", b"--persist-profile"),
             17, (1 << 64) - 1, 0),
            ((b"--txs=1025", b"--keys=7", b"--read-fanout=0", b"--write-every=0",
              b"--determinism-repeats=2"), 1025, 7, 2),
        )
        for i, (args, n, keys, repeats) in enumerate(cases):
            with self.subTest(n=n, keys=keys, repeats=repeats):
                # Classic transaction i sees key i % keys in both sets. The
                # current group is the count of previous writes on that key.
                expected_groups = [range(at, min(at+keys,n)) for at in range(0,n,keys)]
                group_sha = group_digest(expected_groups).hex().encode()
                inp = hashlib.sha256(b"TRNM-BENCH-INPUT-V1\0")
                for j in range(n):
                    key = j % keys
                    inp.update(struct.pack("<8Q", j, 1, key, 1, 1, key, 1, 0))
                normal = []
                for owner, image in (("rust", self.original), ("native", self.native)):
                    r, wall = self.actual(f"classic-aggressive-{i}-{owner}", image, (strategy, *args))
                    self.assertEqual((r.returncode,r.stderr),(0,b""))
                    elapsed, out = stdout_observation(r.stdout,wall)
                    self.events[-1]["observed_elapsed_ms"] = elapsed
                    self.assertNotIn(b"profile.report.", out)
                    fields = dict(line.split(b"=",1) for line in out.splitlines() if b"=" in line)
                    self.assertEqual(fields[b"strategy"],b"AggressiveGreedy")
                    self.assertEqual(fields[b"determinism.input_sha256"],inp.hexdigest().encode())
                    self.assertEqual(fields[b"determinism.groups_sha256"],group_sha)
                    self.assertEqual(fields[b"groups"],str(len(expected_groups)).encode())
                    self.assertEqual(fields[b"grouped"],str(n).encode())
                    self.assertEqual(fields[b"determinism.repeats"],str(repeats).encode())
                    self.assertEqual(fields.get(b"determinism.replay_match"),b"true" if repeats else b"not-requested")
                    normal.append(out)
                self.assertEqual(*normal)
                self.assertFalse(self.run_path.exists())
        over = (strategy, b"--txs=20001", b"--determinism-repeats=1001")
        for owner, image in (("rust", self.original), ("native", self.native)):
            r, _ = self.actual(f"classic-aggressive-over-replay-{owner}",image,over)
            self.assertEqual((r.returncode,r.stdout,r.stderr),(2,b"",REPEAT))

    def test_actual_classic_aggressive_greedy_profile_and_replay(self):
        strategy = (b"--strategy=aggressive-greedy", b"--profile")
        for index, (n, keys, repeats) in enumerate(((19, 3, 2), (1, 1, 1000), (17, 30, 0),
                                                    (20_000, 2_000, 1))):
            pair = []
            args = (*strategy, f"--txs={n}".encode(), f"--keys={keys}".encode(),
                    f"--determinism-repeats={repeats}".encode())
            if index % 2:
                args += (b"--persist-profile",)
            dig_groups = group_digest([range(i, min(n, i+keys)) for i in range(0,n,keys)]).hex().encode()
            for owner, image in (("rust",self.original),("native",self.native)):
                self.reset_profile_path()
                r, wall = self.actual(f"aggressive-profile-{index}-{owner}",image,args)
                comparable, _, raw_file = self.profile_comparable(r,wall,"file")
                fields = dict(line.split(b"=",1) for line in comparable.splitlines() if b"=" in line)
                self.assertEqual(fields[b"profile.report.strategy"],b"AggressiveGreedy")
                self.assertEqual(fields[b"determinism.groups_sha256"],dig_groups)
                self.assertEqual(fields[b"determinism.replay_match"],b"true" if repeats else b"not-requested")
                self.assertEqual(fields[b"profile.conflict_checks"],str(2*n).encode())
                self.assertEqual(fields[b"profile.conflict_hits"],str(n-min(n,keys)).encode())
                for metric in (b"candidate_groups_scanned", b"retry_fallback_new_groups",
                               b"stage_ww_checks", b"stage_ww_hits", b"stage_wr_checks",
                               b"stage_wr_hits", b"stage_rw_checks", b"stage_rw_hits"):
                    self.assertEqual(fields[b"profile."+metric],b"0")
                self.assertNotIn(b"profile.auto.",raw_file)
                self.assertEqual(len(list(self.bench_path.iterdir())),1)
                pair.append(comparable)
            self.assertEqual(*pair)
        self.reset_profile_path()
        for owner,image in (("rust",self.original),("native",self.native)):
            r,_ = self.actual(f"aggressive-profile-over-repeat-{owner}",image,
                              (*strategy,b"--txs=19",b"--determinism-repeats=1001"))
            self.assertEqual((r.returncode,r.stdout,r.stderr),(2,b"",REPEAT))
            self.assertFalse(self.run_path.exists())

    def test_actual_classic_aggressive_greedy_unbound_file_refusal(self):
        unbound, _ = build(self.root / "native-aggressive-unbound")
        args = (b"--txs=19", b"--keys=3", b"--strategy=aggressive-greedy",
                b"--determinism-repeats=2")
        for i, variant in enumerate(((*args,b"--profile"),(*args,b"--profile",b"--persist-profile"))):
            r,_=self.actual(f"aggressive-unbound-profile-{i}",unbound,variant)
            self.assertEqual((r.returncode,r.stdout,r.stderr),(2,b"",OUTSIDE))
            self.assertFalse(self.run_path.exists())
        r,wall=self.actual("aggressive-unbound-no-profile",unbound,args)
        self.assertEqual((r.returncode,r.stderr),(0,b""))
        self.assertIn(b"\nstrategy=AggressiveGreedy\n",stdout_observation(r.stdout,wall)[1])
        self.assertFalse(self.run_path.exists())

    def test_classic_aggressive_greedy_preserves_scope_and_file_refusal(self):
        strategy = (b"--strategy", b"aggressive-greedy", b"--txs=4")
        rows = (
            ((b"--profile",), (b"LANG=C",)), ((b"--profile", b"--persist-profile"), (b"TRNM_AGGR_DEEP_SCAN=1",)),
            ((b"--workload=mixed", b"--keys=1"), ()),
            ((b"--workload=hot-streak", b"--keys=1"), ()),
            ((b"--reader-high-water-v1",), ()), ((), (b"TRNM_AGGR_DEEP_SCAN=1",)),
            ((), (b"TRNM_AGGR_DEEP_SCAN=0",)), ((), (b"TRNM_AGGR_SCAN_WINDOW=1",)),
            ((), (b"TRNM_HOT_BUCKETS=8",)), ((), (b"LANG=C",)),
            ((), (b"LANG=C", b"TRNM_AGGR_DEEP_SCAN=1")),
        )
        for i, (args, entries) in enumerate(rows):
            r, _ = self.actual(f"classic-aggressive-refusal-{i}",self.native,(*strategy,*args),
                               env_entries=entries)
            self.assertEqual((r.returncode,r.stdout,r.stderr),(2,b"",OUTSIDE))
            self.assertFalse(self.run_path.exists())
        r, _ = self.actual("classic-aggressive-refusal-cap",self.native,
                           (b"--strategy=aggressive-greedy",b"--txs=20001"))
        self.assertEqual((r.returncode,r.stdout,r.stderr),(2,b"",OUTSIDE))
        self.assertFalse(self.run_path.exists())

    def test_actual_classic_original_ignores_only_passive_launcher_values(self):
        # All values are constructed here, not inherited or printed. Include
        # duplicates and Linux's longest single NUL-inclusive environment entry.
        roster = (b"PATH=/fixture/bin", b"HOME=/fixture/home", b"LANG=C.UTF-8", b"LC_ALL=C",
                  b"LC_CTYPE=C", b"TERM=dumb", b"TMPDIR=/fixture/tmp")
        secret_free_synthetic = b"opaque-synthetic-not-report-data"
        longest = b"PATH=" + b"x" * (131_071 - len(b"PATH="))
        cases = (((), roster),
                 ((b"--workload=classic", b"--strategy=original", b"--txs=32", b"--keys=7"),
                  (b"PATH=first", b"PATH=second", b"HOME=\xff", b"TERM=", b"TMPDIR=" + secret_free_synthetic)),
                 ((b"--txs=4", b"--keys=2", b"--determinism-repeats=0", b"--persist-profile"),
                  tuple(b"LANG=C" for _ in range(64))),
                 ((b"--txs=2",), (longest,)),
                 ((b"--txs=0", b"--keys=0"), (b"HOME==equals-is-part-of-value",)))
        for i, (args, entries) in enumerate(cases):
            before, before_wall = self.actual(f"launcher-names-{i}-empty-rust", self.original, args)
            rust, rust_wall = self.actual(f"launcher-names-{i}-rust", self.original, args, env_entries=entries)
            native, native_wall = self.actual(f"launcher-names-{i}-native", self.native, args, env_entries=entries)
            for result in (before, rust, native):
                self.assertEqual((result.returncode, result.stderr), (0, b""))
                self.assertNotIn(secret_free_synthetic, result.stdout)
                self.assertNotIn(b"profile.report.", result.stdout)
            self.assertEqual(stdout_observation(before.stdout, before_wall)[1],
                             stdout_observation(rust.stdout, rust_wall)[1])
            self.assertEqual(stdout_observation(rust.stdout, rust_wall)[1],
                             stdout_observation(native.stdout, native_wall)[1])
            self.assertFalse(self.run_path.exists())

    def test_passive_launcher_scope_does_not_admit_other_calls(self):
        rows = (((), (b"UNKNOWN_FIXTURE=value",)), ((), (b"path=x",)),
                ((), (b"LC_CTYPE_MORE=x",)), ((), (b"HOME",)),
                ((), (b"=no-name",)), ((), (b"L\xffNG=x",)),
                ((), tuple(b"LANG=C" for _ in range(65))),
                ((), (b"PATH=/fixture", b"TRNM_HOT_BUCKETS=17")),
                ((b"--profile", b"--txs=3"), (b"PATH=/fixture",)),
                ((b"--txs=4", b"--determinism-repeats=1"), (b"HOME=/fixture",)),
                ((b"--strategy=write-first",), (b"LANG=C",)),
                ((b"--strategy=write-last",), (b"LANG=C",)),
                ((b"--strategy=auto-adaptive",), (b"LANG=C",)),
                ((b"--strategy=hot-bucket-interleave",), (b"HOME=/fixture",)),
                ((b"--workload=mixed", b"--keys=1"), (b"LANG=C",)),
                ((b"--reader-high-water-v1", b"--workload=mixed", b"--keys=1"), (b"LANG=C",)),
                ((b"--help",), (b"TERM=dumb",)),
                ((b"--txs",), (b"HOME=/fixture",)))
        for i, (args, entries) in enumerate(rows):
            new, _ = self.actual(f"launcher-names-denied-{i}", self.native, args, env_entries=entries)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", OUTSIDE))
            self.assertFalse(self.run_path.exists())

    def test_actual_hot_bucket_environment_controls_order(self):
        key = HOT_KEY
        sentinel = b"synthetic fixture only not an integer"
        maximum_value = b"0" * (131072 - len(key) - 3) + b"17"
        common = (b"--txs=64", b"--keys=23", b"--read-fanout=8", b"--write-every=64",
                  b"--determinism-repeats=2", b"--strategy=hot-bucket-interleave")
        expectations = {
            "absent": ((), 8),
            "empty-first": ((key, key+b"17"), 8),
            "invalid-utf8-first": ((key+b"\xff", key+b"17"), 8),
            "invalid-first": ((key+sentinel, key+b"17"), 8),
            "low-clamp": ((key+b"0",), 4),
            "effective-4": ((key+b"4",), 4),
            "default-literal": ((key+b"8",), 8),
            "first-17": ((key+b"17", key+b"64"), 17),
            "formatted-17": ((key+b" \xc2\xa0' +1_7 ' ",), 17),
            "effective-64": ((key+b"64",), 64),
            "high-clamp": ((key+b"18446744073709551615",), 64),
            "overflow-default": ((key+b"18446744073709551616",), 8),
            "full-linux-value": ((key+maximum_value,), 17),
            "64-entries": ((key+b"17",)+(key+b"64",)*63, 17),
        }
        for workload in (b"classic", b"mixed", b"hot-streak"):
            order, input_hashes = {}, set()
            # Full parser/bounds matrix on Classic; the independent WAR
            # admitted multi-key single-writer frames take all four values.
            for name, (entries, bucket) in expectations.items():
                if workload != b"classic" and name not in ("absent", "effective-4", "first-17", "effective-64"):
                    continue
                with self.subTest(workload=workload, case=name):
                    args = (b"--workload=" + workload, *common)
                    matches = []
                    for kind, image in (("original",self.original),("native",self.native)):
                        label = f"hot-env-{workload.decode()}-{name}-{kind}"
                        result, wall = self.actual(label,image,args,env_entries=entries)
                        self.assertEqual((result.returncode,result.stderr),(0,b""))
                        elapsed, stdout = stdout_observation(result.stdout, wall)
                        self.events[-1]["observed_elapsed_ms"] = elapsed
                        self.assertNotIn(sentinel, stdout)
                        self.assertIn(b"\nstrategy=HotBucketInterleave\n",stdout)
                        self.assertIn(b"\ndeterminism.replay_match=true\n",stdout)
                        matches.append(stdout)
                    self.assertEqual(*matches)
                    fields = dict(line.split(b"=",1) for line in matches[0].splitlines() if b"=" in line)
                    input_hashes.add(fields[b"determinism.input_sha256"])
                    group = fields[b"determinism.groups_sha256"]
                    self.assertEqual(order.setdefault(bucket,group),group)
                    self.assertFalse(self.run_path.exists())
            self.assertEqual(len(input_hashes),1)
            self.assertEqual(set(order),{4,8,17,64})
            self.assertEqual(len(set(order.values())),4)

    def test_actual_hot_bucket_environment_profile_and_refusals(self):
        args = (b"--profile",b"--txs=64",b"--keys=23",b"--workload=hot-streak",
                b"--write-every=64",b"--read-fanout=8",
                b"--strategy",b"hot-bucket-interleave",b"--determinism-repeats=2")
        results = []
        for tag,image in (("original",self.original),("native",self.native)):
            self.reset_profile_path()
            result = self.actual("hot-env-profile-"+tag,image,args,env_entries=(HOT_KEY+b"17",))
            report,_,raw = self.profile_comparable(*result,"file")
            self.assertIn(b"\nprofile.report.strategy=HotBucketInterleave\n",report)
            self.assertNotIn(HOT_KEY,raw)
            results.append(report)
        self.assertEqual(*results)
        self.reset_profile_path()
        rejected_entries = ((b"UNRELATED_FIXTURE=do not emit",), (b"TRNM_HOT_BUCKETS",),
                            (b"TRNM_HOT_BUCKETS_EXTRA=17",), (b"trnm_hot_buckets=17",),
                            (HOT_KEY+b"17", b"UNRELATED_FIXTURE=do not emit"),
                            (HOT_KEY+b"17",)*65)
        for i,entries in enumerate(rejected_entries):
            result,_ = self.actual(f"hot-env-refusal-{i}",self.native,args,env_entries=entries)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b"",OUTSIDE))
            self.assertFalse(self.run_path.exists())
        for i,flags in enumerate(((b"--strategy=original",), (b"--strategy=write-last",),
                                 (b"--strategy=hot-bucket-interleave", b"--workload=mixed"),
                                 (b"--strategy=hot-bucket-interleave", b"--workload=hot-streak"))):
            result,_ = self.actual(f"hot-env-workload-refusal-{i}",self.native,(b"--profile",*flags),
                                   env_entries=(HOT_KEY+b"17",))
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b"",OUTSIDE))
            self.assertFalse(self.run_path.exists())

    def test_actual_replay_count_and_independent_membership_digest_guards(self):
        # Test-only synthetic ELF links never become the supported Bench image.
        args = (b"--txs=4", b"--keys=4")
        original, _ = self.actual("replay-leaf-original", self.original,
                                  (*args, b"--determinism-repeats=4"))
        input_digest = re.search(rb"(?m)^determinism.input_sha256=([0-9a-f]{64})$", original.stdout)
        self.assertEqual(original.returncode, 0)
        self.assertIsNotNone(input_digest)
        expected = (b"determinism replay mismatch for input " + input_digest[1] +
                    b" and strategy Original\n")
        count_only = replay_fixture(self.native, self.build, self.root, "count", 0)
        for count in (0, 4, 1000):
            case = (*args, f"--determinism-repeats={count}".encode())
            observed, _ = self.actual(f"replay-leaf-count-{count}", count_only, case)
            self.assertEqual(observed.returncode, 0)
            self.assertEqual(observed.stderr, b"S" * (1 + count))
            self.events[-1]["observed_scheduler_invocations"] = len(observed.stderr)
        observed, _ = self.actual("replay-leaf-before-bound", count_only,
                                  (*args, b"--determinism-repeats=1001"))
        self.assertEqual((observed.returncode, observed.stdout, observed.stderr), (2, b"", REPEAT))
        self.events[-1]["observed_scheduler_invocations"] = 0
        delayed = replay_fixture(self.native, self.build, self.root, "after-clock-delay", 3)
        observed, wall = self.actual("replay-leaf-after-clock-delay", delayed,
                                     (*args, b"--determinism-repeats=4"))
        self.assertEqual((observed.returncode, observed.stderr), (0, b"SSSSS"))
        elapsed, _ = stdout_observation(observed.stdout, wall)
        # Four real 50-ms sleeps occur only after replay callbacks; they
        # cannot fall inside the independently measured first interval.
        self.assertGreaterEqual(wall - elapsed * 1_000_000, 190_000_000)
        self.events[-1].update(observed_scheduler_invocations=5, observed_elapsed_ms=elapsed,
                               injected_post_clock_nanoseconds=200_000_000)
        for mode, label in ((1, "membership-even-with-same-digest"), (2, "digest-only")):
            mutant = replay_fixture(self.native, self.build, self.root, label, mode)
            observed, _ = self.actual(f"replay-leaf-{label}", mutant,
                                      (*args, b"--profile", b"--determinism-repeats=4"))
            # The first replay must stop the loop, and never publish an ordinary
            # report or create the requested file after either mismatch.
            self.assertEqual((observed.returncode, observed.stdout, observed.stderr),
                             (2, b"", b"SS" + expected))
            self.events[-1]["observed_scheduler_invocations"] = 2
            self.assertFalse(self.run_path.exists())


# Independent leaf fixture. It invokes the real scheduler and digest bodies.
# Count markers are just synthetic stderr observations, not business fields.
# Mode 1 changes only the first two replay members and then equalizes its hash
# to expose a missing membership check. Mode 2 touches only the replay digest.
LEAF_FIXTURE_ASM = r"""
.text
.global sched_hook
.global digest_hook
sched_hook:
  push %r12
  mov %rdx,%r12
  push %rdi
  push %rsi
  push %rdx
  push %rcx
  mov $1,%eax
  mov $2,%edi
  lea marker(%rip),%rsi
  mov $1,%edx
  syscall
  pop %rcx
  pop %rdx
  pop %rsi
  pop %rdi
  call *real_sched(%rip)
  test %eax,%eax
  jne sched_done
  lea 0x1741000(%rbx),%rdx
  cmp %rdx,%r12
  jne sched_done
  cmpq $3,mode(%rip)
  je after_clock_delay
  cmpq $1,mode(%rip)
  jne sched_done
  cmpq $4,16(%r12)
  jne fixture_invalid
  cmpq $1,24(%r12)
  jne fixture_invalid
  cmpq $0,272(%r12)
  jne fixture_invalid
  cmpq $1,280(%r12)
  jne fixture_invalid
  movq $1,272(%r12)
  movq $0,280(%r12)
  jmp sched_done
after_clock_delay:
  mov $35,%eax
  lea delay(%rip),%rdi
  xor %esi,%esi
  syscall
  cmp $-4,%rax
  je after_clock_delay
  test %rax,%rax
  jne fixture_invalid
sched_done:
  pop %r12
  ret
digest_hook:
  push %r12
  mov %rdx,%r12
  call *real_digest(%rip)
  test %eax,%eax
  jne digest_done
  lea 5800(%rbx),%rdx
  cmp %rdx,%r12
  jne digest_done
  cmpq $1,mode(%rip)
  je match_digest
  cmpq $2,mode(%rip)
  jne digest_done
  xorb $1,(%r12)
  jmp digest_done
match_digest:
  lea 0x1700310(%rbx),%rsi
  mov %r12,%rdi
  mov $4,%ecx
  rep movsq
digest_done:
  pop %r12
  ret
fixture_invalid:
  ud2
delay:
  .quad 0,50000000
marker:
  .byte 0x53
real_sched:
  .quad REAL_SCHED
real_digest:
  .quad REAL_DIGEST
mode:
  .quad FIXTURE_MODE
"""


def replay_fixture(image, receipt, parent, name, mode):
    if mode not in (0, 1, 2, 3):
        raise ValueError("Unrecognized private replay fixture")
    root = parent / ("fixture-" + name)
    root.mkdir(mode=0o700)
    source = root / "probe.S"
    obj, stub = root / "probe.o", root / "probe.bin"
    addresses = {item["source"]: item["entry_address"] for item in receipt["contained_parts"]}
    scheduler = addresses["src/executor/schedule.hepta"]
    digest_entry = addresses["src/bench/digests.hepta"]
    source.write_text(LEAF_FIXTURE_ASM.replace("REAL_SCHED", str(scheduler))
                      .replace("REAL_DIGEST", str(digest_entry)).replace("FIXTURE_MODE", str(mode)))
    subprocess.run(["as", "--64", "-o", str(obj), str(source)], check=True, timeout=15,
                   capture_output=True)
    subprocess.run(["objcopy", "-O", "binary", "-j", ".text", str(obj), str(stub)], check=True,
                   timeout=15, capture_output=True)
    syms = {}
    for line in subprocess.check_output(["nm", "-P", str(obj)], text=True, timeout=10).splitlines():
        fields = line.split()
        if fields[0] in ("sched_hook", "digest_hook"):
            syms[fields[0]] = int(fields[2], 16)
    raw = stub.read_bytes()
    if set(syms) != {"sched_hook", "digest_hook"} or not all(0 <= n < len(raw) for n in syms.values()):
        raise ValueError("Unexpected private leaf fixture linking")
    if receipt["native_elf"]["sha256"] != digest(image):
        raise ValueError("Fixture original image differs")
    packed = bytearray(image + raw)
    prefix = 176 + receipt["adapter_bytes"]
    for delta, expected, symbol in ((16, scheduler, "sched_hook"), (24, digest_entry, "digest_hook")):
        if struct.unpack_from("<Q", packed, prefix + delta)[0] != expected:
            raise ValueError("Unexpected original dispatch entry")
        struct.pack_into("<Q", packed, prefix + delta, 0x400000 + len(image) + syms[symbol])
    for off in (96, 104):
        struct.pack_into("<Q", packed, off, len(packed))
    final = bytes(packed)
    inspect_executable(final)
    (root / "receipt.json").write_text(json.dumps({
        "test_fixture_only": True, "original_elf_sha256": digest(image),
        "linked_fixture_sha256": digest(final), "fixture_stub_sha256": digest(raw),
        "fixture_mode": mode, "original_runtime_shipped": False,
    }, sort_keys=True, indent=2) + "\n")
    return final
