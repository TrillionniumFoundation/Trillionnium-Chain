"""Original locked Cargo Bench versus a freestanding admitted HIA process."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import tomllib
import unittest

from hia.platform.bench.main_build import build
from hia.platform.build import new_output, sealed_executable
from hia.tests.test_bench_native import run_original_command

ROOT = Path(__file__).resolve().parents[2]
REPEAT = b"--determinism-repeats exceeds bounded maximum 1000\n"
OUTSIDE = b"Bench native candidate: invocation outside admitted Bench scope\n"
PROFILE_ARGS = (b"--profile", b"--txs=4", b"--keys=2")


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

    def actual(self, label, image, args=(), *, env=None, prepare=None):
        current = self.root / (label + ".cwd")
        current.mkdir(mode=0o700)
        fd = sealed_executable(image, label)
        start = time.monotonic_ns()
        start_realtime = time.time_ns()
        try:
            result = subprocess.run([b"trnm-bench", *args], executable=f"/proc/self/fd/{fd}",
                                    cwd=current, env={} if env is None else env, pass_fds=(fd,),
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=25,
                                    preexec_fn=prepare)
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
                self.assertFalse(self.run_path.exists())
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
                                       (b"--txs=40", b"--txs", b"4"), (b"--profile", b"--profile"))):
            old, _ = self.actual(f"invalid-{index}-original", self.original, args)
            new, _ = self.actual(f"invalid-{index}-native", self.native, args)
            self.assertEqual((old.returncode, old.stdout), (2, b""))
            self.assertTrue(old.stderr)
            self.assertEqual((new.returncode, new.stdout, new.stderr), (2, b"", OUTSIDE))

    def test_unsupported_original_modes_never_success_or_write_a_file(self):
        for index, args in enumerate(((b"--profile=true",), (b"--workload=mixed",),
                                      (b"--txs=20001",), (b"--determinism-repeats=1",))):
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
