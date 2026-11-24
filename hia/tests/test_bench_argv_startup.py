"""Actual synthetic execve differentials for the HIA-only standalone argv observer."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import random
import resource
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.platform.bench.startup_build import POLICY, build
from hia.platform.build import new_output, sealed_executable
from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = Path(__file__).with_name("rust_bench_argv_reference.rs")
MARKER = b"BARGV001"
RECORD = 56
WORK = 1208


def subprocess_args(image, argv, *, env, prepare=None, stdout=subprocess.PIPE):
    """Run an immutable image with an explicit argument vector/environment."""
    fd = sealed_executable(image, "trnm-bench-argv-observer")
    try:
        return subprocess.run(argv, executable=f"/proc/self/fd/{fd}", env=env,
                              stdin=subprocess.DEVNULL, stdout=stdout, stderr=subprocess.PIPE,
                              pass_fds=(fd,), preexec_fn=prepare, timeout=25)
    finally:
        os.close(fd)


def large_fixture_stack():
    # Change only this child immediately before execve; never read live args or env.
    stack_limit = 32 << 20
    _, hard = resource.getrlimit(resource.RLIMIT_STACK)
    if hard != resource.RLIM_INFINITY and hard < stack_limit:
        raise ValueError("Synthetic integration needs enough stack for the 2 MiB edge")
    resource.setrlimit(resource.RLIMIT_STACK, (stack_limit, hard))


class BenchArgvStartup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("HIA_BENCH_STARTUP_OBSERVATIONS")
        cls.folder = (new_output(Path(configured)) if configured else Path(cls.enterClassContext(
            tempfile.TemporaryDirectory(prefix="trnm-bench-startup-"))))
        cls.image, cls.receipt = build(cls.folder / "native")
        cls.observations = []
        rustc = os.environ.get("RUSTC", "rustc")
        version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                                 text=True, timeout=15).stdout.split()
        pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        if version[:2] != ["rustc", pin]:
            raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
        original = cls.folder / "reference"
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(ORIGINAL), "-o", str(original)],
                       check=True, capture_output=True, timeout=30)
        cls.reference = original.read_bytes()

    @classmethod
    def tearDownClass(cls):
        report = {"schema": "trnm.hia.bench-argv-observer.observations.v1",
                  "synthetic_argv_only": True, "live_environment_acquisition": False,
                  "original_bench_cli_qualified": False,
                  "observer_sha256": sha256(cls.image).hexdigest(),
                  "rust_reference_sha256": sha256(cls.reference).hexdigest(),
                  "observations": cls.observations}
        (cls.folder / "observations.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")

    def compare(self, argv, *, env, prepare=None):
        original = subprocess_args(self.reference, argv, env=env, prepare=prepare)
        self.assertEqual((original.returncode, original.stderr), (0, b""))
        frame = original.stdout
        # Rust must first witness the exact execve observation, including the
        # contrast between an empty argument and a missing argument.
        direct = struct.pack("<Q", len(argv) - 1) + b"".join(a + b"\0" for a in argv[1:])
        self.assertEqual(frame, direct)
        got = subprocess_args(self.image, argv, env=env, prepare=prepare)
        summary = struct.pack("<8sQQ", MARKER, len(argv) - 1, len(frame) - 8) + sha256(frame).digest()
        self.assertEqual((got.returncode, got.stdout, got.stderr), (0, summary, b""))
        self.assertEqual(len(got.stdout), RECORD)
        self.observations.append({"kind": "paired-execve", "argc_excluding_argv0": len(argv) - 1,
                                  "payload_bytes": len(frame) - 8,
                                  "original_frame_sha256": sha256(frame).hexdigest(),
                                  "observer_record_sha256": sha256(got.stdout).hexdigest(),
                                  "original_exit": original.returncode, "observer_exit": got.returncode})
        return got.stdout

    def test_real_execve_preserves_empty_invalid_bytes_order_and_ignores_argv0_envp(self):
        env = {b"TRNM_AUTO_SAMPLE_LEN": b"1024", b"UNRELATED_FIXTURE": b"not-read"}
        no_args = self.compare([b""], env=env)
        single = self.compare([b"ignored\xff", b""], env=env)
        self.assertNotEqual(no_args, single)
        args = [b"--workload=mixed", b"--txs", b"0001", b"", b"\xff\xc0\xaf", b"--",
                "空白\u00a0é".encode(), b"\n=--profile\t", b"--txs"]
        left = self.compare([b"a" * 129, *args], env={})
        right = self.compare([b"\xff", *args], env=env)
        self.assertEqual(left, right)
        self.assertNotEqual(left, self.compare([b"synthetic", *args[::-1]], env={}))
        rng = random.Random(0xB3E1)
        for case in range(64):
            with self.subTest(fixture=case):
                synthetic = [b"bench"] + [bytes(rng.randrange(1, 256) for _ in range(rng.randrange(96)))
                                          for _ in range(rng.randrange(24))]
                self.compare(synthetic, env=env if case % 2 else {})

    def test_real_execve_long_individual_and_multi_megabyte_aggregate(self):
        # Linux x86-64 MAX_ARG_STRLEN includes the terminator. The repeated
        # case crosses the old 2,098,176-byte default SHA update ceiling.
        max_argument = bytes(range(1, 256)) * 514 + b"x"
        self.assertEqual(len(max_argument), 131071)
        self.compare([b"bench", max_argument, b""], env={})
        many = [b"bench", *([max_argument] * 17), b"here"]
        self.compare(many, env={}, prepare=large_fixture_stack)
        self.compare([b"bench", *([b""] * 8192), b"--profile"], env={})

    def test_refusal_and_fixed_record_never_falls_back_to_raw_argv(self):
        with open("/dev/full", "wb", buffering=0) as full:
            failure = subprocess_args(self.image, [b"bench", b"--profile"], env={}, stdout=full)
        self.assertEqual((failure.returncode, failure.stderr), (4, b""))
        self.observations.append({"kind": "stdout-dev-full", "observer_exit": failure.returncode})
        over_count = subprocess_args(self.image, [b"bench"] + [b""] * 262145,
                                     env={}, prepare=large_fixture_stack)
        self.assertEqual((over_count.returncode, over_count.stdout, over_count.stderr),
                         (2, b"", b""))
        self.observations.append({"kind": "argc-overflow", "observer_exit": over_count.returncode,
                                  "observer_bytes": len(over_count.stdout)})
        with NativeModule(POLICY, byte_exports=("f0",)) as module:
            exact = struct.pack("<Q", 1) + b"\xff\0"
            for raw, n, w in (
                (b"", RECORD, WORK),
                (struct.pack("<Q", 2) + b"a\0", RECORD, WORK),
                (struct.pack("<Q", 1) + b"a\0b", RECORD, WORK),
                (struct.pack("<Q", 262145), RECORD, WORK),
                (exact, RECORD - 1, WORK),
                (exact, RECORD, WORK - 1),
            ):
                request = [raw, b"\xa5" * n, b"\xcc" * w]
                got = module.call("f0", request).require_returned()
                self.assertEqual((got.value, got.arguments), (1, request))
            request = [exact, b"\xa5" * (RECORD + 7), b"\xcc" * (WORK + 9)]
            got = module.call("f0", request).require_returned()
            self.assertEqual(got.value, 0)
            wanted = struct.pack("<8sQQ", MARKER, 1, 2) + sha256(exact).digest()
            self.assertEqual(got.arguments[1], wanted + request[1][RECORD:])
            self.assertEqual(got.arguments[2][WORK:], request[2][WORK:])
