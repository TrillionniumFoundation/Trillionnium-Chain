"""Synthetic Unix execve differential for the allowlisted Bench envp projection."""
from __future__ import annotations

from pathlib import Path
import os
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
HIA = ROOT / "hia/src/bench"
ORIGINAL = ROOT / "trillionnium/crates/trnm-executor/src/lib.rs"
ADAPTER = Path(__file__).with_name("rust_bench_envp_reference.rs")
NAMES = (
    b"TRNM_AGGR_DEEP_SCAN", b"TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", b"TRNM_AGGR_SCAN_ROUND_ROBIN",
    b"TRNM_AGGR_SCAN_WINDOW", b"TRNM_AGGR_SCAN_RR_SEED", b"TRNM_HOT_BUCKETS",
    b"TRNM_AUTO_MIN_BATCH_LEN", b"TRNM_AUTO_SAMPLE_LEN", b"TRNM_AUTO_HOT_STREAK_RATIO",
    b"TRNM_AUTO_REORDER_MIN_MARGIN", b"TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE",
    b"TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE",
)
OUT, WORK = b"\xa5", b"\xcc"
WORK_BYTES, HEADER = 192, 104
MAX = (1 << 64) - 1
BUCKETS, WINDOW, SEED = 1, 4, 5


def startup(*entries):
    return b"".join(x + b"\0" for x in entries)


def compile_original(folder):
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    original = ORIGINAL.read_bytes()
    # Include the contiguous, untransformed active getter source from the
    # executor lib used by Bench, not the unused stand-alone duplicate file.
    declarations = re.findall(rb"(?ms)^#\[inline\]\nfn parse_env_numeric\(.*?"
                              rb"(?=^pub fn auto_adaptive_decision\()", original)
    if len(declarations) != 1:
        raise ValueError("Original Bench executor getter range changed")
    source = folder / "reference.rs"
    executable = folder / "reference"
    source.write_bytes(declarations[0] + ADAPTER.read_bytes())
    subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o",
                    str(executable)], check=True, capture_output=True, timeout=30)
    return executable


class NativeBenchEnvironmentProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-bench-envp-")))
        cls.original = compile_original(folder)
        cls.project = {
            backend: cls.enterClassContext(NativeModule(HIA / "envp.hepta", backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.project["direct"].artifact_sha256 == cls.project["selfhost"].artifact_sha256:
            raise ValueError("Expected distinct native machine artifacts")
        cls.parse = cls.enterClassContext(NativeModule(HIA / "environment.hepta",
                                                       byte_exports=("f0",)))

    def observe_original(self, raw):
        # Use an empty inherited environment. The child performs actual execve
        # with only the given synthetic entries, including any duplicate names.
        result = subprocess.run([str(self.original), "exec"], input=raw, env={},
                                check=True, capture_output=True, timeout=15)
        self.assertEqual(result.stderr, b"")
        frame, effective = result.stdout[:-80], result.stdout[-80:]
        self.assertEqual(frame[:8], b"BENV0001")
        widths = struct.unpack_from("<12Q", frame, 8)
        self.assertEqual(len(frame), HEADER + sum(width for width in widths if width != MAX))
        return frame, effective

    def check_projections(self, corpus):
        original = [self.observe_original(raw) for raw in corpus]
        for backend, module in self.project.items():
            for start in range(0, len(corpus), 24):
                inputs, expected = corpus[start:start + 24], original[start:start + 24]
                requests = [
                    ("f0", [raw, OUT * (len(frame) + (j % 2) * 13), WORK * (WORK_BYTES + j % 3)])
                    for j, (raw, (frame, _)) in enumerate(zip(inputs, expected, strict=True))
                ]
                projected = module.call_many(requests)
                parser_requests = []
                self.assertEqual(len(projected), len(expected))
                for j, (result, request, (frame, _)) in enumerate(zip(projected, requests, expected,
                                                                      strict=True)):
                    with self.subTest(backend=backend, case=start+j):
                        result.require_returned()
                        self.assertEqual(result.value, 0)
                        self.assertEqual(result.arguments[0], request[1][0])
                        self.assertEqual(result.arguments[1], frame + request[1][1][len(frame):])
                        self.assertEqual(result.arguments[2][WORK_BYTES:], request[1][2][WORK_BYTES:])
                        # Derive the actual frame boundary from native output.
                        widths = struct.unpack_from("<12Q", result.arguments[1], 8)
                        used = HEADER + sum(width for width in widths if width != MAX)
                        self.assertEqual(used, len(frame))
                        parser_requests.append(("f0", [result.arguments[1][:used], OUT * 87,
                                                       WORK * (8194 + used)]))
                for result, (_, config) in zip(self.parse.call_many(parser_requests), expected,
                                               strict=True):
                    result.require_returned()
                    self.assertEqual(result.value, 0)
                    self.assertEqual(result.arguments[1], config + OUT * 7)
        return original

    def test_original_first_match_before_invalid_or_empty_defaults(self):
        rows = [
            b"", startup(b""), startup(b"UNRELATED_FIXTURE=ignored"),
            startup(b"TRNM_HOT_BUCKETS", b"TRNM_HOT_BUCKETS=16", b"TRNM_HOT_BUCKETS=32"),
            startup(b"TRNM_HOT_BUCKETS=\xff", b"TRNM_HOT_BUCKETS=32"),
            startup(b"TRNM_HOT_BUCKETS=", b"TRNM_HOT_BUCKETS=32"),
            startup(b"TRNM_HOT_BUCKETS=16=32", b"TRNM_HOT_BUCKETS=32"),
            startup(b"TRNM_AUTO_HOT_STREAK_RATIO=\xc2\xa0'22%'\xe3\x80\x80",
                    b"TRNM_AUTO_REORDER_MIN_MARGIN=-0%", b"TRNM_AGGR_SCAN_WINDOW='4,096'",
                    b"TRNM_AGGR_SCAN_RR_SEED=18446744073709551615"),
            startup(b"trnm_hot_buckets=99", b"TRNM_HOT_BUCKETS_\xff=32", b"=TRNM_HOT_BUCKETS=64",
                    b"TRNM_AGGR_SCAN_ROUND_ROBIN=Off", b"TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS='no'"),
        ]
        expected = self.check_projections(rows)
        self.assertEqual(expected[0], expected[1])
        self.assertEqual(expected[0], expected[2])
        self.assertNotEqual(expected[4][0], expected[5][0])  # invalid and empty stay distinct
        for j, want in ((3, 16), (4, 8), (5, 8), (6, 8)):
            self.assertEqual(struct.unpack("<10Q", expected[j][1])[BUCKETS], want)
        words = struct.unpack("<10Q", expected[7][1])
        self.assertEqual(words[WINDOW:SEED+1], (4096, MAX))
        self.assertEqual(words[7], 1 << 63)  # negative zero survives the parser

    def test_exact_names_bounds_and_order_against_real_startup(self):
        rows = []
        for name in NAMES:
            # Mutate each name byte while keeping length. Full prefix checks and
            # every suffix octet must matter even where neighboring names overlap.
            for j in range(len(name)):
                mutant = name[:j] + bytes([name[j] ^ 0x80]) + name[j+1:]
                rows.append(startup(mutant + b"=not-selected", name + b"=1"))
        rng = random.Random(0x5EED)
        values = [b"", b"0", b"1,024", b"++16", b"2049", b"0.25", b"\xff",
                  b"NaN", b"0,125%", b"OFF", b"+0", b"value=again", b"'yes'"]
        for _ in range(80):
            keys = list(NAMES) + rng.sample(list(NAMES), 6)
            rng.shuffle(keys)
            rows.append(startup(*(key + b"=" + rng.choice(values) for key in keys),
                                b"UNRELATED_FIXTURE=ignored"))
        self.check_projections(rows)

    def test_fail_closed_and_selected_extent_not_unrelated_extent(self):
        long = startup(b"UNRELATED_FIXTURE=" + b"x" * 65_537,
                       b"TRNM_HOT_BUCKETS=17", b"TRNM_HOT_BUCKETS=" + b"y" * 6561)
        original = self.check_projections([long])[0][0]
        self.assertEqual(len(original), HEADER + 2)
        selected = startup(b"TRNM_HOT_BUCKETS=" + b"9" * 8195)
        self.check_projections([selected])
        for backend, module in self.project.items():
            for raw, out_len, work_len, status, unchanged_work in (
                (b"TRNM_HOT_BUCKETS=16", 0, 0, 1, True),
                (startup(b"TRNM_HOT_BUCKETS=16") + b"TRUNCATED", 200, 200, 1, True),
                (b"", HEADER - 1, WORK_BYTES, 100, True),
                (long, len(original), WORK_BYTES - 1, 100, True),
                (long, len(original) - 1, WORK_BYTES + 9, 100, False),
            ):
                with self.subTest(backend=backend, raw_bytes=len(raw), status=status):
                    result = module.call("f0", [raw, OUT * out_len, WORK * work_len])
                    result.require_returned()
                    self.assertEqual(result.value, status)
                    self.assertEqual(result.arguments[0], raw)
                    self.assertEqual(result.arguments[1], OUT * out_len)
                    offset = 0 if unchanged_work else WORK_BYTES
                    self.assertEqual(result.arguments[2][offset:], (WORK * work_len)[offset:])
