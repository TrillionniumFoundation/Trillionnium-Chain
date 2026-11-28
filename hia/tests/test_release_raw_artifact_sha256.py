"""Release-scoped raw SHA-256 lifecycle over two real HIA machine emitters."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/release_bundle/raw_artifact_sha256.hepta"
RELEASE = ROOT / "trillionnium/crates/trnm-release-bundle/src"
DECLARED_MAX = 128 << 30
STATE_SIZE = 1224
STATE_CANARY = b"\xc7"
OUTPUT_CANARY = b"\xa5"
FORMAT, STATE, LENGTH, CAPACITY = (100, 101, 102, 103)
BACKENDS = ("direct", "selfhost")


def start(declared):
    return b"\0" + struct.pack("<Q", declared)


def chunk(data):
    return b"\1" + data


FINISH = b"\2"


def sample(n):
    seed = bytes((i * 97 + i // 17 + 29) & 255 for i in range(4093))
    return (seed * (n // len(seed) + 1))[:n]


def original_feed(parts):
    """Run the exact original LegacyHashReader with a feed-capturing hash sink.

    No dependency fetch or Rust hash replacement is hidden as a real sha2 run.
    Python hashlib independently computes SHA-256 over the captured feed.
    """
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    raw = (RELEASE / "content_v1.rs").read_bytes()
    bodies = re.findall(
        rb"(?ms)^struct LegacyHashReader<'a, R: Read \+ \?Sized> \{.*?^\}\n"
        rb"impl<R: Read \+ \?Sized> Read for LegacyHashReader<'_, R> \{.*?^\}\n", raw)
    limits = re.findall(rb"(?m)^pub const MAX_ARTIFACT_BYTES_V0:.*?;\n",
                        (RELEASE / "lib.rs").read_bytes())
    if len(bodies) != 1 or len(limits) != 1:
        raise ValueError("Original ReleaseBundle feed adapter/size declaration changed")
    # The sink captures what the original adapter sends to SHA-256; it
    # deliberately does not implement another hash or test the outer observer.
    runner = br"""
fn main() -> io::Result<()> {
    let mut frames = Vec::new();
    io::stdin().read_to_end(&mut frames)?;
    let mut pos = 0;
    let mut bytes = Vec::new();
    let mut widths = Vec::new();
    while pos < frames.len() {
        let width = u32::from_le_bytes(frames[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        widths.push(width);
        bytes.extend_from_slice(&frames[pos..pos + width]);
        pos += width;
    }
    let mut raw = &bytes[..];
    let mut read = LegacyHashReader { inner: &mut raw, hash: Sha256(Vec::new()) };
    for width in widths {
        assert_eq!(read.read(&mut vec![0; width])?, width);
    }
    let mut result = io::stdout().lock();
    result.write_all(&MAX_ARTIFACT_BYTES_V0.to_le_bytes())?;
    result.write_all(&read.hash.0)
}
"""
    sink = br"""
use std::io::{self, Read, Write};
struct Sha256(Vec<u8>);
impl Sha256 {
    fn update(&mut self, input: &[u8]) { self.0.extend_from_slice(input); }
}
"""
    with tempfile.TemporaryDirectory(prefix="trnm-release-hash-feed-") as folder:
        source = Path(folder) / "reference.rs"
        executable = Path(folder) / "reference"
        source.write_bytes(sink + limits[0] + bodies[0] + runner)
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o",
                        str(executable)], check=True, capture_output=True, timeout=30)
        report = subprocess.run([str(executable)], check=True,
                                input=b"".join(struct.pack("<I", len(p)) + p for p in parts),
                                capture_output=True, timeout=10)
    if report.stderr or len(report.stdout) < 8:
        raise ValueError("Original byte-feed oracle did not publish a complete observation")
    return int.from_bytes(report.stdout[:8], "little"), report.stdout[8:]


class RawReleaseArtifactSHA256(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        modules = {}
        for backend in BACKENDS:
            module = cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            modules[backend] = module
        if modules["direct"].artifact_sha256 == modules["selfhost"].artifact_sha256:
            raise ValueError("Expected two independently emitted artifacts")
        cls.native = modules

    def observed(self, module, raw, arena, capacity=39, status=0, expected=b"",
                 *, unchanged_state=False):
        initial_output = OUTPUT_CANARY * capacity
        result = module.call("f0", [raw, initial_output, arena], timeout=45)
        result.require_returned()
        self.assertEqual(result.value, status)
        self.assertEqual(result.arguments[0], raw)
        self.assertEqual(result.arguments[1], expected + initial_output[len(expected):])
        next_arena = result.arguments[2]
        self.assertEqual(next_arena[STATE_SIZE:], arena[STATE_SIZE:])
        if unchanged_state or status:
            self.assertEqual(next_arena, arena)
        return next_arena

    def sequence(self, module, data, parts, expected):
        self.assertEqual(data, b"".join(parts))
        arena = self.observed(module, start(len(data)), STATE_CANARY * (STATE_SIZE + 23))
        count = 0
        for part in parts:
            arena = self.observed(module, chunk(part), arena, capacity=0,
                                  unchanged_state=not part)
            count += len(part)
            self.assertEqual(int.from_bytes(arena[1088:1096], "little"), count)
        self.observed(module, FINISH, arena, capacity=31, status=CAPACITY)
        finished = self.observed(module, FINISH, arena, expected=expected)
        self.observed(module, FINISH, finished, status=STATE)
        self.observed(module, chunk(b"unexpected"), finished, status=STATE)
        return finished

    def test_exact_original_byte_feed_and_sha256_padding_edges(self):
        parts = [b"raw-artifact-content", b"", sample(513), b"\x00\xff\x80"]
        declared_max, original_bytes = original_feed(parts)
        self.assertEqual(declared_max, DECLARED_MAX)
        self.assertEqual(original_bytes, b"".join(parts))
        cases = [([b"abc"], bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
                 (parts, hashlib.sha256(original_bytes).digest())]
        for length in (1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129):
            data = sample(length)
            cases.append(([data[:1], data[1:55], b"", data[55:]], hashlib.sha256(data).digest()))
        for backend, module in self.native.items():
            for parts, expected in cases:
                with self.subTest(backend=backend, length=sum(map(len, parts))):
                    self.sequence(module, b"".join(parts), parts, expected)

    def test_multiple_partitions_above_transport_total_limit(self):
        length = 2_098_177  # greater than transport f0's 2,098,176-byte maximum
        data = sample(length)
        for width in (524_279, 401_003):
            parts = [data[i:i + width] for i in range(0, length, width)]
            declared_max, original_bytes = original_feed(parts)
            self.assertEqual((declared_max, original_bytes), (DECLARED_MAX, data))
            expected = hashlib.sha256(original_bytes).digest()
            for backend, module in self.native.items():
                with self.subTest(backend=backend, width=width):
                    self.sequence(module, data, parts, expected)

    def test_no_partial_state_or_digest_on_refusal_and_restart(self):
        blank = STATE_CANARY * (STATE_SIZE + 23)
        for backend, module in self.native.items():
            with self.subTest(backend=backend):
                for malformed in (b"", b"\x03", b"\xffraw", b"\0", start(1) + b"\0",
                                  FINISH + b"\0"):
                    self.observed(module, malformed, blank, status=FORMAT)
                self.observed(module, start(1), blank[:STATE_SIZE - 1], status=FORMAT)
                for invalid in (0, DECLARED_MAX + 1, 2**64 - 1):
                    self.observed(module, start(invalid), blank, status=LENGTH)
                for needs_init in (chunk(b"a"), FINISH):
                    self.observed(module, needs_init, blank, status=STATE)
                largest = self.observed(module, start(DECLARED_MAX), blank)
                largest = self.observed(module, chunk(b"z"), largest)
                self.observed(module, FINISH, largest, status=LENGTH)
                arena = self.observed(module, start(3), largest)
                arena = self.observed(module, chunk(b"ab"), arena)
                self.observed(module, chunk(b"cd"), arena, status=LENGTH)
                self.observed(module, FINISH, arena, capacity=0, status=LENGTH)
                for offset in (1088, 1096, 1200, 1208, 1216):
                    altered = bytearray(arena)
                    altered[offset:offset + 8] = b"\0" * 8 if offset != 1200 else b"\xff" * 8
                    self.observed(module, chunk(b"c"), bytes(altered), status=STATE)
                arena = self.observed(module, chunk(b"c"), arena)
                after = self.observed(module, FINISH, arena, capacity=32,
                                      expected=hashlib.sha256(b"abc").digest())
                restarted = self.observed(module, start(2), after)
                restarted = self.observed(module, chunk(b"QR"), restarted)
                self.observed(module, FINISH, restarted,
                              expected=hashlib.sha256(b"QR").digest())
