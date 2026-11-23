"""Release-scoped CCH1 byte framing against the exact original Rust methods."""
import itertools
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_artifact_header import frame as rac1_request

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/release_bundle/content_claim_frame.hepta"
RAC1 = SOURCE.with_name("artifact_header.hepta")
PROTOCOL = ROOT / "trillionnium/crates/trnm-protocol/src/content_commitment.rs"
RELEASE = ROOT / "trillionnium/crates/trnm-release-bundle/src/lib.rs"
PROFILE = bytes(range(1, 65))
INSTANCE = bytes(range(191, 255))
SUPPLIED = bytes(range(80, 144))
MAX_ARTIFACT = 1 << 37
BAD = 0xFFFFFFFF
SHORT = 0xFFFFFFFE
SENTINEL = b"\x9a"
SCRATCH = b"\xcb" * 17


def extract(source, pattern):
    matches = re.findall(rb"(?ms)^" + pattern, source)
    if len(matches) != 1:
        raise ValueError(f"Original Rust method or declaration changed: {pattern!r}")
    return matches[0]


def reference(directory):
    version = subprocess.run(["rustc", "--version"], capture_output=True, text=True,
                             check=True, timeout=10).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError("The original CCH1 reference requires pinned rustc")
    raw = PROTOCOL.read_bytes()
    release = RELEASE.read_bytes()
    constants = b"".join(extract(raw, expr + rb"[^\n]*\n") for expr in (
        rb"const MAGIC:", rb"pub const CONTENT_CLAIM_BYTES:", rb"const HEADER_BYTES:"))
    result = directory / "reference.rs"
    result.write_bytes(constants
        + extract(release, rb"pub const MAX_ARTIFACT_BYTES_V0:[^\n]*\n")
        + b"#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n"
        + b"struct CryptoProfileId([u8; 64]);\n"
        + b"impl CryptoProfileId { fn as_bytes(&self) -> &[u8;64] { &self.0 } }\n"
        + extract(raw, rb"#\[derive\([^\n]+\)\]\n#\[repr\(u8\)\]\npub enum ContentKind \{.*?^}\n")
        + extract(raw, rb"#\[derive\([^\n]+\)\]\npub struct ContentContextV1 \{.*?^}\n")
        + extract(raw, rb"#\[derive\([^\n]+\)\]\npub struct ContentClaimV1 \{.*?^}\n")
        + b"impl ContentContextV1 {\n"
        + extract(raw, rb"    fn header\(&self, content_len: u64\) -> Vec<u8> \{.*?^    }\n")
        + b"}\nimpl ContentClaimV1 {\n"
        + extract(raw, rb"    pub fn encode\(&self\) -> Vec<u8> \{.*?^    }\n")
        + b"}\n"
        + br"""
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut cursor = 0;
    let mut stdout = io::stdout().lock();
    while cursor < bytes.len() {
        let n = u16::from_le_bytes(bytes[cursor..cursor+2].try_into().unwrap()) as usize;
        cursor += 2;
        let frame = &bytes[cursor..cursor+n];
        cursor += n;
        let context = ContentContextV1 {
            profile_id: CryptoProfileId(frame[6..70].try_into().unwrap()),
            kind: ContentKind::ReleaseArtifact,
            instance: frame[70..134].try_into().unwrap(),
            generation: u64::from_le_bytes(frame[134..142].try_into().unwrap()),
        };
        let size = u64::from_le_bytes(frame[142..150].try_into().unwrap());
        assert!((1..=MAX_ARTIFACT_BYTES_V0).contains(&size));
        let rac1_len = u16::from_le_bytes(frame[150..152].try_into().unwrap());
        let content_len = u64::from(rac1_len).checked_add(size).unwrap();
        let output = if frame[4] == 0 {
            context.header(content_len)
        } else {
            ContentClaimV1 {
                context,
                content_len,
                digest: frame[152..216].try_into().unwrap(),
            }.encode()
        };
        stdout.write_all(&output)?;
    }
    Ok(())
}
""")
    binary = directory / "reference"
    build = subprocess.run(["rustc", "--edition=2021", "-Dwarnings", "-C", "overflow-checks=yes",
                            str(result), "-o", str(binary)],
                           capture_output=True, timeout=30)
    if build.returncode:
        raise RuntimeError(build.stderr.decode())
    return binary


def packet(digest=None, *, profile=PROFILE, instance=INSTANCE, generation=0x0102030405060708,
           raw_size=0x0102030405, header_size=345):
    return (b"CCF1" + bytes([int(digest is not None), 2]) + profile + instance
            + struct.pack("<QQH", generation, raw_size, header_size)
            + (digest if digest is not None else b""))


class ReleaseContentClaimFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix="trnm-cch1-reference-")
        cls.addClassCleanup(temp.cleanup)
        cls.original = reference(Path(temp.name))
        cls.backends = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, backend=backend, byte_exports=("f0",))
            cls.addClassCleanup(module.close)
            cls.backends[backend] = module

    def oracle(self, rows):
        output = subprocess.run([str(self.original)],
                                input=b"".join(struct.pack("<H", len(row)) + row for row in rows),
                                capture_output=True, check=True, timeout=20)
        self.assertEqual(output.stderr, b"")
        position = 0
        result = []
        for row in rows:
            length = (149, 213)[row[4]]
            result.append(output.stdout[position:position + length])
            position += length
        self.assertEqual(position, len(output.stdout))
        return result

    def native(self, rows, backend=None):
        for name, module in self.backends.items():
            if backend is not None and name != backend:
                continue
            self.assertEqual(module.exports, frozenset({"f0"}))
            for start in range(0, len(rows), 64):
                subset = rows[start:start+64]
                got = module.call_many([("f0", (row, SENTINEL * capacity, SCRATCH))
                                        for row, capacity, _, _ in subset])
                for actual, (row, cap, status, output) in zip(got, subset, strict=True):
                    actual.require_returned()
                    self.assertEqual(actual.value, status, (name, row[:16].hex(), cap))
                    self.assertEqual(actual.arguments, [row, output + SENTINEL * (cap-len(output)), SCRATCH])

    def compare(self, rows):
        expected = self.oracle(rows)
        self.native([(row, len(out) + 9, len(out), out)
                     for row, out in zip(rows, expected, strict=True)])
        return expected

    def test_framing_and_endianness(self):
        rows = [packet(), packet(SUPPLIED), packet(bytes(64))]
        prefix = (b"CCH1" + PROFILE + b"\2" + INSTANCE
                  + bytes.fromhex("0102030405060708")
                  + (0x0102030405 + 345).to_bytes(8, "big"))
        self.assertEqual(self.compare(rows), [prefix, prefix + SUPPLIED, prefix + bytes(64)])

    def test_exact_capacity_and_bounds(self):
        args = itertools.product((None, SUPPLIED), (0, 1, (1 << 64) - 1),
                                 (1, MAX_ARTIFACT), (127, 893))
        rows = [packet(digest, generation=gen, raw_size=size, header_size=head)
                for digest, gen, size, head in args]
        expected = self.oracle(rows)
        self.native([(row, cap, status, output)
                     for row, out in zip(rows, expected, strict=True)
                     for cap, status, output in ((len(out), len(out), out),
                                                 (len(out)-1, SHORT, b""), (0, SHORT, b""))])
        self.assertEqual(int.from_bytes(expected[-1][141:149], "big"), MAX_ARTIFACT + 893)

    def test_invalid_precedes_capacity_and_leaves_full_buffers_untouched(self):
        good = packet()
        claim = packet(SUPPLIED)
        rows = [claim[:length] for length in range(len(claim))]
        rows += [b"CCF0" + good[4:], good + b"\0", claim + b"\0",
                 good[:4] + b"\2" + good[5:]]
        rows += [good[:5] + bytes([v]) + good[6:] for v in range(256) if v != 2]
        rows += [packet(profile=bytes(64)), packet(instance=bytes(64))]
        rows += [packet(raw_size=v) for v in (0, MAX_ARTIFACT + 1, (1 << 64) - 1)]
        rows += [packet(header_size=v) for v in (0, 126, 894, (1 << 16) - 1)]
        self.native([(row, cap, BAD, b"") for row in rows for cap in (0, 222)])

    def test_seeded_context_field_pairs(self):
        rng = random.Random(0x43434831)

        def rand64():
            return rng.getrandbits(512).to_bytes(64, "big")

        rows = []
        for _ in range(160):
            values = dict(profile=rand64(), instance=rand64(), generation=rng.getrandbits(64),
                          raw_size=rng.randint(1, MAX_ARTIFACT), header_size=rng.randint(127, 893))
            rows.extend((packet(**values), packet(rand64(), **values)))
        zero_prefix = bytes(63) + b"\x01"
        rows += [packet(profile=zero_prefix), packet(SUPPLIED, instance=zero_prefix)]
        encoded = self.compare(rows)
        self.assertTrue(all(encoded[i] == encoded[i+1][:149] for i in range(0, 320, 2)))

    def test_lengths_from_actual_native_rac1(self):
        for backend in self.backends:
            with NativeModule(RAC1, backend=backend, byte_exports=("f0",)) as artifact:
                for name, media, size, expected_len in (
                    (b" ", b"~", 1, 127), (b"a"*512, b"b"*256, MAX_ARTIFACT, 893),
                ):
                    rc = artifact.call("f0", (rac1_request(name, media, size), SENTINEL*893, SCRATCH))
                    rc.require_returned()
                    self.assertEqual(rc.value, expected_len)
                    self.assertEqual(rc.arguments[1][:4], b"RAC1")
                    supplied = packet(SUPPLIED, raw_size=size, header_size=rc.value)
                    [expected] = self.oracle([supplied])
                    self.assertEqual(int.from_bytes(expected[141:149], "big"), size + rc.value)
                    self.native([(supplied, len(expected), len(expected), expected)], backend=backend)


if __name__ == "__main__":
    unittest.main()
