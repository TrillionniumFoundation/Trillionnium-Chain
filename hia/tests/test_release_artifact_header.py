"""Native RAC1 bytes against the original ReleaseBundle Rust implementation."""
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

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "hia/src/release_bundle/artifact_header.hepta"
RUST = ROOT / "trillionnium/crates/trnm-release-bundle/src"
BAD = 0xFFFFFFFF
SHORT = 0xFFFFFFFE
SENTINEL = b"\xcd"
SCRATCH = b"\x92" * 11
SIZE_CAP = 128 * 1024**3
ALIASES = (bytes(range(32)), bytes(range(32, 64)), bytes(range(224, 256)))


def unique(raw, expression):
    found = re.findall(rb"(?ms)^" + expression, raw)
    if len(found) != 1:
        raise ValueError(f"Original Rust boundary changed: {expression!r}")
    return found[0]


def build_reference(directory):
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = subprocess.run(["rustc", "--version"], check=True, capture_output=True,
                             timeout=10, text=True).stdout.split()
    if version[:2] != ["rustc", pin]:
        raise ValueError("The original ReleaseBundle reference requires the pinned Rust toolchain")
    lib = (RUST / "lib.rs").read_bytes()
    content = (RUST / "content_v1.rs").read_bytes()
    # Use the unchanged original definitions, predicate, validator, and
    # private serializer; reserved errors and wire parsing belong to the adapter.
    constants = b"".join(unique(lib, rb"pub const " + name + rb": [^\n]+\n")
                         for name in (b"MAX_NAME_BYTES_V0", b"MAX_MEDIA_TYPE_BYTES_V0",
                                      b"MAX_ARTIFACT_BYTES_V0"))
    artifact_impl = unique(lib, rb"impl ArtifactEntryV0 \{.*?^}\n")
    source = directory / "reference.rs"
    source.write_bytes(
        unique(lib, rb"#\[derive\([^\n]+\)\]\npub struct Digest32V0\([^\n]+\n")
        + constants
        + unique(lib, rb"fn valid_text\(.*?^}\n")
        + unique(lib, rb"#\[derive\([^\n]+\)\]\npub struct ArtifactEntryV0 \{.*?^}\n")
        + b"pub enum ReleaseBundleErrorV0 { InvalidArtifact }\n"
        + b"enum ReleaseContentError { InvalidArtifact }\n"
        + b"impl ArtifactEntryV0 {\n"
        + unique(artifact_impl, rb"    pub fn validate\(&self\) -> Result<\(\), ReleaseBundleErrorV0> \{.*?^    }\n")
        + b"}\n"
        + unique(content, rb"fn artifact_header\(.*?^}\n")
        + br"""
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut cursor = 0;
    let mut out = io::stdout().lock();
    while cursor < raw.len() {
        let n = u32::from_le_bytes(raw[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let frame = &raw[cursor..cursor + n];
        cursor += n;
        let name_len = u16::from_le_bytes(frame[..2].try_into().unwrap()) as usize;
        let media_len = u16::from_le_bytes(frame[2..4].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 109 + name_len + media_len);
        assert!(frame[12] <= 1);
        let artifact = ArtifactEntryV0 {
            logical_name: frame[109..109 + name_len].to_vec(),
            media_type: frame[109 + name_len..].to_vec(),
            size_bytes: u64::from_le_bytes(frame[4..12].try_into().unwrap()),
            executable: frame[12] == 1,
            content_digest: Digest32V0(frame[13..45].try_into().unwrap()),
            platform_digest: Digest32V0(frame[45..77].try_into().unwrap()),
            source_path_digest: Digest32V0(frame[77..109].try_into().unwrap()),
        };
        match artifact_header(&artifact) {
            Ok(header) => {
                out.write_all(&(header.len() as u32).to_le_bytes())?;
                out.write_all(&header)?;
            }
            Err(ReleaseContentError::InvalidArtifact) =>
                out.write_all(&u32::MAX.to_le_bytes())?,
        }
    }
    Ok(())
}
""")
    executable = directory / "reference"
    build = subprocess.run(["rustc", "--edition=2021", "-Dwarnings", "-C", "overflow-checks=yes",
                            str(source), "-o", str(executable)], capture_output=True,
                           check=False, timeout=30)
    if build.returncode:
        raise RuntimeError(build.stderr.decode())
    return executable


def frame(name=b"archive", media=b"application/octet-stream", size=0x102030405,
          executable=1, aliases=ALIASES):
    return struct.pack("<HHQB", len(name), len(media), size, executable) + b"".join(aliases) + name + media


class ReleaseArtifactHeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-rac1-reference-")
        cls.addClassCleanup(temporary.cleanup)
        cls.original = build_reference(Path(temporary.name))
        cls.backends = {}
        for backend in ("selfhost", "direct"):
            native = NativeModule(NATIVE, backend=backend, byte_exports=("f0",))
            cls.addClassCleanup(native.close)
            cls.backends[backend] = native

    def oracle(self, values):
        result = subprocess.run([str(self.original)],
                                input=b"".join(struct.pack("<I", len(v)) + v for v in values),
                                check=True, capture_output=True, timeout=20)
        self.assertEqual(result.stderr, b"")
        data = result.stdout
        expected = []
        offset = 0
        for _ in values:
            n, = struct.unpack_from("<I", data, offset)
            offset += 4
            if n == BAD:
                expected.append(None)
            else:
                expected.append(data[offset:offset + n])
                offset += n
        self.assertEqual(offset, len(data))
        return expected

    def native_cases(self, cases):
        for backend, native in self.backends.items():
            self.assertEqual(native.exports, frozenset({"f0"}))
            for start in range(0, len(cases), 64):
                batch = cases[start:start + 64]
                observations = native.call_many([
                    ("f0", (data, SENTINEL * capacity, SCRATCH))
                    for data, capacity, _, _ in batch
                ])
                for actual, (data, capacity, status, output) in zip(observations, batch, strict=True):
                    actual.require_returned()
                    self.assertEqual(actual.value, status, (backend, len(data), data[:40].hex()))
                    self.assertEqual(actual.arguments,
                                     [data, output + SENTINEL * (capacity - len(output)), SCRATCH])

    def compare(self, rows):
        expected = self.oracle(rows)
        self.native_cases([(data, 900, BAD if out is None else len(out), out or b"")
                           for data, out in zip(rows, expected, strict=True)])
        return expected

    def test_exact_bytes_extremes_order_and_short_output(self):
        for aliases in itertools.permutations(ALIASES):
            sample = frame(b" ~", b"z", 0x0102030405, 1, aliases)
            expected = (b"RAC1" + bytes.fromhex("0000000000000002") + b" ~"
                        + bytes.fromhex("0000000000000001") + b"z"
                        + bytes.fromhex("0000000102030405") + b"\1" + b"".join(aliases))
            self.assertEqual(self.compare([sample]), [expected])
        rows = [frame(b" ", b"~", 1, 0), frame(b"~" * 512, b" " * 256, SIZE_CAP, 1)]
        expected = self.oracle(rows)
        self.assertEqual([len(value) for value in expected], [127, 893])
        cases = []
        for data, out in zip(rows, expected, strict=True):
            cases.extend([(data, len(out), len(out), out), (data, len(out) - 1, SHORT, b""),
                          (data, 0, SHORT, b"")])
        self.native_cases(cases)

    def test_original_metadata_domain_and_invalid_before_capacity(self):
        rows = [frame(b"", b"abc"), frame(b"a" * 513, b"b"), frame(b"abc", b""),
                frame(b"a", b"b" * 257), frame(size=0), frame(size=SIZE_CAP + 1),
                frame(size=(1 << 64) - 1)]
        for index in range(3):
            altered = list(ALIASES)
            altered[index] = bytes(32)
            rows.append(frame(aliases=altered))
        self.assertEqual(self.oracle(rows), [None] * len(rows))
        self.native_cases([(row, capacity, BAD, b"") for row in rows for capacity in (0, 900)])
        for field in (0, 1):
            values = [(bytes([octet]), b"x") if field == 0 else (b"x", bytes([octet]))
                      for octet in range(256)]
            observed = self.compare([frame(*v) for v in values])
            self.assertEqual([x is not None for x in observed],
                             [32 <= i <= 126 for i in range(256)])

    def test_malformed_frame_refusals_do_not_write(self):
        valid = frame()
        rows = [valid[:end] for end in range(len(valid))]
        rows.extend([valid + b"\0", valid[:12] + b"\2" + valid[13:],
                     valid[:12] + b"\xff" + valid[13:], b"\xff\xff" + valid[2:],
                     valid[:2] + b"\xff\xff" + valid[4:], b"\x00" * 878])
        self.native_cases([(r, cap, BAD, b"") for r in rows for cap in (0, 901)])

    def test_seeded_valid_entries(self):
        rng = random.Random(0x52414331)
        rows = []
        for _ in range(160):
            name = bytes(rng.randrange(32, 127) for _ in range(rng.randint(1, 512)))
            media = bytes(rng.randrange(32, 127) for _ in range(rng.randint(1, 256)))
            aliases = tuple(rng.getrandbits(256).to_bytes(32, "big") for _ in range(3))
            rows.append(frame(name, media, rng.randint(1, SIZE_CAP), rng.randrange(2), aliases))
        self.assertTrue(all(self.compare(rows)))


if __name__ == "__main__":
    unittest.main()
