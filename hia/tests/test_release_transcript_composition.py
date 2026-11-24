"""Test-only owner uses one real raw feed and five native Release/SHA boundaries."""
from dataclasses import dataclass, replace
import hashlib
import io
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.platform.release_file_shadow.owner import (
    BLOCK, BOOT, CCH_LEN, SENTINEL, SHA512_STATE, STREAM, WORK,
    Budget, Candidate, _stream,
)
from hia.tests.test_release_artifact_header import (
    ALIASES, NATIVE as RAC1, RUST as RELEASE, unique,
)
from hia.tests.test_release_content_claim_frame import (
    INSTANCE, PROFILE, PROTOCOL, ROOT, SOURCE as CCH1, packet as cch1_request,
)
from hia.tests.test_release_raw_artifact_sha256 import sample

ORIGINAL_FIXTURE = Path(__file__).with_name("rust_release_transcript_reference.rs")
ZERO_DIGEST = b"\0" * 32


def original_reference(directory, *, held_file=False):
    rustc = os.environ.get("RUSTC", "rustc")
    actual = subprocess.run([rustc, "--version"], capture_output=True, text=True,
                            check=True, timeout=10).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if actual[:2] != ["rustc", pin]:
        raise ValueError(f"Original Release observer requires pinned rustc {pin}")
    lib = (RELEASE / "lib.rs").read_bytes()
    release = (RELEASE / "content_v1.rs").read_bytes()
    protocol = PROTOCOL.read_bytes()
    derive = rb"#\[derive\([^\n]+\)\]\n"
    lib_body = b"".join(unique(lib, expression) for expression in (
        derive + rb"pub struct Digest32V0\([^\n]+\n",
        derive + rb"pub struct ArtifactEntryV0 \{.*?^}\n",
        rb"pub const MAX_NAME_BYTES_V0:[^\n]+\n",
        rb"pub const MAX_MEDIA_TYPE_BYTES_V0:[^\n]+\n",
        rb"pub const MAX_ARTIFACT_BYTES_V0:[^\n]+\n",
        rb"fn valid_text\(.*?^}\n",
    ))
    lib_body += b"#[derive(Debug)] pub enum ReleaseBundleErrorV0 { InvalidArtifact }\n"
    artifact = unique(lib, rb"impl ArtifactEntryV0 \{.*?^}\n")
    lib_body += b"impl ArtifactEntryV0 {\n" + unique(
        artifact, rb"    pub fn validate\(&self\) -> Result<\(\), ReleaseBundleErrorV0> \{.*?^    }\n"
    ) + b"}\n"
    release_body = b"".join(unique(release, expression) for expression in (
        derive + rb"pub enum ReleaseContentError \{.*?^}\n",
        rb"impl std::fmt::Display for ReleaseContentError \{.*?^}\n",
        rb"impl std::error::Error for ReleaseContentError \{\}\n",
        rb"impl From<ContentCommitmentError> for ReleaseContentError \{.*?^}\n",
        rb"impl From<io::Error> for ReleaseContentError \{.*?^}\n",
        rb"fn artifact_header\(.*?^}\n",
        rb"struct LegacyHashReader<'a, R: Read \+ \?Sized> \{.*?^}\n",
        rb"impl<R: Read \+ \?Sized> Read for LegacyHashReader<'_, R> \{.*?^}\n",
        rb"pub fn observe_release_artifact_v1<.*?^}\n",
    ))
    if held_file:
        release_body += unique(release, rb"pub fn observe_release_file_v1\(.*?^}\n")
    protocol_body = b"".join(unique(protocol, expression) for expression in (
        rb"const DOMAIN:[^\n]+\n", rb"const MAGIC:[^\n]+\n",
        rb"pub const CONTENT_CLAIM_BYTES:[^\n]+\n", rb"const HEADER_BYTES:[^\n]+\n",
        derive + rb"#\[repr\(u8\)\]\npub enum ContentKind \{.*?^}\n",
        derive + rb"pub enum ContentCommitmentError \{.*?^}\n",
        rb"impl std::fmt::Display for ContentCommitmentError \{.*?^}\n",
        rb"impl std::error::Error for ContentCommitmentError \{.*?^}\n",
        rb"impl From<io::Error> for ContentCommitmentError \{.*?^}\n",
        derive + rb"pub struct ContentContextV1 \{.*?^}\n",
        derive + rb"pub struct ContentClaimV1 \{.*?^}\n",
        derive + rb"pub struct ObservedContentV1 \{.*?^}\n",
        derive + rb"pub struct ContentReadBudget \{.*?^}\n",
        rb"impl ContentReadBudget \{.*?^}\n",
        rb"pub fn observe_reader<.*?^}\n",
    ))
    protocol_body += b"""#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoProfileId([u8; 64]);
impl CryptoProfileId { fn as_bytes(&self) -> &[u8; 64] { &self.0 } }
impl ContentContextV1 {
"""
    for expression in (rb"    pub fn kind\(&self\) -> ContentKind \{.*?^    }\n",
                       rb"    fn header\(&self, content_len: u64\) -> Vec<u8> \{.*?^    }\n"):
        protocol_body += unique(protocol, expression)
    protocol_body += b"}\nimpl ContentClaimV1 {\n" + unique(
        protocol, rb"    pub fn encode\(&self\) -> Vec<u8> \{.*?^    }\n"
    ) + b"}\n"
    source = directory / "reference.rs"
    fixture = ORIGINAL_FIXTURE.read_bytes()
    if held_file:
        primitives = fixture[:fixture.index(b"struct SliceReader")]
        fixture = primitives + Path(__file__).with_name("rust_release_file_descriptor_reference.rs").read_bytes()
    source.write_bytes(lib_body + release_body + protocol_body + fixture)
    binary = directory / "reference"
    built = subprocess.run([rustc, "--edition=2021", "-Dwarnings", "-C", "overflow-checks=yes",
                            str(source), "-o", str(binary)], capture_output=True, timeout=30)
    if built.returncode:
        raise RuntimeError(built.stderr.decode())
    return binary


@dataclass(frozen=True)
class Case:
    data: bytes
    size: int
    locator: bytes
    name: bytes = b"release artifact"
    media: bytes = b"application/octet-stream"
    generation: int = 0x123456789ABCDE01
    profile: bytes = PROFILE
    instance: bytes = INSTANCE
    kind: int = 2
    max_reads: int = 1
    max_bytes: int = 1 << 38
    precharge: int = 0
    step: int = BLOCK
    fault_at: int = 0xFFFF
    fault_mode: int = 0

    def candidate(self):
        return Candidate(self.size, self.locator, self.name, self.media, *ALIASES[1:],
                         self.profile, self.instance, self.generation, self.kind)

    def metadata(self):
        return self.candidate().rac1_request()

    def original_input(self):
        return (self.profile + self.instance
                + struct.pack("<QBQQQHHBH", self.generation, self.kind,
                              self.max_reads, self.max_bytes, self.precharge, self.step,
                              self.fault_at, self.fault_mode, len(self.metadata()))
                + self.metadata() + self.data)


class ReleaseTranscriptComposition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = Path(cls.enterClassContext(tempfile.TemporaryDirectory(
            prefix="trnm-release-composition-")))
        cls.rust = original_reference(temporary)
        cls.modules = {}
        for backend in ("direct", "selfhost"):
            cls.modules[backend] = {source: cls.enterClassContext(
                NativeModule(source, backend=backend, byte_exports=("f0",)))
                for source in STREAM}

    def call(self, modules, source, frame, output, state, status=0):
        answer = modules[source].call("f0", [frame, output, state]).require_returned()
        self.assertEqual(answer.arguments[0], frame)
        self.assertEqual(answer.value, status)
        return answer.arguments[1:]

    def original(self, case):
        report = subprocess.run([str(self.rust)], input=case.original_input(), check=True,
                                capture_output=True, timeout=20)
        self.assertEqual(report.stderr, b"")
        return report.stdout

    def observed(self, modules, case):
        """Run fault/short-read fixtures through the shared streaming owner."""
        reader = io.BytesIO(case.data)
        budget = Budget(case.max_reads, case.max_bytes)
        if case.precharge:
            self.assertTrue(budget.reserve(case.precharge))
        index = 0

        def read(width):
            nonlocal index
            i, index = index, index + 1
            if case.fault_at == i:
                if case.fault_mode == 2:
                    return bytes(width + 1)
                raise OSError("synthetic original-reader failure")
            return reader.read(min(width, case.step))

        result = _stream(modules, case.candidate(), budget, read)
        self.assertEqual(result.consumed, reader.tell())
        return result.transcript_record()

    def case(self, data):
        return Case(data, len(data), hashlib.sha256(data).digest())

    def test_exact_claim_metadata_changes_and_multiple_real_read_partitions(self):
        item = self.case(sample(BLOCK + 9))
        small = self.case(sample(65))
        metadata_changed = replace(small, name=small.name[::-1])
        generation_changed = replace(small, generation=small.generation + 1)
        rows = [item, replace(item, step=3821), small, metadata_changed, generation_changed]
        reference = [self.original(case) for case in rows]
        claims = [value[-213:] for value in reference]
        self.assertTrue(all(value[0] == 0 for value in reference))
        self.assertEqual(claims[0], claims[1])
        self.assertNotEqual(reference[0], reference[1])  # different real reader requests
        # Same raw and same CCH1 header for the rename; only RAC1 differs.
        self.assertEqual(claims[2][:149], claims[3][:149])
        self.assertEqual(len({claim[149:] for claim in claims[2:]}), 3)
        for backend, modules in self.modules.items():
            for case, expected in zip(rows, reference, strict=True):
                with self.subTest(backend=backend, step=case.step, name=case.name):
                    self.assertEqual(self.observed(modules, case), expected)

    def test_refusal_precedence_and_monotone_read_budget(self):
        value = self.case(b"0123456789")
        wrong = replace(value, locator=b"\x81" * 32)
        reservation = 125 + len(value.name) + len(value.media) + value.size + 1
        rows = [
            (replace(wrong, kind=1, max_bytes=1), 1),
            (replace(wrong, locator=ZERO_DIGEST, max_bytes=1), 1),
            (replace(wrong, max_bytes=1), 2),
            (replace(wrong, precharge=1), 2),  # cumulative read slots exhausted
            (replace(wrong, max_reads=2, precharge=1, max_bytes=reservation + 1), 2),
            (replace(wrong, data=value.data[:-1]), 3),
            (replace(wrong, data=value.data + b"!"), 5),
            (replace(wrong, fault_at=0, fault_mode=2), 4),
            (replace(wrong, data=value.data + b"!", fault_at=1, fault_mode=1), 4),
            (replace(wrong, fault_at=1, fault_mode=3), 4),
            (replace(wrong, max_bytes=reservation), 6),
            (replace(value, max_bytes=reservation), 0),
        ]
        reference = [self.original(case) for case, _ in rows]
        self.assertEqual([x[0] for x in reference], [code for _, code in rows])
        for expected in reference:
            raw_calls = struct.unpack_from("<H", expected, 26)[0]
            self.assertEqual(len(expected), 28 + raw_calls * 2 + (213 if expected[0] == 0 else 0))
        for backend, modules in self.modules.items():
            for (case, code), expected in zip(rows, reference, strict=True):
                with self.subTest(backend=backend, status=code, fault=case.fault_mode):
                    self.assertEqual(self.observed(modules, case), expected)

    def test_bootstrap_rejects_reordered_wrong_kind_or_mismatched_length_without_mutating(self):
        item = self.case(b"x")
        for backend, modules in self.modules.items():
            with self.subTest(backend=backend):
                m = modules[RAC1].call("f0", [item.metadata(), SENTINEL * 900, b""]).require_returned()
                self.assertTrue(127 <= m.value <= 893)
                rac = m.arguments[1][:m.value]
                cch, _ = self.call(modules, CCH1, cch1_request(raw_size=item.size,
                    header_size=len(rac)), SENTINEL * CCH_LEN, b"", status=CCH_LEN)
                valid = cch + rac
                state = WORK * (SHA512_STATE + 19)
                untouched = SENTINEL * 11
                for invalid in (rac + cch, valid[:68] + b"\1" + valid[69:],
                                valid[:141] + b"\0" * 8 + valid[149:],
                                valid[:-1], valid + b"\0", valid + b"\0" * 1000):
                    self.assertEqual(self.call(modules, BOOT, invalid, untouched, state, status=100),
                                     [untouched, state])
                short = state[:SHA512_STATE - 1]
                self.assertEqual(self.call(modules, BOOT, valid, untouched, short, status=101),
                                 [untouched, short])
                out, after = self.call(modules, BOOT, valid, untouched, state)
                self.assertEqual(out, untouched)
                self.assertEqual(after[SHA512_STATE:], state[SHA512_STATE:])
                self.assertEqual(int.from_bytes(after[1472:1480], "little"), 32 + len(valid))
