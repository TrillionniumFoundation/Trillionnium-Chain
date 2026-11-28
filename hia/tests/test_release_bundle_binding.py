"""Differential of M15 binding, with original verifier and a refusing signature seam."""
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
from hia.tests.test_release_exact_source import (
    ADAPTER as SHA_ADAPTER,
    ORIGINAL,
    ROOT,
    transcript as exact_source_transcript,
)

SOURCE = ROOT / "hia/src/release_bundle/bundle_binding.hepta"
ADAPTER = Path(__file__).with_name("rust_release_bundle_binding_reference.rs")
STATE, SCRATCH = 1208, 2302
PREFIX = 517
FORMAT, INVALID_SOURCE, SHORT, MISMATCH = 100, 101, 102, 104


def canonical_transcript(frame):
    name_width, version_width = struct.unpack_from("<HH", frame, 513)
    boundary = PREFIX + name_width
    end = boundary + version_width
    if end != len(frame):
        raise ValueError("Fixture frame extent differs")
    exact_source_digest = hashlib.sha256(exact_source_transcript(frame[:193])).digest()
    fields = [
        b"trnm.release.bundle.v0", frame[PREFIX:boundary], frame[boundary:end],
        frame[193:225], exact_source_digest, frame[225:257], frame[257:289],
        frame[289:321], frame[321:353], frame[353:385],
    ]
    return b"".join(len(part).to_bytes(8, "big") + part for part in fields)


def original_rows():
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    raw = ORIGINAL.read_bytes()
    patterns = [
        (raw, rb"(?ms)^use std::\{collections::BTreeSet, error::Error, fmt\};\n"
              rb".*?(?=^#\[cfg\(test\)\]\nmod tests \{)"),
        (raw, rb"(?ms)^    fn d\(byte: u8\) -> Digest32V0 \{.*?^    \}\n"),
        (raw, rb"(?ms)^    fn bundle\(builder: u8, artifact_digest: u8\) -> ReleaseBundleV0 "
              rb"\{.*?^    \}\n"),
        (SHA_ADAPTER.read_bytes(),
         rb"(?ms)^use std::io::\{self, Read, Write\};\n.*?(?=^fn main\()"),
    ]
    blocks = []
    for data, pattern in patterns:
        matches = re.findall(pattern, data)
        if len(matches) != 1:
            raise ValueError(f"Original ReleaseBundle or digest-seam source changed: {pattern!r}")
        blocks.append(matches[0])
    blocks[-1] = blocks[-1].replace(b"{self, Read, Write}", b"{self, Write}")
    with tempfile.TemporaryDirectory(prefix="trnm-release-binding-oracle-") as tmp:
        code = Path(tmp) / "binding.rs"
        program = Path(tmp) / "binding"
        code.write_bytes(b"\n".join([*blocks, ADAPTER.read_bytes()]))
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(code), "-o", str(program)],
                       check=True, capture_output=True, timeout=30)
        run = subprocess.run([str(program)], check=True, capture_output=True, timeout=40)

    data = run.stdout
    if run.stderr:
        raise ValueError("Unexpected output from original ReleaseBundle")
    rows = []
    while data:
        status, stage, extent = struct.unpack_from("<BBH", data)
        end = 36 + extent
        if not PREFIX <= extent <= PREFIX + 768 or end > len(data):
            raise ValueError("Truncated or overlong original ReleaseBundle observation")
        digest = data[4:36] if status == 0 else b""
        rows.append((data[36:end], status, stage, digest))
        data = data[end:]
    return rows


class NativeReleaseBundleBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = original_rows()
        cls.native = {
            backend: cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.native["direct"].artifact_sha256 == cls.native["selfhost"].artifact_sha256:
            raise ValueError("Expected separately emitted machine artifacts")

    def check(self, cases):
        for backend, module in self.native.items():
            calls = [("f0", [frame, b"\x93" * width, b"\xc3" * scratch])
                     for frame, width, scratch, status, stage, digest in cases]
            observations = module.call_many(calls, timeout=45)
            self.assertEqual(len(observations), len(cases))
            for i, (row, call, observed) in enumerate(zip(cases, calls, observations)):
                frame, width, scratch, status, stage, digest = row
                with self.subTest(backend=backend, row=i, status=status):
                    observed.require_returned()
                    self.assertEqual(observed.value, status)
                    self.assertEqual(observed.arguments[0], frame)
                    self.assertEqual(observed.arguments[1], digest + call[1][1][len(digest):])
                    work = observed.arguments[2]
                    self.assertEqual(work[SCRATCH:], call[1][2][SCRATCH:])
                    if status in (FORMAT, INVALID_SOURCE, SHORT):
                        self.assertEqual(work, call[1][2])
                    if stage == 2:
                        original_source = exact_source_transcript(frame[:193])
                        self.assertEqual(work[STATE:STATE + len(original_source)], original_source)
                        self.assertEqual(work[STATE + len(original_source):],
                                         call[1][2][STATE + len(original_source):])
                    if stage in (0, 3, 4):
                        expected_transcript = canonical_transcript(frame)
                        self.assertEqual(work[STATE:STATE + len(expected_transcript)],
                                         expected_transcript)
                        if status == 0:
                            self.assertEqual(digest, hashlib.sha256(expected_transcript).digest())

    def test_original_release_bundle_and_early_binding_stages(self):
        self.assertEqual(len(self.rows), 38)
        self.assertEqual(sum(code == INVALID_SOURCE for _, code, _, _ in self.rows), 7)
        self.assertEqual(sum(code == MISMATCH for _, code, _, _ in self.rows), 13)
        self.check([(frame, 39, SCRATCH + 13, status, stage, digest)
                    for frame, status, stage, digest in self.rows])

    def test_framing_precedence_capacity_and_atomic_publication(self):
        frame, code, stage, digest = self.rows[0]
        self.assertEqual((code, stage), (0, 0))
        malformed = [frame[:n] for n in (0, 192, 513, 514, 515, 516, len(frame) - 1)]
        malformed += [frame + b"\0", frame[:513] + b"\x01\x02" + frame[515:],
                      frame[:515] + b"\x01\x01" + frame[PREFIX:],
                      frame[:192] + b"\xff" + frame[193:]]
        malformed += [frame[:513] + struct.pack("<HH", n, v) + b"x" * (n + v)
                      for n, v in ((513, 0), (0, 257), (513, 257))]
        malformed.append(frame[:192] + b"\xff" + frame[193:] + bytes(1))
        invalid = frame[:192] + b"\1" + frame[193:]
        cases = [(bad, 0, 0, FORMAT, -1, b"") for bad in malformed]
        cases += [(bad, 39, SCRATCH + 13, FORMAT, -1, b"") for bad in malformed]
        cases += [(invalid, 0, 0, INVALID_SOURCE, -1, b""),
                  (frame, 31, SCRATCH + 13, SHORT, -1, b""),
                  (frame, 32, SCRATCH - 1, SHORT, -1, b""),
                  (frame, 32, SCRATCH, 0, 0, digest)]
        self.check(cases)


if __name__ == "__main__":
    unittest.main()
