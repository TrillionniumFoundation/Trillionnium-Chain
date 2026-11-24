"""Differential for the borrowed native ReleaseBundle exact-source admission."""
from __future__ import annotations

import hashlib
import itertools
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/release_bundle/exact_source.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-release-bundle/src/lib.rs"
ADAPTER = Path(__file__).with_name("rust_release_exact_source_reference.rs")
DOMAIN = b"trnm.release.exact-source.v0"
CANDIDATE = bytes(range(192)) + bytes(1)
KNOWN = bytes.fromhex("d73dcc8df8bb8d14709985059c61a5665cb088d1da8985aebc5b00481b6988c1")
FRAME, INVALID, CAPACITY = 100, 101, 102
STATE, SCRATCH = 1208, 1493


def replace(data, start, replacement):
    return data[:start] + replacement + data[start + len(replacement):]


def transcript(frame):
    chunks = [DOMAIN, *(frame[i:i + 32] for i in range(0, 192, 32)), frame[192:]]
    return b"".join(len(part).to_bytes(8, "big") + part for part in chunks)


def original_results(cases):
    """Compile exact Rust types, methods and length framing, with a digest seam."""
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    original = ORIGINAL.read_bytes()
    patterns = (
        rb"(?m)^#\[derive\([^\n]+\)\]\npub struct Digest32V0\(pub \[u8; 32\]\);\n",
        rb"(?ms)^impl Digest32V0 \{.*?^\}\n",
        rb"(?ms)^#\[derive\([^\n]+\)\]\npub struct ExactSourceV0 \{.*?^\}\n",
        rb"(?ms)^impl ExactSourceV0 \{.*?^\}\n",
        rb"(?ms)^#\[derive\([^\n]+\)\]\npub enum ReleaseBundleErrorV0 \{.*?^\}\n",
    )
    declarations = []
    for pattern in patterns:
        matches = re.findall(pattern, original)
        if len(matches) != 1:
            raise ValueError(f"Original ReleaseBundle declaration changed: {pattern!r}")
        declarations.append(matches[0])

    with tempfile.TemporaryDirectory(prefix="trnm-release-source-oracle-") as folder:
        source = Path(folder) / "reference.rs"
        executable = Path(folder) / "reference"
        source.write_bytes(b"\n".join([*declarations, ADAPTER.read_bytes()]))
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o",
                        str(executable)], check=True, capture_output=True, timeout=30)
        report = subprocess.run([str(executable)], check=True, input=b"".join(cases),
                                capture_output=True, timeout=30)

    observed = []
    data = report.stdout
    for _ in cases:
        status = data[0]
        extent = {0: 33, INVALID: 1}[status]
        if len(data) < extent:
            raise ValueError("Truncated original exact-source observation")
        observed.append((status, data[1:extent]))
        data = data[extent:]
    if data or report.stderr:
        raise ValueError("Trailing original exact-source observations")
    return observed


class NativeReleaseExactSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = {
            backend: cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.native["direct"].artifact_sha256 == cls.native["selfhost"].artifact_sha256:
            raise ValueError("Expected separately emitted machine artifacts")

    def check_cases(self, cases):
        for backend, module in self.native.items():
            for start in range(0, len(cases), 64):
                batch = cases[start:start + 64]
                requests = [("f0", [frame, b"\xa5" * out_width, b"\xcc" * scratch_width])
                            for frame, out_width, scratch_width, _, _ in batch]
                results = module.call_many(requests)
                self.assertEqual(len(results), len(batch))
                for i, (case, request, result) in enumerate(zip(batch, requests, results)):
                    with self.subTest(backend=backend, case=start + i):
                        frame, _, _, status, digest = case
                        result.require_returned()
                        self.assertEqual(result.value, status)
                        self.assertEqual(result.arguments[0], frame)
                        before_out, before_scratch = request[1][1:]
                        self.assertEqual(result.arguments[1], digest + before_out[len(digest):])
                        if status:
                            self.assertEqual(result.arguments[2], before_scratch)
                        else:
                            self.assertEqual(result.arguments[2][STATE:SCRATCH], transcript(frame))
                            self.assertEqual(result.arguments[2][SCRATCH:], before_scratch[SCRATCH:])

    def test_original_typed_validation_and_canonical_digest(self):
        cases = [CANDIDATE]
        # Each octet affects the digest, including zero/high-bit octets.
        cases.extend(replace(CANDIDATE, i, bytes([CANDIDATE[i] ^ 0xa3])) for i in range(192))
        # Each position alone can make one of the six fields nonzero. The
        # neighbouring five digests stay nonzero: a global OR would be wrong.
        for field in range(6):
            offset = field * 32
            cases.append(replace(CANDIDATE, offset, bytes(32)))
            cases.extend(replace(CANDIDATE, offset, bytes(i) + b"\x80" + bytes(31 - i))
                         for i in range(32))
        fields = [CANDIDATE[i:i + 32] for i in range(0, 192, 32)]
        for a, b in itertools.combinations(range(6), 2):
            swapped = fields.copy()
            swapped[a], swapped[b] = swapped[b], swapped[a]
            cases.append(b"".join(swapped) + bytes(1))
        cases.extend([CANDIDATE[:-1] + b"\1", bytes(193), bytes(192) + b"\1",
                      CANDIDATE[:32] * 6 + bytes(1)])
        expected = original_results(cases)
        self.assertEqual(expected[0], (0, KNOWN))
        self.assertEqual(sum(status == INVALID for status, _ in expected), 9)
        for frame, (status, digest) in zip(cases, expected):
            if status == 0:
                self.assertEqual(digest, hashlib.sha256(transcript(frame)).digest())
        self.check_cases([(frame, 39, SCRATCH + 17, status, digest)
                          for frame, (status, digest) in zip(cases, expected)])

    def test_precedence_exact_extent_and_untouched_caller_buffers(self):
        semantic_invalid = [CANDIDATE[:-1] + b"\1", replace(CANDIDATE, 160, bytes(32)),
                            replace(CANDIDATE[:-1] + b"\1", 160, bytes(32))]
        invalid_frames = [CANDIDATE[:i] for i in (0, 1, 31, 32, 191, 192)]
        invalid_frames.extend([CANDIDATE + bytes(1), CANDIDATE + b"trailing"])
        invalid_frames.extend(CANDIDATE[:-1] + bytes([i]) for i in range(2, 256))
        invalid_frames.append(bytes(192) + b"\xff")
        # Framing precedes semantic validity, and semantic validity precedes
        # capacity. Neither rejection may reveal a digest or mutate scratch.
        cases = [(frame, out, scratch, code, b"")
                 for frames, code in ((invalid_frames, FRAME), (semantic_invalid, INVALID))
                 for frame in frames
                 for out, scratch in ((0, 0), (32, SCRATCH))]
        cases.extend((CANDIDATE, out, scratch, CAPACITY, b"")
                     for out, scratch in ((0, 0), (31, SCRATCH), (32, SCRATCH - 1),
                                          (32, 0), (31, SCRATCH - 1)))
        cases.append((CANDIDATE, 32, SCRATCH, 0, KNOWN))
        self.check_cases(cases)


if __name__ == "__main__":
    unittest.main()
