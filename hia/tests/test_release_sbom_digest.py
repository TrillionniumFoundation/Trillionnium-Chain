"""Compare native SBOM members, sorting and final digest with original Rust V0."""
from __future__ import annotations

import hashlib
import itertools
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_bundle_binding import (
    ORIGINAL,
    ROOT,
    SHA_ADAPTER,
    original_rows as original_binding_rows,
)

SOURCE = ROOT / "hia/src/release_bundle/sbom_digest.hepta"
BINDING = SOURCE.with_name("bundle_binding.hepta")
ADAPTER = Path(__file__).with_name("rust_release_sbom_digest_reference.rs")
SET_DOMAIN = b"trnm.release.sbom.v0"
PACKAGE_DOMAIN = b"trnm.release.sbom-package.v0"
EMPTY_GOLDEN = bytes.fromhex("5095af4785cc3a8ba6bad65fff6fb0259f4480f8f9c0a49a554f89f4b00e187a")
ROW, SET_START, SCRATCH = 1351, 2800, 4868
FORMAT, SHORT = 100, 102


def byte_digest(value):
    return bytes([value]) * 32


BASE = (b"trnm-portable-node", b"0.1.0", byte_digest(10), byte_digest(11),
        b"Apache-2.0", True)


def replace(row, field, value):
    return row[:field] + (value,) + row[field + 1:]


def pack_row(row, pad):
    n, v, src, checksum, license_text, direct = row
    output = struct.pack("<HHHB", len(n), len(v), len(license_text), direct)
    output += src + checksum
    for text, width in zip((n, v, license_text), (512, 256, 512)):
        output += text.ljust(width, bytes([pad]))
    if len(output) != ROW:
        raise ValueError("Invalid fixture slot width")
    return output


def frame(rows, *, pad=0):
    return struct.pack("<H", len(rows)) + b"".join(pack_row(row, pad) for row in rows)


def payload(row):
    return b"".join(len(part).to_bytes(8, "big") + part
                    for part in (PACKAGE_DOMAIN, *row[:-1], bytes([row[-1]])))


def sorted_leaf_hashes(rows):
    return b"".join(hashlib.sha256(payload(row)).digest() for row in sorted(rows))


def exact_comparison_source():
    """Read unchanged original Rust implementation and fixture, plus the SHA seam."""
    original = ORIGINAL.read_bytes()
    specs = [
        (original, rb"(?ms)^use std::\{collections::BTreeSet, error::Error, fmt\};\n"
                   rb".*?(?=^#\[cfg\(test\)\]\nmod tests \{)"),
        (original, rb"(?ms)^    fn d\(byte: u8\) -> Digest32V0 \{.*?^    \}\n"),
        (original, rb"(?ms)^    fn bundle\(builder: u8, artifact_digest: u8\) -> ReleaseBundleV0 "
                   rb"\{.*?^    \}\n"),
        (SHA_ADAPTER.read_bytes(),
         rb"(?ms)^use std::io::\{self, Read, Write\};\n.*?(?=^fn main\()"),
    ]
    blocks = []
    for raw, pattern in specs:
        matches = re.findall(pattern, raw)
        if len(matches) != 1:
            raise ValueError(f"Original Rust ownership or SHA seam changed: {pattern!r}")
        blocks.append(matches[0])
    blocks[-1] = blocks[-1].replace(b"{self, Read, Write}", b"{self, Write}")
    return b"\n".join([*blocks, ADAPTER.read_bytes()])


def rust_observations(rosters):
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    with tempfile.TemporaryDirectory(prefix="trnm-release-sbom-oracle-") as work:
        path = Path(work) / "reference.rs"
        executable = path.with_suffix("")
        path.write_bytes(exact_comparison_source())
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(path), "-o", str(executable)],
                       check=True, capture_output=True, timeout=30)
        result = subprocess.run([str(executable)], input=b"".join(frame(r) for r in rosters),
                                check=True, capture_output=True, timeout=60)
    data, rows = result.stdout, []
    for roster in rosters:
        end = 32 * (1 + len(roster))
        if len(data) < end:
            raise ValueError("Truncated comparison output from Rust")
        rows.append((data[:32], data[32:end]))
        data = data[end:]
    if result.stderr or data:
        raise ValueError("Trailing comparison output from Rust")
    return rows


class NativeReleaseSbomDigest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {
            backend: cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.modules["direct"].artifact_sha256 == cls.modules["selfhost"].artifact_sha256:
            raise ValueError("Expected different machine artifacts")

    def check_cases(self, cases):
        for backend, module in self.modules.items():
            for start in range(0, len(cases), 8):
                group = cases[start:start + 8]
                requests = [("f0", [data, b"\xa1" * capacity, b"\xc6" * work])
                            for data, capacity, work, _, _, _ in group]
                observations = module.call_many(requests, timeout=45)
                self.assertEqual(len(observations), len(group))
                for i, (request, case, observed) in enumerate(zip(requests, group, observations)):
                    data, _, _, code, digest, leaves = case
                    with self.subTest(backend=backend, row=start + i, code=code):
                        observed.require_returned()
                        self.assertEqual(observed.value, code)
                        self.assertEqual(observed.arguments[0], data)
                        self.assertEqual(observed.arguments[1], digest + request[1][1][len(digest):])
                        if code == 0:
                            transcript = SET_DOMAIN + leaves
                            self.assertEqual(observed.arguments[2][SET_START:SET_START + len(transcript)],
                                             transcript)
                            self.assertEqual(observed.arguments[2][SCRATCH:], request[1][2][SCRATCH:])
                        else:
                            self.assertEqual(observed.arguments[2], request[1][2])

    def test_original_member_order_and_aggregate_parity(self):
        rosters = [[], [BASE], [BASE, BASE], [BASE, replace(BASE, 5, False), BASE]]
        for field in (0, 1, 4):
            strings = [b"", b"a", b"a\x00", b"a\x01", b"aa", b"b", b"\x80", b"\xff",
                       "é".encode(), "中".encode(), "😀".encode(), "😀é".encode(),
                       b"\x00x", "e\u0301".encode()]
            candidates = [replace(BASE, field, name) for name in strings]
            rosters += [candidates, candidates[::-1], candidates[7:] + candidates[:7]]
        late = [replace(BASE, 2, bytes(31) + bytes([n])) for n in (0, 1, 127, 128, 255)]
        late += [replace(BASE, 3, bytes(31) + bytes([n])) for n in (0, 1, 127, 128, 255)]
        late += [replace(BASE, 4, BASE[4] + b"!"), replace(BASE, 5, False), BASE]
        late += [replace(replace(BASE, 0, BASE[0] + b"\0"), 2, bytes(32))]
        rosters += [late, late[::-1]]
        tie_group = [replace(BASE, 5, False), BASE, replace(BASE, 4, BASE[4] + b".")]
        rosters += list(itertools.permutations(tie_group))
        extrema = replace(replace(replace(BASE, 0, b"x" * 512), 1, b"v" * 256), 4, b"Z" * 512)
        rosters += [[extrema], [extrema] * 64]
        seeded = random.Random(0x51b0)
        deep = [replace(extrema, 4, extrema[4][:-2] + i.to_bytes(2, "big"))
                for i in range(64)]
        seeded.shuffle(deep)
        rosters += [deep, deep[::-1]]
        expected = rust_observations(rosters)
        self.assertEqual(expected[0], (EMPTY_GOLDEN, b""))
        self.assertNotEqual(expected[1][0], expected[2][0])
        cases = []
        for i, (roster, (digest, leaves)) in enumerate(zip(rosters, expected)):
            self.assertEqual(leaves, sorted_leaf_hashes(roster))
            self.assertEqual(digest, hashlib.sha256(SET_DOMAIN + leaves).digest())
            cases.append((frame(roster, pad=0xfe if i % 2 else 0), 39, SCRATCH + 17, 0,
                          digest, leaves))
        self.check_cases(cases)

    def test_refusal_precedence_and_no_partial_publication(self):
        valid = frame([BASE])
        field_errors = [(0, 513), (2, 257), (4, 513)]
        malformed = [b"", b"\x01", valid[:-1], valid + bytes(1), frame([BASE] * 65),
                     frame([BASE])[:8] + b"\x02" + frame([BASE])[9:]]
        malformed.extend(valid[:2 + at] + struct.pack("<H", new) + valid[4 + at:]
                         for at, new in field_errors)
        late_bad = frame([BASE] * 2)
        malformed.append(late_bad[:2 + ROW + 6] + b"\xff" + late_bad[2 + ROW + 7:])
        cases = [(bad, out, work, FORMAT, b"", b"") for bad in malformed
                 for out, work in ((0, 0), (39, SCRATCH + 17))]
        cases += [(valid, capacity, work, SHORT, b"", b"")
                  for capacity, work in ((0, 0), (31, SCRATCH), (32, SCRATCH - 1))]
        leaves = sorted_leaf_hashes([BASE])
        cases.append((valid, 32, SCRATCH, 0, hashlib.sha256(SET_DOMAIN + leaves).digest(), leaves))
        self.check_cases(cases)

    def test_native_aggregate_supplies_published_bundle_binding(self):
        original_frame, status, stage, digest = original_binding_rows()[0]
        self.assertEqual((status, stage), (0, 0))
        for backend, sbom in self.modules.items():
            with self.subTest(backend=backend), NativeModule(BINDING, backend=backend,
                                                            byte_exports=("f0",)) as binding:
                for roster, expected in (([BASE], 0), ([BASE, BASE], 104)):
                    out = sbom.call("f0", [frame(roster), bytes(32), bytes(SCRATCH)]).require_returned()
                    self.assertEqual(out.value, 0)
                    native = out.arguments[1]
                    self.assertEqual(native == original_frame[257:289], expected == 0)
                    packet = original_frame[:257] + native + original_frame[289:]
                    marker = b"\xd3" * 39
                    observed = binding.call("f0", [packet, marker, bytes(2302)]).require_returned()
                    self.assertEqual(observed.value, expected)
                    self.assertEqual(observed.arguments[1], digest + marker[32:] if expected == 0 else marker)


if __name__ == "__main__":
    unittest.main()
