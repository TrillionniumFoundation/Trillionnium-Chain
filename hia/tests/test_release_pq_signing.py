"""Exact V1 signing transcript and V0-bridge signature locator, not authorization."""
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
from hia.tests.test_release_exact_source import ADAPTER as SHA_ADAPTER, ROOT

DIR = ROOT / "hia/src/release_bundle"
RELEASE = ROOT / "trillionnium/crates/trnm-release-bundle/src/pq_release.rs"
FRAME = ROOT / "trillionnium/crates/trnm-protocol/src/pq_frame.rs"
ADAPTER = Path(__file__).with_name("rust_release_pq_signing_reference.rs")
MESSAGE_DOMAIN = b"TRNM/Release/PQ/ML-DSA-65/v1\0"
SET_DOMAIN = b"TRNM/Release/PQ/SignatureSet/v1\0"
ROW, WORK, SIGNATURE = 4130, 1240, 3309
ZERO = bytes(32)


def payload(role=1, network=b"\x19" * 32, values=(1, 256, 65537),
            checkpoint=bytes(range(32)), previous=None, content=b"\x81" * 32, rollback=0):
    return (bytes([role]) + network + struct.pack("<QQQ", *values) + checkpoint
            + bytes([previous is not None]) + (previous if previous is not None else ZERO)
            + content + bytes([rollback]))


def message(data):
    integers = struct.pack(">QQQ", *struct.unpack_from("<QQQ", data, 33))
    return MESSAGE_DOMAIN + data[:33] + integers + data[57:]


def pack_signatures(sigs, *, pad=0):
    return struct.pack("<H", len(sigs)) + b"".join(
        key + struct.pack("<H", len(sig)) + sig.ljust(4096, bytes([pad])) for key, sig in sigs
    )


def locator(sigs):
    # The stable Rust roster order is independent of signature bytes.
    return hashlib.sha256(SET_DOMAIN + b"".join(k + s for k, s in sorted(sigs, key=lambda row: row[0]))).digest()


def fixtures(index, size=SIGNATURE):
    return bytes((index + i * 73 + i // 17) & 255 for i in range(size))


def original(cases):
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    source = RELEASE.read_bytes()
    patterns = [
        (source, rb"(?m)^pub const (?:RELEASE_PQ_PROFILE_V1|MAX_RELEASE_KEYS_V1):[^\n]+;\n", 2),
        (source, rb"(?m)^pub type (?:ReleaseDigestV1|ReleaseKeyIdV1) = \[u8; 32\];\n", 2),
        (source, rb"(?ms)^#\[derive[^\n]+\n#\[repr\(u8\)\]\npub enum PqReleaseRoleV1 \{.*?^\}\n", 1),
        (source, rb"(?ms)^#\[derive[^\n]+\npub struct PqReleaseMetadataV1 \{.*?^\}\n", 1),
        (source, rb"(?ms)^impl PqReleaseMetadataV1 \{.*?^\}\n", 1),
        (source, rb"(?ms)^#\[derive[^\n]+\npub struct PqReleaseSignatureV1 \{.*?^\}\n", 1),
        (source, rb"(?ms)^pub fn pq_release_signature_digest_v1\(.*?^\}\n", 1),
        (source, rb"(?ms)^#\[derive[^\n]+\npub enum PqReleaseErrorV1 \{.*?^\}\n", 1),
        (FRAME.read_bytes(), rb"(?m)^pub const ML_DSA_65_SIGNATURE_BYTES: usize = [\d_]+;\n", 1),
        (SHA_ADAPTER.read_bytes(), rb"(?ms)^use std::io::\{self, Read, Write\};\n.*?(?=^fn main\()", 1),
    ]
    rust = []
    for data, pattern, expected in patterns:
        found = re.findall(pattern, data)
        if len(found) != expected:
            raise ValueError(f"Original method/constant ownership changed: {pattern!r}")
        rust.extend(found)
    rust[-1] = rust[-1].replace(b"{self, Read, Write}", b"{self, Write}")
    with tempfile.TemporaryDirectory(prefix="trnm-pq-release-message-set-") as tmp:
        source_path = Path(tmp) / "original.rs"
        program = source_path.with_suffix("")
        source_path.write_bytes(b"\n".join([*rust, ADAPTER.read_bytes()]))
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source_path), "-o",
                        str(program)], check=True, capture_output=True, timeout=30)
        encoded = b"".join(struct.pack("<BI", op, len(frame)) + frame for op, frame in cases)
        report = subprocess.run([str(program)], check=True, input=encoded, capture_output=True,
                                timeout=50)
    raw, values = report.stdout, []
    for op, _ in cases:
        status = raw[0]
        size = (184, 32)[op] if status == 0 else 0
        if len(raw) < size + 1:
            raise ValueError("Original differential output was truncated")
        values.append((status, raw[1:size + 1]))
        raw = raw[size + 1:]
    if raw or report.stderr:
        raise ValueError("Unexpected original result tail")
    return values


class NativePqReleaseSigning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = {
            stem: {
                backend: cls.enterClassContext(NativeModule(DIR / f"{stem}.hepta",
                                                            backend=backend,
                                                            byte_exports=("f0",)))
                for backend in ("direct", "selfhost")
            }
            for stem in ("pq_signing_message", "pq_signature_set")
        }
        for pair in cls.native.values():
            if pair["direct"].artifact_sha256 == pair["selfhost"].artifact_sha256:
                raise ValueError("Expected independent native emitters")

    def check(self, stem, cases):
        for backend, module in self.native[stem].items():
            for start in range(0, len(cases), 4):
                batch = cases[start:start + 4]
                requests = [("f0", [raw, b"\xcc" * out, b"\xd2" * work])
                            for raw, out, work, _, _ in batch]
                answers = module.call_many(requests, timeout=45)
                self.assertEqual(len(answers), len(batch))
                for i, (ask, answer, case) in enumerate(zip(requests, answers, batch)):
                    raw, _, _, status, result = case
                    with self.subTest(module=stem, backend=backend, case=start + i):
                        answer.require_returned()
                        self.assertEqual(answer.value, status)
                        self.assertEqual(answer.arguments[0], raw)
                        self.assertEqual(answer.arguments[1], result + ask[1][1][len(result):])
                        scratch = answer.arguments[2]
                        if status or stem == "pq_signing_message":
                            self.assertEqual(scratch, ask[1][2])
                        else:
                            self.assertEqual(scratch[1208:1240], SET_DOMAIN)
                            self.assertEqual(scratch[1240:], ask[1][2][1240:])

    def test_exact_v1_transcript_no_context_no_policy_and_u64_byte_order(self):
        data = [payload(role=r, previous=prev, rollback=rollback,
                        values=(0x0123456789abcdef, 0x8000000000000000, 2**64 - 1))
                for r, prev, rollback in itertools.product(
                    range(1, 5), (None, ZERO, bytes(reversed(range(32)))), (0, 1))]
        data += [payload(role=4, network=ZERO, values=(0, 0, 0), checkpoint=ZERO,
                         content=ZERO, rollback=1)]
        for pos in (1, 32, 57, 88, 122, 153):
            row = bytearray(payload())
            row[pos] ^= 0x80
            data.append(bytes(row))
        self.assertNotEqual(message(data[0]), message(data[2]))
        expected = original([(0, row) for row in data])
        self.assertEqual(expected, [(0, message(row)) for row in data])
        self.check("pq_signing_message", [(row, 191, i % 3, status, value)
                                          for i, (row, (status, value)) in
                                          enumerate(zip(data, expected))])

    def test_sorted_signature_locator_stable_tie_and_actual_width(self):
        three = [(bytes(31) + bytes([b]), fixtures(b)) for b in (1, 0x80, 0xff)]
        a, b, c = three
        invalid_a = (a[0], fixtures(5, SIGNATURE - 1))
        invalid_later = (c[0], fixtures(6, SIGNATURE + 1))
        randomizer = random.Random(33)
        maximum = [(i.to_bytes(32, "big"), fixtures(i)) for i in range(16)]
        randomizer.shuffle(maximum)
        rows = [(list(r), 0) for r in itertools.permutations(three)]
        rows += [([(ZERO, bytes(SIGNATURE))], 0), (maximum, 0), (maximum[::-1], 0),
                 ([], 105), (maximum + [invalid_a], 105), (maximum + maximum, 105),
                 ([a, a], 107), ([a, invalid_a], 107), ([invalid_a, a], 106),
                 ([invalid_later, a, a], 107), ([invalid_a, c, c], 106),
                 ([b, invalid_later], 106)]
        rows.extend([([(a[0], fixtures(9, n))], 106) for n in (0, 1, 3308, 3310, 4096)])
        originals = original([(1, pack_signatures(r)) for r, _ in rows])
        expected = [(code, locator(r) if code == 0 else b"") for r, code in rows]
        self.assertEqual(originals, expected)
        self.check("pq_signature_set", [(pack_signatures(r, pad=0xff if i % 2 else 0),
                                         41, WORK + 17, status, value)
                                        for i, ((r, _), (status, value)) in
                                        enumerate(zip(rows, originals))])

    def test_no_partial_outputs_when_framing_or_capacity_refuses(self):
        good = payload()
        bad = [good[:i] for i in (0, 1, 154)] + [good + bytes(1)]
        bad += [bytes([role]) + good[1:] for role in (0, 5, 255)]
        bad += [good[:89] + b"\x02" + good[90:], good[:-1] + b"\x02",
                good[:90] + b"\x80" + good[91:]]
        self.check("pq_signing_message", [(x, extent, 6, 100, b"") for x in bad
                                          for extent in (0, 184)] +
                   [(good, 183, 0, 102, b""), (good, 184, 0, 0, message(good))])

        valid = [(bytes(31) + b"\x80", fixtures(77))]
        raw = pack_signatures(valid)
        malformed = [b"", b"\x01", raw[:-1], raw + b"\x00",
                     raw[:34] + struct.pack("<H", 4097) + raw[36:],
                     pack_signatures(valid * 33)]
        checks = [(frame, out, scratch, 100, b"") for frame in malformed
                  for out, scratch in ((0, 0), (32, WORK))]
        checks += [
            (pack_signatures([]), 0, 0, 105, b""),
            (pack_signatures(valid + valid), 0, 0, 107, b""),
            (pack_signatures([(valid[0][0], b"short")]), 0, 0, 106, b""),
            (raw, 31, WORK, 102, b""), (raw, 32, WORK - 1, 102, b""),
            (raw, 32, WORK, 0, locator(valid)),
        ]
        self.check("pq_signature_set", checks)


if __name__ == "__main__":
    unittest.main()
