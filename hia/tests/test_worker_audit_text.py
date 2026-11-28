"""Actual self-hosted Worker Agent audit-cell formatting and original parity."""
from __future__ import annotations

import hashlib
import itertools
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/worker_agent/audit_text.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-worker-agent/src/audit_render.rs"
ORIGINAL_SHA256 = "87a0dc64f1621c47d214e5efa122c408cb36f16025e2f8bd1a5142e9682f2253"
ADAPTER = ROOT / "hia/tests/rust_worker_audit_text_reference.rs"
INVALID = 0xFFFFFFFF
SHORT = 0xFFFFFFFE
SENTINEL = b"\xa5"
SCRATCH = b"\x13" * 29

FIXED = (
    (None, b"-"),
    ("", b""),
    ("-", b"-"),
    ("\r\n", b"  "),
    ("\\||", b"\\\\|\\|"),
    ("a\r|\nb", b"a \\| b"),
    ("é|链|😀\0\t", "é\\|链\\|😀\0\t".encode()),
    ("e\u0301 / \u2028\u2029\u0085", "e\u0301 / \u2028\u2029\u0085".encode()),
    ("|" * 32768, b"\\|" * 32768),
)


def request(value):
    return b"\0" if value is None else b"\1" + value.encode()


def payloads():
    values = [value for value, _ in FIXED]
    alphabet = "\r\n|\\A\0"
    values.extend("".join(word) for n in range(1, 4)
                  for word in itertools.product(alphabet, repeat=n))
    values.extend(chr(codepoint) for codepoint in range(256))
    rng = random.Random(0x57415544)
    unicode_alphabet = alphabet + "é\u0301链😀\u2028\u2029\u0085\ufeff\U0010ffff"
    values.extend("".join(rng.choices(unicode_alphabet, k=rng.randrange(65)))
                  for _ in range(384))
    return values


def golden(value):
    if value is None:
        return b"-"
    escapes = {"\r": b" ", "\n": b" ", "|": b"\\|"}
    return b"".join(escapes.get(character, character.encode()) for character in value)


def wire(value):
    return struct.pack("<I", len(value)) + value


class WorkerAuditText(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_native(self, cases):
        for offset in range(0, len(cases), 48):
            batch = cases[offset:offset + 48]
            results = self.native.call_many([
                ("f0", [raw, SENTINEL * capacity, SCRATCH])
                for raw, capacity, _, _ in batch
            ])
            for actual, (raw, capacity, status, output) in zip(results, batch, strict=True):
                actual.require_returned()
                self.assertEqual(actual.value, status, raw[:32].hex())
                self.assertEqual(actual.arguments,
                                 [raw, output + SENTINEL * (capacity - len(output)), SCRATCH])

    def test_fixed_and_generated_bytes(self):
        self.assertEqual(hashlib.sha256(ORIGINAL.read_bytes()).hexdigest(), ORIGINAL_SHA256)
        for value, expected in FIXED:
            self.assertEqual(golden(value), expected)
        outputs = [(request(value), golden(value)) for value in payloads()]
        self.check_native([(raw, len(out) + 7, len(out), out) for raw, out in outputs])

    def test_exact_fit_and_capacity_are_atomic(self):
        cases = []
        for raw, out in [(request(value), golden(value)) for value, _ in FIXED]:
            cases.append((raw, len(out), len(out), out))
            if out:
                cases.append((raw, len(out) - 1, SHORT, b""))
                cases.append((raw, 0, SHORT, b""))
        self.check_native(cases)

    def test_invalid_framing_leaves_entire_output_unchanged(self):
        invalid = [b"", b"\0extra", b"\0\0"] + [bytes([n]) for n in range(2, 256)]
        self.check_native([(raw, capacity, INVALID, b"")
                           for raw in invalid for capacity in (0, 11)])

    def test_exact_compiled_rust_original(self):
        original = ORIGINAL.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), ORIGINAL_SHA256)
        pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        rustc = os.environ.get("RUSTC", "rustc")
        version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                                 text=True, timeout=15).stdout.split()
        self.assertEqual(version[:2], ["rustc", pin])
        values = payloads()
        inputs = [request(value) for value in values]
        with tempfile.TemporaryDirectory(prefix="trnm-worker-audit-rust-") as temp:
            executable = Path(temp) / "original"
            subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(ADAPTER), "-o",
                            str(executable)], check=True, capture_output=True, timeout=30)
            observed = subprocess.run([str(executable)], input=b"".join(map(wire, inputs)),
                                      check=True, capture_output=True, timeout=30)
        self.assertEqual(observed.stderr, b"")
        self.assertEqual(ORIGINAL.read_bytes(), original)
        expected = [golden(value) for value in values]
        self.assertEqual(observed.stdout, b"".join(map(wire, expected)))
        self.check_native([(raw, len(out) + 1, len(out), out)
                           for raw, out in zip(inputs, expected, strict=True)])


if __name__ == "__main__":
    unittest.main()
