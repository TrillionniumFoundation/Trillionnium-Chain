"""Actual unchanged Rust merkle_root_v0 vs two native HIA backends."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_header import original_defs, original_dependency

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs"
SOURCE = ROOT / "hia/src/state_import/export_merkle_root.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_merkle_reference.rs"
FIXED_WORK = 1336
ABI_LIMIT = 1 << 20
MAX_LEAVES = (ABI_LIMIT - FIXED_WORK) // 32


def source_bytes(raw):
    [merkle] = re.findall(
        rb"(?ms)^#\[must_use\]\npub fn merkle_root_v0\(digests: &\[Digest32V0\]\) -> Digest32V0 \{\n.*?^}\n", raw)
    return b"use sha2::{Digest, Sha256};\n" + original_defs(raw) + merkle


def original_roots(rows):
    artifact = original_dependency()
    identity = hashlib.sha256(artifact.read_bytes()).digest()
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-merkle-reference-") as tmp:
        source, exe = Path(tmp) / "original.rs", Path(tmp) / "original"
        source.write_bytes(source_bytes(ORIGINAL.read_bytes()) + ADAPTER.read_bytes())
        rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
        build = subprocess.run([rustc, "--edition=2024", "-O", "--extern", "sha2=" + str(artifact),
                                "-L", "dependency=" + str(artifact.parent), str(source), "-o", str(exe)],
                               capture_output=True, timeout=60)
        if build.returncode:
            raise ValueError(build.stderr.decode())
        raw = b"".join(struct.pack("<I", len(inp) // 32) + inp for inp in rows)
        finished = subprocess.run([str(exe)], input=raw, check=True, capture_output=True, timeout=30)
    if (finished.stderr or len(finished.stdout) != 32 * len(rows)
            or hashlib.sha256(artifact.read_bytes()).digest() != identity):
        raise ValueError("incomplete or changed original Merkle observation")
    return [finished.stdout[i:i + 32] for i in range(0, len(finished.stdout), 32)]


def bound_hash(domain, *fields):
    return hashlib.sha256(b"".join(struct.pack(">Q", len(p)) + p for p in (domain, *fields))).digest()


def independent(raw):
    if not raw:
        return bound_hash(b"trnm.migration.empty-root.v0")
    level = [raw[i:i + 32] for i in range(0, len(raw), 32)]
    while len(level) > 1:
        level = [bound_hash(b"trnm.migration.merkle-node.v0", level[i], level[min(i + 1, len(level) - 1)])
                 for i in range(0, len(level), 2)]
    return level[0]


def fixtures():
    rng = random.Random(0x4D3133_4D45524B)
    primary = tuple(bytes([n]) * 32 for n in (0x11, 0x22, 0x33, 0x44, 0xff))
    seq = [b"", bytes(32), *primary, b"".join(primary[:3]), b"".join(primary[:3] + primary[2:3]),
           b"".join(primary[2::-1]), b"".join(primary), b"".join(primary[:-1])]
    seq.extend(rng.randbytes(n * 32) for n in range(2, 80))
    seq.extend(rng.randbytes(n * 32) for n in (127, 128, 129, 255, 256, 257, 1023, 1024, 1025, MAX_LEAVES))
    return seq


class StateImportOriginalMerkle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend)
            cls.addClassCleanup(module.close)
            cls.modules[backend] = module

    def test_actual_original_odd_carry_order_and_maximum_stock_scratch(self):
        rows = fixtures()
        expected = original_roots(rows)
        self.assertEqual(expected, [independent(row) for row in rows])
        self.assertEqual(expected[7], expected[8])  # the original odd leaf repeats at its layer
        self.assertNotEqual(expected[7], expected[9])  # order changes the root
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for i in (0, 1, 7):
                    raw = rows[i]
                    minimal = [raw, bytes(32), bytes(FIXED_WORK + len(raw))]
                    got = module.call("f0", minimal).require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (0, [raw, expected[i]]))
                for start in range(0, len(rows), 16):
                    batch = rows[start:start + 16]
                    args = [[r, b"\xa5" * 37, b"\x6d" * min(ABI_LIMIT, FIXED_WORK + len(r) + 8)] for r in batch]
                    for i, got in enumerate(module.call_many([("f0", row) for row in args], timeout=45), start):
                        self.assertEqual(got.require_returned().value, 0, i)
                        self.assertEqual(got.arguments[:2], [rows[i], expected[i] + b"\xa5" * 5])
                        self.assertEqual(got.arguments[2][FIXED_WORK + len(rows[i]):],
                                         b"\x6d" * min(8, ABI_LIMIT - (FIXED_WORK + len(rows[i]))))

    def test_extent_and_capacity_refuse_without_publish(self):
        cases = [(b"\0" * n, 0, 0, 100) for n in (1, 31, 33, 63, 65)]
        cases.extend([(b"", 31, FIXED_WORK, 102), (b"", 32, FIXED_WORK - 1, 102),
                      (bytes(96), 32, FIXED_WORK + 95, 102),
                      (bytes((MAX_LEAVES + 1) * 32), 32, ABI_LIMIT, 102)])
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                spans = [[raw, b"\xa5" * n, b"\x6d" * w] for raw, n, w, _ in cases]
                for i, got in enumerate(module.call_many([("f0", a) for a in spans])):
                    self.assertEqual((got.require_returned().value, got.arguments), (cases[i][3], spans[i]))
