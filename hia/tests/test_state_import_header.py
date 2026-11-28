"""Exact unchanged original M13 header commitments against real HIA images."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import re
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule, unlinked_path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/finalized_export_header_digest.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_state_import_header_reference.rs"
DOMAIN = b"trnm.migration.finalized-export-header.v0"
WIDTHS = (32, 32, 8, 32, 32, 32, 8, 32)
SIZE = 240
WORK = 1529


def original_defs(raw):
    pieces = []
    for name in (b"Digest32V0", b"FinalizedExportHeaderV0"):
        [struct] = re.findall(rb"(?ms)^#\[derive\([^\n]+\)\]\npub struct " + name
                              + rb"(?:\([^\n]+\);\n| \{\n.*?^}\n)", raw)
        [impl] = re.findall(rb"(?ms)^impl " + name + rb" \{\n.*?^}\n", raw)
        pieces.extend((struct, impl))
    return b"".join(pieces)


def original_dependency():
    artifact = unlinked_path(os.environ["HIA_CONTROL_PLANE_SHA2"])
    match = re.fullmatch(r"libsha2-([a-f0-9]{16})\.rlib", artifact.name)
    if match is None or artifact.parent.name != "deps":
        raise ValueError("expected exact original locked SHA2 artifact address")
    fingerprint = artifact.parent.parent / ".fingerprint" / ("sha2-" + match[1]) / "lib-sha2.json"
    data = json.loads(unlinked_path(fingerprint).read_text())
    features = tuple(json.loads(data["features"]))
    if (features not in (("default", "std"), ("asm", "default", "sha2-asm", "std"))
            or data["rustflags"] != [] or data["compile_kind"] != 0):
        raise ValueError("unexpected original native SHA2 build profile")
    lock = tomllib.loads((ROOT / "trillionnium/Cargo.lock").read_text())["package"]
    [owner] = [row for row in lock if row["name"] == "trnm-state-import"]
    [dep] = [row for row in lock if row["name"] == "sha2" and row["version"] == "0.10.9"]
    if "sha2 0.10.9" not in owner["dependencies"] or not re.fullmatch(r"[a-f0-9]{64}", dep["checksum"]):
        raise ValueError("the original StateImport owner does not bind the expected locked SHA2")
    dep_info = unlinked_path(artifact.parent / ("sha2-" + match[1] + ".d")).read_text()
    if "/sha2-0.10.9/src/lib.rs" not in dep_info:
        raise ValueError("original SHA2 artifact source identity differs")
    return artifact


def original_digest_rows(rows):
    artifact = original_dependency()
    dependency_before = hashlib.sha256(artifact.read_bytes()).digest()
    defs = original_defs(ORIGINAL.read_bytes())
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-header-oracle-") as tmp:
        src, binary = Path(tmp) / "oracle.rs", Path(tmp) / "oracle"
        src.write_bytes(b"use sha2::{Digest, Sha256};\n" + defs + ADAPTER.read_bytes())
        rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
        build = subprocess.run([rustc, "--edition=2024", "-O", "--extern", "sha2=" + str(artifact),
                                "-L", "dependency=" + str(artifact.parent), str(src), "-o", str(binary)],
                               capture_output=True, timeout=60)
        if build.returncode:
            raise ValueError(build.stderr.decode())
        observed = subprocess.run([str(binary)], input=b"".join(rows), check=True,
                                  capture_output=True, timeout=20)
        if observed.stderr or len(observed.stdout) != 32 * len(rows):
            raise ValueError("incomplete original StateImport header output")
    if dependency_before != hashlib.sha256(artifact.read_bytes()).digest():
        raise ValueError("original locked SHA2 artifact changed during execution")
    return [observed.stdout[i:i + 32] for i in range(0, len(observed.stdout), 32)]


def contract_hash(row):
    transcript = bytearray(len(DOMAIN).to_bytes(8, "big") + DOMAIN)
    start = 0
    for width in WIDTHS:
        transcript.extend(width.to_bytes(8, "big"))
        transcript.extend(row[start:start + width])
        start += width
    return hashlib.sha256(transcript).digest()


def corpus():
    fixed = bytes(range(SIZE))
    rows = [fixed, bytes(SIZE), b"\xff" * SIZE]
    for pos in range(SIZE):
        rows.append(fixed[:pos] + bytes((fixed[pos] ^ 0x80,)) + fixed[pos + 1:])
    for pos in (64, 168):
        for n in (0, 1, 2**32 - 1, 2**32, 2**63, 2**64 - 1):
            rows.append(fixed[:pos] + n.to_bytes(8, "big") + fixed[pos + 8:])
    rng = random.Random(0x4D3133_464548)
    rows.extend(rng.randbytes(SIZE) for _ in range(96))
    return rows


class StateImportFinalizedExportHeader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend)
            cls.addClassCleanup(module.close)
            cls.modules[backend] = module

    def test_exact_original_digests_including_ignored_self_digest(self):
        rows = corpus()
        expected = original_digest_rows(rows)
        self.assertEqual(expected, [contract_hash(row) for row in rows])
        self.assertTrue(all(v != expected[0] for v in expected[3:3 + 208]))
        self.assertTrue(all(v == expected[0] for v in expected[3 + 208:3 + SIZE]))
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for start in range(0, len(rows), 64):
                    batch = rows[start:start + 64]
                    for i, (row, call) in enumerate(zip(batch, module.call_many([
                            ("f0", [row, b"\xaa" * 37, b"\xcc" * (WORK + 5)]) for row in batch
                    ])), start):
                        self.assertEqual(call.require_returned().value, 0)
                        self.assertEqual(call.arguments[:2], [row, expected[i] + b"\xaa" * 5])
                        self.assertEqual(call.arguments[2][-5:], b"\xcc" * 5)

    def test_bad_extent_and_capacity_do_not_write_or_publish(self):
        row = bytes(SIZE)
        cases = [(row[:n], 32, WORK, 100) for n in (0, 1, 207, 208, SIZE - 1)]
        cases.extend([(row + b"\0", 32, WORK, 100), (row, 31, WORK, 102),
                      (row, 32, WORK - 1, 102), (row, 0, 0, 102), (b"", 0, 0, 100)])
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for raw, out, work, status in cases:
                    spans = [raw, b"\xaa" * out, b"\xcc" * work]
                    got = module.call("f0", spans).require_returned()
                    self.assertEqual((got.value, got.arguments), (status, spans))
