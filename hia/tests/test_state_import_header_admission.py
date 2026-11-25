"""Original pre-finality check of verify_export_v0 against real native code."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import re
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_header import contract_hash, original_dependency
from hia.tests.test_state_import_merkle import source_bytes
from hia.tests.test_state_import_row import select_original

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/export_header_admission.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_state_import_header_admission_reference.rs"
WORK = 1529
MAX_ROWS = 100_000_000


def oracle_defs(raw):
    # Combine the original row types and methods with the exact original
    # Merkle helper, verifier API and verify_export_v0. The sentinel never
    # permits entry into the original post-finality loop.
    merkle = source_bytes(raw)
    merkle = merkle[merkle.index(b"#[must_use]\npub fn merkle_root_v0"):]
    pieces = [select_original(raw), merkle]
    for grammar in (
        rb"(?m)^pub const MAX_EXPORT_ROWS_V0: u64 = [^;\n]+;\n",
        rb"(?ms)^pub trait SourceFinalityVerifierV0 \{\n.*?^}\n",
        rb"(?ms)^pub struct VerifiedExportV0 \{\n.*?^}\n",
        rb"(?ms)^pub enum MigrationHostErrorV0<AdapterError> \{\n.*?^}\n",
        rb"(?ms)^pub fn verify_export_v0<V>\(\n.*?^}\n",
    ):
        [piece] = re.findall(grammar, raw)
        pieces.append(piece)
    return b"\n".join(pieces)


def original_rows(rows):
    artifact = original_dependency()
    binding = hashlib.sha256(artifact.read_bytes()).digest()
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-header-admission-") as tmp:
        source, exe = Path(tmp) / "oracle.rs", Path(tmp) / "oracle"
        source.write_bytes(oracle_defs(ORIGINAL.read_bytes()) + ADAPTER.read_bytes())
        rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
        build = subprocess.run([rustc, "--edition=2024", "-O", "--extern", "sha2=" + str(artifact),
                                "-L", "dependency=" + str(artifact.parent), str(source), "-o", str(exe)],
                               capture_output=True, timeout=60)
        if build.returncode:
            raise ValueError(build.stderr.decode())
        done = subprocess.run([str(exe)], input=b"".join(r for r, _ in rows),
                              check=True, capture_output=True, timeout=20)
    if (done.stderr or len(done.stdout) != 2 * len(rows)
            or hashlib.sha256(artifact.read_bytes()).digest() != binding):
        raise ValueError("incomplete original pre-finality check")
    return list(zip(done.stdout[::2], done.stdout[1::2]))


def patch(data, position, part):
    return data[:position] + part + data[position + len(part):]


def u64(value):
    return value.to_bytes(8, "big")


def sealed(prefix, actual):
    return prefix + contract_hash(prefix) + u64(actual)


def fixtures():
    base = bytes(range(208))
    prefix = patch(base, 168, u64(1))
    valid = sealed(prefix, 1)
    rows = [(valid, 0), (sealed(patch(prefix, 168, u64(0)), 0), 107),
            (sealed(prefix, 0), 107), (sealed(prefix, 2), 107)]
    rows += [(sealed(patch(prefix, i, bytes(32)), 1), 107) for i in (0, 32, 72, 104, 136, 176)]
    rows.append((sealed(patch(prefix, 64, bytes(8)), 1), 107))
    rows.append((patch(valid, 208, bytes(32)), 107))
    for i in range(240):
        rows.append((patch(valid, i, bytes([valid[i] ^ 0x80])), 107))
    for count in (2, 7, 256, 1024):
        rows.append((sealed(patch(prefix, 168, u64(count)), count), 0))
    for count in (MAX_ROWS, MAX_ROWS + 1, 2**64 - 1):
        rows.append((sealed(patch(prefix, 168, u64(count)), 1), 107))
    rng = random.Random(0x4D3133_484144)
    for i in range(64):
        frame_prefix = patch(rng.randbytes(208), 168, u64((i % 13) + 1))
        rows.append((sealed(frame_prefix, (i % 13) + 1), 0))
    return rows


class StateImportHeaderAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend)
            cls.addClassCleanup(module.close)
            cls.modules[backend] = module

    def test_original_callback_reachability_without_authorization(self):
        rows = fixtures()
        observed = original_rows(rows)
        self.assertEqual(observed, [(status, 1 if status == 0 else 0) for _, status in rows])
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for i in range(0, len(rows), 64):
                    batch = rows[i:i + 64]
                    args = [[r, b"\xaa" * 7, b"\xcc" * (WORK + 7)] for r, _ in batch]
                    for j, result in enumerate(module.call_many([("f0", a) for a in args])):
                        self.assertEqual(result.require_returned().value, observed[i + j][0])
                        self.assertEqual(result.arguments[:2], args[j][:2])
                        self.assertEqual(result.arguments[2][-7:], b"\xcc" * 7)
                        if observed[i + j][0] == 0:
                            self.assertEqual(result.arguments[2][1168:1200], batch[j][0][208:240])

    def test_stock_transport_and_full_declared_count_boundary(self):
        valid = fixtures()[0][0]
        prefix = valid[:208]
        cases = [(valid[:-1], 100, 0), (valid + b"\0", 100, 0), (valid, 102, WORK - 1),
                 (patch(valid, 208, bytes(32)), 107, 0),
                 (sealed(patch(prefix, 168, u64(MAX_ROWS)), MAX_ROWS), 0, WORK),
                 (sealed(patch(prefix, 168, u64(MAX_ROWS + 1)), MAX_ROWS + 1), 107, WORK),
                 (sealed(patch(prefix, 168, u64(2**64 - 1)), 2**64 - 1), 107, WORK)]
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for raw, status, work in cases:
                    args = [raw, b"\xaa" * 7, b"\xcc" * work]
                    got = module.call("f0", args).require_returned()
                    self.assertEqual(got.value, status)
                    self.assertEqual(got.arguments[:2], args[:2])
                    if status != 0:
                        self.assertEqual(got.arguments[2], args[2])
