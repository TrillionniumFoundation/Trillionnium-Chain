"""Source-paired HIA row validation followed by original strict tuple order."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_header import original_dependency
from hia.tests.test_state_import_header_admission import oracle_defs
from hia.tests.test_state_import_namespace import PREFIXES
from hia.tests.test_state_import_row import digest_of, expected as row_status

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/export_order_step.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_state_import_order_step_reference.rs"
WORK = 1248
LIMIT = 1 << 20


def frame(now, old=(b"", b""), seal=None):
    parts = (*now, *old)
    return b"".join(parts) + struct.pack("<IIIII", *(len(p) for p in parts)) + (
        digest_of(now) if seal is None else seal)


def original(rows):
    artifact = original_dependency()
    sha = hashlib.sha256(artifact.read_bytes()).digest()
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-order-step-") as tmp:
        src, bin = Path(tmp) / "oracle.rs", Path(tmp) / "oracle"
        src.write_bytes(oracle_defs(ORIGINAL.read_bytes()) + ADAPTER.read_bytes())
        rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
        build = subprocess.run([rustc, "--edition=2024", "-O", "--extern", "sha2=" + str(artifact),
                                "-L", "dependency=" + str(artifact.parent), str(src), "-o", str(bin)],
                               capture_output=True, timeout=60)
        if build.returncode:
            raise ValueError(build.stderr.decode())
        done = subprocess.run([str(bin)], input=b"".join(struct.pack("<I", len(r)) + r for r in rows),
                              check=True, capture_output=True, timeout=30)
    if (len(done.stdout) != len(rows) or done.stderr
            or hashlib.sha256(artifact.read_bytes()).digest() != sha):
        raise ValueError("incomplete or changed original order-step differential")
    return done.stdout


def corpus():
    rows = [((b"n", b"k", b""), (b"", b""), None), ((b"n", b"", b""), (b"", b""), None)]
    # Exhaust ordered prefixes, namespace/key priority, equal and high-bit bytes.
    tokens = (b"n", b"n\0", b"n\0\0", b"na", b"n\xff", b"z", b"\x7f", b"\x80", b"\xff")
    for a in tokens:
        for b in tokens:
            rows.extend([((a, b"zz", b"v"), (b, b"aa"), None),
                         ((b"m", a, b""), (b"m", b), None)])
    for p in PREFIXES:
        rows.extend([((p,b"k",b""), (b"\xff",b"k"), None),  # forbidden before reverse order
                     ((p,b"k",b""), (b"\xff",b"k"), bytes(32)),  # bad digest first
                     ((p,b"",b""), (b"\xff",b"k"), None)])  # invalid length first
    rows.extend([((b"n",b"k",b"new"), (b"n",b"k"), None),
                 ((b"n",b"k",b"new"), (b"n",b"k"), bytes(32)),
                 ((b"a",b"x",b"v"), (b"z",b"k"), bytes(32)),
                 ((b"\0" * 128, b"q" * 65536,b""), (b"\0" * 128,b"q" * 65535), None),
                 ((b"\0" * 128, b"q" * 65535,b""), (b"\0" * 128,b"q" * 65536), None),
                 ((b"\0" * 128, b"q" * 65536,b""), (b"\0" * 128,b"q" * 65536), None)])
    rng = random.Random(0x4D3133_53544550)
    for _ in range(96):
        a, b, c, d = (rng.randbytes(rng.randrange(1, 25)) for _ in range(4))
        rows.append(((a,b,rng.randbytes(16)),(c,d),None))
        rows.append(((a,b,rng.randbytes(16)),(a,d),None))
    giant = (b"n", b"k", b"v" * (LIMIT - 52 - 1 - 1 - 1 - 1))
    rows.append((giant, (b"m", b"k"), None))
    return rows


def model(now, old, seal):
    status = row_status(now, digest_of(now) if seal is None else seal)
    return status if status else 109 if old[0] and now[:2] <= old else 0


class StateImportOrderStep(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend)
            cls.addClassCleanup(module.close)
            cls.modules[backend] = module

    def test_original_row_error_precedence_and_order(self):
        rows = corpus()
        wire = [frame(*r) for r in rows]
        values = original(wire)
        self.assertEqual(values, bytes(model(*r) for r in rows))
        self.assertEqual(set(values), {0, 101, 104, 109})
        self.assertEqual(max(map(len, wire)), LIMIT)
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for start in range(0, len(wire), 32):
                    batch = [[r, b"\x96" * 7, b"\x6d" * (WORK + 7)] for r in wire[start:start + 32]]
                    for i, got in enumerate(module.call_many([("f0", a) for a in batch], timeout=45)):
                        self.assertEqual(got.require_returned().value, values[start + i], start + i)
                        self.assertEqual(got.arguments[:2], batch[i][:2])
                        self.assertEqual(got.arguments[2][-7:], b"\x6d" * 7)

    def test_malformed_prior_and_extent_do_not_publish(self):
        valid = frame((b"n", b"k", b""), (b"m", b"k"))
        cases = [(b"", 100, 0), (valid[:-1], 100, WORK), (valid + b"\0", 100, WORK),
                 (frame((b"n", b"k", b""), (b"", b"k")), 100, WORK),
                 (frame((b"n", b"k", b""), (b"n", b"")), 100, WORK),
                 (frame((b"n", b"k", b""), (b"n" * 129, b"k")), 100, WORK),
                 (valid, 102, WORK - 1),
                 (frame((b"", b"k", b""), (b"m", b"k")), 101, 0)]
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                args = [[r, b"native-is-read-only", b"\x6d" * w] for r, _, w in cases]
                for i, got in enumerate(module.call_many([("f0", a) for a in args])):
                    self.assertEqual((got.require_returned().value, got.arguments), (cases[i][1], args[i]))
