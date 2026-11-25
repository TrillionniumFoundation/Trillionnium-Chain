"""Finite post-finality batch fold versus exact original verify_export_v0."""
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
from hia.tests.test_state_import_merkle import independent
from hia.tests.test_state_import_namespace import PREFIXES
from hia.tests.test_state_import_order_step import model
from hia.tests.test_state_import_row import digest_of

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/export_post_finality_fold.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_state_import_post_finality_fold_reference.rs"
WORK = 1400
LIMIT = 1 << 20
DOMAIN = b"trnm.migration.ordered-rows.v0"


def frame(rows, corrupt_root=False):
    leaves = b"".join(digest_of(row) if saved is None else saved for row, saved in rows)
    root = independent(leaves)
    if corrupt_root:
        root = bytes((root[0] ^ 128,)) + root[1:]
    payload = [root, struct.pack("<I", len(rows))]
    for row, saved in rows:
        payload += [struct.pack("<III", *(len(x) for x in row)),
                    digest_of(row) if saved is None else saved, *row]
    return b"".join(payload), leaves


def original(wire):
    artifact = original_dependency()
    sha = hashlib.sha256(artifact.read_bytes()).digest()
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-batch-fold-") as tmp:
        src, exe = Path(tmp) / "oracle.rs", Path(tmp) / "oracle"
        src.write_bytes(oracle_defs(ORIGINAL.read_bytes()) + ADAPTER.read_bytes())
        rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
        build = subprocess.run([rustc, "--edition=2024", "-O", "--extern", "sha2=" + str(artifact),
                                "-L", "dependency=" + str(artifact.parent), str(src), "-o", str(exe)],
                               capture_output=True, timeout=60)
        if build.returncode:
            raise ValueError(build.stderr.decode())
        done = subprocess.run([str(exe)], input=b"".join(struct.pack("<I", len(r)) + r for r in wire),
                              check=True, capture_output=True, timeout=35)
    if (len(done.stdout) != 33 * len(wire) or done.stderr
            or hashlib.sha256(artifact.read_bytes()).digest() != sha):
        raise ValueError("incomplete or changed original post-finality batch readback")
    return [(done.stdout[i], done.stdout[i+1:i+33]) for i in range(0, len(done.stdout), 33)]


def row(i, value=b"v", namespace=b"valid", *, seal=None):
    return ((namespace, i.to_bytes(2, "big"), value), seal)


def corpus():
    cases = [([row(i) for i in range(n)], n % 2 == 0) for n in range(1, 32)]
    cases += [([row(i) for i in range(n)], False) for n in (64, 127, 128, 129, 255, 256, 1024, 16384)]
    # Mixed failures in either order, independently crossed with wrong roots.
    bad = row(0, seal=bytes(32))
    unsorted = [row(3), row(2)]
    for p in PREFIXES:
        forbidden = row(0, namespace=p)
        cases += [(x, wrong) for wrong in (False, True) for x in (
            [bad, forbidden, *unsorted], [forbidden, bad, *unsorted],
            [*unsorted, bad, forbidden], [row(1), row(2), bad, forbidden],
            [row(1), row(2), forbidden, bad], [row(1), row(1), forbidden, bad],
            [row(1), row(1, seal=bytes(32)), forbidden],
            [row(4), row(1, namespace=p, seal=bytes(32)), row(5)],
        )]
    rng = random.Random(0x4D31334241544348)
    for n in range(1, 17):
        pairs = sorted({(rng.randbytes(rng.randrange(1, 19)), rng.randbytes(6)) for _ in range(n + 1)})
        made = [((ns, key, rng.randbytes(n * 6)), None) for ns, key in pairs]
        cases.append((made, False))
        shuffled = made[:]
        shuffled[0], shuffled[-1] = shuffled[-1], shuffled[0]
        cases.append((shuffled, n % 2 == 0))
    fixed = [row(1, b"", b"n"), row(2, b"", b"n"), row(3, b"", b"n")]
    extra = LIMIT - len(frame(fixed)[0])
    fixed[1] = row(2, b"x" * extra, b"n")
    cases += [(fixed, False)]
    return cases


def expected(case, leaves):
    rows, wrong_root = case
    held = (b"", b"")
    for value, seal in rows:
        status = model(value, held, seal)
        if status:
            return status, bytes(32)
        held = value[:2]
    return (108, bytes(32)) if wrong_root else (0, hashlib.sha256(DOMAIN + leaves).digest())


class StateImportPostFinalityFold(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend)
            cls.addClassCleanup(module.close)
            cls.modules[backend] = module

    def test_native_multi_row_first_error_and_atomic_root_join(self):
        cases = corpus()
        decoded = [frame(rows, wrong) for rows, wrong in cases]
        wire = [raw for raw, _ in decoded]
        results = original(wire)
        self.assertEqual(results, [expected(case, leaves) for case, (_, leaves) in zip(cases, decoded)])
        self.assertEqual({code for code, _ in results}, {0, 101, 104, 108, 109})
        self.assertEqual(max(map(len, wire)), LIMIT)
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for start in range(0, len(wire), 12):
                    batch = [[r, b"\x96" * 37, b"\x6d" * (WORK + 32 * len(cases[i][0]) + 7)]
                             for i, r in enumerate(wire[start:start + 12], start)]
                    for i, got in enumerate(module.call_many([("f0", a) for a in batch], timeout=45), start):
                        code, digest = results[i]
                        self.assertEqual(got.require_returned().value, code, i)
                        sent = batch[i - start]
                        self.assertEqual(got.arguments[:2], [sent[0], digest + b"\x96" * 5 if code == 0 else sent[1]])
                        self.assertEqual(got.arguments[2][-7:], b"\x6d" * 7)

    def test_transport_and_capacity_failures_never_publish(self):
        valid, _ = frame([row(0), row(1), row(2)])
        trailing = valid + b"\x00"
        truncated = valid[:-1]
        huge_count = valid[:32] + b"\xff" * 4 + valid[36:]
        zero_count = valid[:32] + bytes(4) + valid[36:]
        malformed_later = bytearray(valid)
        offset = 36 + 44 + sum(len(v) for v in row(0)[0])
        malformed_later[offset:offset+4] = b"\xff" * 4
        cases = [(b"", 0, 0, 100), (valid[:79], 32, WORK + 96, 100),
                 (huge_count, 32, WORK + 96, 100), (zero_count, 32, WORK + 96, 100),
                 (truncated, 32, WORK + 96, 100), (bytes(malformed_later), 32, WORK + 96, 100),
                 (trailing, 32, WORK + 96, 100), (valid, 31, WORK + 96, 102),
                 (valid, 32, WORK + 95, 102), (valid, 32, WORK + 96, 0)]
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                args = [[r, b"\x96" * o, b"\x6d" * w] for r, o, w, _ in cases]
                for i, got in enumerate(module.call_many([("f0", a) for a in args])):
                    status = cases[i][3]
                    self.assertEqual(got.require_returned().value, status)
                    if status:
                        self.assertEqual(got.arguments[:2], args[i][:2])
                        if i in (0, 1, 2, 3, 7, 8):
                            self.assertEqual(got.arguments[2], args[i][2])
