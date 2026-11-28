"""Source-paired real native ExportRowV0 validation, without import authority."""
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
from hia.tests.test_state_import_header import original_dependency, original_defs
from hia.tests.test_state_import_namespace import PREFIXES, original_function

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/export_row_validate.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_state_import_row_reference.rs"
WORK = 1248
ABI_LIMIT = 1 << 20
DOMAIN = b"trnm.migration.export-row.v0"
LIMITS = (128, 65536, 16777216)


def select_original(raw):
    pieces = [b"use sha2::{Digest, Sha256};\n", original_defs(raw), original_function(raw)]
    for name in (b"MAX_NAMESPACE_BYTES_V0", b"MAX_KEY_BYTES_V0", b"MAX_VALUE_BYTES_V0"):
        [constant] = re.findall(rb"(?m)^pub const " + name + rb": usize = [^;\n]+;\n", raw)
        pieces.append(constant)
    for grammar in (
        rb"(?ms)^#\[derive\([^\n]+\)\]\npub struct ExportRowV0 \{\n.*?^}\n",
        rb"(?ms)^impl ExportRowV0 \{\n.*?^}\n",
        rb"(?ms)^#\[derive\([^\n]+\)\]\npub enum MigrationErrorV0 \{\n.*?^}\n",
    ):
        [piece] = re.findall(grammar, raw)
        pieces.append(piece)
    return b"\n".join(pieces)


def digest_of(parts):
    return hashlib.sha256(b"".join(len(p).to_bytes(8, "big") + p for p in (DOMAIN, *parts))).digest()


def frame(parts, seal=None):
    return b"".join(parts) + struct.pack("<III", *(len(p) for p in parts)) + (
        digest_of(parts) if seal is None else seal)


def original_rows(rows):
    artifact = original_dependency()
    binding = hashlib.sha256(artifact.read_bytes()).digest()
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-row-oracle-") as tmp:
        src = Path(tmp) / "oracle.rs"
        binary = Path(tmp) / "oracle"
        src.write_bytes(select_original(ORIGINAL.read_bytes()) + ADAPTER.read_bytes())
        rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
        build = subprocess.run([rustc, "--edition=2024", "-O", "--extern", "sha2=" + str(artifact),
                                "-L", "dependency=" + str(artifact.parent), str(src), "-o", str(binary)],
                               capture_output=True, timeout=60)
        if build.returncode:
            raise ValueError(build.stderr.decode())
        finished = subprocess.run([str(binary)], input=b"".join(struct.pack("<I", len(r)) + r for r in rows),
                                  check=True, capture_output=True, timeout=40)
        if finished.stderr or len(finished.stdout) != 33 * len(rows):
            raise ValueError("incomplete actual ExportRowV0 differential output")
    if binding != hashlib.sha256(artifact.read_bytes()).digest():
        raise ValueError("original SHA2 library changed across row verification")
    return [(finished.stdout[i], finished.stdout[i + 1:i + 33]) for i in range(0, len(finished.stdout), 33)]


def structure(parts):
    namespace, key, value = parts
    return (0 < len(namespace) <= LIMITS[0] and 0 < len(key) <= LIMITS[1]
            and len(value) <= LIMITS[2])


def expected(parts, seal):
    if not structure(parts) or seal != digest_of(parts):
        return 101
    return 104 if any(parts[0].startswith(prefix) for prefix in PREFIXES) else 0


def corpus():
    rows = [(b"", b"k", b""), (b"ns", b"", b""), (b"", b"", b""),
            (b"\x00\xff", b"\x00", b"\x80"), (b"ns", b"k", b"")]
    rows += [(b"n" * n, b"k" * k, b"v") for n, k in ((127, 1), (128, 65536),
                                                       (129, 65536), (128, 65537), (1, 65535))]
    for prefix in PREFIXES:
        rows += [(prefix, b"k", b"v"), (prefix + b"\x00", b"k", b""),
                 (prefix[:-1], b"k", b""), (prefix.upper(), b"k", b""),
                 (prefix, b"", b"x"), (prefix[:1], prefix[1:], b"x"),
                 (prefix[:1], b"k", prefix[1:]), (prefix + b"\0" * 128, b"k", b"v")]
    width = (1, 2, 7, 8, 22, 23, 31, 32, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256)
    rows += [(b"row", b"key", b"v" * n) for n in width]
    rng = random.Random(0x4D3133_524F57)
    rows += [tuple(rng.randbytes(rng.randrange(n)) for n in (133, 87, 223)) for _ in range(64)]
    single = [(r, digest_of(r)) for r in rows]
    single += [(r, b"\xff" * 32) for r in rows[::2]]
    valid = (b"namespace", b"key", b"value")
    seal = digest_of(valid)
    single += [(valid, seal[:i] + bytes((seal[i] ^ 0x80,)) + seal[i + 1:]) for i in range(32)]
    near_max = (b"n" * 128, b"k" * 65536, b"v" * (ABI_LIMIT - 44 - 128 - 65536))
    single.append((near_max, digest_of(near_max)))
    return single


class StateImportExportRow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend)
            cls.addClassCleanup(module.close)
            cls.modules[backend] = module

    def test_native_admission_and_error_priority_match_actual_original(self):
        fixtures = corpus()
        wire = [frame(parts, seal) for parts, seal in fixtures]
        observed = original_rows(wire)
        self.assertEqual(max(map(len, wire)), ABI_LIMIT)
        self.assertEqual(observed, [(expected(p, d), digest_of(p)) for p, d in fixtures])
        self.assertEqual({status for status, _ in observed}, {0, 101, 104})
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for start in range(0, len(wire), 32):
                    spans = [[row, b"\xaa" * 7, b"\xcc" * (WORK + 7)] for row in wire[start:start + 32]]
                    calls = module.call_many([("f0", args) for args in spans], timeout=45)
                    for idx, (call, args) in enumerate(zip(calls, spans), start):
                        status, canonical = observed[idx]
                        self.assertEqual(call.require_returned().value, status, idx)
                        self.assertEqual(call.arguments[:2], args[:2])
                        self.assertEqual(call.arguments[2][-7:], b"\xcc" * 7)
                        if structure(fixtures[idx][0]):
                            self.assertEqual(call.arguments[2][1168:1200], canonical)
                        else:
                            self.assertEqual(call.arguments[2], args[2])

    def test_malformed_fixture_extent_and_short_scratch_do_not_write(self):
        valid = frame((b"n", b"k", b"v"))
        cases = [(b"", 100, 0), (valid[:43], 100, WORK),
                 (valid[:-1], 100, WORK), (valid + b"\0", 100, WORK),
                 (valid[:3] + struct.pack("<III", 2**32 - 1, 1, 1) + valid[-32:], 100, WORK),
                 (valid, 102, WORK - 1), (valid, 102, 0),
                 (frame((b"", b"k", b"v")), 101, 0)]
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                args = [[raw, b"\xaa" * 7, b"\xcc" * work] for raw, _, work in cases]
                for i, call in enumerate(module.call_many([("f0", row) for row in args])):
                    self.assertEqual((call.require_returned().value, call.arguments), (cases[i][1], args[i]))


    def test_selfhost_original_absolute_row_extent(self):
        namespace = b"n" * LIMITS[0]
        key = b"k" * LIMITS[1]
        # Non-periodic ends distinguish hashing the full value from a truncated
        # or repeated prefix without using a second implementation for admission.
        value = b"start" + bytes(range(256)) * ((LIMITS[2] - 9) // 256)
        value += b"\xa5" * (LIMITS[2] - len(value) - 4) + b"last"
        max_wire = sum(LIMITS) + 44
        with NativeModule(SOURCE, byte_exports=("f0",), backend="selfhost",
                          max_input_extent=max_wire + 1) as wide:
            for parts, known_status in (((namespace, key, value), 0),
                                        ((namespace, key, value + b"!"), 101)):
                with self.subTest(value_bytes=len(parts[2])):
                    row = frame(parts)
                    self.assertEqual(len(row), max_wire + (known_status != 0))
                    [(status, digest)] = original_rows([row])
                    self.assertEqual(status, known_status)
                    before = b"\xcc" * WORK
                    call = wide.call("f0", [row, b"keep", before], timeout=45).require_returned()
                    self.assertEqual(call.value, status)
                    self.assertEqual(call.arguments[:2], [row, b"keep"])
                    if status == 0:
                        self.assertEqual(call.arguments[2][1168:1200], digest)
                    else:
                        self.assertEqual(call.arguments[2], before)
            with self.assertRaises(ValueError):
                wide.call("f0", [b"", b"", bytearray(ABI_LIMIT + 1)])
        for backend in ("selfhost", "direct"):
            with self.assertRaises(ValueError):
                self.modules[backend].call("f0", [bytearray(ABI_LIMIT + 1), b"", b""])
        with self.assertRaises(ValueError):
            NativeModule(SOURCE, byte_exports=("f0",), backend="direct", max_input_extent=max_wire)
