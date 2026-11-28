"""Compare the exact original pre-root apply witness, never application/custody."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_state_import_incremental_delta_header import change, context, digest, u64
from hia.tests.test_state_import_snapshot_shadow import CRATE, LOCK, MANIFEST, _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/incremental_delta_base_witness.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_incremental_delta_base_witness_reference.rs"
WORK = 1656
OUT = b"\xa5" * 21


def row(ns, key, value):
    return struct.pack("<4I", len(ns), len(key), len(value), 0) + ns + key + value


def header(count):
    source = context(255, 2, 42)
    target = context(256, 3, 42)
    return source + target + source + target + u64(0) + digest(7) + u64(count)


class StateImportIncrementalDeltaBaseWitness(unittest.TestCase):
    def test_exact_context_rows_count_and_digest_before_root_owner(self):
        a = row(b"a", b"\0", b"")
        b = row(b"a", b"\x80", b"\0")
        c = row(b"aa", b"k", b"v")
        invalid = row(b"", b"k", b"v")
        ordered = tuple(row(b"n", bytes([i]), bytes([i]) * i) for i in range(8))
        large = MAX_EXTENT - 1008 - 16 - 2
        cases = [(ordered[:n], 0, (), 0) for n in range(9)]
        cases += [
            ((a, b, c), 0, (), 0),
            ((a, b, c), 1, ((960, u64(2)),), 115),
            ((a, b, c), 2, (), 115),
            ((a, b, c), 3, ((960, u64(100_000_000)),), 115),
            ((a, b, c), 0, ((480 + 136, u64(1)),), 117),
            ((a, b, c), 0, ((720 + 208, digest(18)),), 117),
            ((a, invalid), 3, ((480, digest(18)),), 117),
            ((a, invalid), 3, (), 118),
            ((b, a, invalid), 3, (), 109),
            ((a, row(b"a", b"\0", b"updated")), 0, (), 109),
            ((a, row(b"a", b"", b"")), 2, (), 118),
            ((a, row(b"validator_signing_state/x", b"k", b"")), 2, (), 118),
            ((a, row(b"validator_signing_stat", b"ek", b"")), 0, (), 0),
            ((row(b"n" * 128, b"k" * 65536, b"v"),), 0, (), 0),
            ((row(b"n" * 129, b"k", b""),), 0, (), 118),
            ((row(b"n", b"k" * 65537, b""),), 0, (), 118),
            ((row(b"n", b"k", b"x" * large),), 0, (), 0),
            ((row(b"n", b"k", b"x" * (large + 1)),), 0, (), 0),
        ]
        source_inputs = (MANIFEST, LOCK, CRATE / "Cargo.toml", CRATE / "src/lib.rs", ADAPTER)
        before = tuple(hashlib.sha256(p.read_bytes()).digest() for p in source_inputs)
        packets = [bytes([mode]) + change(header(len(rows)), *edits) + b"".join(rows)
                   for rows, mode, edits, _ in cases]
        with tempfile.TemporaryDirectory(prefix="m13-original-pre-root-base-") as tmp:
            binary, _ = _build_original(Path(tmp), ADAPTER)
            records = _run([binary], input=b"".join(struct.pack("<I", len(p)) + p for p in packets)).stdout
        self.assertEqual(tuple(hashlib.sha256(p.read_bytes()).digest() for p in source_inputs), before)
        self.assertEqual(len(records), 1016 * len(cases))
        wires = []
        for i, (rows, _, _, expected) in enumerate(cases):
            record = records[1016 * i:1016 * (i + 1)]
            original, calls = struct.unpack_from("<II", record)
            self.assertEqual((original, calls), (expected, int(expected == 0)), i)
            self.assertEqual(record[8:968], packets[i][1:961])
            self.assertEqual(record[-8:], u64(len(rows)))
            wires.append((record[8:] + b"".join(rows), expected))
        self.assertEqual([len(w) for w, _ in wires[-2:]], [MAX_EXTENT, MAX_EXTENT + 1])
        empty = wires[0][0]
        good = wires[2][0]
        prefix = [
            (b"", WORK, 100), (empty[:-1], WORK, 100), (good[:-1], WORK, 100),
            (empty + a, WORK, 100), (good + a, WORK, 100),
            (change(good, (1020, bytes([1]))), WORK, 100),
            (change(good, (1000, u64(9))), WORK, 102), (good, WORK - 1, 102),
        ]
        fixtures = [(wire, WORK + 7, status) for wire, status in wires[:-1]] + prefix
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as m:
                requests = [("f0", [wire, OUT, b"\x6d" * work]) for wire, work, _ in fixtures]
                for i, result in enumerate(m.call_many(requests, timeout=55)):
                    wire, work, expected = fixtures[i]
                    self.assertEqual(result.require_returned().value, expected, i)
                    self.assertEqual(result.arguments[:2], [wire, OUT], i)
                    self.assertEqual(result.arguments[2][WORK:], b"\x6d" * max(0, work - WORK), i)
                    if expected in (100, 102, 109, 117, 118):
                        self.assertEqual(result.arguments[2], b"\x6d" * work, i)
