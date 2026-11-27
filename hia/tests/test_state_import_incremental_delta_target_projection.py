"""Actual pure target projection versus locked original callback observations."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_state_import_incremental_delta_header import change, u64
from hia.tests.test_state_import_snapshot_shadow import CRATE, LOCK, MANIFEST, _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/incremental_delta_target_projection.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_incremental_delta_target_projection_reference.rs"
WORK = 2896
OUT = b"\xa5" * 61


def encode(row):
    ns, key, val = row
    value = val or b""
    return struct.pack("<4I", len(ns), len(key), len(value), val is not None) + ns + key + value


def selected(base, operations, labels):
    return [operations[code - 128] if code >= 128 else base[code] for code in labels]


def fixture(base, operations, labels, mode=0, alternate=0):
    golden = selected(base, operations, labels)
    header = u64(len(base)) + u64(len(operations))
    body = b"".join(map(encode, (*base, *operations)))
    recipe = bytes([mode]) + header + u64(len(golden)) + u64(alternate) + body + b"".join(map(encode, golden))
    return recipe, header, body, bytes(labels), golden, (119 if mode else 0)


class StateImportIncrementalDeltaTargetProjection(unittest.TestCase):
    def test_actual_original_target_rows_and_two_callback_boundary(self):
        first = (b"a", b"\0", b"old")
        high = (b"a", b"\xff", b"old")
        end = (b"z", b"0", b"keep")
        base = (first, high, end)
        mixed = (
            (b"a", b"\0", None), (b"a", b"\1", b""), (b"a", b"\xff", b"new"),
            (b"b", b"0", None), (b"zz", b"0", b"late"),
        )
        private_max_base = tuple((b"a", bytes([i]), b"base") for i in range(8))
        private_max_ops = tuple((b"z", bytes([i]), b"") for i in range(8))
        wide = MAX_EXTENT - 56 - 16 - 2
        specs = [
            ((), (), []), (base, (), [0, 1, 2]), ((), mixed, [129, 130, 132]),
            (base, mixed, [129, 130, 2, 132]),
            ((first,), (first,), [128]),
            ((first,), ((b"a", b"\0", None),), []),
            ((first,), ((b"a", b"\1", None),), [0]),
            ((high,), ((b"a", b"\0", b""),), [128, 0]),
            ((first, end), ((b"a", b"\0extra", b"between"),), [0, 128, 1]),
            ((first, end), ((b"aa", b"\0", b"middle"),), [0, 128, 1]),
            (private_max_base, private_max_ops, [*range(8), *range(128, 136)]),
            ((), ((b"a", b"k", b"v" * wide),), [128]),
            ((), ((b"a", b"k", b"v" * (wide + 1)),), [128]),
            (base, mixed, [129, 130, 2, 132], 1, 3),
            (base, mixed, [129, 130, 2, 132], 2),
            ((first,), ((b"a", b"\1", None),), [0], 1, 2),  # Only Some can grow.
            ((first,), (first,), [128], 1, 2),  # Budget can pass but exact count fails.
            (private_max_base, private_max_ops, [*range(8), *range(128, 136)], 3, 17),
            ((), (), [], 2),
        ]
        fixtures = [fixture(*spec) for spec in specs]
        paths = (MANIFEST, LOCK, CRATE / "Cargo.toml", CRATE / "src/lib.rs", ADAPTER)
        stamps = tuple(hashlib.sha256(p.read_bytes()).digest() for p in paths)
        with tempfile.TemporaryDirectory(prefix="m13-original-target-projection-") as tmp:
            original, _ = _build_original(Path(tmp), ADAPTER)
            packets = b"".join(struct.pack("<I", len(rec)) + rec for rec, *_ in fixtures)
            observations = _run([original], input=packets).stdout
        self.assertEqual(tuple(hashlib.sha256(p.read_bytes()).digest() for p in paths), stamps)
        wires = []
        offset = 0
        for i, (_, header, body, selects, golden, expected) in enumerate(fixtures):
            status, called = struct.unpack_from("<II", observations, offset)
            declared = observations[offset + 8:offset + 16]
            digest = observations[offset + 16:offset + 48]
            observed_count, = struct.unpack_from("<I", observations, offset + 48)
            offset += 52
            self.assertEqual((status, called), (expected, 1 if expected else 2), i)
            self.assertEqual(observed_count, 0 if expected else len(golden), i)
            result = []
            for _ in range(observed_count):
                row = []
                for _ in range(3):
                    field_len, = struct.unpack_from("<I", observations, offset)
                    start = offset + 4
                    offset = start + field_len
                    row.append(observations[start:offset])
                result.append(tuple(row))
            if expected == 0:
                self.assertEqual(result, golden, i)
            exact = struct.pack("<Q", observed_count) + digest + selects
            wires.append((header + declared + digest + body, expected, exact))
        self.assertEqual(offset, len(observations))
        self.assertEqual([len(wires[n][0]) for n in (11, 12)], [MAX_EXTENT, MAX_EXTENT + 1])
        empty = wires[0][0]
        ordinary = wires[1][0]
        one = encode(first)
        bad_row = encode((b"", b"k", b""))
        controls = [
            (b"", 100, b"", WORK, len(OUT)), (empty[:-1], 100, b"", WORK, len(OUT)),
            (ordinary + one, 100, b"", WORK, len(OUT)), (ordinary[:-1], 100, b"", WORK, len(OUT)),
            (change(ordinary, (68, b"\0")), 100, b"", WORK, len(OUT)),  # base must be present
            (change(empty, (0, u64(9))), 102, b"", WORK, len(OUT)),
            (change(empty, (8, u64(9))), 102, b"", WORK, len(OUT)),
            (empty, 102, b"", WORK - 1, len(OUT)), (empty, 102, b"", WORK, 55),
            (change(empty, (0, u64(1))) + bad_row, 118, b"", WORK, len(OUT)),
            (change(empty, (8, u64(1))) + bad_row, 101, b"", WORK, len(OUT)),
            (change(empty, (0, u64(2))) + one * 2, 109, b"", WORK, len(OUT)),
        ]
        trials = [(wire, status, exact, WORK + 7, len(OUT))
                  for i, (wire, status, exact) in enumerate(wires) if i != 12] + controls
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as m:
                requests = [("f0", [wire, OUT[:out_size], b"\x6d" * scratch])
                            for wire, _, _, scratch, out_size in trials]
                for i, result in enumerate(m.call_many(requests, timeout=55)):
                    raw, expected, exact, scratch, out_size = trials[i]
                    self.assertEqual(result.require_returned().value, expected, i)
                    initial = OUT[:out_size]
                    self.assertEqual(result.arguments[:2], [raw, initial if expected else exact + initial[len(exact):]], i)
                    self.assertEqual(result.arguments[2][WORK:], b"\x6d" * max(0, scratch - WORK), i)
