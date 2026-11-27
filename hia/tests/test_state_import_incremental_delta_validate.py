"""Frozen composed validation using the genuine locked original state-import crate."""
import hashlib
import re
import struct
import tempfile
import unittest
from pathlib import Path

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_state_import_incremental_delta_header import change, digest, header, u64
from hia.tests.test_state_import_snapshot_shadow import CRATE, LOCK, MANIFEST, _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/incremental_delta_validate.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_incremental_delta_validate_reference.rs"
OUTPUT = b"\xa5" * 21
WORK = 2016


def function(source, name):
    [body] = re.findall(fr"(?ms)^fn {name}\(.*?^end$", source.read_text())
    return body


def row(namespace, key, value, corrupt=0):
    payload = namespace + key + (value or b"")
    widths = struct.pack("<4I", len(namespace), len(key), len(value or b""), value is not None)
    return widths, bytes([corrupt]), payload


class StateImportIncrementalDeltaValidate(unittest.TestCase):
    def test_same_input_control_has_only_frozen_offset_derivation(self):
        header_body = function(SOURCE.parent / "incremental_delta_header_validate.hepta", "f0")
        header_body = header_body[header_body.index("block source("):]
        header_body = re.sub(r"(?ms)^block (?:malformed|short)\(\).*?(?=^block )", "", header_body)
        native_header = function(SOURCE, "same_input_header")
        self.assertEqual(native_header[native_header.index("block source("):], header_body)
        batch = function(SOURCE.parent / "target_delta_rows_root.hepta", "f0")
        batch = batch[batch.index("block dispatch("):]
        expected_at = '  expected13:u64 = const() {"value":4}'
        self.assertEqual(batch.count(expected_at), 1)
        batch = batch.replace(expected_at, expected_at.replace('4}', '688}'))
        composed = function(SOURCE, "f0")
        self.assertEqual(composed[composed.index("block dispatch("):], batch)

    def test_exact_original_compound_priority_and_count_agreement(self):
        a = row(b"a", b"\0", None)
        b = row(b"a", b"\x80", b"")
        c = row(b"aa", b"\0", b"z")
        duplicate = row(b"a", b"\0", b"different value")
        invalid_a = row(b"a", b"\0", None, 32)
        seq = tuple(row(b"n", bytes([i]), (None, b"", b"x")[i % 3]) for i in range(8))
        large_value = MAX_EXTENT - 760 - 48 - 2
        cases = [(seq[:n], 0, (), 0) for n in range(9)]
        cases += [
            ((a, b, c), 0, (), 0),
            ((a, b, c), 2, (), 112),
            ((a, b, c), 3, (), 114),
            ((b, invalid_a, c), 2, (), 101),
            ((b, a, invalid_a), 2, (), 109),
            ((a, duplicate, c), 0, (), 109),
            ((b, invalid_a, c), 3, (), 114),
            ((b, invalid_a, c), 3, ((128, u64(0)),), 113),
            ((b, invalid_a, c), 3, ((240, digest(0)),), 113),
            ((b, invalid_a, c), 0, ((480, digest(0)),), 114),
            ((b, invalid_a, c), 0, ((272, digest(21)),), 114),
            ((b, invalid_a, c), 0, ((384, digest(21)),), 114),
            ((a, row(b"0", b"k", None)), 2, (), 109),
            ((a, row(b"validator_signing_state/x", b"k", None)), 2, (), 101),
            ((a, row(b"a", b"", b"")), 2, (), 101),
            ((a, b, c), 0, ((136, u64((1 << 64) - 1)), (376, u64((1 << 64) - 1))), 0),
            ((row(b"a", b"k", b"x" * large_value),), 0, (), 0),
            ((row(b"a", b"k", b"x" * (large_value + 1)),), 0, (), 0),
        ]
        recipes = [
            bytes([mode]) + change(header(len(rows)), *edits) + b"".join(w + f + p for w, f, p in rows)
            for rows, mode, edits, _ in cases
        ]
        protected = (MANIFEST, LOCK, CRATE / "Cargo.toml", CRATE / "src/lib.rs", ADAPTER)
        before = tuple(hashlib.sha256(p.read_bytes()).digest() for p in protected)
        with tempfile.TemporaryDirectory(prefix="m13-original-delta-validate-") as tmp:
            binary, _ = _build_original(Path(tmp), ADAPTER)
            output = _run([binary], input=b"".join(struct.pack("<I", len(r)) + r for r in recipes)).stdout
        self.assertEqual(tuple(hashlib.sha256(p.read_bytes()).digest() for p in protected), before)
        at, wires = 0, []
        for case_index, (rows, _, _, expected) in enumerate(cases):
            original_status, owner_called = struct.unpack_from("<II", output, at)
            self.assertEqual((original_status, owner_called), (expected, int(expected == 0)), case_index)
            original_header = output[at + 8:at + 768]
            self.assertEqual(original_header[752:], u64(len(rows)))
            at += 768
            native_rows = []
            for widths, _, payload in rows:
                native_rows.append(widths + output[at:at + 32] + payload)
                at += 32
            wires.append((original_header + b"".join(native_rows), original_status, native_rows))
        self.assertEqual(at, len(output))
        self.assertEqual([len(w) for w, _, _ in wires[-2:]], [MAX_EXTENT, MAX_EXTENT + 1])

        empty, _, _ = wires[0]
        ordinary, _, pieces = wires[3]
        single, _, one = wires[1]
        controls = [
            (b"", WORK, 100), (empty[:-1], WORK, 100),
            (empty, WORK - 1, 102), (change(empty, (752, u64(9))), WORK, 102),
            (empty + one[0], WORK, 100),  # original zero count may not leave an extra row
            (ordinary[:-len(pieces[-1])], WORK, 100),  # unchanged counted header, missing complete row
            (ordinary + one[0], WORK, 100),  # unchanged count, extra complete row
            (ordinary[:-1], WORK, 100),
            (change(ordinary, (752, u64(2))), WORK, 114),  # count is hashed by the same call
            (change(ordinary, (688, digest(44))), WORK, 114),  # root is hashed by the same call
            (single[:772] + b"\x02" + single[773:], WORK, 100),
        ]
        calls = [(raw, WORK + 9, want) for raw, want, _ in wires[:-1]] + controls
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as m:
                reqs = [("f0", [wire, OUTPUT, b"\x6d" * scratch]) for wire, scratch, _ in calls]
                for i, result in enumerate(m.call_many(reqs, timeout=55)):
                    wire, work, expected = calls[i]
                    self.assertEqual(result.require_returned().value, expected, i)
                    self.assertEqual(result.arguments[:2], [wire, OUTPUT], i)
                    self.assertEqual(result.arguments[2][WORK:], b"\x6d" * max(0, work - WORK), i)
                    if expected == 102 or len(wire) < 760:
                        self.assertEqual(result.arguments[2], b"\x6d" * work, i)
