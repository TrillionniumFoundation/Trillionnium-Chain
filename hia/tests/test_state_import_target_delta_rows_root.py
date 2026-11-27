"""Exact ordered target-delta row and root substage against original Rust."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_state_import_snapshot_shadow import CRATE, LOCK, MANIFEST, _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/target_delta_rows_root.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_target_delta_rows_root_reference.rs"
SCRATCH = 2016
UNUSED = b"\xa5" * 23
RESERVED = (b"validator_signing_state", b"consensus_private_key", b"signer_journal",
            b"safety_store", b"remote_signer_watermark", b"node_commit_ledger", b"operator_recovery_key")


def row(ns, key, value, changed=0):
    payload = ns + key + (value or b"")
    widths = struct.pack("<4I", len(ns), len(key), len(value or b""), value is not None)
    return widths, bytes([changed]), payload


class StateImportTargetDeltaRowsRoot(unittest.TestCase):
    def test_original_row_order_and_real_merkle_before_callback(self):
        # All operations and context values are synthetic. No runtime owner is consulted.
        ordered = tuple(row(b"a", bytes([i]), (None, b"", b"data")[i % 3]) for i in range(8))
        low = row(b"a", b"\x00", None)
        prefix = row(b"a", b"\x00x", b"")
        high = row(b"a", b"\xff", b"x")
        next_ns = row(b"aa", b"\x00", b"")
        invalid_low = row(b"a", b"\x00", None, 6)
        large = row(b"a", b"k", b"A" * (MAX_EXTENT - 36 - 48 - 2))
        cases = [
            *((ordered[:n], False, 0) for n in range(9)),
            ((), True, 112),
            ((low, prefix, high, next_ns), False, 0),
            ((low, high, next_ns), True, 112),
            ((low, row(b"a", b"\x00", b""), next_ns), False, 109),
            ((high, low, next_ns), True, 109),
            ((high, invalid_low), True, 101),
            ((high, low, invalid_low), True, 109),
            ((row(b"", b"k", None), next_ns), False, 101),
            ((row(b"a", b"", b"x"),), False, 101),
            ((row(b"a", b"k", None, 32),), False, 101),
            *(([row(b"0", b"k", None), row(p + b"/x", b"k", None)], False, 101)
              for p in RESERVED),
            *(([row(b"0", b"k", None), row(p[:-1], p[-1:] + b"k", b"")], False, 0)
              for p in RESERVED),
            ((large,), False, 0),
            ((row(b"a", b"k", b"A" * (MAX_EXTENT - 36 - 48 - 1)),), False, 0),
        ]
        recipes = [struct.pack("<IB", len(rows), wrong) + b"".join(w + f + p for w, f, p in rows)
                   for rows, wrong, _ in cases]
        dependencies = (MANIFEST, LOCK, CRATE / "Cargo.toml", CRATE / "src/lib.rs", ADAPTER)
        before = tuple(hashlib.sha256(p.read_bytes()).digest() for p in dependencies)
        with tempfile.TemporaryDirectory(prefix="m13-original-target-delta-rows-") as tmp:
            original, _ = _build_original(Path(tmp), ADAPTER)
            observations = _run([original], input=b"".join(struct.pack("<I", len(r)) + r for r in recipes)).stdout
        self.assertEqual(tuple(hashlib.sha256(p.read_bytes()).digest() for p in dependencies), before)

        wires = []
        at = 0
        for rows, _, original_status in cases:
            status, calls = struct.unpack_from("<II", observations, at)
            root = observations[at + 8:at + 40]
            at += 40
            self.assertEqual((status, calls), (original_status, int(original_status == 0)))
            chunks = []
            for widths, _, payload in rows:
                chunks.append(widths + observations[at:at + 32] + payload)
                at += 32
            wires.append((struct.pack("<I", len(rows)) + root + b"".join(chunks), status))
        self.assertEqual(at, len(observations))
        self.assertEqual([len(wire) for wire, _ in wires[-2:]], [MAX_EXTENT, MAX_EXTENT + 1])

        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as machine:
                first, _ = wires[1]
                eight, _ = wires[8]
                invalid_tag = first[:48] + b"\x02" + first[49:]
                controls = [
                    (b"", SCRATCH, 100), (first[:83], SCRATCH, 100),
                    (first[:-1], SCRATCH, 100), (first + b"x", SCRATCH, 100),
                    (invalid_tag, SCRATCH, 100),
                    (struct.pack("<I", 9) + eight[4:], SCRATCH, 102),
                    (wires[0][0], SCRATCH - 1, 102),
                    (wires[0][0] + b"x", SCRATCH, 100),
                ]
                fixtures = [(wire, SCRATCH + 8, status) for wire, status in wires[:-1]] + controls
                requests = [("f0", [wire, UNUSED, b"\x6d" * work]) for wire, work, _ in fixtures]
                for i, result in enumerate(machine.call_many(requests, timeout=55)):
                    wire, work, status = fixtures[i]
                    self.assertEqual(result.require_returned().value, status, i)
                    self.assertEqual(result.arguments[:2], [wire, UNUSED], i)
                    self.assertEqual(result.arguments[2][SCRATCH:], b"\x6d" * max(0, work - SCRATCH), i)
