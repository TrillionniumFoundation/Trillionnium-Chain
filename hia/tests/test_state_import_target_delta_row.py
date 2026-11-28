"""Exercise the unchanged TargetDeltaRowV0 method and both real HIA ELFs."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_state_import_snapshot_shadow import CRATE, LOCK, MANIFEST, _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/target_delta_row_validate.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_target_delta_row_reference.rs"
SCRATCH = 1256
UNUSED = b"\xa5" * 23


def recipe(namespace, key, value, change=0):
    payload = namespace + key + (value or b"")
    lengths = struct.pack("<4I", len(namespace), len(key), len(value or b""), value is not None)
    return payload, lengths, bytes([change])


class StateImportTargetDeltaRow(unittest.TestCase):
    def test_exact_original_typed_row_and_stock_guards(self):
        ns, key = b"ordinary\x00", b"\xffkey"
        large_size = MAX_EXTENT - len(ns) - len(key) - 48
        cases = [
            (recipe(ns, key, None), 0),
            (recipe(ns, key, b""), 0),
            (recipe(ns, key, b"\x00"), 0),
            (recipe(ns, key, b"\x00", 1), 101),
            (recipe(ns, key, b"\x00", 32), 101),
            (recipe(b"", key, None), 101),
            (recipe(ns, b"", b""), 101),
            (recipe(b"x" * 128, b"\xff" * 65536, b"value"), 0),
            (recipe(b"x" * 129, key, None), 101),
            (recipe(ns, b"\xff" * 65537, None), 101),
            (recipe(b"validator_signing_state/x", key, b""), 101),
            (recipe(b"validator_signing_state/x", key, b"", 7), 101),
            (recipe(b"validator_signing_stat", key, b""), 0),
            *((recipe(ns, key, bytes([n & 255]) * n), 0) for n in (25, 26, 27, 34, 35, 36, 255, 256, 257)),
            (recipe(ns, key, b"r" * large_size), 0),
            (recipe(ns, key, b"r" * (large_size + 1)), 0),  # independently Rust only
        ]
        requests = [lengths + flag + payload for (payload, lengths, flag), _ in cases]
        rust_inputs = (MANIFEST, LOCK, CRATE / "Cargo.toml", CRATE / "src/lib.rs", ADAPTER)
        before = tuple(hashlib.sha256(path.read_bytes()).digest() for path in rust_inputs)
        with tempfile.TemporaryDirectory(prefix="m13-original-target-delta-row-") as tmp:
            original, _ = _build_original(Path(tmp), ADAPTER)
            stream = b"".join(struct.pack("<I", len(r)) + r for r in requests)
            observed = _run([original], input=stream).stdout
        self.assertEqual(tuple(hashlib.sha256(path.read_bytes()).digest() for path in rust_inputs), before)
        self.assertEqual(len(observed), 36 * len(cases))
        results = list(struct.iter_unpack("<I32s", observed))
        self.assertEqual([status for status, _ in results], [status for _, status in cases])
        self.assertNotEqual(results[0][1], results[1][1])  # Delete != Some(empty).
        wires = [(payload + widths + stored, status)
                 for ((payload, widths, _), _), (status, stored) in zip(cases, results, strict=True)]
        self.assertEqual([len(w) for w, _ in wires[-2:]], [MAX_EXTENT, MAX_EXTENT + 1])

        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as module:
                # Test a Rust-computed delete digest under a same-width present tag.
                # Only the option kind changed, so shape alone must not accept it.
                delete, _ = wires[0]
                replaced = delete[:-36] + b"\x01" + delete[-35:]
                valid, _ = wires[2]
                refused = [
                    (b"", SCRATCH, 100), (valid[:-1], SCRATCH, 100),
                    (b"\x00" + valid, SCRATCH, 100),
                    (delete[:-36] + b"\x02" + delete[-35:], SCRATCH, 100),
                    (delete[:-35] + b"\x01" + delete[-34:], SCRATCH, 100),
                    (valid[:-36] + bytes(4) + valid[-32:], SCRATCH, 100),
                    (valid, SCRATCH - 1, 102),
                    (wires[10][0], 0, 101), (wires[5][0], 0, 101),
                ]
                all_cases = [(wire, SCRATCH + 11, status) for wire, status in wires[:-1]]
                all_cases += [(replaced, SCRATCH, 101), *refused]
                requests = [("f0", [wire, UNUSED, b"\x6d" * work]) for wire, work, _ in all_cases]
                for i, item in enumerate(module.call_many(requests, timeout=55)):
                    wire, work, status = all_cases[i]
                    self.assertEqual(item.require_returned().value, status, i)
                    self.assertEqual(item.arguments[:2], [wire, UNUSED], i)
                    if status in (100, 102) or work == 0:
                        self.assertEqual(item.arguments[2], b"\x6d" * work, i)
                    self.assertEqual(item.arguments[2][SCRATCH:], b"\x6d" * max(0, work - SCRATCH), i)
