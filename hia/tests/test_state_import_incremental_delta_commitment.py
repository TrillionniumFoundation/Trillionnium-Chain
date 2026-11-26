"""Original locked StateImport delta commitment vs stock native ELF engines."""
import random
import struct
import tempfile
import unittest
from pathlib import Path

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/incremental_delta_commitment.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_incremental_delta_commitment_reference.rs"


def row(ns, key, value):
    descriptor = 0 if value is None else (len(value) << 8) | 1
    return (struct.pack("<QQQ", descriptor, len(ns), len(key)) + ns.ljust(64, b"\0")
            + key.ljust(64, b"\0") + (value or b"").ljust(128, b"\0"))


class StateImportIncrementalDeltaCommitment(unittest.TestCase):
    def test_original_ordered_root_and_full_commitment(self):
        rng = random.Random(0x4d313344454c)
        fields = rng.randbytes(208)
        contexts = rng.randbytes(480)
        delete = row(b"\0", b"\xff", None)
        empty = row(b"\0", b"\xff", b"")
        random_rows = [row(rng.randbytes(n), rng.randbytes(n), rng.randbytes(2 * n))
                       for n in (1, 7, 8, 31, 32, 37, 63, 64)]
        cases = [b"".join(random_rows[:n]) for n in range(9)]
        cases += [delete, empty, delete + empty, empty + delete,
                  b"".join(random_rows[:3]), b"".join(random_rows[:3] + random_rows[2:3])]
        heads = [(contexts, fields)] * len(cases)
        # Independently vary every original top-level field and both context identities.
        for offset in [0, 240] + [480 + n for n in (0, 32, 64, 96, 128, 160, 192, 200)]:
            changed = bytearray(contexts + fields)
            changed[offset] ^= 128
            heads.append((changed[:480], changed[480:]))
            cases.append(b"")
        with tempfile.TemporaryDirectory(prefix="m13-incremental-original-") as tmp:
            oracle, _ = _build_original(Path(tmp), ADAPTER)
            wires = [ctx + hdr + rows for (ctx, hdr), rows in zip(heads, cases)]
            original = _run([oracle], input=b"".join(struct.pack("<H", len(r)) + r for r in wires)).stdout
        self.assertEqual(len(original), len(cases) * 128)
        chunks = [original[n:n+128] for n in range(0, len(original), 128)]
        # Root preserves odd duplication but the canonical digest also commits to entry count.
        self.assertEqual(chunks[13][64:96], chunks[14][64:96])
        self.assertNotEqual(chunks[13][96:], chunks[14][96:])
        self.assertNotEqual(chunks[9][64:], chunks[10][64:])
        self.assertNotEqual(chunks[11][64:], chunks[12][64:])
        self.assertEqual(len({chunks[n][96:] for n in [0, *range(15, len(chunks))]}), 11)
        native_input = [hdr[:64] + expected[:64] + hdr[64:] + rows
                        for (_, hdr), rows, expected in zip(heads, cases, chunks)]
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as module:
                args = [[wire, b"\xa5" * 73, b"\x6d" * 2021] for wire in native_input]
                for i, got in enumerate(module.call_many([("f0", a) for a in args])):
                    self.assertEqual(got.require_returned().value, 0, i)
                    self.assertEqual(got.arguments[:2], [native_input[i], chunks[i][64:] + b"\xa5" * 9], i)
                    self.assertEqual(got.arguments[2][2016:], b"\x6d" * 5)
                head = native_input[0]
                bad_tag = struct.pack("<Q", 2) + delete[8:]
                bad_delete = struct.pack("<Q", 256) + delete[8:]
                oversize_value = struct.pack("<Q", (129 << 8) | 1) + delete[8:]
                blank = struct.pack("<Q", 0) + delete[16:24]
                refused = [(head[:-1], 64, 2016, 100), (head + delete * 9, 64, 2016, 100),
                           (head + delete[:-1], 64, 2016, 100), (head + delete + bad_tag, 64, 2016, 100),
                           (head + bad_delete, 64, 2016, 100), (head + oversize_value, 64, 2016, 100),
                           (head + delete[:8] + blank + delete[24:], 64, 2016, 100),
                           (head, 63, 2016, 102), (head, 64, 2015, 102)]
                args = [[wire, b"\xa5" * out_len, b"\x6d" * work_len] for wire, out_len, work_len, _ in refused]
                for i, got in enumerate(module.call_many([("f0", a) for a in args])):
                    self.assertEqual((got.require_returned().value, got.arguments[:2]),
                                     (refused[i][3], args[i][:2]), i)
