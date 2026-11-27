"""Compare the original typed incremental header stage with both stock ELFs."""
import hashlib
import re
import struct
import tempfile
import unittest
from pathlib import Path

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import CRATE, LOCK, MANIFEST, _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/incremental_delta_header_validate.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_incremental_delta_header_reference.rs"
WORK = 1808
OUT = b"\xb6" * 23
U64_MAX = (1 << 64) - 1


def u64(n):
    return struct.pack(">Q", n)


def digest(n):
    return bytes([n]) * 32


def context(height, epoch, root):
    return b"".join([*(digest(n) for n in (1, 2, 3, 4)), u64(height), u64(epoch),
                     digest(root), digest(5), digest(6)])


def header(count):
    return (context(255, 2, 42) + context(256, 3, 43)
            + b"".join(digest(n) for n in (11, 12, 13, 42, 14, 43))
            + u64(0) * 2 + digest(15) + digest(16) + u64(count))


def change(wire, *mutations):
    changed = bytearray(wire)
    for offset, value in mutations:
        changed[offset:offset + len(value)] = value
    return bytes(changed)


def function(source, name):
    [body] = re.findall(fr"(?ms)^fn {name}\(.*?^end$", source)
    return body


class StateImportIncrementalDeltaHeader(unittest.TestCase):
    def test_pair_context_helpers_only_translate_owned_read_offsets(self):
        frozen = (SOURCE.parent / "checkpoint_context.hepta").read_text()
        composed = SOURCE.read_text()
        for original, current, signature in (
            ("mcc_shape", "dh_context_shape", "raw:readbuf"),
            ("mcc_hash", "dh_context_hash", "raw:readbuf,work:mutbuf"),
        ):
            with self.subTest(helper=original):
                expected = function(frozen, original).replace(original, current)
                expected = expected.replace(f"({signature})", f"({signature},base:u64)", 2)
                if original == "mcc_shape":
                    expected, changes = re.subn(
                        r"(?m)^  (\w+:\w+ = call\(raw,)(ht|p[0-6])\)",
                        lambda m: f"  {m[2]}_at:u64 = int.add.wrap(base,{m[2]})\n  {m[1]}{m[2]}_at)",
                        expected,
                    )
                    self.assertEqual(changes, 8)
                else:
                    expected, changes = re.subn(
                        r"(?m)^  (copy[0-8]:u64 = call\(raw,)(a[0-8]),work",
                        lambda m: f"  raw_{m[2]}:u64 = int.add.wrap(base,{m[2]})\n  {m[1]}raw_{m[2]},work",
                        expected,
                    )
                    self.assertEqual(changes, 9)
                self.assertEqual(function(composed, current), expected)

    def test_original_header_and_context_priority(self):
        valid = header(3)
        cases = [(header(n), 0, 0, 116) for n in range(9)]
        cases += [
            (valid, 1, 114, 0),
            (valid, 2, 0, 112),  # actual original row/root stage refuses after header
            (valid, 4, 0, 101),
            (valid, 6, 0, 101),
            (valid, 5, 114, 0),  # invalid declared digest precedes invalid row
            (change(valid, (128, u64(0)), (480, digest(0))), 5, 113, 0),
            (change(valid, (240, digest(0)), (512, digest(0))), 5, 113, 0),
            (change(valid, (128, u64(0)), (368, u64(0))), 5, 113, 0),
            (change(valid, (672, u64(100_000_000))), 0, 0, 115),
            (change(valid, (680, u64(100_000_000))), 0, 0, 116),
            (change(valid, (672, u64(100_000_001))), 0, 114, 0),
            (change(valid, (680, u64(100_000_001))), 0, 114, 0),
            (change(valid, (672, u64(U64_MAX))), 0, 114, 0),
            (change(valid, (368, u64(255))), 0, 114, 0),
            (change(valid, (368, u64(254))), 0, 114, 0),
            (change(valid, (368, u64(U64_MAX))), 0, 0, 116),
            (change(valid, (376, u64(2))), 0, 0, 116),
            (change(valid, (376, u64(1))), 0, 114, 0),
            (change(valid, (376, u64(4))), 0, 114, 0),
            (change(valid, (136, u64(U64_MAX - 1)), (376, u64(U64_MAX))), 0, 0, 116),
            (change(valid, (136, u64(U64_MAX)), (376, u64(U64_MAX))), 0, 0, 116),
            (change(valid, (136, u64(U64_MAX)), (376, u64(0))), 0, 114, 0),
            (change(valid, (240, digest(21))), 0, 114, 0),
            (change(valid, (272, digest(22))), 0, 114, 0),
            (change(valid, (144, digest(23))), 0, 114, 0),
            (change(valid, (384, digest(24))), 0, 114, 0),
            (change(valid, (544, digest(0))), 8, 114, 0),
            (change(valid, (688, digest(0))), 2, 114, 0),
        ]
        cases += [(change(valid, (at, digest(0))), 0, 114, 0) for at in (480, 512, 576, 608, 640)]
        cases += [(change(valid, (base + at, digest(0))), 0, 113, 0)
                  for base in (0, 240) for at in (0, 32, 64, 96, 144, 176, 208)]
        self.assertTrue(all(len(raw) == 760 for raw, *_ in cases))
        deps = (MANIFEST, LOCK, CRATE / "Cargo.toml", CRATE / "src/lib.rs", ADAPTER)
        before = tuple(hashlib.sha256(path.read_bytes()).digest() for path in deps)
        with tempfile.TemporaryDirectory(prefix="m13-original-delta-header-") as tmp:
            oracle, _ = _build_original(Path(tmp), ADAPTER)
            observed = _run([oracle], input=b"".join(bytes([mode]) + raw for raw, mode, *_ in cases)).stdout
        self.assertEqual(tuple(hashlib.sha256(path.read_bytes()).digest() for path in deps), before)
        self.assertEqual(len(observed), len(cases) * 772)
        wires = []
        for i, (raw, mode, expected, downstream) in enumerate(cases):
            result = observed[772 * i:772 * (i + 1)]
            status, after, calls = struct.unpack_from("<III", result)
            self.assertEqual((status, after, calls), (expected, downstream, int(downstream == 116)), i)
            wire = result[12:]
            self.assertEqual(wire[:544], raw[:544])
            self.assertEqual(wire[576:688], raw[576:688])
            self.assertEqual(wire[752:], raw[752:])
            if mode & 8:
                self.assertEqual(wire[544:576], raw[544:576])
            if mode & 2:
                self.assertEqual(wire[688:720], raw[688:720])
            wires.append((wire, WORK + 7, status))
        good = wires[3][0]
        wires.extend([(b"", WORK, 100), (good[:-1], WORK, 100), (good + b"\0", WORK, 100),
                      (good, WORK - 1, 102), (change(good, (752, u64(9))), WORK, 102)])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as machine:
                requests = [("f0", [raw, OUT, b"\x6d" * scratch]) for raw, scratch, _ in wires]
                for i, result in enumerate(machine.call_many(requests)):
                    raw, scratch, expected = wires[i]
                    self.assertEqual(result.require_returned().value, expected, i)
                    self.assertEqual(result.arguments[:2], [raw, OUT], i)
                    self.assertEqual(result.arguments[2][WORK:], b"\x6d" * max(0, scratch - WORK), i)
                    if expected in (100, 102):
                        self.assertEqual(result.arguments[2], b"\x6d" * scratch, i)
