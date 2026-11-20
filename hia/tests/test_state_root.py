"""Native complete sparse state roots, independent byte oracle and original Rust.

The local SRV1 descriptor supplies actual key/value bytes. No caller-supplied
leaf, path, root, validation bit or admission capability is accepted. These
tests concern pon_wire's byte relation, not M06's JSON grammar or a store owner.
The maximum-count and real-pointer controls live in the independent suite.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
import itertools
import os
from pathlib import Path
import random
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule

SOURCE = Path(__file__).resolve().parents[1] / "src/protocol/state_root.hepta"
OUTPUT = b"\xc7" * 49


def descriptor(rows):
    return b"SRV1" + struct.pack("<I", len(rows)) + b"".join(
        struct.pack("<II", len(key), len(value)) + key + value for key, value in rows)


def domain(tag, *parts):
    return hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag + b"".join(
        struct.pack("<I", len(part)) + part for part in parts)).digest()


@lru_cache(maxsize=1)
def empty_roots():
    values = [b""] * 257
    values[256] = domain(b"state-empty")
    for depth in range(255, -1, -1):
        values[depth] = domain(b"state-node", values[depth + 1], values[depth + 1])
    return values


def reference(rows):
    if len(rows) > 65536 or any(len(key) > 160 or len(value) > 4096 for key, value in rows):
        return 4, None
    leaves = sorted((domain(b"state-key", key), domain(b"state-leaf", key, value))
                    for key, value in rows)
    if any(left[0] == right[0] for left, right in zip(leaves, leaves[1:])):
        return 5, None
    empty = empty_roots()

    def subtree(values, depth):
        if not values:
            return empty[depth]
        if depth == 256:
            return values[0][1]
        mask = 128 >> (depth % 8)
        left = [row for row in values if not row[0][depth // 8] & mask]
        right = [row for row in values if row[0][depth // 8] & mask]
        return domain(b"state-node", subtree(left, depth + 1), subtree(right, depth + 1))

    return 0, subtree(leaves, 0)


class StateRootContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def invoke(self, raw, *, count=None, output=OUTPUT, scratch_size=None, backend=None):
        if count is None:
            count = int.from_bytes(raw[4:8], "little") if len(raw) >= 8 else 0
        if scratch_size is None:
            scratch_size = 157024 + 64 * min(count, 65536) + 29
        scratch = b"\xa5" * scratch_size
        result = (backend or self.native).call("f0", [raw, output, scratch], timeout=60).require_returned()
        self.assertEqual(result.arguments[0], raw)
        if result.value:
            self.assertEqual(result.arguments[1], output)
        else:
            self.assertEqual(result.arguments[1][32:], output[32:])
            self.assertEqual(result.arguments[2][157024 + 64 * count:],
                             scratch[157024 + 64 * count:])
        return result, scratch

    def check_rows(self, rows, backend=None):
        result, _ = self.invoke(descriptor(rows), backend=backend)
        code, digest = reference(rows)
        self.assertEqual(result.value, code)
        if not code:
            self.assertEqual(result.arguments[1][:32], digest)
        return result

    def test_empty_single_and_absence_are_distinct(self):
        empty = self.check_rows([]).arguments[1][:32]
        self.assertEqual(empty.hex(), "3065e2b0b90b9dbec19b9e6d8c574dd19dc42d59628dbbe65826dbaa0c558f29")
        present = self.check_rows([(b"", b"")]).arguments[1][:32]
        self.assertNotEqual(empty, present)
        self.check_rows([(b"a", b"null")])
        self.check_rows([(b"z", b"1"), (b"b", b"2")])

    def test_arbitrary_binary_keys_and_value_extent_boundaries(self):
        for key_length, value_length in itertools.product((0, 1, 31, 159, 160),
                                                          (0, 1, 55, 56, 63, 64, 65, 4095, 4096)):
            with self.subTest(key=key_length, value=value_length):
                self.check_rows([(bytes((i * 79 + 181) & 255 for i in range(key_length)),
                                  bytes((i * 113 + 251) & 255 for i in range(value_length)))])

    def test_entry_order_does_not_change_the_root(self):
        rows = [(b"", b""), (b"\xff\0", b"left"), (b"alpha", b"right"), (b"\0", b"\xff")]
        expected = reference(rows)[1]
        for values in itertools.permutations(rows):
            result, _ = self.invoke(descriptor(values))
            self.assertEqual(result.value, 0)
            self.assertEqual(result.arguments[1][:32], expected)

    def test_random_sparse_paths_and_unbalanced_heap_lengths(self):
        rng = random.Random(0x53525631)
        for count in (1, 2, 3, 7, 17, 33, 64, 127):
            rows = [(index.to_bytes(4, "big") + rng.randbytes(index % 23), rng.randbytes(index % 97))
                    for index in range(count)]
            rng.shuffle(rows)
            self.check_rows(rows)

    def test_every_truncation_and_trailing_byte_preserves_outputs(self):
        raw = descriptor([(b"key", b"value"), (b"other", b"\0\xff")])
        for length in range(len(raw)):
            result, scratch = self.invoke(raw[:length], count=2)
            self.assertEqual(result.value, 1, length)
            self.assertEqual(result.arguments[2], scratch)
        result, scratch = self.invoke(raw + b"\0", count=2)
        self.assertEqual(result.value, 1)
        self.assertEqual(result.arguments[2], scratch)

    def test_limit_and_descriptor_error_precedence(self):
        controls = [
            (b"SRV2" + struct.pack("<I", 0), 2),
            (b"SRV1" + struct.pack("<I", 65537), 4),
            (b"SRV1" + struct.pack("<I", 0xffffffff), 4),
            (b"SRV1" + struct.pack("<III", 1, 161, 0), 4),
            (b"SRV1" + struct.pack("<III", 1, 0, 4097), 4),
            (b"SRV1" + struct.pack("<III", 1, 0xffffffff, 0xffffffff), 4),
            (b"SRV1" + struct.pack("<III", 1, 160, 4096), 1),
            (descriptor([]) + b"\0", 1),
        ]
        for raw, expected in controls:
            result, scratch = self.invoke(raw, count=1)
            self.assertEqual(result.value, expected)
            self.assertEqual(result.arguments[2], scratch)
        result, _ = self.invoke(b"SRV1" + struct.pack("<I", 65537), count=0,
                                output=b"", scratch_size=0)
        self.assertEqual(result.value, 4)

    def test_capacity_refusals_write_nothing(self):
        for rows in ([], [(b"a", b"b")], [(b"x", b""), (b"y", b"z")]):
            raw = descriptor(rows)
            needed = 157024 + 64 * len(rows)
            for out_size, scratch_size in ((0, needed), (31, needed), (32, 0), (32, needed - 1)):
                result, scratch = self.invoke(raw, output=b"\x6d" * out_size, scratch_size=scratch_size)
                self.assertEqual(result.value, 100)
                self.assertEqual(result.arguments[2], scratch)
            result, _ = self.invoke(raw, output=b"\x6d" * 32, scratch_size=needed)
            self.assertEqual(result.value, 0)

    def test_duplicate_paths_are_not_collapsed_or_accepted(self):
        rows = [(b"same", b"old"), (b"same", b"new"), (b"other", b"ok")]
        for values in itertools.permutations(rows):
            self.assertEqual(self.check_rows(values).value, 5)
        self.assertEqual(self.check_rows([(b"", b""), (b"", b"")]).value, 5)

    def test_actual_key_and_value_bytes_are_hashed(self):
        original = [(b"a\x00\xff", b"data\x00\xff"), (b"other", b"")]
        expected = reference(original)[1]
        for field in range(2):
            for index in range(len(original[0][field])):
                pair = list(original[0])
                value = bytearray(pair[field]); value[index] ^= 0x80; pair[field] = bytes(value)
                result = self.check_rows([tuple(pair), original[1]])
                self.assertNotEqual(result.arguments[1][:32], expected)

    def test_separately_selected_direct_machine_backend(self):
        with NativeModule(SOURCE, byte_exports=("f0",), backend="direct") as direct:
            for rows in ([], [(b"\xff", b"\0")], [(str(i).encode(), bytes([i])) for i in range(19)],
                         [(b"same", b""), (b"same", b"x")]):
                self.check_rows(rows, backend=direct)

    def test_original_rust_protocol_relation(self):
        reference_executable = os.environ.get("TRNM_HIA_RUST_PROTOCOL_REFERENCE")
        if not reference_executable:
            self.skipTest("Original Rust protocol oracle not configured; required by CI")
        cases = [[], [(b"", b"")], [(b"a", b"null")],
                 [(b"\xff" * 160, b"x" * 4096)], [(b"a" * 161, b"")], [(b"", b"x" * 4097)],
                 [(b"same", b"old"), (b"same", b"new")]]
        for count in (2, 7, 31, 128):
            cases.append([(i.to_bytes(4, "little"), bytes([i & 255]) * (i % 71)) for i in reversed(range(count))])
        encoded = [descriptor(rows) for rows in cases]
        result = subprocess.run([reference_executable], input="".join("S " + raw.hex() + "\n" for raw in encoded),
                                text=True, capture_output=True, timeout=60, check=True)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(encoded))
        for raw, line in zip(encoded, lines):
            status, root = line.split()
            observed, _ = self.invoke(raw)
            self.assertEqual(observed.value, int(status))
            if not observed.value:
                self.assertEqual(observed.arguments[1][:32].hex(), root)


if __name__ == "__main__":
    unittest.main()
