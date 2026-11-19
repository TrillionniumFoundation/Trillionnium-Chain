"""W1 HIA kernels against independently computed integer and byte contracts."""
from __future__ import annotations

from pathlib import Path
import random
import struct
import unittest

try:
    from .native_support import NativeModule
except ImportError:
    from native_support import NativeModule

ROOT = Path(__file__).resolve().parents[1] / "src" / "work"
Q = (1 << 32) - 5
PROOF_BYTES = 4 + 3 * 4096 * 4 + 32


def words(values):
    return struct.pack("<" + "I" * len(values), *values)


def request(a, b, rows, inner, cols, version=1):
    return bytes((rows, inner, cols, version)) + words(a) + words(b)


def reference_product(a, b, rows, inner, cols):
    # Python's unbounded sum intentionally differs from the HIA per-term
    # u64 reduction. This is the original Rust u128 dot-product equation.
    return words([sum(a[i * inner + k] * b[k * cols + j]
                      for k in range(inner)) % Q
                  for i in range(rows) for j in range(cols)])


class FieldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(ROOT / "field.hepta")

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def test_u64_reduction_boundaries_and_random(self):
        rng = random.Random(0x504E5731)
        values = [0, 1, Q - 1, Q, Q + 1, (1 << 32) - 1,
                  (1 << 32), (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        values += [rng.getrandbits(64) for _ in range(1024)]
        results = self.native.call_many([("f0", [x]) for x in values])
        for x, got in zip(values, results):
            self.assertEqual(got.require_returned().value, x % Q, x)

    def test_multiply_add_and_denoise(self):
        rng = random.Random(0xF1E1D)
        edges = [0, 1, 2, Q // 2, Q - 2, Q - 1, Q, (1 << 32) - 1]
        pairs = [(a, b) for a in edges for b in edges]
        pairs += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(1024)]
        triples = [(a, b, c) for a in edges for b in edges for c in edges]
        triples += [(rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(32))
                    for _ in range(1024)]
        cases = [("f1", [a, b]) for a, b in pairs]
        expected = [(a * b) % Q for a, b in pairs]
        cases += [("f2", [a, b]) for a, b in pairs]
        expected += [(a + b) % Q for a, b in pairs]
        cases += [("f3", [a, b, c]) for a, b, c in triples]
        expected += [(a - b - c) % Q for a, b, c in triples]
        for case, want, got in zip(cases, expected, self.native.call_many(cases)):
            self.assertEqual(got.require_returned().value, want, case)


class EncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(ROOT / "encoding.hepta", byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_cases(self, cases):
        # Keep the private child comfortably below its fixed 256 MiB limit.
        for start in range(0, len(cases), 32):
            batch = cases[start:start + 32]
            calls = [("f0", [raw, b"out-canary", b"scratch-canary"]) for raw, _ in batch]
            results = self.native.call_many(calls)
            for (_, expected), got in zip(batch, results):
                got.require_returned()
                self.assertEqual(got.value, expected)
                self.assertEqual(got.arguments[1:], [b"out-canary", b"scratch-canary"])

    def test_length_magic_and_field_order(self):
        base = b"PNW1" + bytes(PROOF_BYTES - 4)
        cases = [(base, 0)]
        for size in [0, 1, 3, 4, 16387, 49155, PROOF_BYTES - 1, PROOF_BYTES + 1]:
            cases.append(((base + b"x")[:size], 1))
        bad = bytearray(base)
        bad[0] ^= 1
        bad[4:8] = words([Q])
        cases.append((bytes(bad), 2))
        cases.append((bytes(bad[:-1]), 1))
        for at in range(4):
            bad = bytearray(base)
            bad[at] ^= 0x80
            cases.append((bytes(bad), 2))
        self.check_cases(cases)

    def test_all_three_matrices_and_noncanonical_values(self):
        rng = random.Random(0xE0C0DE)
        base = b"PNW1" + words([Q - 1] * (3 * 4096)) + bytes(range(32))
        cases = [(base, 0)]
        # First/last words in every row, plus randomly selected interior words,
        # exercise every row and the exact end of all three matrices.
        for matrix in range(3):
            for row in range(64):
                for column in (0, 63, rng.randrange(64)):
                    offset = 4 + 4 * (matrix * 4096 + row * 64 + column)
                    bad = bytearray(base)
                    bad[offset:offset + 4] = words([Q + (row % 5)])
                    cases.append((bytes(bad), 3))
        # The final 32-byte digest is opaque, including 0xffffffff words.
        cases.append((base[:-32] + b"\xff" * 32, 0))
        self.check_cases(cases)


class MatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(ROOT / "matrix.hepta", byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def test_exact_modular_products(self):
        rng = random.Random(0x6408)
        cases, expected = [], []
        shapes = [(1, 1, 1), (1, 64, 1), (2, 3, 4), (8, 64, 64),
                  (64, 8, 64), (64, 64, 8), (64, 64, 64)]
        shapes += [(rng.randrange(1, 10), rng.randrange(1, 10), rng.randrange(1, 10))
                   for _ in range(40)]
        for rows, inner, cols in shapes:
            for pattern in range(3):
                if pattern == 0:
                    a, b = [Q - 1] * (rows * inner), [Q - 1] * (inner * cols)
                elif pattern == 1:
                    a = [int(i % inner == i // inner) for i in range(rows * inner)]
                    b = [rng.randrange(Q) for _ in range(inner * cols)]
                else:
                    a = [rng.randrange(Q) for _ in range(rows * inner)]
                    b = [rng.randrange(Q) for _ in range(inner * cols)]
                raw = request(a, b, rows, inner, cols)
                cases.append(("f0", [raw, b"\xa5" * (rows * cols * 4), b"scratch-canary"]))
                expected.append(reference_product(a, b, rows, inner, cols))
        for args, want, got in zip(cases, expected, self.native.call_many(cases)):
            got.require_returned()
            self.assertEqual(got.value, 0, args[1][0][:4])
            self.assertEqual(got.arguments[1], want, args[1][0][:4])
            self.assertEqual(got.arguments[2], b"scratch-canary")

    def test_rejections_never_modify_outputs(self):
        good = request([1, 2], [3, 4], 1, 2, 1)
        cases = []
        for size in range(4):
            cases.append((good[:size], b"\xa5" * 4, 1))
        cases += [(good[:-1], b"\xa5" * 4, 1), (good + b"x", b"\xa5" * 4, 1),
                  (good, b"\xa5" * 3, 1), (good, b"\xa5" * 5, 1)]
        cases += [(request([1, 2], [3, 4], 1, 2, 1, version), b"\xa5" * 4, 2)
                  for version in (0, 2, 255)]
        for at in range(3):
            for value in (0, 65, 255):
                bad = bytearray(good); bad[at] = value
                cases.append((bytes(bad), b"\xa5" * 4, 4))
        for at in range(4):
            for value in range(Q, 1 << 32):
                bad = bytearray(good); bad[4 + 4 * at:8 + 4 * at] = words([value])
                cases.append((bytes(bad), b"\xa5" * 4, 3))
        calls = [("f0", [raw, output, b"scratch-canary"]) for raw, output, _ in cases]
        for (_, output, expected), got in zip(cases, self.native.call_many(calls)):
            got.require_returned()
            self.assertEqual(got.value, expected)
            self.assertEqual(got.arguments[1:], [output, b"scratch-canary"])


if __name__ == "__main__":
    unittest.main()
