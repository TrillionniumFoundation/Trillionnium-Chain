"""Native RS(6,4) codec against independent polynomial arithmetic and pins."""
from __future__ import annotations

import hashlib
import itertools
from pathlib import Path
import random
import struct
import unittest

try:
    from .native_support import NativeModule
    from .rs46_native import MAX_SOURCE, RS46Native, SOURCE
except ImportError:
    from native_support import NativeModule
    from rs46_native import MAX_SOURCE, RS46Native, SOURCE

GENERATOR = ((1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1),
             (27, 28, 18, 20), (28, 27, 20, 18))
MANIFEST = bytes.fromhex("a58a797159f1411bd6b08afd69729812647137897c0ae9aaf30c7c773d5c8496")


def polynomial_product(a, b):
    """Polynomial long division, independent of native shift/reduce multiplication."""
    value = 0
    for bit in range(8):
        if b >> bit & 1:
            value ^= a << bit
    for degree in range(14, 7, -1):
        if value >> degree & 1:
            value ^= 0x11d << (degree - 8)
    return value


def request(payload, *, shards=None, manifest=MANIFEST, index=0, digest=None):
    digest = hashlib.sha256(payload).digest() if digest is None else digest
    header = (b"HRS1" + bytes((1, int(shards is not None), 0 if shards is None else len(shards), 0))
              + manifest + struct.pack("<II", index, len(payload)) + digest)
    return header + (payload if shards is None else b"".join(shards))


def reference_shards(payload, *, manifest=MANIFEST, index=0, padded=None):
    length = (len(payload) + 3) // 4
    padded = payload + bytes(4 * length - len(payload)) if padded is None else padded
    if len(padded) != 4 * length:
        raise ValueError("Wrong independently encoded padding length")
    data = [padded[i * length:(i + 1) * length] for i in range(4)]
    tables = {coefficient: bytes(polynomial_product(coefficient, value) for value in range(256))
              for coefficients in GENERATOR for coefficient in coefficients}
    rows = list(data)
    for coefficients in GENERATOR[4:]:
        rows.append(bytes(tables[coefficients[0]][data[0][i]]
                          ^ tables[coefficients[1]][data[1][i]]
                          ^ tables[coefficients[2]][data[2][i]]
                          ^ tables[coefficients[3]][data[3][i]] for i in range(length)))
    pin = manifest + struct.pack(">II", index, len(payload)) + hashlib.sha256(payload).digest()
    return [b"CRS1" + pin + bytes((i,)) + struct.pack(">I", length) + row
            for i, row in enumerate(rows)]


def split_shards(wire, source_size):
    length = 81 + (source_size + 3) // 4
    if len(wire) != length * 6:
        raise AssertionError("Native encoded extent differs")
    return [wire[i * length:(i + 1) * length] for i in range(6)]


class Rs46Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = RS46Native()
        cls.scalar = NativeModule(SOURCE)

    @classmethod
    def tearDownClass(cls):
        cls.scalar.close()
        cls.native.close()

    def assert_cases(self, cases, *, batch=32):
        """Rows are input, output size, status, expected output (None=canary)."""
        for start in range(0, len(cases), batch):
            selected = cases[start:start + batch]
            results = self.native.call_many([(raw, size) for raw, size, _, _ in selected])
            for (raw, size, code, want), got in zip(selected, results):
                got.require_returned()
                self.assertEqual(got.value, code, (start, raw[:80].hex()))
                self.assertEqual(got.arguments[1], b"\xa5" * size if want is None else want)

    def test_pinned_selfhost_artifact_and_no_runtime_fallback(self):
        for module in (self.native, self.scalar):
            self.assertTrue(module.receipt["claims"]["self_hosted"])
            self.assertFalse(module.receipt["claims"]["python_emitter_used"])
            self.assertFalse(module.receipt["claims"]["fallback_used"])
            inputs = {row["path"] for row in module.receipt["chain_migration"]["inputs"]}
            self.assertEqual(inputs, {"src/data_availability/rs46.hepta", "components.json",
                                      "src/crypto/sha256_stream.hepta"})

    def test_every_field_product_matches_polynomial_division(self):
        for a0 in range(0, 256, 16):
            pairs = [(a, b) for a in range(a0, a0 + 16) for b in range(256)]
            got = self.scalar.call_many([("rs_mul", [a, b]) for a, b in pairs])
            for (a, b), result in zip(pairs, got):
                self.assertEqual(result.require_returned().value, polynomial_product(a, b), (a, b))

    def test_field_inverse_and_generator(self):
        cases = [("rs_pow", [a, 254]) for a in range(1, 256)]
        for a, got in enumerate(self.scalar.call_many(cases), 1):
            self.assertEqual(polynomial_product(a, got.require_returned().value), 1, a)
        cases = [("rs_coeff", [r, c]) for r in range(6) for c in range(4)]
        expected = [v for row in GENERATOR for v in row]
        self.assertEqual([r.require_returned().value for r in self.scalar.call_many(cases)], expected)

    def test_exact_crs1_vectors_and_non_aligned_data(self):
        payload = bytes((1, 2, 3, 4))
        shards = reference_shards(payload)
        self.assertEqual([s[-1] for s in shards], [1, 2, 3, 4, 0x45, 0x5e])
        self.assertEqual(shards[4].hex(),
                         "43525331a58a797159f1411bd6b08afd69729812647137897c0ae9aaf30c7c773d5c8496"
                         "00000000000000049f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"
                         "040000000145")
        cases = []
        for payload in (payload, b"abcde", b"x"):
            encoded = b"".join(reference_shards(payload))
            cases.append((request(payload), len(encoded), 0, encoded))
        self.assert_cases(cases)

    def test_all_fifteen_four_six_five_and_six_shard_subsets(self):
        payload = bytes(i % 251 for i in range(16401))
        shards = reference_shards(payload, index=16383)
        encoded = b"".join(shards)
        self.assert_cases([(request(payload, index=16383), len(encoded), 0, encoded)])
        cases = []
        for count in (4, 5, 6):
            for subset in itertools.combinations(range(6), count):
                cases.append((request(payload, shards=[shards[i] for i in subset], index=16383),
                              len(payload), 0, payload))
        self.assertEqual(len(cases), 22)
        self.assert_cases(cases)

    def test_small_lengths_padding_and_sha_block_boundaries(self):
        rng = random.Random(0x52533436)
        cases = []
        for size in [*range(1, 21), 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257,
                     4095, 4096, 4097]:
            payload = rng.randbytes(size)
            shards = reference_shards(payload)
            wire = b"".join(shards)
            cases.append((request(payload), len(wire), 0, wire))
            for subset in ((0, 1, 2, 3), (0, 2, 4, 5), (1, 3, 4, 5), (0, 1, 2, 4, 5)):
                cases.append((request(payload, shards=[shards[i] for i in subset]), size, 0, payload))
        self.assert_cases(cases)

    def test_original_four_mib_limit_and_unaligned_maximum(self):
        for size in (MAX_SOURCE - 1, MAX_SOURCE):
            payload = (bytes(range(256)) * ((size + 255) // 256))[:size]
            length = (size + 3) // 4
            got = self.native.call(request(payload, index=16383), 6 * (81 + length), timeout=120)
            self.assertEqual(got.require_returned().value, 0)
            shards = split_shards(got.arguments[1], size)
            self.assertEqual(shards, reference_shards(payload, index=16383))
            selected = [shards[i] for i in (1, 3, 4, 5)]
            got = self.native.call(request(payload, shards=selected, index=16383), size, timeout=120)
            self.assertEqual(got.require_returned().value, 0)
            self.assertEqual(got.arguments[1], payload)

    def test_maximum_six_shard_input_and_late_extra_corruption(self):
        payload = (bytes(range(256)) * ((MAX_SOURCE + 255) // 256))[:MAX_SOURCE]
        shards = reference_shards(payload, index=16383)
        raw = request(payload, shards=shards, index=16383)
        self.assertEqual(len(raw), 6_292_022)
        got = self.native.call(raw, MAX_SOURCE, timeout=120)
        self.assertEqual(got.require_returned().value, 0)
        self.assertEqual(got.arguments[1], payload)

        # The four decoding rows and source hash remain valid. Refusal occurs
        # only at the final byte of the last extra shard, before publication.
        changed = bytearray(raw)
        changed[-1] ^= 1
        got = self.native.call(bytes(changed), MAX_SOURCE, timeout=120)
        self.assertEqual(got.require_returned().value, 10)
        self.assertEqual(got.arguments[1], b"\xa5" * MAX_SOURCE)

    def test_each_wire_byte_mutation_is_rejected_without_output(self):
        payload = b"abcde"
        shards = reference_shards(payload)
        raw = request(payload, shards=shards)
        cases = []
        for offset in range(80, len(raw)):
            changed = bytearray(raw)
            changed[offset] ^= 1
            cases.append(bytes(changed))
        for start in range(0, len(cases), 64):
            batch = cases[start:start + 64]
            for raw, got in zip(batch, self.native.call_many([(raw, len(payload)) for raw in batch])):
                got.require_returned()
                self.assertNotEqual(got.value, 0, raw.hex())
                self.assertEqual(got.arguments[1], b"\xa5" * len(payload))

    def test_required_corruption_and_extra_parity_retain_distinct_errors(self):
        payload = bytes(range(64))
        good = reference_shards(payload)
        cases = []
        for index in range(6):
            bad = [bytearray(s) for s in good]
            bad[index][81] ^= 1
            cases.append((request(payload, shards=[bytes(s) for s in bad]), len(payload),
                          9 if index < 4 else 10, None))
        for subset in ((0, 1, 4, 5), (0, 2, 4, 5), (1, 3, 4, 5)):
            chosen = [bytearray(good[i]) for i in subset]
            chosen[-1][-1] ^= 1
            cases.append((request(payload, shards=[bytes(s) for s in chosen]), len(payload), 9, None))
        self.assert_cases(cases)

    def test_nonzero_padding_fails_before_hash_even_with_consistent_parity(self):
        cases = []
        for payload in (b"x", b"abcde", b"abcdef"):
            extent = 4 * ((len(payload) + 3) // 4)
            for offset in range(len(payload), extent):
                padded = bytearray(payload + bytes(extent - len(payload)))
                padded[offset] = 1
                shards = reference_shards(payload, padded=padded)
                for subset in itertools.combinations(range(6), 4):
                    cases.append((request(payload, shards=[shards[i] for i in subset]),
                                  len(payload), 8, None))
        self.assert_cases(cases)

    def test_strict_order_duplicate_and_count_refusals(self):
        payload = b"abcde"
        shards = reference_shards(payload)
        cases = []
        for subset in ((0, 1, 2, 2), (3, 2, 1, 0), (0, 2, 1, 5), (0, 1, 1, 4, 5),
                       (0, 1, 2, 4, 3, 5)):
            cases.append((request(payload, shards=[shards[i] for i in subset]), len(payload), 6, None))
        for count in (0, 1, 2, 3, 7, 255):
            raw = bytearray(request(payload, shards=shards))
            raw[6] = count
            cases.append((bytes(raw), len(payload), 4, None))
        raw = bytearray(request(payload))
        raw[6] = 1
        cases.append((bytes(raw), 498, 4, None))
        self.assert_cases(cases)

    def test_context_source_hash_and_header_pins_are_checked(self):
        payload = b"abcde"
        shards = reference_shards(payload)
        cases = []
        for offset in (*range(8, 40), *range(48, 80), 40):
            raw = bytearray(request(payload, shards=shards))
            raw[offset] ^= 1
            cases.append((bytes(raw), len(payload), 7, None))
        bad_hash = bytearray(request(payload))
        bad_hash[48] ^= 1
        cases.append((bytes(bad_hash), 498, 9, None))
        bad_data = bytearray(request(payload))
        bad_data[-1] ^= 1
        cases.append((bytes(bad_data), 498, 9, None))
        self.assert_cases(cases)

    def test_malformed_wrappers_shapes_lengths_and_extents(self):
        payload = b"abcde"
        shards = reference_shards(payload)
        base = request(payload, shards=shards)
        cases = [(base[:i], 5, 1, None) for i in range(80)]
        for offset in (0, 1, 2, 3, 4, 7):
            bad = bytearray(base)
            bad[offset] ^= 1
            cases.append((bytes(bad), 5, 1, None))
        for operation in (2, 127, 255):
            bad = bytearray(base); bad[5] = operation
            cases.append((bytes(bad), 5, 1, None))
        for size in (0, MAX_SOURCE + 1, 0xffffffff):
            bad = bytearray(base); bad[44:48] = struct.pack("<I", size)
            cases.append((bytes(bad), 5, 2, None))
        for index in (16384, 0xffffffff):
            bad = bytearray(base); bad[40:44] = struct.pack("<I", index)
            cases.append((bytes(bad), 5, 3, None))
        for size in (80, 81, 162, len(base) - 1):
            cases.append((base[:size], 5, 1, None))
        cases.extend([(base + b"x", 5, 1, None), (base, 4, 1, None), (base, 6, 1, None)])
        for value, offset in ((0, 40), (MAX_SOURCE + 1, 40), (16384, 36), (0xffffffff, 36),
                              (0, 77), (3, 77)):
            bad = bytearray(base); bad[80 + offset:84 + offset] = struct.pack(">I", value)
            cases.append((bytes(bad), 5, 5, None))
        self.assert_cases(cases, batch=16)
        for scratch_length in (0, 1, 4096, 4103):
            got = self.native.call(base, 5, scratch_length=scratch_length)
            self.assertEqual(got.require_returned().value, 1)
            self.assertEqual(got.arguments[1], b"\xa5" * 5)

    def test_direct_and_selfhost_compilers_agree_on_exact_wire_and_recovery(self):
        payload = bytes(range(251)) + b"partial"
        shards = reference_shards(payload)
        cases = [(request(payload), 6 * len(shards[0]), b"".join(shards))]
        for count in (4, 5, 6):
            for subset in itertools.combinations(range(6), count):
                cases.append((request(payload, shards=[shards[i] for i in subset]), len(payload), payload))
        with NativeModule(SOURCE, byte_exports=("f0",), backend="direct") as direct:
            rows = [("f0", [raw, b"\xa5" * size, b"\x5a" * (4096 + 4 * ((len(payload) + 3) // 4))])
                    for raw, size, _ in cases]
            for (_, _, expected), got in zip(cases, direct.call_many(rows)):
                self.assertEqual(got.require_returned().value, 0)
                self.assertEqual(got.arguments[1], expected)


if __name__ == "__main__":
    unittest.main()
