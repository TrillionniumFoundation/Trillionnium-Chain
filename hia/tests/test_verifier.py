"""Complete non-cancelling PNW1 relation against an independent exact oracle.

The oracle forms C directly as A*B. HIA reconstructs C using the two noise
corrections, so a shared denoising mistake cannot manufacture agreement.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import random
import struct
import unittest

try:
    from .native_support import NativeModule
except ImportError:
    from native_support import NativeModule

Q = (1 << 32) - 5
N = 64
R = 8
SCRATCH_BYTES = 259232
SOURCE = Path(__file__).resolve().parents[1] / "src" / "work" / "verify.hepta"


def packed(values):
    return struct.pack("<" + "I" * len(values), *values)


def tagged(tag, *parts):
    wire = b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
    wire += b"".join(struct.pack("<I", len(part)) + part for part in parts)
    return hashlib.sha256(wire).digest()


def multiply(a, b, rows, inner, cols):
    return [sum(a[i * inner + k] * b[k * cols + j] for k in range(inner)) % Q
            for i in range(rows) for j in range(cols)]


def noise(challenge, label):
    values = []
    for counter in range(128):
        block = tagged(b"noise", challenge, bytes([label]), struct.pack("<I", counter))
        for value in struct.unpack("<8I", block):
            if value < Q:
                values.append(value)
                if len(values) == N * R:
                    return values
    raise AssertionError("Independent reference reached the original NoiseBudget limit")


def original_scalar_proof(challenge, a, b):
    e = multiply(noise(challenge, 0), noise(challenge, 1), N, R, N)
    f = multiply(noise(challenge, 2), noise(challenge, 3), N, R, N)
    ap = [(x + y) % Q for x, y in zip(a, e)]
    bp = [(x + y) % Q for x, y in zip(b, f)]
    cp = [0] * (N * N)
    trace = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    for bi in range(N // R):
        for bj in range(N // R):
            for bk in range(N // R):
                for i in range(bi * R, (bi + 1) * R):
                    for j in range(bj * R, (bj + 1) * R):
                        index = i * N + j
                        cp[index] = (cp[index] + sum(ap[i * N + k] * bp[k * N + j]
                                                    for k in range(bk * R, (bk + 1) * R))) % Q
                        trace.update(struct.pack("<I", cp[index]))
    product = packed(multiply(a, b, N, N, N))
    return b"PNW1" + packed(a) + packed(b) + product + trace.digest(), product


def framed(challenge, proof, task=None, target=b"\xff" * 32):
    if task is None:
        task = tagged(b"task", proof[4:16388], proof[16388:32772])
    return challenge + task + target + proof


class CompleteVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))
        rng = random.Random(0x504E57316408)
        fixtures = [
            (bytes(32), [0] * 4096, [Q - 1] * 4096),
            (bytes(range(32)), [int(i // N == i % N) for i in range(4096)],
             [rng.randrange(Q) for _ in range(4096)]),
            (b"\xff" * 32, [Q - 1 - i % 257 for i in range(4096)],
             [(i * 65537 + 258) % Q for i in range(4096)]),
        ]
        cls.fixtures = [(ch, *original_scalar_proof(ch, a, b)) for ch, a, b in fixtures]

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def invoke(self, rows):
        # rows: request, expected WorkError code, product on success.
        canary = b"\xa5" * 16384
        tail = b"unmodified-workspace-tail"
        calls = [("f0", [raw, canary, bytes(SCRATCH_BYTES) + tail]) for raw, _, _ in rows]
        answers = self.native.call_many(calls, timeout=60)
        for (raw, code, product), answer in zip(rows, answers):
            answer.require_returned()
            self.assertEqual(answer.value, code, (len(raw), raw[:8].hex()))
            self.assertEqual(answer.arguments[1], product if code == 0 else canary)
            self.assertEqual(answer.arguments[2][SCRATCH_BYTES:], tail)

    def test_complete_relation_and_product(self):
        self.invoke([(framed(ch, proof), 0, product) for ch, proof, product in self.fixtures])

    def test_original_error_order_and_late_refusals(self):
        ch, proof, product = self.fixtures[1]
        valid = framed(ch, proof)
        rows = [(valid[:-1], 1, None), (valid + b"x", 1, None)]
        broken = bytearray(proof); broken[0] ^= 1
        rows.append((framed(ch, bytes(broken), target=bytes(32)), 2, None))
        rows.append((framed(ch, proof, target=bytes(32)), 7, None))
        for offset in (4, 16384, 16388, 32768, 32772, 49152):
            broken = bytearray(proof); broken[offset:offset + 4] = struct.pack("<I", Q)
            rows.append((framed(ch, bytes(broken), task=bytes(32)), 3, None))
            rows.append((framed(ch, bytes(broken), target=bytes(32)), 7, None))
        rows.append((framed(ch, proof, task=bytes(32), target=b"\x01" + bytes(31)), 4, None))
        # Exact target equality passes. Decrementing the big-endian target
        # rejects before the expensive relation replay.
        ticket = tagged(b"ticket", ch, proof[-32:])
        rows.append((framed(ch, proof, target=ticket), 0, product))
        smaller = (int.from_bytes(ticket, "big") - 1).to_bytes(32, "big")
        rows.append((framed(ch, proof, target=smaller), 7, None))
        trace_bad = bytearray(proof); trace_bad[-1] ^= 1
        rows.append((framed(ch, bytes(trace_bad)), 5, None))
        product_bad = bytearray(proof)
        value = struct.unpack_from("<I", product_bad, 32772)[0]
        struct.pack_into("<I", product_bad, 32772, (value + 1) % Q)
        rows.append((framed(ch, bytes(product_bad)), 6, None))
        product_bad[-1] ^= 1
        rows.append((framed(ch, bytes(product_bad)), 5, None))
        changed_challenge = bytes([ch[0] ^ 1]) + ch[1:]
        rows.append((framed(changed_challenge, proof), 5, None))
        self.invoke(rows)

    def test_abi_extent_refusals_leave_all_bytes_unchanged(self):
        ch, proof, _ = self.fixtures[0]
        raw = framed(ch, proof)
        calls = [
            ("f0", [raw, b"\xa5" * 16383, bytes(SCRATCH_BYTES)]),
            ("f0", [raw, b"\xa5" * 16385, bytes(SCRATCH_BYTES)]),
            ("f0", [raw, b"\xa5" * 16384, bytes(SCRATCH_BYTES - 1)]),
            ("f0", [b"", b"\xa5" * 16384, bytes(SCRATCH_BYTES)]),
        ]
        for (_, arguments), result in zip(calls, self.native.call_many(calls)):
            self.assertEqual(result.require_returned().value, 1)
            self.assertEqual(result.arguments, arguments)

    def test_dense_relation_with_nonzero_scratch_and_late_product_refusal(self):
        # Both factors are independent dense matrices. Initial scratch must not
        # supply any implicit zero matrix, hash padding, or accumulator value.
        rng = random.Random(0x64656E73655731)
        challenge = bytes(rng.randrange(256) for _ in range(32))
        a = [rng.randrange(Q) for _ in range(N * N)]
        b = [rng.randrange(Q) for _ in range(N * N)]
        proof, product = original_scalar_proof(challenge, a, b)
        canary = bytes((i * 19 + 37) & 255 for i in range(16384))
        tail = b"independent-review-workspace-guard"
        varied = bytes((i * 29 + i // 251 + 90) & 255 for i in range(SCRATCH_BYTES))
        rows = [
            (framed(challenge, proof), 0, b"\xa5" * SCRATCH_BYTES),
            (framed(challenge, proof), 0, varied),
        ]
        # Refusal at the last product word still must leave the whole output
        # unchanged; row-boundary cells additionally detect indexing mistakes.
        for cell in (63, 64, N * N - 1):
            wrong = bytearray(proof)
            offset = 4 + 2 * N * N * 4 + cell * 4
            value = struct.unpack_from("<I", wrong, offset)[0]
            struct.pack_into("<I", wrong, offset, (value + 1) % Q)
            rows.append((framed(challenge, bytes(wrong)), 6, varied))
        calls = [("f0", [raw, canary, scratch + tail]) for raw, _, scratch in rows]
        answers = self.native.call_many(calls, timeout=60)
        self.assertEqual(len(answers), len(rows))
        for (raw, expected, _), answer in zip(rows, answers):
            with self.subTest(expected=expected, request_sha=hashlib.sha256(raw).hexdigest()):
                answer.require_returned()
                self.assertEqual(answer.value, expected)
                self.assertEqual(answer.arguments[0], raw)
                self.assertEqual(answer.arguments[1], product if expected == 0 else canary)
                self.assertEqual(answer.arguments[2][SCRATCH_BYTES:], tail)

    def test_target_uses_first_differing_big_endian_byte(self):
        challenge, proof, product = self.fixtures[2]
        ticket = tagged(b"ticket", challenge, proof[-32:])
        rows = []
        for position in (0, 1, 7, 15, 30, 31):
            prefix = ticket[:position]
            if ticket[position] > 0:
                # The maximal suffix cannot reverse an earlier smaller byte.
                smaller = prefix + bytes([ticket[position] - 1]) + b"\xff" * (31 - position)
                self.assertLess(smaller, ticket)
                rows.append((framed(challenge, proof, target=smaller), 7, None))
            if ticket[position] < 255:
                # The minimal suffix cannot reverse an earlier larger byte.
                larger = prefix + bytes([ticket[position] + 1]) + bytes(31 - position)
                self.assertGreater(larger, ticket)
                rows.append((framed(challenge, proof, target=larger), 0, product))
        self.invoke(rows)


if __name__ == "__main__":
    unittest.main()
