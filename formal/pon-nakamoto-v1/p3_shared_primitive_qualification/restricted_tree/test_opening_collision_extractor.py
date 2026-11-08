#!/usr/bin/env python3
"""Falsifying controls for a structural extractor, never a security estimate."""
import hashlib
import unittest
from opening_collision_extractor import (
    BRANCH_TAG, GOLDILOCKS, LEAF_TAG, Collision, Context, Opening, Recorder,
    evaluate, extract_collision, verify_collision,
)


def row_byte_hash(message: bytes) -> bytes:
    """Intentionally broken toy: different leaves, colliding every branch."""
    if message.startswith(LEAF_TAG):
        return message[-8:-7]
    if message.startswith(BRANCH_TAG):
        return b"\xff"
    raise ValueError("unknown test role")


class ExtractionTests(unittest.TestCase):
    def test_leaf_collision_height_zero(self):
        c = Context(b"toy", 0, 0, 1, 1)
        function = lambda _: b"\x00"
        witness = extract_collision(c, b"\x00", Opening((1,), ()), Opening((2,), ()), function)
        self.assertEqual((witness.level, witness.role, witness.hash_calls), (0, "leaf", 2))
        self.assertTrue(verify_collision(witness, function))

    def test_branch_first_merge_all_positions_arbitrary_siblings(self):
        for height in (1, 2, 3):
            for index in range(1 << height):
                c = Context(b"toy", height, index, 1, 1)
                a = Opening((1,), tuple(bytes([17 + j]) for j in range(height)))
                b = Opening((2,), tuple(bytes([231 - j]) for j in range(height)))
                witness = extract_collision(c, b"\xff", a, b, row_byte_hash)
                self.assertEqual((witness.level, witness.role), (1, "branch"))
                self.assertEqual(witness.hash_calls, 2 * (height + 1))
                self.assertTrue(verify_collision(witness, row_byte_hash))
                self.assertNotEqual(witness.message0, witness.message1)

    def test_late_branch_merge(self):
        c = Context(b"toy", 2, 2, 1, 1)
        a, b = Opening((1,), (b"\x03", b"\x09")), Opening((2,), (b"\x04", b"\x0a"))
        def broken(message):
            if message.startswith(LEAF_TAG):
                return message[-8:-7]
            pair = message[-2:]
            if pair in (b"\x09\x05", b"\x0a\x06"):
                return b"\xaa"
            return {b"\x01\x03": b"\x05", b"\x02\x04": b"\x06"}[pair]
        witness = extract_collision(c, b"\xaa", a, b, broken)
        self.assertEqual((witness.level, witness.hash_calls), (2, 6))
        self.assertTrue(verify_collision(witness, broken))

    def test_sha3_control_valid_path_and_rejected_conflict(self):
        c = Context(b"sha3-control", 2, 1, 2, 64)
        function = lambda message: hashlib.sha3_512(message).digest()
        a = Opening((1, 2), (b"\x00" * 64, b"\xff" * 64))
        root = evaluate(c, a, function)[-1].digest
        self.assertEqual(len(root), 64)
        b = Opening((1, 3), a.siblings)
        with self.assertRaisesRegex(ValueError, "both openings must be accepted"):
            extract_collision(c, root, a, b, function)
        with self.assertRaisesRegex(ValueError, "distinct rows"):
            extract_collision(c, root, a, a, function)

    def test_canonical_leaf_encoding_and_role_framing(self):
        c = Context(b"test", 0, 0, 2, 64)
        encoded = c.leaf_input((1, GOLDILOCKS - 1))
        self.assertTrue(encoded.endswith((1).to_bytes(8, "little") + (GOLDILOCKS - 1).to_bytes(8, "little")))
        self.assertNotEqual(encoded, c.branch_input(b"\x00" * 64, b"\x00" * 64))
        for invalid in (-1, GOLDILOCKS, True):
            with self.assertRaisesRegex(ValueError, "canonical Goldilocks"):
                c.leaf_input((1, invalid))
        with self.assertRaisesRegex(ValueError, "leaf width"):
            c.leaf_input((1,))
        with self.assertRaisesRegex(ValueError, "outside"):
            Context(b"x", 0, 1, 1, 1).validate()
        with self.assertRaisesRegex(ValueError, "path length"):
            evaluate(Context(b"x", 1, 0, 1, 1), Opening((1,), ()), row_byte_hash)

    def test_output_truncation_and_nondeterminism_rejected(self):
        recorder = Recorder(lambda _: b"\x00" * 32, 64)
        with self.assertRaisesRegex(ValueError, "complete declared output"):
            recorder(b"x")
        n = iter((b"\x00", b"\x01"))
        recorder = Recorder(lambda _: next(n), 1)
        recorder(b"x")
        with self.assertRaisesRegex(ValueError, "not deterministic"):
            recorder(b"x")


if __name__ == "__main__":
    unittest.main()
