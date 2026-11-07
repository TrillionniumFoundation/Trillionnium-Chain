"""Reduced-fixture byte scopes, real SHA continuation and stale-cache controls."""
from dataclasses import replace
import hashlib
import struct
import unittest
from unittest.mock import patch

from test_w1_quantum_oracle import fixture
from w1_quantum_oracle import FixedTemplate, OracleProgram, Shape, h_bytes
from w1_quantum_primitives import digest_bytes
from w1_quantum_restricted_oracle import PrefixRestrictedProgram
import w1_preprocessing_reuse as reuse


def changed_header(template, offset):
    header = bytearray(template.header)
    header[offset] ^= 1
    return FixedTemplate.from_header(bytes(header), template.a, template.b,
                                     template.nonce_bits, template.shape)


def changed_task(template):
    b = ((template.b[0] + 1) % template.shape.q,) + template.b[1:]
    field = lambda values: struct.pack("<" + "I" * len(values), *values)
    header = bytearray(template.header)
    offset = 278 + (4 if template.profile == "PGH2" else 0)
    header[offset:offset + 32] = hashlib.sha256(h_bytes(b"task", field(template.a), field(b))).digest()
    return FixedTemplate.from_header(bytes(header), template.a, b,
                                     template.nonce_bits, template.shape)


def wire_fields(template, nonce):
    # Independent decode in Rust Header::encode order; do not reuse mutation offsets.
    header = template.header_for(nonce)[4:] if template.profile == "PGH2" else template.header_for(nonce)
    names = ("magic version network parameters parent height timestamp target miner "
             "transactions state receipts work_task nonce").split()
    fields = dict(zip(names, struct.unpack("<4sH" + "32s" * 3 + "QQ" + "32s" * 6 + "Q", header[:318])))
    return {**fields, "profile": template.profile, "witness": header[318:]}


class PreprocessingReuseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plain = p = fixture(nonce_bits=2)
        cls.growth = g = fixture(profile="PGH2", nonce_bits=2)
        # Expected block counts follow the wire field offsets, not the diagnostic.
        cls.cases = (
            ("nonce", p, p, 1, 5, True),
            ("parent", p, changed_header(p, 70), 0, 1, True),
            ("target", p, changed_header(p, 118), 0, 2, True),
            ("timestamp", p, changed_header(p, 110), 0, 2, True),
            ("profile", p, g, 0, 0, True),
            ("growth_witness", g, changed_header(g, 322), 0, 5, True),
            ("task_PNH1", p, changed_task(p), 0, 4, False),
            ("task_PGH2", g, changed_task(g), 0, 5, False),
        )

    def test_eight_changes_reuse_only_equal_prefix_and_continue_full_hash(self):
        for name, left, right, nonce, blocks, same_task in self.cases:
            with self.subTest(case=name):
                before, after = wire_fields(left, 0), wire_fields(right, nonce)
                expected_fields = {"profile": {"profile", "witness"}, "growth_witness": {"witness"},
                                   "task_PNH1": {"work_task"}, "task_PGH2": {"work_task"}}.get(name, {name})
                self.assertEqual({field for field in before if before[field] != after[field]}, expected_fields)
                report = reuse.compare_preprocessing(left, right, right_nonce=nonce)
                expected = hashlib.sha256(h_bytes(right.challenge_tag, right.header_for(nonce))).hexdigest()
                self.assertEqual(report["matching_fixed_prefix_blocks"], blocks)
                self.assertEqual(report["fixed_five_block_input_equal"], blocks == 5)
                self.assertEqual(report["ab_inputs_equal"], same_task)
                self.assertEqual(report["task_commitment_input_equal"], same_task)
                self.assertFalse(report["challenge_input_equal"])
                self.assertNotEqual(report["left_challenge_sha256"], expected)
                self.assertEqual(report["resumed_challenge_sha256"], expected)
                self.assertEqual(report["expected_challenge_sha256"], expected)
                self.assertTrue(report["continuation_matches_hashlib"])
                total_blocks = 6 if right.profile == "PNH1" else 7
                self.assertEqual(report["sha_compressions_after_checkpoint"], total_blocks - blocks)
                self.assertTrue(all(value is False for value in report["claims"].values()))

    def test_identity_and_actual_full_restricted_hashplan_checkpoints(self):
        for template in (self.plain, self.growth):
            report = reuse.compare_preprocessing(template, template)
            self.assertTrue(report["challenge_input_equal"])
            self.assertTrue(report["ab_inputs_equal"])
            self.assertTrue(report["task_commitment_input_equal"])
            self.assertEqual(report["matching_fixed_prefix_blocks"], 5)
            self.assertEqual(report["left_five_block_chaining_state_hex"],
                             report["right_five_block_chaining_state_hex"])
            for program_type in (OracleProgram, PrefixRestrictedProgram):
                with self.subTest(profile=template.profile, program=program_type.__name__):
                    program = program_type(template)  # Construction only; no execute/resources call.
                    self.assertEqual(program.challenge.precomputed_blocks, 5)
                    self.assertEqual(digest_bytes(program.challenge.initial).hex(),
                                     report["left_five_block_chaining_state_hex"])
                    self.assertEqual(len(program.challenge.messages),
                                     report["sha_compressions_after_checkpoint"])

    def test_unguarded_stale_five_block_checkpoint_fails_changed_prefix_controls(self):
        for name, left, right, nonce, blocks, _ in self.cases:
            if blocks == 5:
                continue
            with self.subTest(case=name):
                old_frame = h_bytes(left.challenge_tag, left.header_for(0))
                new_frame = h_bytes(right.challenge_tag, right.header_for(nonce))
                stale = reuse._continue(new_frame, reuse._prefix_states(old_frame)[5], 5)
                self.assertNotEqual(stale, hashlib.sha256(new_frame).digest())

    def test_rejects_forged_canonical_metadata_nonce_field_and_task_binding(self):
        p = self.plain
        header = p.header[:118] + (1).to_bytes(32, "big") + p.header[150:]
        target_one = FixedTemplate.from_header(header, p.a, p.b, p.nonce_bits, p.shape)
        forged = (None, replace(p, target=True), replace(p, target=p.target - 1),
                  replace(target_one, target=True),  # True == 1 must not pass canonical checking.
                  replace(p, profile="PGH2"), replace(p, challenge_tag=b"wrong"),
                  replace(p, challenge_tag=bytearray(p.challenge_tag)),
                  replace(p, nonce_offset=1), replace(p, nonce_offset=float(p.nonce_offset)),
                  replace(p, a=list(p.a)), replace(p, b=((p.b[0] + 1) % p.shape.q,)),
                  replace(p, header=p.header_for(1)), replace(p, nonce_bits=True),
                  replace(p, shape=object()))
        for value in forged:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    reuse.compare_preprocessing(value, p)
                with self.assertRaises(ValueError):
                    reuse.compare_preprocessing(p, value)

    def test_rejects_bad_nonces_on_both_sides(self):
        for nonce in (-1, 4, True, 0.0, "0"):
            with self.subTest(nonce=nonce):
                with self.assertRaises(ValueError):
                    reuse.compare_preprocessing(self.plain, self.plain, left_nonce=nonce)
                with self.assertRaises(ValueError):
                    reuse.compare_preprocessing(self.plain, self.plain, right_nonce=nonce)

    def test_ab_depends_on_modulus_but_task_hash_does_not(self):
        p = self.plain
        for shape, same_ab in ((Shape(1, 1, 5, 1), False), (Shape(1, 1, 4, 2), True)):
            other = FixedTemplate.from_header(p.header, p.a, p.b, p.nonce_bits, shape)
            report = reuse.compare_preprocessing(p, other)
            self.assertEqual(report["ab_inputs_equal"], same_ab)
            self.assertTrue(report["task_commitment_input_equal"])
            self.assertTrue(report["challenge_input_equal"])

    def test_continuation_mismatch_fails_closed(self):
        with patch.object(reuse, "_continue", return_value=b"wrong"):
            with self.assertRaisesRegex(ValueError, "PREPROCESS_SHA_CONTINUATION_MISMATCH"):
                reuse.compare_preprocessing(self.plain, self.growth)


if __name__ == "__main__":
    unittest.main()
