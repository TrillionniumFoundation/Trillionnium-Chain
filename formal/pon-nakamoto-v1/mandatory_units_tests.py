"""Whole-relation, native differential and exact-query controls for MU1.

Run with MU1_NATIVE_WORK and MU1_NATIVE_PREPARED naming the built existing
pon_work_io and pon_zero_io examples.  A missing required native bridge is an
explicit failure, never a skipped successful substitute.
"""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from functools import lru_cache
from math import comb
import os
from pathlib import Path
import struct
import unittest

import mandatory_units_query as query
import mandatory_units_relation as mu
import mandatory_units_vectors as vectors


@lru_cache(maxsize=1)
def bridges() -> tuple[Path, Path]:
    result = []
    for variable in ("MU1_NATIVE_WORK", "MU1_NATIVE_PREPARED"):
        path = os.environ.get(variable)
        if path is None or not Path(path).is_file():
            raise RuntimeError(variable + " must name the existing, built native example")
        result.append(Path(path))
    return tuple(result)


@lru_cache(maxsize=1)
def fixtures() -> tuple[vectors.Vector, ...]:
    return vectors.build_vectors(bridges()[1])


class ContextContractTests(unittest.TestCase):
    def setUp(self):
        self.c = vectors.make_context((vectors.label("task-A"), vectors.label("task-B")))

    def test_canonical_context_roundtrip_and_exact_extent(self):
        raw = mu.encode_context(self.c)
        self.assertEqual(len(raw), 368 + 32 * 2)
        self.assertEqual(mu.decode_context(raw), self.c)
        for altered in (raw[:-1], raw + b"\0"):
            with self.assertRaisesRegex(mu.RelationError, "CONTEXT_LENGTH"):
                mu.decode_context(altered)

    def test_every_declared_context_field_changes_both_unit_challenges(self):
        original = tuple(mu.unit_challenge(self.c, j) for j in range(2))
        changes = {
            name: vectors.label("different-" + name)
            for name in ("network", "chain_parameters", "window_anchor", "parent",
                         "miner", "tx_root", "state_root", "receipts_root")
        }
        changes.update(window_start_height=99, window_end_height=201,
                       height=145, timestamp=self.c.timestamp + 1, nonce=1,
                       tasks=tuple(reversed(self.c.tasks)))
        for name, value in changes.items():
            with self.subTest(field=name):
                altered = replace(self.c, **{name: value})
                self.assertNotEqual(mu.context_digest(altered), mu.context_digest(self.c))
                for j in range(2):
                    self.assertNotEqual(mu.unit_challenge(altered, j), original[j])

    def test_target_profile_and_version_are_fixed(self):
        self.assertEqual(int.from_bytes(mu.T0, "big"), (1 << 252) - 1)
        self.assertEqual(Fraction(int.from_bytes(mu.T0, "big") + 1, 1 << 256), Fraction(1, 16))
        for c, error in (
            (replace(self.c, target=mu.UNIT_TARGET), "FIXED_TARGET"),
            (replace(self.c, target=bytes(32)), "FIXED_TARGET"),
            (replace(self.c, relation_parameters=vectors.label("other-profile")), "RELATION_PARAMETERS"),
        ):
            with self.subTest(error=error), self.assertRaisesRegex(mu.RelationError, error):
                mu.encode_context(c)
        raw = mu.encode_context(self.c)
        for old in (b"PNH1", b"PMH2"):
            with self.assertRaisesRegex(mu.RelationError, "CONTEXT_VERSION"):
                mu.decode_context(old + raw[4:])

    def test_u_limits_and_noncanonical_python_types_are_refused(self):
        for tasks in ((), tuple([self.c.tasks[0]] * 9), list(self.c.tasks)):
            with self.subTest(tasks=len(tasks)), self.assertRaisesRegex(mu.RelationError, "UNIT_COUNT"):
                mu.encode_context(replace(self.c, tasks=tasks))
        for value in (True, -1, 1 << 64, 1.5):
            with self.subTest(value=value), self.assertRaisesRegex(mu.RelationError, "CONTEXT_U64"):
                mu.encode_context(replace(self.c, nonce=value))
        with self.assertRaisesRegex(mu.RelationError, "TASK_HASH"):
            mu.encode_context(replace(self.c, tasks=(b"short",)))

    def test_window_membership_is_checked_but_anchor_authenticity_is_not_claimed(self):
        for height in (99, 201):
            with self.assertRaisesRegex(mu.RelationError, "HEIGHT_WINDOW"):
                mu.encode_context(replace(self.c, height=height))
        for height in (100, 200):
            self.assertEqual(mu.decode_context(mu.encode_context(replace(self.c, height=height))).height,
                             height)

    def test_task_repetition_is_legal_but_unit_addresses_are_distinct(self):
        repeated = replace(self.c, tasks=tuple([self.c.tasks[0]] * 8))
        self.assertEqual(len({mu.unit_challenge(repeated, i) for i in range(8)}), 8)
        self.assertEqual(mu.MAX_CREDIT, 128)
        self.assertEqual(mu.MAX_PACKET_BYTES, 394406)


class CompleteRelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native, cls.prepared = bridges()
        cls.rows = fixtures()
        cls.two = cls.rows[1]

    def test_all_five_winning_envelopes_pass_scalar_and_native_complete_verifiers(self):
        for vector in self.rows:
            with self.subTest(vector=vector.name):
                scalar = mu.verify_packet(vector.packet, vector.context)
                native = mu.verify_packet(vector.packet, vector.context, backend="native",
                                          native_verifier=self.native)
                self.assertEqual(scalar, native)
                self.assertEqual(scalar.credit, 16 * vector.context.units)
                self.assertEqual(scalar.packet_bytes, 374 + 49254 * vector.context.units)
                self.assertFalse(any(row["winner"] for row in vector.attempts[:-1]))
                self.assertTrue(vector.attempts[-1]["winner"])

    def test_fresh_prepared_scalar_and_native_encodings_are_byte_identical(self):
        for vector in self.rows:
            for backend, path in (("scalar-fresh", None), ("scalar-prepared", None),
                                  ("native-fresh", self.native), ("native-prepared", self.prepared)):
                with self.subTest(vector=vector.name, backend=backend):
                    self.assertEqual(mu.produce_packet(vector.context, vector.material,
                                                       backend=backend, native_prover=path),
                                     vector.packet)

    def test_subunit_tickets_are_not_extra_lottery_gates(self):
        missed = 0
        for vector in self.rows:
            parsed = mu.inspect_packet(vector.packet, vector.context)
            for j, proof in enumerate(parsed.proofs):
                unit_ticket = mu.w1_hash("ticket", mu.unit_challenge(vector.context, j), proof[-32:])
                if unit_ticket > mu.T0:
                    missed += 1
                    with self.assertRaisesRegex(ValueError, "TARGET"):
                        mu.w1.verify(mu.unit_challenge(vector.context, j), vector.context.tasks[j],
                                     mu.T0, proof)
        self.assertGreater(missed, 0)

    def test_full_size_negative_controls_reject_with_exact_scalar_reasons(self):
        for name, context, raw, reason in vectors.mutations(self.two):
            with self.subTest(control=name), self.assertRaisesRegex(mu.RelationError, "^" + reason + "$"):
                mu.verify_packet(raw, context)

    def test_native_complete_relation_rejects_the_same_unit_tampering(self):
        for name, context, raw, reason in vectors.mutations(self.two):
            if reason.startswith("W1_"):
                with self.subTest(control=name), self.assertRaisesRegex(mu.RelationError, "^NATIVE_W1_INVALID$"):
                    mu.verify_packet(raw, context, backend="native", native_verifier=self.native)

    def test_expected_context_cannot_be_supplied_by_untrusted_packet(self):
        changed = replace(self.two.context, nonce=self.two.context.nonce + 1)
        with self.assertRaisesRegex(mu.RelationError, "EXPECTED_CONTEXT"):
            mu.verify_packet(self.two.packet, changed)

    def test_a_valid_prefix_is_not_a_valid_smaller_u_attempt(self):
        vector = self.rows[3]
        parsed = mu.inspect_packet(vector.packet, vector.context)
        c = replace(vector.context, tasks=vector.context.tasks[:4])
        raw = mu.encode_packet(c, parsed.proofs[:4])
        with self.assertRaisesRegex(mu.RelationError, "W1_TRANSCRIPT"):
            mu.verify_packet(raw, c)

    def test_task_order_is_part_of_the_whole_attempt(self):
        vector = self.rows[4]
        parsed = mu.inspect_packet(vector.packet, vector.context)
        c = replace(vector.context, tasks=tuple(reversed(vector.context.tasks)))
        raw = mu.encode_packet(c, tuple(reversed(parsed.proofs)))
        with self.assertRaisesRegex(mu.RelationError, "W1_TRANSCRIPT"):
            mu.verify_packet(raw, c)

    def test_repeated_packet_adds_no_unique_credit(self):
        book = mu.UniqueWorkCounter()
        self.assertEqual(book.admit(self.two.packet, self.two.context), 32)
        self.assertEqual(book.admit(self.two.packet, self.two.context), 0)
        other = self.rows[0]
        self.assertEqual(book.admit(other.packet, other.context), 16)
        self.assertEqual(book.total_credit, 48)
        with self.assertRaisesRegex(mu.RelationError, "PACKET_LENGTH"):
            book.admit(self.two.packet + b"\0", self.two.context)
        self.assertEqual(book.total_credit, 48)

    def test_preparation_reuse_is_real_and_transcript_reuse_is_not(self):
        vector = self.two
        self.assertIs(vector.material[0], vector.material[1])
        parsed = mu.inspect_packet(vector.packet, vector.context)
        self.assertEqual(parsed.proofs[0][:-32], parsed.proofs[1][:-32])
        self.assertNotEqual(parsed.proofs[0][-32:], parsed.proofs[1][-32:])
        other = replace(vector.context, nonce=vector.context.nonce + 1)
        later = mu.produce_packet(other, vector.material, backend="scalar-prepared")
        second = mu.inspect_packet(later, other)
        self.assertEqual(parsed.proofs[0][:-32], second.proofs[0][:-32])
        self.assertNotEqual(parsed.proofs[0][-32:], second.proofs[0][-32:])
        # This checks the full W1 relation even if the later aggregate ticket loses.
        for j, proof in enumerate(second.proofs):
            mu.w1.verify(mu.unit_challenge(other, j), other.tasks[j], mu.UNIT_TARGET, proof)

    def test_fabricated_trace_can_win_outer_filter_but_never_earns_verified_credit(self):
        c = self.two.context
        original = mu.inspect_packet(self.two.packet, c).proofs[0]
        forged = None
        for nonce in range(4096):
            fake_trace = mu.mu_hash(b"negative-control-false-trace", struct.pack("<I", nonce))
            raw = vectors.replace_proof(self.two.packet, c, 0, original[:-32] + fake_trace)
            if mu.inspect_packet(raw, c).ticket <= mu.T0:
                forged = raw
                break
        self.assertIsNotNone(forged)
        with self.assertRaisesRegex(mu.RelationError, "W1_TRANSCRIPT"):
            mu.verify_packet(forged, c)
        with self.assertRaisesRegex(mu.RelationError, "NATIVE_W1_INVALID"):
            mu.verify_packet(forged, c, backend="native", native_verifier=self.native)

    def test_winning_predicate_still_required_after_all_unit_relations(self):
        vector = self.two
        missed = next(row for row in vector.attempts if not row["winner"])
        c = replace(vector.context, nonce=missed["nonce"])
        raw = mu.produce_packet(c, vector.material, backend="native-prepared", native_prover=self.prepared)
        for backend, path in (("scalar", None), ("native", self.native)):
            with self.subTest(backend=backend), self.assertRaisesRegex(mu.RelationError, "AGGREGATE_TARGET"):
                mu.verify_packet(raw, c, backend=backend, native_verifier=path)

    def test_unavailable_or_unrecognized_backend_never_silently_falls_back(self):
        for options, reason in (({"backend": "native", "native_verifier": "/does/not/exist"}, "NATIVE_UNAVAILABLE"),
                                ({"backend": "mock"}, "VERIFIER_BACKEND")):
            with self.assertRaisesRegex(mu.RelationError, reason):
                mu.verify_packet(self.two.packet, self.two.context, **options)

    def test_literal_serialized_byte_bound_is_exactly_a_format_bound(self):
        total_bytes, total_credit = 0, 0
        for vector in self.rows:
            total_bytes += len(vector.packet)
            total_credit += 16 * vector.context.units
            self.assertLess(16 * vector.context.units,
                            mu.canonical_byte_credit_bound(len(vector.packet)))
        self.assertLess(total_credit, mu.canonical_byte_credit_bound(total_bytes))


class QueryCertificateTests(unittest.TestCase):
    def test_virtual_verification_cost_and_weight_cap_are_explicit(self):
        row = query.quantum_weight_bound(query.QueryBudget(3, 4, True, True), 257)
        self.assertEqual(row["simulated_bit_queries_N"], 10)
        self.assertEqual(row["required_distinct_successes_k"], 3)
        self.assertFalse(row["mandatory_u_minimum_gate_cost_proved"])
        self.assertFalse(row["attacker_only_online_query_budget"])

    def test_unpaid_history_and_unbounded_outputs_refuse(self):
        for budget, message in (
            (query.QueryBudget(1, 8, False, True), "UNPAID_PREPROCESSING"),
            (query.QueryBudget(1, 8, True, False), "UNPAID_PUBLIC_HELP"),
            (query.QueryBudget(1, 8, True, True, "known-winning-advice"), "UNQUALIFIED_RESIDUAL_STATE"),
            (query.QueryBudget(1, None, True, True), "FINITE_OUTPUT_CHECK_LIMIT"),
            (query.QueryBudget(True, 8, True, True), "FINITE_QUERY_CHECK_LIMIT"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                query.quantum_weight_bound(budget, 128)

    def test_output_cap_is_a_deterministic_refusal_boundary(self):
        for q in (0, 1, 20):
            row = query.quantum_weight_bound(query.QueryBudget(q, 3, True, True), 385)
            self.assertEqual(row["bound"], 0)
            self.assertEqual(query.classical_weight_bound(query.QueryBudget(q, 3, True, True), 385), 0)

    def test_zero_query_selected_output_bound_matches_blind_success(self):
        for k in range(1, 9):
            row = query.bernoulli_bounds(0, k)
            self.assertEqual(row["bound"], Fraction(1, 16) ** k)
        self.assertEqual(query.quantum_weight_bound(query.QueryBudget(0, 0, True, True), 0)["bound"], 1)

    def test_saturated_cauchy_example_is_nontrivial_only_in_its_ideal_model(self):
        row = query.quantum_weight_bound(query.QueryBudget(1, 32, True, True), 4096)
        self.assertLess(row["bound"], Fraction(7, 100))
        self.assertGreater(row["bound"], Fraction(6, 100))
        self.assertEqual(row["bound"], min(row["triangle_rational"], row["cauchy_saturated"]))

    def test_exact_one_grover_step_controls_respect_the_conservative_formula(self):
        # Independently average a one-step Grover circuit over every possible
        # marked-count class on 16 addresses, then use independent groups.
        for p in (Fraction(1, 16), Fraction(1, 4), Fraction(1, 2)):
            single = sum((Fraction(comb(16, marks)) * p ** marks * (1 - p) ** (16 - marks)
                          * Fraction(marks, 16) * (3 - 4 * Fraction(marks, 16)) ** 2
                          for marks in range(17)), Fraction(0))
            for k in range(1, 9):
                with self.subTest(p=str(p), independent_groups=k):
                    row = query.bernoulli_bounds(k, k, p)
                    self.assertLessEqual(single ** k, row["triangle_rational"])
                    self.assertLessEqual(single ** k, row["cauchy_saturated"])

    def test_residual_joint_profile_recovers_the_fresh_cauchy_branch(self):
        for n in (0, 1, 4, 34):
            for k in (0, 1, 4, 32):
                profile = (Fraction(1),) + (Fraction(0),) * k
                residual = query.residual_bernoulli_bound(n, k, profile)
                self.assertEqual(residual["bound"],
                                 query.bernoulli_bounds(n, k)["cauchy_saturated"])
                self.assertFalse(residual["input_tail_certificate_proved_by_this_function"])

    def test_unrestricted_or_known_winner_residual_state_is_not_fresh(self):
        for n in (0, 1, 5):
            for k in (1, 2, 8):
                profile = (Fraction(1),) * (k + 1)
                self.assertEqual(query.residual_bernoulli_bound(n, k, profile)["bound"], 1)
        # One standard-basis oracle bit known to equal one transforms to a
        # record bit with probability 1-p of being one.  No new query is needed
        # to publish this known winner.  Its joint profile is not (1,0).
        p = Fraction(1, 16)
        row = query.residual_bernoulli_bound(0, 1, (Fraction(1), 1 - p), p)
        self.assertEqual(row["bound"], 1)
        self.assertEqual(query.bernoulli_bounds(0, 1, p)["bound"], p)

    def test_malformed_residual_profiles_refuse_instead_of_proving_advice(self):
        for bad in ((Fraction(1),), (Fraction(1), Fraction(-1)),
                    (Fraction(0), Fraction(0)), (Fraction(1), 0),
                    [Fraction(1), Fraction(0)]):
            with self.subTest(profile=bad), self.assertRaisesRegex(ValueError, "JOINT_RECORD_TAIL_PROFILE"):
                query.residual_bernoulli_bound(1, 1, bad)
        with self.assertRaisesRegex(ValueError, "JOINT_RECORD_TAIL_PROFILE"):
            query.residual_bernoulli_bound(1, 2, (Fraction(1), Fraction(1, 4), Fraction(1, 2)))

    def test_classical_tail_matches_independent_finite_enumeration(self):
        # Enumerate the 2^6 success strings independently of the helper's binomial sum.
        p, direct = Fraction(1, 16), Fraction(0)
        for mask in range(1 << 6):
            hits = mask.bit_count()
            if hits >= 3:
                direct += p ** hits * (1 - p) ** (6 - hits)
        self.assertEqual(query.classical_weight_bound(query.QueryBudget(2, 4, True, True), 384), direct)


if __name__ == "__main__":
    unittest.main(verbosity=2)
