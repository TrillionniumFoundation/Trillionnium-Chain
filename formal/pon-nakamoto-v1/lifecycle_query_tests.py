"""Independent finite-law and reference-dispatch checks for LQC1 (stdlib only).

Run directly or with unittest discovery. Actual full W1/MU1 calls are REQUIRED
by the separate lifecycle_query_evidence.py command; this suite cannot silently
substitute a framing fixture for native work validity.
"""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from itertools import combinations, product
from math import comb
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

import mandatory_units_relation as mu
from mandatory_units_query import QueryBudget, bernoulli_bounds, quantum_weight_bound
from mandatory_units_vectors import label, make_context
from lifecycle_query_bound import (LifetimeCaps, MAX_FULL_QUERIES, UNATTESTED,
                                  binomial_tail, continuation_given_complete_prefix,
                                  fixed_list_bound, global_lifecycle_weight_bound)
from lifecycle_query_runtime import ReferenceQueryOwner, terminal_address_without_ticket


P = Fraction(1, 16)


def law(bits):
    return P ** sum(bits) * (1 - P) ** (len(bits) - sum(bits))


def padded_prefix(bits):
    # Bounded adaptive stopping: if first reveal hits, stop early. Padding
    # gifts address 1; otherwise the actual second reveal is address 2.
    actual = [(0, bits[0])]
    if not bits[0]:
        actual.append((2, bits[2]))
    padded = actual + ([(1, bits[1])] if len(actual) == 1 else [])
    return tuple(padded), len(actual)


class BoundsTests(unittest.TestCase):
    def test_no_query_single_fixed_list_includes_blind_outputs(self):
        for k in range(1, 13):
            self.assertEqual(fixed_list_bound(0, k, k), P ** k)

    def test_list_union_dominates_exact_blind_list_law(self):
        for m in range(1, 10):
            for k in range(1, m + 1):
                exact = binomial_tail(m, k, P)
                self.assertLessEqual(exact, fixed_list_bound(0, m, k))

    def test_fixed_subset_union_is_pathwise_with_duplicates_and_short_lists(self):
        for slots in ((), (0,), (1, 1), (2, 0, 2, 1)):
            distinct = tuple(dict.fromkeys(slots))
            for bits in product((0, 1), repeat=3):
                for k in range(1, 4):
                    event = sum(bits[a] for a in distinct) >= k
                    union = any(all(bits[distinct[i]] for i in subset)
                                for subset in combinations(range(len(distinct)), k))
                    self.assertEqual(event, union)

    def test_zero_threshold_and_impossible_capacity(self):
        self.assertEqual(global_lifecycle_weight_bound(LifetimeCaps(0, 0, 0), 0)["bound"], 1)
        self.assertEqual(global_lifecycle_weight_bound(LifetimeCaps(8, 1, 3), 513)["bound"], 0)
        self.assertEqual(fixed_list_bound(0, 0, 1), 0)

    def test_removing_virtual_checks_is_material(self):
        new = global_lifecycle_weight_bound(LifetimeCaps(0, 1, 32), 4096)
        old = quantum_weight_bound(QueryBudget(1, 32, True, True), 4096)
        self.assertEqual(new["bound"], bernoulli_bounds(2, 32)["bound"])
        self.assertLess(new["bound"], old["bound"] / (10 ** 20))
        self.assertEqual(new["virtual_output_queries_added"], 0)

    def test_unconditional_prefix_is_not_a_conditional_restart(self):
        global_result = global_lifecycle_weight_bound(LifetimeCaps(1, 0, 1), 128)
        given_hit = continuation_given_complete_prefix(
            distinct_seen=1, marked_seen=1, post_queries=0, output_slots=1, credit=128)
        given_miss = continuation_given_complete_prefix(
            distinct_seen=1, marked_seen=0, post_queries=0, output_slots=1, credit=128)
        self.assertEqual(global_result["bound"], Fraction(31, 256))
        self.assertEqual(given_hit["bound"], 1)
        self.assertEqual(given_miss["bound"], P)
        self.assertNotEqual(global_result["probability_scope"], given_hit["probability_scope"])

    def test_adaptive_stop_padding_has_binomial_global_law(self):
        masses = [Fraction(0)] * 3
        for bits in product((0, 1), repeat=5):
            prefix, actual_count = padded_prefix(bits)
            self.assertLessEqual(actual_count, 2)
            self.assertEqual(len({a for a, _ in prefix}), 2)
            masses[sum(v for _, v in prefix)] += law(bits)
        self.assertEqual(masses, [Fraction(comb(2, s)) * P ** s * (1 - P) ** (2 - s)
                                  for s in range(3)])

    def test_complete_adaptive_prefix_leaves_full_complement_iid(self):
        groups = {}
        for bits in product((0, 1), repeat=5):
            prefix, _ = padded_prefix(bits)
            seen = {a for a, _ in prefix}
            unseen = tuple(bits[a] for a in range(5) if a not in seen)
            row = groups.setdefault(prefix, {})
            row[unseen] = row.get(unseen, Fraction(0)) + law(bits)
        for row in groups.values():
            total = sum(row.values(), Fraction(0))
            for unseen, mass in row.items():
                self.assertEqual(mass / total, law(unseen))

    def test_classical_prefix_formula_matches_complete_finite_game(self):
        observed = Fraction(0)
        for bits in product((0, 1), repeat=5):
            prefix, _ = padded_prefix(bits)
            known = [a for a, value in prefix if value]
            seen = {a for a, _ in prefix}
            chosen = known[:2] + [a for a in range(5) if a not in seen][:max(0, 2 - len(known))]
            if sum(bits[a] for a in chosen) >= 2:
                observed += law(bits)
        result = global_lifecycle_weight_bound(LifetimeCaps(2, 0, 2, 5), 256)
        self.assertEqual(observed, result["prefix_convolution_bound"])
        self.assertEqual(observed, result["bound"])

    def test_all_required_outputs_classical_closed_form(self):
        # Independent closed form when C<=M=k and domain is not exhausted:
        # sum_s binom(C,s)p^s(1-p)^(C-s)p^(M-s) = p^M(2-p)^C.
        for c in range(6):
            for m in range(max(1, c), 9):
                result = global_lifecycle_weight_bound(LifetimeCaps(c, 0, m), 128 * m)
                self.assertEqual(result["prefix_convolution_bound"], P ** m * (2 - P) ** c)

    def test_known_winner_augmentation_is_pointwise(self):
        for m in range(1, 6):
            for s in range(m):
                for r in range(s + 1):
                    for unknown in product((0, 1), repeat=m - r):
                        before = r + sum(unknown)
                        after = s + sum(unknown[:m - s])
                        self.assertGreaterEqual(after, before)

    def test_q_positive_unknown_slots_use_M_minus_s(self):
        result = continuation_given_complete_prefix(
            distinct_seen=3, marked_seen=2, post_queries=1, output_slots=8, credit=768)
        self.assertEqual(result["unknown_output_slots"], 6)
        self.assertEqual(result["bound"], fixed_list_bound(2, 6, 4))

    def test_domain_exhaustion_has_no_dummy_query_assumption(self):
        result = global_lifecycle_weight_bound(LifetimeCaps(8, 3, 2, 2), 256)
        self.assertEqual(result["padded_distinct_prefix_C_effective"], 2)
        self.assertEqual(result["bound"], P ** 2)
        given = continuation_given_complete_prefix(
            distinct_seen=2, marked_seen=1, post_queries=5, output_slots=2, credit=256, domain_size=2)
        self.assertEqual(given["bound"], 0)
        self.assertEqual(global_lifecycle_weight_bound(LifetimeCaps(0, 0, 0, 0), 1)["bound"], 0)

    def test_one_phase_query_grover_finite_exact_law(self):
        success = Fraction(0)
        for bits in product((0, 1), repeat=4):
            phase = [Fraction(-1 if mark else 1, 2) for mark in bits]
            average = sum(phase, Fraction(0)) / 4
            final = [2 * average - a for a in phase]
            self.assertEqual(sum((a * a for a in final), Fraction(0)), 1)
            success += law(bits) * sum((a * a for a, hit in zip(final, bits) if hit), Fraction(0))
        self.assertLessEqual(success, fixed_list_bound(1, 1, 1))
        self.assertGreater(success, P)
        # A classical reveal of Grover's selected address is biased. It must
        # stay in post-prefix Q, not be relabeled an independent prefix trial.
        self.assertNotEqual(success, P)

    def test_input_shape_and_check_limits_fail_closed(self):
        for caps in (LifetimeCaps(True, 0, 1), LifetimeCaps(-1, 0, 1),
                     LifetimeCaps(0, 0, 65), LifetimeCaps(MAX_FULL_QUERIES, 1, 1)):
            with self.assertRaises(ValueError):
                global_lifecycle_weight_bound(caps, 128)
        with self.assertRaisesRegex(ValueError, "MARKED_SEEN"):
            continuation_given_complete_prefix(distinct_seen=1, marked_seen=2,
                                               post_queries=0, output_slots=1, credit=1)
        with self.assertRaisesRegex(ValueError, "BERNOULLI_PROBABILITY"):
            fixed_list_bound(0, 1, 1, 0.0625)
        with self.assertRaisesRegex(ValueError, "FROZEN_MU1_TERMINAL_PROBABILITY"):
            global_lifecycle_weight_bound(LifetimeCaps(0, 0, 1), 128, Fraction(1, 32))
        with self.assertRaisesRegex(ValueError, "FROZEN_MU1_TERMINAL_PROBABILITY"):
            continuation_given_complete_prefix(distinct_seen=0, marked_seen=0,
                post_queries=0, output_slots=1, credit=128, p=Fraction(1, 32))

    def test_math_does_not_authenticate_assumptions_or_native_risk(self):
        rows = (global_lifecycle_weight_bound(LifetimeCaps(0, 1, 32), 4096),
                continuation_given_complete_prefix(distinct_seen=0, marked_seen=0,
                    post_queries=1, output_slots=32, credit=4096))
        for row in rows:
            for claim in UNATTESTED:
                self.assertIs(row[claim], False)


class ReferenceDispatchTests(unittest.TestCase):
    def owner(self, scope="one", c=2, q=1, m=2):
        return ReferenceQueryOwner(scope, LifetimeCaps(c, q, m))

    def test_cache_reuse_preserves_origin_without_extra_query(self):
        owner = self.owner()
        d, r = label("d"), label("r")
        value = owner.query(d, r, "producer")
        ref = owner.reference(d, r)
        self.assertEqual(owner.read_reference(ref, "public-helper"), value)
        self.assertEqual(owner.query(d, r, "third-participant"), value)
        self.assertEqual(owner.hash_evaluations, 1)
        self.assertEqual(owner.cache_reads, 2)
        self.assertEqual(owner.reference(d, r).origin_sequence, ref.origin_sequence)

    def test_shared_frontier_is_irreversible_and_late_helper_cannot_reset_it(self):
        owner = self.owner()
        owner.query(label("prefix"), label("r"))
        owner.begin_post_prefix()
        owner.query(label("late-helper"), label("r"), "new-helper")
        self.assertEqual((owner.prefix_used, owner.post_used), (1, 1))
        with self.assertRaisesRegex(ValueError, "PREFIX_ALREADY_CLOSED"):
            owner.begin_post_prefix()
        with self.assertRaisesRegex(ValueError, "QUERY_CAP"):
            owner.query(label("later"), label("r"), "new-helper")
        self.assertEqual(owner.hash_evaluations, 2)

    def test_foreign_cache_and_fresh_owner_are_not_paid_imports(self):
        owner = self.owner()
        owner.query(label("d"), label("r"))
        ref = owner.reference(label("d"), label("r"))
        with self.assertRaisesRegex(ValueError, "FOREIGN_CACHE_SCOPE"):
            self.owner("other").read_reference(ref)
        with self.assertRaisesRegex(ValueError, "UNOBSERVED_OR_CHANGED_CACHE_ORIGIN"):
            self.owner("one").read_reference(ref)
        with self.assertRaisesRegex(ValueError, "UNOBSERVED_OR_CHANGED_CACHE_ORIGIN"):
            owner.read_reference(replace(ref, ticket=bytes(32)))

    def test_cap_refuses_before_actual_terminal_call(self):
        owner = self.owner(c=0, q=0)
        with self.assertRaisesRegex(ValueError, "QUERY_CAP"):
            owner.query(label("d"), label("r"))
        self.assertEqual(owner.hash_evaluations, 0)
        self.assertEqual(owner.events[-1]["kind"], "denied-before-hash")

    def test_frozen_ticket_hook_counts_real_feedback_and_restores_on_error(self):
        owner = self.owner()
        original = mu.mu_hash
        with self.assertRaisesRegex(ValueError, "deliberate"):
            with owner.intercept_frozen_terminal("validator-feedback"):
                self.assertEqual(mu.mu_hash(b"ticket", label("d"), label("r")),
                                 original(b"ticket", label("d"), label("r")))
                raise ValueError("deliberate")
        self.assertIs(mu.mu_hash, original)
        self.assertEqual(owner.prefix_used, 1)

    def test_nested_hooks_are_refused(self):
        owner = self.owner()
        with owner.intercept_frozen_terminal():
            with self.assertRaisesRegex(ValueError, "TERMINAL_HOOK_ALREADY_ACTIVE"):
                with self.owner("second").intercept_frozen_terminal():
                    pass

    def test_oracle_free_extractor_matches_frozen_framing(self):
        # Deliberately INVALID WORK: only framing/extraction is exercised here.
        # Native validity is never inferred from this test fixture.
        original = mu.mu_hash

        def nonterminal_only(tag, *parts):
            self.assertNotEqual(tag, b"ticket", "extractor queried terminal oracle")
            return original(tag, *parts)

        for units in (1, 2, 4, 8):
            context = make_context(tuple(label("framing-task-" + str(j)) for j in range(units)))
            proofs = tuple(b"PNW1" + bytes([j]) * (mu.w1.PROOF_BYTES - 4) for j in range(units))
            packet = mu.encode_packet(context, proofs)
            expected = mu.inspect_packet(packet, context)
            with patch("lifecycle_query_runtime._MU_HASH", side_effect=nonterminal_only):
                with patch.object(mu, "mu_hash", side_effect=AssertionError("frozen inspect forbidden")):
                    address = terminal_address_without_ticket(packet, context)
            self.assertEqual((address.context_digest, address.ordered_root, address.identity),
                             (expected.context_hash, expected.outputs_root, expected.identity))
        with self.assertRaisesRegex(ValueError, "EXPECTED_CONTEXT"):
            terminal_address_without_ticket(packet, replace(context, nonce=context.nonce + 1))

    def test_shape_only_extractor_is_not_a_work_validator(self):
        context = make_context((label("framing-task"),))
        proof = b"PNW1" + bytes(mu.w1.PROOF_BYTES - 4)
        packet = mu.encode_packet(context, (proof,))
        self.assertEqual(len(terminal_address_without_ticket(packet, context).identity), 32)
        with self.assertRaises(mu.RelationError):
            mu.verify_packet(packet, context, backend="scalar")

    def test_observation_cannot_be_promoted_to_global_budget(self):
        owner = self.owner()
        owner.query(label("known-before-owner-is-possible"), label("r"))
        self.assertTrue(owner.report()["reference_cap_checks_pass"])
        with self.assertRaisesRegex(ValueError, "GLOBAL_QUERY_CLOSURE"):
            owner.global_budget_certificate()
        for key in UNATTESTED:
            self.assertIs(owner.report()[key], False)

    def test_bounded_exchange_failure_keeps_partial_bytes_and_failed_status(self):
        from bounded_process import ProcessFailure
        from lifecycle_query_evidence import native_recording
        failure = ProcessFailure("NATIVE_STDOUT_LIMIT", returncode=0,
                                 stdout=b"partial", stderr=b"diagnostic", stdin_written=3,
                                 stdout_truncated=True, stderr_truncated=False)
        # Error-path unit fixture only; no producer or valid-work claim.
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            with patch.object(mu, "run_bounded", side_effect=failure):
                with native_recording(out) as calls:
                    with self.assertRaises(ProcessFailure):
                        mu.run_bounded(["error-fixture-not-a-producer", "verify"], b"input")
            directory = out / "native-calls" / "0001"
            self.assertEqual((directory / "stdout.bin").read_bytes(), b"partial")
            self.assertEqual((directory / "stderr.bin").read_bytes(), b"diagnostic")
            recorded = json.loads((directory / "observation.json").read_text())
            self.assertEqual(recorded["exchange_status"], "FAILED")
            self.assertEqual(recorded["returncode"], 0)
            self.assertTrue(recorded["stdout_truncated"])
            self.assertEqual(calls[0]["stdin_written"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
