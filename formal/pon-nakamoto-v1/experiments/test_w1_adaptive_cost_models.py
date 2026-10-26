"""Small independent enumerations of the adaptive cost-model premises."""

from __future__ import annotations

from collections import defaultdict
from fractions import Fraction as F
from functools import lru_cache
from itertools import product
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w1_adaptive_cost_models as models


def worlds(count, probability):
    for bits in product((False, True), repeat=count):
        yield bits, probability**sum(bits) * (1 - probability)**(count - sum(bits))


def simulate_hybrid(bits, budget, useful, floor, schedule):
    spent = wins = cursor = 0
    ready = False
    while True:
        if not ready or schedule == "fresh-every-query":
            if spent + useful > budget:
                break
            spent += useful
            ready = True
        if spent + floor > budget:
            break
        spent += floor
        hit = bits[cursor]
        cursor += 1
        wins += hit
        if schedule == "reuse-until-success" and hit:
            ready = False
    return wins


def enumerate_screen_policies(initial_budget, screen, classes):
    """Enumerate every attainable distribution, not just a Bellman optimum.

    Continuations after a win, miss or public class may choose different policies.
    This intentionally tiny exhaustive checker is independent of the value DP.
    """
    width = initial_budget + 1
    empty = (F(1),) + (F(),) * (width - 1)

    @lru_cache(None)
    def possibilities(budget):
        if budget < screen:
            return frozenset((empty,))
        remaining = budget - screen
        options = []
        for item in classes:
            choices = set(possibilities(remaining))  # Discard after paid screening.
            if remaining >= item.completion_cost:
                future = possibilities(remaining - item.completion_cost)
                for after_hit, after_miss in product(future, repeat=2):
                    choices.add(tuple(
                        item.hit_probability * (after_hit[k - 1] if k else 0)
                        + (1 - item.hit_probability) * after_miss[k]
                        for k in range(width)))
            options.append(choices)
        result = set()
        for chosen in product(*options):
            result.add(tuple(sum((item.frequency * dist[k]
                                  for item, dist in zip(classes, chosen)), F())
                             for k in range(width)))
        return frozenset(result)

    return possibilities(initial_budget)


class AdaptiveCostModels(unittest.TestCase):
    def test_unqueried_submission_is_a_real_lottery(self):
        self.assertEqual(models.completed_query_bound(0, 1, F(1, 2), 1), F(1, 2))
        self.assertEqual(models.completed_query_bound(0, 0, F(1, 2), 1), 0)
        for k in range(7):
            exact = sum((prob for bits, prob in worlds(5, F(1, 3))
                         if sum(bits) >= k), F())
            self.assertEqual(models.completed_query_bound(3, 2, F(1, 3), k), exact)

    def test_floor_fanout_invalidates_injective_count_bound(self):
        actual = sum((prob for bits, prob in worlds(1, F(1, 2))
                      if 3 * sum(bits) >= 2), F())
        self.assertEqual(actual, F(1, 2))
        self.assertEqual(models.completed_query_bound(1, 0, F(1, 2), 2, fanout=3), actual)
        self.assertEqual(models.completed_query_bound(1, 0, F(1, 2), 2), 0)
        for count in range(5):
            for k in range(3 * count + 2):
                exact = sum((prob for bits, prob in worlds(count, F(1, 4))
                             if 3 * sum(bits) >= k), F())
                self.assertEqual(models.completed_query_bound(
                    count, 0, F(1, 4), k, fanout=3), exact)

    def test_known_initial_winner_is_not_zero_online_work_impossibility(self):
        self.assertEqual(models.completed_query_bound(
            0, 0, F(1, 2), 1, initial_credit_cap=1), 1)
        self.assertEqual(models.completed_query_bound(0, 0, F(1, 2), 1), 0)
        self.assertEqual(models.completed_query_bound(
            2, 0, F(1, 2), 3, initial_credit_cap=1), F(1, 4))

    def test_zero_cost_is_not_replaced_by_a_positive_lower_bound(self):
        self.assertIsNone(models.resource_query_cap(0, 0))
        self.assertIsNone(models.resource_query_cap(100, 0))
        self.assertEqual(models.resource_query_cap(0, 0, finite_domain=4), 4)
        self.assertEqual(models.resource_query_cap(11, 3), 3)
        self.assertEqual(models.resource_query_cap(11, 3, finite_domain=2), 2)

    def test_preprocessing_context_selection_changes_the_game(self):
        result = models.cached_context_lottery((2, 0, 0, 0), F(1, 2))
        fresh = chosen = F()
        for bits, prob in worlds(2, F(1, 2)):
            for context in range(4):
                fresh += prob * F(1, 4) * (context == 0 and any(bits))
            chosen += prob * any(bits)
        self.assertEqual(result["uniform_fresh_context_at_least_one"], fresh)
        self.assertEqual(fresh, F(3, 16))
        self.assertEqual(result["chosen_context_at_least_one"], chosen)
        self.assertEqual(chosen, F(3, 4))
        self.assertEqual(result["prepaid_queries"], 2)

    def test_entropy_bound_cannot_be_reused_after_context_selection(self):
        # One covered context in a uniform four-context release: exactly 1/4.
        self.assertEqual(models.fresh_context_bank_overlap_bound(1, 2), F(1, 4))
        self.assertEqual(models.fresh_context_bank_overlap_bound(1, 2, 3), F(3, 4))
        self.assertEqual(models.fresh_context_bank_overlap_bound(1, 2, 8), 1)
        # Choosing the covered context after preparation makes overlap certain.
        chosen_overlap = F(1)
        self.assertGreater(chosen_overlap, models.fresh_context_bank_overlap_bound(1, 2))

    def test_hybrid_distributions_against_independent_execution(self):
        for budget, useful, floor, p in ((8, 3, 1, F(1, 2)), (7, 2, 2, F(1, 3)),
                                        (0, 1, 1, F(1)), (2, 3, 1, F())):
            for schedule in ("fresh-every-query", "reuse-until-success", "reuse-many-credits"):
                exact = defaultdict(F)
                for bits, prob in worlds(budget // floor, p):
                    exact[simulate_hybrid(bits, budget, useful, floor, schedule)] += prob
                observed = models.hybrid_budget_distribution(budget, useful, floor, p, schedule)
                for winners in range(max(max(exact), len(observed) - 1) + 1):
                    self.assertEqual(observed[winners] if winners < len(observed) else 0,
                                     exact[winners])
                self.assertEqual(sum(observed), 1)

    def test_one_credit_per_useful_result_still_allows_failed_nonce_reuse(self):
        means = models.hybrid_first_win_costs(9, 1, F(1, 2))
        self.assertEqual(means["fresh-every-query"], 20)
        self.assertEqual(means["reuse-until-success"], 11)
        strict = models.hybrid_budget_distribution(20, 9, 1, F(1, 2), "fresh-every-query")
        reused = models.hybrid_budget_distribution(20, 9, 1, F(1, 2), "reuse-until-success")
        many = models.hybrid_budget_distribution(20, 9, 1, F(1, 2), "reuse-many-credits")
        self.assertEqual(models.mean(strict), 1)
        self.assertEqual(models.mean(reused), F(2559, 2048))
        self.assertEqual(models.mean(many), F(11, 2))
        self.assertNotEqual(models.mean(reused) / models.mean(strict), F(20, 11))

    def test_screening_optimizer_against_all_small_policy_distributions(self):
        classes = (models.ScreenClass("cheap", F(1, 2), 1, F(1, 2)),
                   models.ScreenClass("expensive", F(1, 2), 2, F(1, 3)))
        for budget in range(5):
            attainable = enumerate_screen_policies(budget, 1, classes)
            self.assertTrue(all(sum(distribution) == 1 for distribution in attainable))
            self.assertEqual(models.optimal_screening_value(budget, 1, classes),
                             max(models.mean(distribution) for distribution in attainable))
            for threshold in range(4):
                self.assertEqual(models.optimal_screening_value(
                    budget, 1, classes, winners_required=threshold),
                    max(models.tail(distribution, threshold) for distribution in attainable))

    def test_uninformative_screening_reduces_to_fixed_complete_attempts(self):
        classes = (models.ScreenClass("same-a", F(1, 3), 2, F(1, 4)),
                   models.ScreenClass("same-b", F(2, 3), 2, F(1, 4)))
        for budget in range(13):
            distribution = models.binomial_pmf(budget // 3, F(1, 4))
            self.assertEqual(models.optimal_screening_value(budget, 1, classes),
                             models.mean(distribution))
            for threshold in range(4):
                self.assertEqual(models.optimal_screening_value(
                    budget, 1, classes, winners_required=threshold),
                    models.tail(distribution, threshold))

    def test_screening_target_before_completion_cannot_be_one_fair_coin(self):
        classes = (models.ScreenClass("revealed-miss", F(1, 2), 8, F()),
                   models.ScreenClass("revealed-hit", F(1, 2), 8, F(1)))
        exact = sum((prob for bits, prob in worlds(4, F(1, 2)) if any(bits)), F())
        self.assertEqual(exact, F(15, 16))
        self.assertEqual(models.optimal_screening_value(12, 1, classes,
                                                       winners_required=1), exact)
        self.assertGreater(exact, F(1, 2))
        # No free completion: eight units cannot pay even one screen plus finish.
        self.assertEqual(models.optimal_screening_value(8, 1, classes), 0)

    def test_predictable_adaptive_weighted_process_obeys_ville(self):
        def policy(history):
            bound = F(1, 4) if sum(history) % 2 else F(1, 2)
            return bound, bound, 2 if history and history[-1] else 1

        for horizon in range(7):
            audited = models.enumerate_predictable_policy(
                horizon, policy, z=F(3), boundary=F(4))
            self.assertEqual(audited["total_probability"], 1)
            self.assertEqual(audited["mean_terminal_e_value"], 1)
            self.assertLessEqual(audited["any_crossing_probability"], F(1, 4))
        conservative = models.enumerate_predictable_policy(
            6, lambda h: (F(1, 4), F(1, 2), 1), z=F(3), boundary=F(4))
        self.assertLess(conservative["mean_terminal_e_value"], 1)

    def test_dropping_screened_misses_breaks_the_same_e_bound(self):
        selected_cross = full_cross = F()
        for bits, prob in worlds(4, F(1, 2)):
            kept = []
            for hit in bits:
                kept.append(models.PredictableReveal(F(1, 2), 1, hit))
                if hit:
                    break
            correct = models.e_process_prefixes(kept, F(3))
            full_cross += prob * (max(correct) >= F(3, 2))
            # Invalid: discard every miss, present the selected hit as a fresh coin.
            selected_cross += prob * any(bits)
        self.assertEqual(selected_cross, F(15, 16))
        self.assertEqual(full_cross, F(1, 2))
        self.assertGreater(selected_cross, F(2, 3))
        self.assertLessEqual(full_cross, F(2, 3))

    def test_boundary_probabilities_and_rejected_ambiguous_inputs(self):
        self.assertEqual(models.completed_query_bound(8, 0, F(), 1), 0)
        self.assertEqual(models.completed_query_bound(8, 0, F(1), 8), 1)
        self.assertEqual(models.e_process_prefixes(
            (models.PredictableReveal(F(), 7, False),), F(2)), (F(1), F(1)))
        bad = [lambda: models.binomial_pmf(True, F(1, 2)),
               lambda: models.binomial_pmf(2, 0.5),
               lambda: models.completed_query_bound(1, 1, F(1, 2), 1, fanout=0),
               lambda: models.hybrid_first_win_costs(2, 1, F()),
               lambda: models.hybrid_budget_distribution(3, 2, 1, F(1, 2), "unknown"),
               lambda: models.optimal_screening_value(3, 0, ()),
               lambda: models.e_process_prefixes((), F(1, 2)),
               lambda: models.enumerate_predictable_policy(
                   1, lambda h: (F(1), F(1, 2), 1), z=F(2), boundary=F(2))]
        for invalid in bad:
            with self.assertRaises(ValueError):
                invalid()

    def test_literal_trace_geometry_does_not_equal_wire_proof_size(self):
        geometry = models.trace_geometry()
        self.assertEqual(geometry["trace_words"], 32768)
        self.assertEqual(geometry["trace_message_bytes"], 131120)
        self.assertEqual(geometry["ordinary_sha256_compression_blocks"], 2049)
        self.assertEqual(geometry["submitted_proof_bytes"], 49188)
        self.assertGreater(geometry["trace_message_bytes"], geometry["submitted_proof_bytes"])
        for n, tile in ((1, 1), (4, 1), (4, 2), (4, 4), (8, 2)):
            report = models.trace_geometry(n, tile)
            # Independently form the actual framing and word count, then pad it.
            literal = b"TRNM-PON-TRACE1\0" + bytes(32)
            for _bi in range(0, n, tile):
                for _bj in range(0, n, tile):
                    for _bk in range(0, n, tile):
                        literal += bytes(4 * tile * tile)
            self.assertEqual(len(literal), report["trace_message_bytes"])
            bit_length = (len(literal) * 8).to_bytes(8, "big")
            padded = literal + b"\x80"
            while len(padded) % 64 != 56:
                padded += b"\0"
            padded += bit_length
            self.assertEqual(len(padded) // 64, report["ordinary_sha256_compression_blocks"])

    def test_factorized_prefixes_match_independent_arbitrary_residue_products(self):
        def multiply(a, b, modulus):
            return tuple(tuple(sum(x * y for x, y in zip(row, column)) % modulus
                               for column in zip(*b)) for row in a)

        def reference(a, b, tile, modulus):
            n = len(a)
            # Compute every complete restricted-prefix product independently.
            full = {end: tuple(tuple(sum(a[i][k] * b[k][j] for k in range(end)) % modulus
                                     for j in range(n)) for i in range(n))
                    for end in range(tile, n + 1, tile)}
            return tuple(full[end][i][j]
                         for bi in range(0, n, tile) for bj in range(0, n, tile)
                         for end in range(tile, n + 1, tile)
                         for i in range(bi, bi + tile) for j in range(bj, bj + tile))

        for n, tile, a, b in ((2, 1, 1, 1), (4, 2, 2, 3), (4, 4, 3, 1), (8, 2, 3, 2)):
            for modulus in (17, 4294967291):
                for pattern in (0, 1, 2):
                    def matrix(rows, columns, salt):
                        return tuple(tuple((0 if pattern == 0 else modulus - 1 if pattern == 1
                                            else (31 * i + 7 * j + salt * 13)) % modulus
                                           for j in range(columns)) for i in range(rows))
                    left, il = matrix(n, a, 1), matrix(a, n, 2)
                    ir, right = matrix(n, b, 3), matrix(b, n, 4)
                    words = models.factored_prefix_words(left, il, ir, right, tile, modulus)
                    expected = reference(multiply(left, il, modulus),
                                         multiply(ir, right, modulus), tile, modulus)
                    self.assertEqual(words, expected)
                    self.assertEqual(len(words), n * n * (n // tile))

    def test_low_rank_operation_count_is_only_the_declared_schedule(self):
        counts = models.factored_prefix_multiplications(64, 8, 8, 8)
        self.assertEqual(counts, {"middle_prefix_updates": 4096, "prefix_lifts": 32768,
                                  "prefix_output_products": 262144, "total": 299008})
        # Final product only would omit almost all of the required prefix bytes.
        self.assertGreater(counts["total"], 64 * 8 * 8 + 64 * 64 * 8)
        # Supplied rank-one task factors plus rank-eight noise need rank nine.
        # Even these factors do not imply fewer scalar multiplies at this size.
        self.assertGreater(models.factored_prefix_multiplications(64, 8, 9, 9)["total"],
                           64**3 + 2 * 64**2 * 8)
        left = models.factored_prefix_multiplications(8, 2, 2, 3)
        right = models.factored_prefix_multiplications(8, 2, 3, 2)
        self.assertEqual(left, right)

    def test_trace_oracle_guessing_and_wrong_message_collision_are_distinct(self):
        for bits in (1, 2, 3):
            domain = range(2**bits)
            # Query one noncanonical message, then submit its returned digest.
            # The private verifier queries the different canonical message.
            matches = sum(wrong == canonical for wrong in domain for canonical in domain)
            actual = F(matches, len(domain)**2)
            bound = models.trace_extraction_failure_bound(0, 1, 1, bits)
            self.assertEqual(actual, F(1, 2**bits))
            self.assertEqual(actual, bound["unqueried_digest_guess_bound"])
            self.assertLessEqual(actual, bound["combined_bound"])
            # Both messages queried: a matching digest gives ambiguous extraction.
            self.assertEqual(actual, models.trace_extraction_failure_bound(
                0, 2, 0, bits)["trace_response_collision_bound"])

    def test_fixed_batch_guesses_count_all_candidates_not_only_accepted_output(self):
        for bits in (1, 2, 3):
            for guesses in range(2**bits + 2):
                # Many guesses for one unknown digest; repeated guesses add no hit.
                submitted = [index % (2**bits) for index in range(guesses)]
                actual = F(sum(secret in submitted for secret in range(2**bits)), 2**bits)
                bound = models.trace_extraction_failure_bound(0, 0, guesses, bits)
                self.assertEqual(actual, min(F(1), F(guesses, 2**bits)))
                self.assertLessEqual(actual, bound["combined_bound"])
        frozen = models.trace_extraction_failure_bound(2, 1, 1)
        self.assertEqual(frozen["distinct_trace_input_cap_including_private_verifier"], 4)
        self.assertEqual(frozen["combined_bound"], F(7, 2**256))
        # Hidden preparation is not equivalent to an unqueried guess: the bank
        # can already contain the canonical message and its correct digest.
        no_bank_claim = models.trace_extraction_failure_bound(0, 0, 1, 3)
        self.assertGreater(F(1), no_bank_claim["combined_bound"])

    def test_conditional_trace_extraction_requires_collision_free_known_table(self):
        for bits in (2, 3):
            size = 2**bits
            # Fix one preparation answer, then expose two distinct new inputs.
            # Their collision event is enumerated after fixing that actual table.
            collision_mass = F(sum(x == 0 or y == 0 or x == y
                                   for x in range(size) for y in range(size)), size**2)
            bound = models.trace_extraction_failure_bound(
                1, 2, 0, bits, conditioning="fixed-collision-free-preparation")
            self.assertLessEqual(collision_mass, bound["trace_response_collision_bound"])
            self.assertEqual(bound["combined_bound"], min(F(1), F(3, size)))
        conditional = models.trace_extraction_failure_bound(
            2, 1, 1, conditioning="fixed-collision-free-preparation")
        self.assertEqual(conditional["combined_bound"], F(6, 2**256))
        # Given a known prior collision, its probability is one even with no
        # future calls; the premise cannot be inferred from a finite query cap.
        unavailable_claim = models.trace_extraction_failure_bound(
            2, 0, 0, 2, conditioning="fixed-collision-free-preparation")
        self.assertEqual(unavailable_claim["combined_bound"], 0)
        self.assertGreater(F(1), unavailable_claim["combined_bound"])

    def test_trace_models_reject_ambiguous_or_oversized_parameters(self):
        invalid = [lambda: models.trace_geometry(0, 1),
                   lambda: models.trace_geometry(4, 0),
                   lambda: models.trace_geometry(4, 3),
                   lambda: models.trace_geometry(True, 1),
                   lambda: models.factored_prefix_multiplications(4, 2, 0, 2),
                   lambda: models.trace_extraction_failure_bound(-1, 0, 1),
                   lambda: models.trace_extraction_failure_bound(0, True, 1),
                   lambda: models.trace_extraction_failure_bound(0, 0, 1, 0),
                   lambda: models.trace_extraction_failure_bound(
                       0, 0, 1, conditioning="unexamined-state"),
                   lambda: models.factored_prefix_words(((1,),), ((1,),), ((1,),),
                                                       ((1,),), 1, 1),
                   lambda: models.factored_prefix_words(((1,),), ((1,),), ((1,),),
                                                       ((2,),), 1, 2),
                   lambda: models.factored_prefix_words(((1,),), ((1, 2),), ((1,),),
                                                       ((1,),), 1, 3)]
        for operation in invalid:
            with self.assertRaises(ValueError):
                operation()

    def test_report_is_explicitly_nonqualifying_and_exact(self):
        report = models.research_report()
        self.assertFalse(report["native_measurement"])
        self.assertFalse(report["current_W1_vulnerability_demonstrated"])
        self.assertFalse(report["universal_cost_bound_established"])
        self.assertFalse(report["production_activation"])
        self.assertEqual(report["unqueried_submission"]["correct_query_completed_bound"], "1/2")
        self.assertEqual(report["screening"][
            "perfectly_revealed_target_budget_12_screen_1_completion_8"], "15/16")


if __name__ == "__main__":
    unittest.main()
