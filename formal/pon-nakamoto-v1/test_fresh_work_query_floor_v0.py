"""Independent small-oracle controls for conditional fresh-ticket accounting."""
from dataclasses import replace
from fractions import Fraction
from itertools import product
import unittest

import fresh_work_query_floor_v0 as F


def candidate(identity=b'candidate-a', *, length=2, target=1, seed=0, profile='toy-two'):
    return F.Candidate(identity, seed, target, profile, length)


class FractionTheoremTests(unittest.TestCase):
    def test_predictable_target_expectation_and_fixed_research_length(self):
        for bits in range(2, 8):
            size = 1 << bits
            for target in range(1, size):
                award = F.nominal_award(target, bits=bits, length=64)
                self.assertLessEqual(Fraction(award * (target + 1), size), 64)
        self.assertEqual(F.RESEARCH_STEPS, 64)
        self.assertEqual(F.nominal_award((1 << 252) - 1), 1024)

    def test_stopping_time_mean_uses_unconditional_bound(self):
        # Final guess first; continue to the prefix only when that guessed
        # final answer hits the target. The stopping cost correlates with wins.
        bits, size, target, length = 2, 4, 1, 2
        total_credit = total_cost = 0
        for actual_prefix, guessed_final in product(range(size), repeat=2):
            total_cost += 1
            if guessed_final <= target:
                total_cost += 1
                if actual_prefix == 0:
                    total_credit += F.nominal_award(target, bits=bits, length=length)
        mean_cost = Fraction(total_cost, size ** 2)
        mean_credit = Fraction(total_credit, size ** 2)
        self.assertEqual(mean_cost, Fraction(3, 2))
        self.assertEqual(mean_credit, Fraction(1, 2))
        self.assertLessEqual(mean_credit, F.expected_credit_bound(
            2, bits=bits, length=length, expected_queries=mean_cost))

    def test_lazy_match_bound_accounts_for_a_prequeried_suffix(self):
        # z1=H1(seed) is unknown. H2(0)=0 has already been queried. The attacker
        # guesses z2=0 for H3. Enumerate all remaining H2 rows independently.
        size = 4
        hits = total = 0
        for first, rest in product(range(size), product(range(size), repeat=size - 1)):
            second_row = (0,) + rest
            hits += second_row[first] == 0
            total += 1
        probability = Fraction(hits, total)
        self.assertEqual(probability, Fraction(7, 16))
        self.assertLessEqual(probability, F.lazy_predecessor_bound(1, bits=2))
        self.assertGreater(probability, Fraction(1, size))

    def test_exact_query_cap_envelope_and_no_quantum_conversion(self):
        for bits in range(2, 7):
            size = 1 << bits
            for q in range(10):
                expected = min(Fraction(64 * q),
                               Fraction(q) + Fraction(64 * q * (q + 1), 2 * size))
                self.assertEqual(F.expected_credit_bound(q, bits=bits), expected)
        self.assertEqual(F.expected_credit_bound(0), 0)
        self.assertEqual(F.backward_edge_union_bound(2, bits=2), Fraction(1, 4))
        self.assertEqual(F.backward_edge_union_bound(100, bits=2), 1)

    def test_bad_event_transfer_requires_both_caps(self):
        self.assertEqual(F.bounded_failure_allowance(Fraction(1, 16),
            maximum_admissions=8, maximum_award=64), 32)
        for invalid in (0.5, True, Fraction(-1), Fraction(2)):
            with self.assertRaises(ValueError):
                F.bounded_failure_allowance(invalid, maximum_admissions=1, maximum_award=1)

    def test_post_ticket_target_is_a_real_counterexample_to_premise(self):
        size = 256
        after_the_fact = sum(Fraction(size // (max(ticket, 1) + 1), size)
                             for ticket in range(size))
        self.assertEqual(after_the_fact, Fraction(669, 128))
        self.assertGreater(after_the_fact, 1)

    def test_strict_types_and_invalid_expected_cost(self):
        for invalid in (True, 0.0, -1):
            with self.assertRaises(ValueError):
                F.expected_credit_bound(invalid)
        for invalid in (1, 0.5, Fraction(-1), Fraction(3)):
            with self.assertRaises(ValueError):
                F.expected_credit_bound(2, expected_queries=invalid)
        with self.assertRaises(ValueError):
            F.nominal_award(0)


class QueryLedgerTests(unittest.TestCase):
    def test_ordered_chain_has_disjoint_charge_and_one_award(self):
        c = candidate()
        queries = [F.Query(c.identity, 1, 0, 3), F.Query(c.identity, 2, 3, 0)]
        report = F.audit_query_log([c], queries, [F.Claim(c.identity, 0, 2)], bits=2)
        self.assertEqual(report['prefix_revealed_final_queries'], [2])
        self.assertEqual(report['lazy_final_queries'], [])
        self.assertEqual(report['completed_chain_query_charge'], 2)
        self.assertEqual(report['nominal_model_credit'], 4)
        self.assertEqual(report['actual_chainwork'], 0)
        self.assertEqual(report['backward_edges'], [])
        for name in ('producer_own_resource_floor_proved', 'physical_cost_floor_proved',
                     'neural_work_floor_proved', 'sha256_hardness_proved',
                     'quantum_bound_proved', 'production_activation'):
            self.assertFalse(report[name])

    def test_lucky_backward_query_is_possible_and_detected(self):
        c = candidate()
        # A possible 2-bit oracle realization: lucky guessed predecessor 3.
        queries = [F.Query(c.identity, 2, 3, 0), F.Query(c.identity, 1, 0, 3)]
        report = F.audit_query_log([c], queries, [F.Claim(c.identity, 0, 2)], bits=2)
        self.assertEqual(report['prefix_revealed_final_queries'], [])
        self.assertEqual(report['lazy_final_queries'], [1])
        self.assertEqual(report['accepted_unique_candidates'], 1)
        self.assertEqual(report['completed_chain_query_charge'], 2)
        self.assertEqual(report['backward_edges'], [dict(identity=c.identity.hex(),
            predecessor_step=1, next_step=2, predecessor_query=2, guessed_query=1)])

    def test_unqueried_endpoint_guess_can_be_valid_but_verifier_pays(self):
        c = candidate()
        # Producer performs zero calls and guesses endpoint zero. The hidden
        # oracle happens to give H1(0)=2 and H2(2)=0; verifier reveals both.
        queries = [F.Query(c.identity, 1, 0, 2, 'verifier'),
                   F.Query(c.identity, 2, 2, 0, 'verifier')]
        claims = [F.Claim(c.identity, 0, 0), F.Claim(c.identity, 0, 2)]
        report = F.audit_query_log([c], queries, claims, bits=2)
        self.assertEqual([row['outcome'] for row in report['claim_rows']],
                         ['UNREVEALED_CHAIN', 'MODEL_ACCEPTED'])
        self.assertEqual(report['query_counts_by_owner'], {'verifier': 2})
        self.assertEqual(report['completed_chain_query_charge'], 2)
        self.assertFalse(report['producer_own_resource_floor_proved'])

    def test_rejected_lazy_guess_and_verifier_replay_cost_are_retained(self):
        c = candidate()
        queries = [F.Query(c.identity, 2, 3, 0),
                   F.Query(c.identity, 1, 0, 2, 'verifier'),
                   F.Query(c.identity, 2, 2, 3, 'verifier')]
        report = F.audit_query_log([c], queries,
                                  [F.Claim(c.identity, 0, 3)], bits=2)
        self.assertEqual(report['total_queries'], 3)
        self.assertEqual(report['distinct_queries'], 3)
        self.assertEqual(report['claim_rows'][0]['outcome'], 'ENDPOINT_MISMATCH')
        self.assertEqual(report['nominal_model_credit'], 0)
        self.assertEqual(report['lazy_final_queries'], [1])
        self.assertEqual(report['prefix_revealed_final_queries'], [3])

    def test_preprocessing_delegation_and_repeated_queries_are_not_free(self):
        c = candidate(length=3, profile='toy-three')
        queries = [F.Query(c.identity, 1, 0, 1, 'preprocessing'),
                   F.Query(c.identity, 2, 1, 2, 'delegate'),
                   F.Query(c.identity, 3, 2, 0),
                   F.Query(c.identity, 3, 2, 0, 'verifier')]
        report = F.audit_query_log([c], queries, [F.Claim(c.identity, 0, 4)], bits=2)
        self.assertEqual(report['total_queries'], 4)
        self.assertEqual(report['distinct_queries'], 3)
        self.assertEqual(report['completed_chain_query_charge'], 3)
        self.assertEqual(report['query_counts_by_owner'],
                         {'delegate': 1, 'preprocessing': 1, 'producer': 1, 'verifier': 1})
        self.assertEqual(report['query_rows'][-1]['classification'], 'repeat')

    def test_different_candidates_cannot_reuse_same_numeric_prefix(self):
        a, b = candidate(), candidate(b'candidate-b')
        queries = [F.Query(c.identity, 1, 0, 2) for c in (a, b)]
        queries += [F.Query(c.identity, 2, 2, 0) for c in (a, b)]
        claims = [F.Claim(c.identity, 0, 4) for c in (a, b)]
        report = F.audit_query_log([a, b], queries, claims, bits=2)
        self.assertEqual(report['distinct_queries'], 4)
        self.assertEqual(report['completed_chain_query_charge'], 4)
        self.assertEqual(report['accepted_unique_candidates'], 2)

    def test_64_carriers_and_duplicate_candidate_do_not_create_new_tickets(self):
        c = candidate()
        queries = [F.Query(c.identity, 1, 0, 2), F.Query(c.identity, 2, 2, 0)]
        claims = [F.Claim(c.identity, 0, 2, bytes([i])) for i in range(64)]
        report = F.audit_query_log([c, c], queries, claims, bits=2)
        self.assertEqual(report['accepted_unique_candidates'], 1)
        self.assertEqual(report['nominal_model_credit'], 4)
        self.assertEqual(sum(row['outcome'] == 'DUPLICATE' for row in report['claim_rows']), 63)
        self.assertEqual(report['distinct_queries'], 2)

    def test_prefix_out_of_order_does_not_bias_current_fresh_final_answer(self):
        c = candidate(length=3, profile='toy-three')
        queries = [F.Query(c.identity, 2, 3, 2), F.Query(c.identity, 1, 0, 3),
                   F.Query(c.identity, 3, 2, 0)]
        report = F.audit_query_log([c], queries, bits=2)
        self.assertEqual(report['prefix_revealed_final_queries'], [3])
        self.assertEqual(report['prefix_revealed_chain_query_charge'], 3)
        self.assertEqual(len(report['backward_edges']), 1)

    def test_target_seed_profile_and_length_rebinding_are_rejected(self):
        c = candidate()
        for changed in (replace(c, target=2), replace(c, seed=1),
                        replace(c, profile='toy-other'), replace(c, length=3)):
            with self.assertRaisesRegex(ValueError, 'CANDIDATE_REBINDING'):
                F.audit_query_log([c, changed], [], bits=2)
        with self.assertRaisesRegex(ValueError, 'PROFILE_SCALING_CONFLICT'):
            F.audit_query_log([c, candidate(b'b', length=3)], [], bits=2)
        with self.assertRaisesRegex(ValueError, 'RESEARCH_PROFILE_FIXED_LENGTH'):
            F.audit_query_log([replace(c, profile=F.RESEARCH_PROFILE)], [], bits=2)

    def test_known_wrong_predecessor_is_not_an_eligible_final_query(self):
        c = candidate()
        queries = [F.Query(c.identity, 1, 0, 2), F.Query(c.identity, 2, 3, 0)]
        report = F.audit_query_log([c], queries, [F.Claim(c.identity, 0, 2)], bits=2)
        self.assertEqual(report['query_rows'][-1]['classification'], 'wrong-known-predecessor')
        self.assertEqual(report['claim_rows'][0]['outcome'], 'UNREVEALED_CHAIN')
        self.assertEqual(report['prefix_revealed_chain_query_charge'], 0)

    def test_oracle_inconsistency_and_claim_time_rewind_fail_closed(self):
        c = candidate()
        with self.assertRaisesRegex(ValueError, 'INCONSISTENT_ORACLE'):
            F.audit_query_log([c], [F.Query(c.identity, 1, 0, 1),
                                   F.Query(c.identity, 1, 0, 2)], bits=2)
        with self.assertRaisesRegex(ValueError, 'CLAIM_TIME'):
            F.audit_query_log([c], [F.Query(c.identity, 1, 0, 1)],
                [F.Claim(c.identity, 0, 1), F.Claim(c.identity, 0, 0)], bits=2)

    def test_exhaustive_small_oracle_with_speculation_and_full_replay(self):
        # This fixture enumerates the hidden function independently of the
        # auditor: one H1(seed) value and every value of the H2 row, 4**5 cases.
        size, c = 4, candidate()
        total_credit = total_backward = cases = 0
        for first, final_row in product(range(size), product(range(size), repeat=size)):
            queries = [F.Query(c.identity, 2, 0, final_row[0]),
                       F.Query(c.identity, 1, 0, first, 'verifier'),
                       F.Query(c.identity, 2, first, final_row[first], 'verifier')]
            report = F.audit_query_log([c], queries,
                [F.Claim(c.identity, final_row[first], 3)], bits=2)
            self.assertEqual(report['completed_chain_query_charge'], 2)
            self.assertLessEqual(report['prefix_revealed_chain_query_charge'],
                                 report['distinct_queries'])
            self.assertEqual(report['accepted_unique_candidates'],
                             int(final_row[first] <= c.target))
            total_credit += report['nominal_model_credit']
            total_backward += len(report['backward_edges'])
            cases += 1
        self.assertEqual(cases, 1024)
        self.assertEqual(Fraction(total_credit, cases), 2)
        self.assertEqual(Fraction(total_backward, cases), Fraction(1, 4))

    def test_fixed_64_step_research_profile_and_unhashable_aliases(self):
        c = F.Candidate(b'fixed64', 0, 255)
        state, queries = c.seed, []
        for index in range(1, 65):
            following = (index * 3) % 256
            queries.append(F.Query(c.identity, index, state, following))
            state = following
        report = F.audit_query_log([c], queries, [F.Claim(c.identity, state, 64)], bits=8)
        self.assertEqual(report['completed_chain_query_charge'], 64)
        self.assertEqual(report['nominal_model_credit'], 64)
        for malformed in (F.Query([], 1, 0, 1), F.Query(c.identity, 1, 0, 1, [])):
            with self.assertRaises(ValueError):
                F.audit_query_log([c], [malformed], bits=8)
        with self.assertRaises(ValueError):
            F.audit_query_log([c], [], [F.Claim([], 0, 0)], bits=8)


class CoalitionFeedbackTests(unittest.TestCase):
    def test_single_unqueried_winning_guess_has_non_negligible_mean_at_tiny_target(self):
        # Uniform endpoint, no coalition chain calls, one claim of zero.
        # Hash length does not make the mean vanish when award grows with M.
        for bits in (2, 8, 32, 256):
            size = 1 << bits
            award = F.nominal_award(1, bits=bits, length=64)
            exact_mean = Fraction(award, size)
            self.assertEqual(exact_mean, 32)
            self.assertLessEqual(exact_mean, F.coalition_credit_bound(
                0, 1, award, bits=bits, length=64))
        size = 1 << 256
        self.assertEqual(Fraction(F.nominal_award(2), size),
                         Fraction(64, 3) * (1 - Fraction(1, size)))

    def test_adaptive_guesses_are_counted_after_failures_and_close_on_success(self):
        size, target, length = 8, 3, 2
        award = F.nominal_award(target, bits=3, length=length)
        total_credit = total_checks = 0
        for endpoint in range(size):
            for guess in (0, 1):
                total_checks += 1
                if guess == endpoint:
                    total_credit += award
                    break  # Success closes c; no duplicate award.
        self.assertEqual(Fraction(total_checks, size), Fraction(15, 8))
        exact_mean = Fraction(total_credit, size)
        self.assertEqual(exact_mean, 1)
        self.assertLessEqual(exact_mean, F.coalition_credit_bound(
            0, 2, award, bits=3, length=length))

    def test_rejected_miss_guess_increases_later_winning_query_probability(self):
        # L=1. Verify guessed endpoint seven first. On failure, query the
        # canonical oracle input and claim a hit if it is zero or one.
        size, target, length = 8, 1, 1
        award = F.nominal_award(target, bits=3, length=length)
        own_queries = credit = surviving = surviving_hits = 0
        for endpoint in range(size):
            if endpoint == 7:  # Correct equality, but miss; candidate closed.
                continue
            surviving += 1
            own_queries += 1
            if endpoint <= target:
                surviving_hits += 1
                credit += award
        self.assertEqual(Fraction(surviving_hits, surviving), Fraction(2, 7))
        self.assertGreater(Fraction(surviving_hits, surviving), Fraction(2, 8))
        mean_queries, mean_credit = Fraction(own_queries, size), Fraction(credit, size)
        self.assertGreater(mean_credit, mean_queries)
        self.assertLessEqual(mean_credit, F.coalition_credit_bound(
            1, 2, award, bits=3, length=length, expected_queries=mean_queries))

    def test_failed_verification_conditions_a_nonuniform_unrevealed_chain(self):
        # H2(0)=0 is the coalition's one known final input. H1(seed) is
        # unknown. Enumerating its value and a fresh alternate final answer
        # gives the endpoint marginal without enumerating the whole table.
        size, all_endpoints = 8, []
        for prefix, fresh_answer in product(range(size), repeat=2):
            all_endpoints.append(0 if prefix == 0 else fresh_answer)
        self.assertEqual(Fraction(all_endpoints.count(0), len(all_endpoints)),
                         Fraction(15, 64))
        after_reject_zero = [value for value in all_endpoints if value != 0]
        posterior_one = Fraction(after_reject_zero.count(1), len(after_reject_zero))
        self.assertEqual(posterior_one, Fraction(1, 7))
        base_one = Fraction(all_endpoints.count(1), len(all_endpoints))
        self.assertGreater(posterior_one, base_one)
        denominator = F.coalition_feedback_denominator(1, 2, bits=3)
        self.assertLessEqual(posterior_one / base_one, Fraction(size, denominator))
        self.assertLessEqual(posterior_one, Fraction(1, denominator))

    def test_exhaustive_lazy_final_query_plus_hidden_verification(self):
        # Coalition queries H2(0) but never H1(seed). It claims that observed
        # endpoint if winning, otherwise guesses zero. Hidden verifier uses
        # the true chain. This distinguishes lazy known answers from wholly
        # unqueried canonical final answers in all 4**5 oracle worlds.
        size, target, length = 4, 1, 2
        award = F.nominal_award(target, bits=2, length=length)
        credit = queried_wins = unqueried_wins = cases = 0
        for first, final_row in product(range(size), product(range(size), repeat=size)):
            guessed = final_row[0] if final_row[0] <= target else 0
            if final_row[first] == guessed:
                credit += award
                queried_wins += first == 0
                unqueried_wins += first != 0
            cases += 1
        self.assertEqual(cases, 1024)
        self.assertEqual(Fraction(queried_wins, cases), Fraction(1, 8))
        self.assertEqual(Fraction(unqueried_wins, cases), Fraction(3, 16))
        exact_credit = Fraction(credit, cases)
        self.assertEqual(exact_credit, Fraction(5, 4))
        self.assertGreater(exact_credit, 1)  # More than the one coalition call.
        self.assertLessEqual(exact_credit, F.coalition_credit_bound(
            1, 1, award, bits=2, length=length))

    def test_award_cap_from_target_floor_and_positive_residual_space(self):
        for floor in range(1, 32):
            maximum = F.nominal_award(floor, bits=5)
            for target in range(floor, 32):
                self.assertLessEqual(F.nominal_award(target, bits=5), maximum)
        # Unlimited feedback cannot be hidden behind a finite candidate set.
        with self.assertRaisesRegex(ValueError, 'FEEDBACK_BUDGET_EXHAUSTS_ORACLE_SPACE'):
            F.coalition_credit_bound(0, 4, 8, bits=2)
        with self.assertRaisesRegex(ValueError, 'FEEDBACK_BUDGET_EXHAUSTS_ORACLE_SPACE'):
            F.coalition_credit_bound(1, 2, 8, bits=2)
        self.assertEqual(F.coalition_credit_bound(100, 0, 1024), 0)
        self.assertFalse(F.COALITION_IMPLEMENTATION_TRANSFER_ESTABLISHED)
        self.assertFalse(F.COALITION_PHYSICAL_COST_FLOOR_PROVED)

    def test_exact_general_feedback_formula_and_strict_caps(self):
        q, checks, maximum, bits, length = 3, 2, 8, 8, 2
        mean = Fraction(5, 2)
        size, denominator = 1 << bits, (1 << bits) - checks * (q + 1)
        expected = min(Fraction(checks * maximum),
            Fraction(size, denominator) * mean +
            Fraction(length * q * (q + 1), 2 * denominator) +
            Fraction(checks * maximum, denominator))
        self.assertEqual(F.coalition_credit_bound(q, checks, maximum,
            bits=bits, length=length, expected_queries=mean), expected)
        for wrong in (True, -1, 1.0):
            with self.assertRaises(ValueError):
                F.coalition_credit_bound(1, wrong, maximum)
            with self.assertRaises(ValueError):
                F.coalition_credit_bound(1, 1, wrong)
        for wrong in (1, 0.5, Fraction(-1), Fraction(2)):
            with self.assertRaises(ValueError):
                F.coalition_credit_bound(1, 1, maximum, expected_queries=wrong)


if __name__ == '__main__':
    unittest.main()
