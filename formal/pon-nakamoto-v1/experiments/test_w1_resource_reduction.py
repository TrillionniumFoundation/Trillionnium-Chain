"""Independent small controls for conditional resource accounting, not benchmarks."""
from __future__ import annotations

from fractions import Fraction
from itertools import product
from pathlib import Path
import sys
import unittest

import w1_resource_reduction as model

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import contract_wire as wire


def padded(values, length):
    return tuple(values) + (Fraction(),) * (length - len(values))


def enumerate_gated_schedule(budget, useful, proof, probability):
    """Independent padded coin space and imperative executor, without DP."""
    result = [Fraction()] * (budget // useful + 1)
    count = budget // useful
    for coins in product((0, 1), repeat=count):
        mass = probability ** sum(coins) * (1 - probability) ** (count - sum(coins))
        left, wins = budget, 0
        for hit in coins:
            if left < useful:
                break
            left -= useful
            if hit:
                if left < proof:
                    break
                left -= proof
                wins += 1
        result[wins] += mass
    return tuple(result)


class NativeIdentityControls(unittest.TestCase):
    def setUp(self):
        self.header = {row['name']: bytes([index + 1]) * 32 if row['type'] == 'hash32' else index + 1
                       for index, row in enumerate(wire.SCHEMA['header'])}
        self.encoded = wire.header_encode(self.header)
        self.trace = bytes(range(32))

    def test_actual_framing_matches_independent_wire_oracle(self):
        ids = model.actual_w1_identities(self.encoded, self.trace)
        challenge = wire.H('challenge', self.encoded)
        ticket = wire.H('ticket', challenge, self.trace)
        self.assertEqual(len(self.encoded), 318)
        self.assertEqual(ids, {
            'challenge': challenge, 'ticket': ticket,
            'block_id': wire.H('block', self.encoded, self.trace),
            'research_semantic_id': wire.H('w1-cost-game-semantic-ticket-v1', self.header['work_task'], challenge, ticket),
        })

    def test_every_existing_header_field_is_inside_challenge(self):
        original = model.actual_w1_identities(self.encoded, self.trace)
        for name, value in self.header.items():
            changed = dict(self.header)
            changed[name] = bytes([value[0] ^ 1]) + value[1:] if isinstance(value, bytes) else value ^ 1
            ids = model.actual_w1_identities(wire.header_encode(changed), self.trace)
            self.assertNotEqual(ids['challenge'], original['challenge'], name)
            self.assertNotEqual(ids['ticket'], original['ticket'], name)
            self.assertNotEqual(ids['block_id'], original['block_id'], name)

    def test_trace_changes_lottery_and_block_but_not_challenge(self):
        first = model.actual_w1_identities(self.encoded, self.trace)
        second = model.actual_w1_identities(self.encoded, bytes(32))
        self.assertEqual(first['challenge'], second['challenge'])
        self.assertNotEqual(first['ticket'], second['ticket'])
        self.assertNotEqual(first['block_id'], second['block_id'])
        self.assertEqual(first, model.actual_w1_identities(self.encoded, self.trace))

    def test_envelopes_are_strict_without_claiming_full_work_verification(self):
        for header in (self.encoded[:-1], self.encoded + b'0', b'PNH2' + self.encoded[4:], bytearray(self.encoded)):
            with self.assertRaises(ValueError):
                model.actual_w1_identities(header, self.trace)
        with self.assertRaises(ValueError):
            model.actual_w1_identities(self.encoded, bytes(31))
        # A made-up trace still has an identity. Identity is not a validity check.
        self.assertEqual(len(model.actual_w1_identities(self.encoded, b'x' * 32)['ticket']), 32)

    def test_inclusive_ideal_target_and_native_zero_rejection(self):
        self.assertEqual(model.target_probability(bytes(32)), 0)
        self.assertEqual(model.target_probability((1).to_bytes(32, 'big')), Fraction(2, 1 << 256))
        self.assertEqual(model.target_probability(((1 << 255) - 1).to_bytes(32, 'big')), Fraction(1, 2))
        self.assertEqual(model.target_probability(b'\xff' * 32), 1)
        with self.assertRaises(ValueError):
            model.target_probability(bytes(31))


class ResourceTransferControls(unittest.TestCase):
    def oracle_args(self):
        return dict(preprocessing_trace_queries=2, online_trace_queries=4,
                    preprocessing_lottery_queries=2, online_lottery_queries=8,
                    header_queries=8, task_queries=3, submissions=2)

    def test_temporal_bound_counts_preparation_all_queries_and_terminal_checks(self):
        result = model.temporal_oracle_failure_bound(**self.oracle_args())
        self.assertEqual(result['trace_query_cap_including_terminal_audit'], 8)
        self.assertEqual(result['lottery_reference_cap_including_submissions'], 12)
        denominator = 1 << 256
        expected = {'trace_response_collision': 28, 'header_response_collision': 28,
                    'task_response_collision': 3, 'late_header_opening': 96,
                    'late_task_opening': 24, 'early_trace_guess': 12}
        for name, numerator in expected.items():
            self.assertEqual(result[name], Fraction(numerator, denominator))
        self.assertEqual(result['union_bound'], Fraction(191, denominator))
        changed = self.oracle_args()
        changed['preprocessing_lottery_queries'] += 1
        other = model.temporal_oracle_failure_bound(**changed)
        self.assertGreater(other['early_trace_guess'], result['early_trace_guess'])
        self.assertEqual(model.temporal_oracle_failure_bound(**self.oracle_args(), digest_bits=1)['union_bound'], 1)

    def test_resource_inequality_and_candidate_overhead_are_explicit(self):
        cap = model.extraction_resource_cap(budget=100, prefix_cost=12, fixed_overhead=3,
                preprocessing_credit=5, per_correct_overhead=2, per_candidate_overhead=1, candidate_cap=40)
        self.assertEqual(cap, 14)
        self.assertLessEqual(12 * cap - 5, 100 + 3 + 2 * cap + 40)
        self.assertGreater(12 * (cap + 1) - 5, 100 + 3 + 2 * (cap + 1) + 40)
        self.assertEqual(model.extraction_resource_cap(budget=100, prefix_cost=10,
                         per_candidate_overhead=1, candidate_cap=100), 20)
        self.assertEqual(model.extraction_resource_cap(budget=100, prefix_cost=10), 10)

    def test_output_lower_bound_cancels_extractor_output_cost(self):
        for overhead in (12, 13, 100):
            self.assertIsNone(model.extraction_resource_cap(budget=100, prefix_cost=12,
                                                          per_correct_overhead=overhead))
        self.assertEqual(model.extraction_resource_cap(budget=5, prefix_cost=Fraction(3, 2),
                         per_correct_overhead=Fraction(1, 2)), 5)

    def test_affine_bound_is_largest_feasible_integer_on_small_grid(self):
        for ell in range(1, 7):
            for overhead in range(ell):
                for budget in range(7):
                    cap = model.extraction_resource_cap(budget=budget, prefix_cost=ell,
                            preprocessing_credit=2, per_correct_overhead=overhead,
                            per_candidate_overhead=Fraction(1, 2), candidate_cap=3)
                    feasible = [m for m in range(30) if ell * m - 2 <= budget + overhead * m + Fraction(3, 2)]
                    self.assertEqual(cap, max(feasible))

    def test_prepared_unqueried_bank_is_separate_from_raw_query_bound(self):
        self.assertEqual(model.fresh_opportunity_cap(new_prefix_cap=2, prepared_unqueried_cap=5,
                         online_lottery_queries=8, submissions=2), 7)
        self.assertEqual(model.fresh_opportunity_cap(new_prefix_cap=20, prepared_unqueried_cap=5,
                         online_lottery_queries=8, submissions=2), 10)
        self.assertIsNone(model.fresh_opportunity_cap(new_prefix_cap=None, prepared_unqueried_cap=5,
                                                    online_lottery_queries=8, submissions=2))

    def test_tail_bound_against_independent_coin_spaces_and_bad_event(self):
        p, eps = Fraction(1, 2), Fraction(1, 8)
        for trials in range(5):
            for bank, fanout, output_cap in ((0, 1, 5), (2, 2, 6), (3, 3, 4), (0, 2, 0)):
                outcomes = [(min(output_cap, bank + fanout * sum(bits)), Fraction(1, 2 ** trials))
                            for bits in product((0, 1), repeat=trials)]
                for threshold in range(output_cap + 2):
                    result = model.conditional_ticket_bounds(fresh_opportunities=trials, probability=p,
                        known_winning_credit=bank, fanout=fanout, failure_probability=eps,
                        output_cap=output_cap, at_least=threshold)
                    actual_tail = (1 - eps) * sum(mass for n, mass in outcomes if n >= threshold)
                    actual_tail += eps * int(output_cap >= threshold)
                    actual_mean = (1 - eps) * sum(n * mass for n, mass in outcomes) + eps * output_cap
                    self.assertLessEqual(actual_tail, result['tail_bound'])
                    self.assertLessEqual(actual_mean, result['expectation_bound'])

    def test_early_guess_model_has_independent_exhaustive_control(self):
        for space in (2, 4, 8):
            for guesses in range(space + 1):
                p = Fraction(1, 2)
                accepted = Fraction()
                for actual in range(space):
                    for bits in product((0, 1), repeat=guesses):
                        if actual < guesses and bits[actual]:
                            accepted += Fraction(1, space * 2 ** guesses)
                result = model.early_screening_countermodel(trace_values=space, distinct_guesses=guesses, probability=p)
                self.assertEqual(result['accepted_winning_pair'], accepted)
        example = model.early_screening_countermodel(trace_values=8, distinct_guesses=4, probability=Fraction(1, 2))
        self.assertEqual(example['accepted_winning_pair'], Fraction(1, 4))
        self.assertGreater(example['accepted_winning_pair'], example['incorrect_final_one_output_guess_bound'])

    def test_cost_and_probability_inputs_reject_implicit_or_inexact_values(self):
        with self.assertRaises(ValueError):
            model.extraction_resource_cap(budget=10.0, prefix_cost=2)
        with self.assertRaises(ValueError):
            model.extraction_resource_cap(budget=10, prefix_cost=0)
        with self.assertRaises(ValueError):
            model.extraction_resource_cap(budget=10, prefix_cost=2, candidate_cap=True)
        for value in (-1, True, 1.0):
            args = self.oracle_args()
            args['online_lottery_queries'] = value
            with self.assertRaises(ValueError):
                model.temporal_oracle_failure_bound(**args)
        with self.assertRaises(ValueError):
            model.early_screening_countermodel(trace_values=2, distinct_guesses=3, probability=Fraction(1, 2))


class CompositionControls(unittest.TestCase):
    def test_winner_only_dp_matches_independent_execution_enumeration(self):
        for useful, proof in ((1, 0), (1, 3), (2, 1), (3, 4)):
            for budget in range(9):
                for p in (Fraction(), Fraction(1, 3), Fraction(1, 2), Fraction(1)):
                    expected = enumerate_gated_schedule(budget, useful, proof, p)
                    actual = model.winner_only_proof_pmf(budget, useful, proof, p)
                    self.assertEqual(padded(actual, len(expected)), expected,
                                     (budget, useful, proof, p))
                    self.assertEqual(sum(actual), 1)

    def test_poml_completion_is_not_a_per_lottery_proof_charge(self):
        p = Fraction(1, 2)
        eager = model.eager_proof_pmf(36, 9, 9, p)
        winner_only = model.winner_only_proof_pmf(36, 9, 9, p)
        self.assertEqual(eager, (Fraction(1, 4), Fraction(1, 2), Fraction(1, 4)))
        self.assertEqual(winner_only, (Fraction(1, 8), Fraction(5, 8), Fraction(1, 4)))
        self.assertEqual(model.mean(eager), 1)
        self.assertEqual(model.mean(winner_only), Fraction(9, 8))
        expectations = model.proof_gating_expectations(9, 9, p)
        self.assertEqual(expectations['winner_only_per_started_useful_attempt'], Fraction(27, 2))
        self.assertEqual(expectations['winner_only_first_accepted_win'], 27)
        self.assertEqual(expectations['eager_first_accepted_win'], 36)

    def test_unaffordable_proof_is_never_credited_or_refunded(self):
        for budget in (0, 8, 9, 17):
            self.assertEqual(model.winner_only_proof_pmf(budget, 9, 9, Fraction(1)), (Fraction(1),))
        self.assertEqual(model.winner_only_proof_pmf(18, 9, 9, Fraction(1)), (Fraction(), Fraction(1)))
        self.assertIsNone(model.proof_gating_expectations(9, 9, Fraction())['winner_only_first_accepted_win'])
        with self.assertRaises(ValueError):
            model.winner_only_proof_pmf(20, 0, 1, Fraction(1, 2))
        with self.assertRaises(ValueError):
            model.winner_only_proof_pmf(129, 1, 1, Fraction(1, 2))

    def test_proof_policy_pmfs_match_independent_identity_enumeration(self):
        for variants in range(1, 5):
            for lottery, credit in product((False, True), repeat=2):
                rows = model.proof_variant_structure(variants, lottery_binds_proof=lottery, credit_binds_proof=credit)
                inputs = sorted({x for x, _ in rows})
                for p in (Fraction(), Fraction(1, 3), Fraction(1, 2), Fraction(1)):
                    expected = [Fraction()] * (variants + 1)
                    for bits in product((0, 1), repeat=len(inputs)):
                        winners = {key for key, bit in zip(inputs, bits) if bit}
                        credited = {credit_key for input_key, credit_key in rows if input_key in winners}
                        expected[len(credited)] += p ** sum(bits) * (1 - p) ** (len(bits) - sum(bits))
                    pmf = model.proof_variant_credit_pmf(variants, p, lottery_binds_proof=lottery, credit_binds_proof=credit)
                    self.assertEqual(padded(pmf, len(expected)), tuple(expected))

    def test_single_credit_key_still_allows_proof_lottery_grinding(self):
        p = Fraction(1, 2)
        safe = model.proof_variant_credit_pmf(4, p, lottery_binds_proof=False, credit_binds_proof=False)
        grinding = model.proof_variant_credit_pmf(4, p, lottery_binds_proof=True, credit_binds_proof=False)
        fanout = model.proof_variant_credit_pmf(4, p, lottery_binds_proof=False, credit_binds_proof=True)
        self.assertEqual(model.tail(safe, 1), Fraction(1, 2))
        self.assertEqual(model.tail(grinding, 1), Fraction(15, 16))
        self.assertEqual(model.mean(fanout), 2)
        self.assertEqual(fanout, (Fraction(1, 2), Fraction(), Fraction(), Fraction(), Fraction(1, 2)))

    def test_consumption_is_unique_only_in_its_monotone_namespace(self):
        events = [('parent-a', 'useful'), ('parent-a', 'useful'), ('parent-b', 'useful')]
        self.assertEqual(model.monotone_consumption_count(events, include_scope_in_key=False), 1)
        self.assertEqual(model.monotone_consumption_count(events, include_scope_in_key=True), 2)
        reset_total = sum(model.monotone_consumption_count([event], include_scope_in_key=False)
                          for event in (events[0], events[2]))
        self.assertEqual(reset_total, 2)
        with self.assertRaises(ValueError):
            model.monotone_consumption_count([('parent', 0)], include_scope_in_key=False)

    def test_separate_cost_bounds_imply_max_without_disjointness(self):
        same = model.shared_component_cost(range(10), range(10))
        self.assertEqual(same, {'first': 10, 'second': 10, 'overlap': 10, 'joint': 10, 'unjustified_sum': 20})
        partial = model.shared_component_cost(range(10), range(5, 15))
        self.assertEqual(partial['joint'], 15)
        disjoint = model.shared_component_cost(range(10), range(10, 20))
        self.assertEqual(disjoint['joint'], 20)

    def test_report_never_promotes_unknown_hardness_or_production(self):
        report = model.report()
        for name in ('sha256_extraction_established', 'adaptive_prefix_hardness_established',
                     'physical_resource_floor_established', 'o01_closed',
                     'o05_production_composition_closed', 'o07_production_zk_closed', 'production_activation'):
            self.assertIs(report[name], False)
        self.assertEqual(report['abstract_resource_transfer']['new_prefix_cap'], 14)
        self.assertIsNone(report['abstract_resource_transfer']['output_only_bound_cancels'])
        def visit(value):
            self.assertIsNot(type(value), float)
            if isinstance(value, dict):
                for item in value.values():
                    visit(item)
            elif isinstance(value, (tuple, list)):
                for item in value:
                    visit(item)
        visit(report)


if __name__ == '__main__':
    unittest.main()
