#!/usr/bin/env python3
"""Executable counterexamples; no source-independent or production acceptance."""
from __future__ import annotations

from dataclasses import replace
from itertools import combinations, permutations, product, repeat
import unittest

from settlement_risk_v2 import Reject, U128_MAX, fixtures, self_test, validate_batch
from poco_consensus_risk_v1 import (ConsensusRiskPolicyV1, ValidatorRiskV1, analyze_set,
                                   analyze_handoff, possible_consumption_cycles, quorum,
                                   _minimum_coalition_cost)


class SettlementSecurityTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.actors, self.facts = fixtures()

    def exposures(self, amounts):
        return [replace(fact, escrow_amount=value, provider_bond=value,
                        challenge_bond=value if fact.challenger else 0)
                for fact, value in zip(self.facts, amounts)]

    def test_provider_fractional_basis_point_bypass_rejected(self):
        self.assertEqual(40001 * 10000 // 100000, 4000)  # The previous comparison lost the excess.
        with self.assertRaisesRegex(Reject, '^provider-concentration$'):
            validate_batch(self.policy, self.actors, self.exposures([40001, 30000, 29999]))

    def test_owner_fractional_basis_point_bypass_rejected(self):
        policy = replace(self.policy, max_provider_exposure_bps=10000)
        with self.assertRaisesRegex(Reject, '^beneficial-owner-sybil-concentration$'):
            validate_batch(policy, self.actors, self.exposures([40001, 30000, 29999]))

    def test_exact_cap_and_one_unit_below_are_admitted(self):
        for amounts in ([40000, 30000, 30000], [39999, 30001, 30000]):
            with self.subTest(amounts=amounts):
                self.assertEqual(validate_batch(self.policy, self.actors, self.exposures(amounts))['tasks'], 3)

    def test_amounts_are_checked_unsigned_integers_not_python_numbers(self):
        for value in (True, False, 1.5, float('nan'), -1, U128_MAX + 1):
            for field in ('escrow_amount', 'provider_bond', 'challenge_bond'):
                with self.subTest(value=value, field=field), self.assertRaises(Reject):
                    validate_batch(self.policy, self.actors, [replace(self.facts[0], **{field: value}), *self.facts[1:]])

    def test_policy_bools_do_not_pass_as_integer_basis_points(self):
        for field in ('min_provider_bond_bps', 'min_challenge_bond_bps',
                      'max_provider_exposure_bps', 'max_owner_exposure_bps'):
            with self.subTest(field=field), self.assertRaises(Reject):
                validate_batch(replace(self.policy, **{field: True}), self.actors, self.facts)

    def test_policy_flags_must_be_actual_booleans(self):
        for field in ('allow_related_party', 'allow_provider_verifier_overlap'):
            with self.subTest(field=field), self.assertRaises(Reject):
                validate_batch(replace(self.policy, **{field: 'false'}), self.actors, self.facts)

    def test_u128_multiplication_overflow_rejects(self):
        with self.assertRaisesRegex(Reject, 'arithmetic-overflow'):
            validate_batch(self.policy, self.actors, [replace(self.facts[0], provider_bond=U128_MAX), *self.facts[1:]])

    def test_infinite_input_is_bounded_before_materialization(self):
        for actors, facts in ((repeat(self.actors[0]), self.facts), (self.actors, repeat(self.facts[0]))):
            with self.subTest(), self.assertRaisesRegex(Reject, 'limit'):
                validate_batch(self.policy, actors, facts)

    def test_unknown_role_and_missing_owner_do_not_create_independence(self):
        for actor in (replace(self.actors[0], beneficial_owner=''),
                      replace(self.actors[0], roles=frozenset({'independent'}))):
            with self.subTest(), self.assertRaises(Reject):
                validate_batch(self.policy, [actor, *self.actors[1:]], self.facts)

    def test_valid_root_unchanged_and_self_test_positives_executed(self):
        report = self_test()
        self.assertEqual(report['positive'], 4)
        self.assertEqual(len(report['negative']), 11)
        self.assertEqual(report['risk_root'], '8c9b246d0c94f0ffaf477c9385f296cc98f70951bed9316eb970efedb15d3a57')
        self.assertFalse(report['identity_claims_authenticated'])
        self.assertFalse(report['poco_weight_eligible'])


class ConsensusSecurityTests(unittest.TestCase):
    def setUp(self):
        self.policy = ConsensusRiskPolicyV1(10, 4, 2, 5, 10, 250000, 100000)
        self.validators = [ValidatorRiskV1(f'v{i}', f'owner{i}', 1, f'bond{i}', 100, 20)
                           for i in range(4)]

    def test_integer_quorum_and_blocking_thresholds(self):
        for total in range(1, 101):
            q = quorum(total)
            self.assertGreater(3 * q, 2 * total)
            self.assertLessEqual(3 * (q - 1), 2 * total)
            blocking = total - q + 1
            self.assertLess(total - blocking, q)
            self.assertGreaterEqual(total - blocking + 1, q)

    def test_two_quorum_intersection_bound_by_exhaustive_small_sets(self):
        for weights in product(range(1, 4), repeat=4):
            total = sum(weights)
            q = quorum(total)
            masks = [set(i for i in range(4) if mask & (1 << i)) for mask in range(16)]
            quorums = [mask for mask in masks if sum(weights[i] for i in mask) >= q]
            for left in quorums:
                for right in quorums:
                    self.assertGreaterEqual(sum(weights[i] for i in left & right), 2 * q - total)

    def test_controller_identity_splitting_does_not_split_concentration(self):
        split = [replace(row, controller_id='controller') if i < 2 else row
                 for i, row in enumerate(self.validators)]
        report = analyze_set(self.policy, split, ['controller'])
        self.assertEqual(report['controller_cap_violations'], ['controller'])
        self.assertFalse(report['strict_byzantine_weight_assumption_holds'])
        self.assertEqual(report['faulty_weight'], 2)

    def test_low_weight_many_identities_can_dominate_unweighted_leader_slots(self):
        rows = [ValidatorRiskV1(f'a{i:02}', 'adversary', 1, f'a-bond{i}', 100, 20) for i in range(9)]
        rows += [ValidatorRiskV1(f'h{i}', f'honest{i}', 100, f'h-bond{i}', 10000, 20) for i in range(4)]
        report = analyze_set(self.policy, rows, ['adversary'])
        self.assertTrue(report['strict_byzantine_weight_assumption_holds'])
        self.assertEqual((report['faulty_leader_slots'], report['leader_slots']), (9, 13))
        self.assertEqual(report['maximum_consecutive_faulty_slots'], 9)
        self.assertEqual(report['controller_cap_violations'], [])

    def test_withdrawal_at_evidence_endpoint_is_not_covered(self):
        rows = [replace(self.validators[0], locked_until_epoch=14), *self.validators[1:]]
        report = analyze_set(self.policy, rows)
        self.assertEqual(report['uncovered_validators'], ['v0'])
        self.assertEqual(report['controllers']['owner0']['model_penalty'], 0)

    def test_bond_shortfall_not_counted_as_economic_security(self):
        rows = [replace(self.validators[0], bond=9), *self.validators[1:]]
        self.assertEqual(analyze_set(self.policy, rows)['uncovered_validators'], ['v0'])

    def test_same_bond_cannot_back_two_declared_validators(self):
        with self.assertRaisesRegex(Reject, 'bond-double-pledge'):
            analyze_set(self.policy, [self.validators[0], replace(self.validators[1], bond_id='bond0')])

    def test_unresolved_controller_does_not_get_a_fresh_independent_bucket(self):
        with self.assertRaisesRegex(Reject, 'identity-unresolved'):
            analyze_set(self.policy, [replace(self.validators[0], controller_id=''), *self.validators[1:]])

    def test_long_range_window_and_epoch_overflow_reject(self):
        for policy in (replace(self.policy, unbonding_delay_epochs=2),
                       replace(self.policy, unbonding_delay_epochs=3),
                       replace(self.policy, target_epoch=(1 << 64) - 1)):
            with self.subTest(), self.assertRaises(Reject):
                analyze_set(policy, self.validators)

    def test_amount_bool_zero_and_model_capacity_reject(self):
        for row in (replace(self.validators[0], weight=True), replace(self.validators[0], weight=0),
                    replace(self.validators[0], bond=True), replace(self.validators[0], weight=100001)):
            with self.subTest(), self.assertRaises(Reject):
                analyze_set(self.policy, [row, *self.validators[1:]])
        with self.assertRaisesRegex(Reject, 'validator-count'):
            analyze_set(self.policy, repeat(self.validators[0]))

    def test_cost_dynamic_program_matches_exhaustive_coalitions(self):
        for weights in product(range(1, 4), repeat=3):
            groups = list(zip(weights, [7, 11, 4]))
            for threshold in range(1, sum(weights) + 1):
                brute = min(sum(groups[i][1] for i in subset)
                            for count in range(1, 4) for subset in combinations(range(3), count)
                            if sum(groups[i][0] for i in subset) >= threshold)
                self.assertEqual(_minimum_coalition_cost(groups, threshold), brute)

    def test_penalty_rounding_is_per_validator_not_after_owner_aggregation(self):
        policy = replace(self.policy, bond_per_weight=1, assumed_double_vote_slash_ppm=333333)
        rows = [replace(row, controller_id='one', bond=2) for row in self.validators]
        self.assertEqual(analyze_set(policy, rows)['controllers']['one']['model_penalty'], 0)

    def test_all_input_permutations_have_one_input_commitment(self):
        roots = {analyze_set(self.policy, rows, ['owner0'])['input_commitment']
                 for rows in permutations(self.validators)}
        self.assertEqual(len(roots), 1)
        changed = analyze_set(replace(self.policy, assumed_double_vote_slash_ppm=200000), self.validators)['input_commitment']
        self.assertNotIn(changed, roots)

    def test_each_handoff_role_checks_its_own_weight_bound(self):
        old = [replace(row, controller_id='bad') if i < 2 else row for i, row in enumerate(self.validators)]
        new = [replace(row, controller_id='bad') if i == 0 else row for i, row in enumerate(self.validators)]
        report = analyze_handoff(self.policy, old, replace(self.policy, target_epoch=11), new, ['bad'])
        self.assertFalse(report['old']['strict_byzantine_weight_assumption_holds'])
        self.assertTrue(report['new']['strict_byzantine_weight_assumption_holds'])
        self.assertFalse(report['both_declared_fault_bounds_hold'])
        self.assertFalse(report['joint_certificate_verified'])
        self.assertFalse(report['signing_authority'])

    def test_cycles_longer_than_reciprocal_pair_are_reported(self):
        flows = [('a', 'b'), ('b', 'c'), ('c', 'a'), ('independent', 'supplier'), ('self', 'self')]
        self.assertEqual(possible_consumption_cycles(flows), [['a', 'b', 'c'], ['self']])
        self.assertEqual(possible_consumption_cycles(reversed(flows)), [['a', 'b', 'c'], ['self']])
        self.assertEqual(possible_consumption_cycles([('a', 'b'), ('b', 'c')]), [])

    def test_cycle_graph_bounds(self):
        with self.assertRaisesRegex(Reject, 'flow-count'):
            possible_consumption_cycles(repeat(('a', 'b')))

    def test_report_does_not_certify_assumed_identities_or_custody(self):
        report = analyze_set(self.policy, self.validators)
        for field in ('identity_claims_authenticated', 'collateral_claims_authenticated', 'safety_proof',
                      'economic_activation_authority', 'production_activation'):
            self.assertIs(report[field], False)
        self.assertEqual(report['blocking_weight'], 2)
        self.assertEqual(report['two_quorum_intersection_weight'], 2)


if __name__ == '__main__':
    unittest.main()
