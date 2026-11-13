"""Independent finite-policy and adverse-advice controls for tail transfer.

The finite policies are controls for the arithmetic and its premises. They do
not exhaust actual W1 implementations or authenticate a supplied cap theorem.
"""
from __future__ import annotations

import copy
from fractions import Fraction
from functools import lru_cache
from itertools import combinations, product
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import cost_tail_transfer as transfer


F = Fraction


def rational(wire):
    return F(wire["numerator"], wire["denominator"])


def independent_prior(domain, p):
    return tuple((table, p ** sum(table) * (1 - p) ** (domain - sum(table)))
                 for table in product((0, 1), repeat=domain))


def policy_pairs(prior, cap, free_outputs=0):
    """Enumerate exact success/cost pairs from complete tiny decision trees.

    Every reachable observation history has its own stopping/output/query
    choice. Repeated queries are included. Stopping after a known winner
    dominates paying for further observations on that history.
    """
    domain = len(prior[0][0])

    @lru_cache(None)
    def visit(known, remaining):
        possible = tuple((table, mass) for table, mass in prior
                         if all(bit == -1 or bit == table[index]
                                for index, bit in enumerate(known)))
        normalizer = sum((mass for _, mass in possible), F(0))
        if not normalizer:
            return frozenset()
        if 1 in known:
            return frozenset(((F(0), F(0)), (F(1), F(0))))
        unknown = tuple(index for index, bit in enumerate(known) if bit == -1)
        outcomes = {(F(0), F(0))}
        for size in range(min(free_outputs, len(unknown)) + 1):
            for guesses in combinations(unknown, size):
                marked = sum((mass for table, mass in possible
                              if any(table[index] for index in guesses)), F(0))
                outcomes.add((marked / normalizer, F(0)))
        if not remaining:
            return frozenset(outcomes)
        for address in range(domain):
            branches = []
            for answer in (0, 1):
                mass = sum((mass for table, mass in possible
                            if table[address] == answer), F(0))
                if mass:
                    updated = list(known)
                    updated[address] = answer
                    branches.append((mass / normalizer,
                                     visit(tuple(updated), remaining - 1)))
            for choices in product(*(pairs for _, pairs in branches)):
                success = sum((weight * choice[0]
                               for (weight, _), choice in zip(branches, choices)), F(0))
                cost = 1 + sum((weight * choice[1]
                                for (weight, _), choice in zip(branches, choices)), F(0))
                outcomes.add((success, cost))
        return frozenset(outcomes)

    return visit((-1,) * domain, cap)


class IndependentPolicyTests(unittest.TestCase):
    def checked(self, spec):
        certificate = transfer.build_certificate(spec)
        self.assertTrue(transfer.verify_certificate(spec, certificate))
        return certificate

    def test_caps_match_all_tiny_feedback_trees_and_terminal_output_choices(self):
        comparisons = 0
        for domain, p, free in product(range(1, 4), (F(1, 4), F(1, 2)), range(2)):
            prior = independent_prior(domain, p)
            exact_caps = tuple(max(success for success, _ in policy_pairs(prior, q, free))
                               for q in range(domain + 1))
            self.assertEqual(transfer.bernoulli_caps(p, domain, domain, free), exact_caps)
            all_pairs = policy_pairs(prior, domain, free)
            for alpha in (F(0), F(1, 4), F(1, 2), F(3, 4), F(1)):
                certificate = self.checked(transfer.TransferSpec(alpha, exact_caps, domain + 1))
                lower = rational(certificate["sum_lower"])
                for success, cost in all_pairs:
                    if success >= alpha:
                        self.assertLessEqual(lower, cost)
                        comparisons += 1
        self.assertGreater(comparisons, 100)

    def test_correlated_tables_use_their_own_full_policy_caps(self):
        # These priors have Bernoulli-looking marginals but are not iid.
        priors = (
            (((0, 1), F(1, 2)), ((1, 0), F(1, 2))),
            (((0, 0), F(3, 4)), ((1, 1), F(1, 4))),
        )
        for prior in priors:
            caps = tuple(max(success for success, _ in policy_pairs(prior, q))
                         for q in range(3))
            for alpha in (F(1, 4), F(1, 2), F(3, 4), F(1)):
                with self.subTest(prior=prior, alpha=alpha):
                    certificate = self.checked(transfer.TransferSpec(alpha, caps, 3))
                    for success, cost in policy_pairs(prior, 2):
                        if success >= alpha:
                            self.assertLessEqual(rational(certificate["sum_lower"]), cost)
        fixed_one = priors[0]
        self.assertEqual(max(s for s, _ in policy_pairs(fixed_one, 2)), 1)
        self.assertEqual(transfer.bernoulli_caps(F(1, 2), 2, 2)[2], F(3, 4))

    def test_private_policy_mixtures_preserve_the_unconditional_bound(self):
        prior = independent_prior(2, F(1, 4))
        pairs = tuple(policy_pairs(prior, 2))
        caps = tuple(max(s for s, _ in policy_pairs(prior, q)) for q in range(3))
        comparisons = 0
        for first, second, weight in product(pairs, pairs, (F(1, 3), F(1, 2), F(2, 3))):
            success = weight * first[0] + (1 - weight) * second[0]
            mean_cost = weight * first[1] + (1 - weight) * second[1]
            certificate = self.checked(transfer.TransferSpec(success, caps, 3))
            self.assertLessEqual(rational(certificate["sum_lower"]), mean_cost)
            comparisons += 1
        self.assertGreater(comparisons, 100)

    def test_tail_sum_dominates_every_single_cut_with_exact_inequalities(self):
        for p, alpha, domination, overhead in product(
                (F(1, 16), F(1, 4), F(1, 2)),
                (F(1, 4), F(1, 2), F(1)), (F(1), F(2), F(3)), (F(0), F(1))):
            spec = transfer.TransferSpec(alpha, transfer.bernoulli_caps(p, 16, 16), 12,
                                         overhead=overhead, domination=domination)
            certificate = self.checked(spec)
            total = rational(certificate["sum_lower"])
            for row in certificate["rows"]:
                self.assertGreaterEqual(total, (row["budget"] + 1) * rational(row["tail_lower"]))
            self.assertGreaterEqual(total, rational(certificate["markov_lower"]))

    def test_exact_domination_two_improvement_over_markov(self):
        spec = transfer.TransferSpec(F(1, 2), transfer.bernoulli_caps(F(1, 16), 11, 11),
                                     12, domination=F(2))
        certificate = self.checked(spec)
        self.assertEqual(rational(certificate["sum_lower"]), F(43441, 32768))
        self.assertEqual(rational(certificate["markov_lower"]), F(99, 128))
        self.assertEqual([rational(row["tail_lower"]) for row in certificate["rows"][:5]],
                         [F(1, 2), F(3, 8), F(33, 128), F(303, 2048), F(1473, 32768)])
        self.assertTrue(all(rational(row["tail_lower"]) == 0
                            for row in certificate["rows"][5:]))

    def test_one_advice_bit_refutes_direct_expected_frontier_transport(self):
        prior = independent_prior(11, F(1, 16))
        success = mean_queries = F(0)
        for table, mass in prior:
            # Reference advice is fair; actual advice reveals existence only.
            advice = int(any(table))
            for bit in (0, 1):
                self.assertLessEqual(F(int(bit == advice)), 2 * F(1, 2))
            if advice:
                success += mass
                mean_queries += mass * (table.index(1) + 1)
        self.assertEqual(success, F(8942430185041, 17592186044416))
        self.assertEqual(mean_queries, F(47931568507531, 17592186044416))
        self.assertGreaterEqual(success, F(1, 2))
        # Incorrectly transporting the independent expected-cost frontier
        # through lambda=2 would claim cost >= (alpha/lambda)/p = 4.
        self.assertLess(mean_queries, F(4))
        spec = transfer.TransferSpec(F(1, 2), transfer.bernoulli_caps(F(1, 16), 11, 11),
                                     12, domination=F(2))
        certificate = self.checked(spec)
        self.assertLessEqual(rational(certificate["sum_lower"]), mean_queries)

    def test_finite_prefix_never_extrapolates_missing_tail(self):
        caps = (F(0), F(1, 8), F(1, 4))
        short = self.checked(transfer.TransferSpec(F(1, 2), caps, 1))
        longer = self.checked(transfer.TransferSpec(F(1, 2), caps, 3))
        self.assertEqual(rational(short["sum_lower"]), F(1, 2))
        self.assertEqual(rational(longer["sum_lower"]), F(9, 8))
        self.assertEqual(len(short["rows"]), 1)
        self.assertEqual(short["tail_scope"], "finite-prefix-only-no-tail-extrapolation")
        with self.assertRaises(transfer.TransferError):
            transfer.build_certificate(transfer.TransferSpec(F(1, 2), caps, 4))

    def test_virtual_check_overhead_is_inside_the_cap_not_deducted_from_result(self):
        caps = transfer.bernoulli_caps(F(1, 16), 11, 11)
        ordinary = self.checked(transfer.TransferSpec(F(1, 2), caps, 1))
        virtual = self.checked(transfer.TransferSpec(F(1, 2), caps, 1, overhead=F(11)))
        self.assertEqual(rational(ordinary["sum_lower"]), F(1, 2))
        self.assertEqual(rational(virtual["sum_lower"]), 0)
        self.assertEqual(virtual["rows"][0]["query_cap"], 11)
        free = self.checked(transfer.TransferSpec(
            F(1, 2), transfer.bernoulli_caps(F(1, 16), 11, 0, 11), 1))
        self.assertEqual(rational(free["sum_lower"]), 0)

    def test_fractional_resource_conversion_floors_each_query_cap(self):
        caps = (F(0), F(1, 4), F(1, 2), F(3, 4), F(1))
        spec = transfer.TransferSpec(F(1), caps, 5, rate=F(2, 3), overhead=F(1, 2))
        certificate = self.checked(spec)
        self.assertEqual([row["query_cap"] for row in certificate["rows"]], [0, 1, 1, 2, 3])
        self.assertEqual(rational(certificate["sum_lower"]), F(13, 4))
        # No expected-resource division is licensed by this pathwise model.
        zero_rate = self.checked(transfer.TransferSpec(F(1, 2), (F(0),), 3, rate=F(0)))
        self.assertEqual(rational(zero_rate["sum_lower"]), F(3, 2))

    def test_additive_failure_allowance_precedes_probability_saturation(self):
        spec = transfer.TransferSpec(F(3, 4), (F(0), F(1, 4), F(1, 2), F(3, 4), F(1)),
                                     5, domination=F(2), excess=F(1, 8))
        certificate = self.checked(spec)
        self.assertEqual([rational(row["success_cap"]) for row in certificate["rows"]],
                         [F(1, 8), F(5, 8), F(1), F(1), F(1)])
        self.assertEqual(rational(certificate["sum_lower"]), F(3, 4))
        self.assertEqual(rational(certificate["markov_lower"]), F(5, 8))
        for alpha, excess in ((F(0), F(0)), (F(1), F(1))):
            endpoint = self.checked(transfer.TransferSpec(alpha, (F(0),), 3,
                                                          rate=F(0), excess=excess))
            self.assertEqual(rational(endpoint["sum_lower"]), 0)

    def test_arbitrary_input_caps_remain_unverified_even_when_the_sum_is_large(self):
        certificate = self.checked(transfer.TransferSpec(F(1, 2), (F(0),), 12, rate=F(0)))
        self.assertEqual(rational(certificate["sum_lower"]), F(6))
        self.assertFalse(certificate["reference_cap_theorem_verified"])
        self.assertFalse(certificate["all_legal_resource_simulation_verified"])
        self.assertFalse(certificate["actual_w1_cost_bound"])


class CertificateBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.spec = transfer.TransferSpec(F(1, 2), transfer.bernoulli_caps(F(1, 16), 11, 11),
                                          12, domination=F(2))
        self.certificate = transfer.build_certificate(self.spec)

    def test_verifier_does_not_call_the_constructor(self):
        with patch.object(transfer, "build_certificate", side_effect=AssertionError("constructor")):
            self.assertTrue(transfer.verify_certificate(self.spec, self.certificate))

    def test_every_row_field_order_and_complete_prefix_are_bound(self):
        for field in self.certificate["rows"][0]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.certificate)
                changed["rows"][0][field] = 999
                with self.assertRaises(transfer.TransferError):
                    transfer.verify_certificate(self.spec, changed)
        for rows in (self.certificate["rows"][:-1], list(reversed(self.certificate["rows"])),
                     self.certificate["rows"] + [self.certificate["rows"][-1]]):
            changed = copy.deepcopy(self.certificate)
            changed["rows"] = rows
            with self.assertRaises(transfer.TransferError):
                transfer.verify_certificate(self.spec, changed)

    def test_scope_flags_cannot_be_promoted_or_retyped(self):
        changes = {
            "qualification": "PASS", "premises_verified": True,
            "reference_cap_theorem_verified": True, "initial_state_coverage_verified": True,
            "all_legal_resource_simulation_verified": True, "actual_w1_cost_bound": True,
            "production_activation": True, "arithmetic_only": 1,
            "cost_unit": "seconds", "tail_scope": "infinite-tail-certified",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(self.certificate)
                changed[field] = value
                with self.assertRaises(transfer.TransferError):
                    transfer.verify_certificate(self.spec, changed)

    def test_input_and_exact_sum_encodings_are_bound(self):
        for field in ("sum_lower", "markov_lower"):
            for value in ({"numerator": 0, "denominator": 1},
                          {"numerator": True, "denominator": 1},
                          {"numerator": 86882, "denominator": 65536}, 1.0):
                changed = copy.deepcopy(self.certificate)
                changed[field] = value
                with self.assertRaises(transfer.TransferError):
                    transfer.verify_certificate(self.spec, changed)
        changed = copy.deepcopy(self.certificate)
        changed["input"]["budgets"] -= 1
        with self.assertRaises(transfer.TransferError):
            transfer.verify_certificate(self.spec, changed)
        changed = copy.deepcopy(self.certificate)
        changed["activation"] = False
        with self.assertRaises(transfer.TransferError):
            transfer.verify_certificate(self.spec, changed)

    def test_invalid_exact_types_probability_ranges_and_missing_caps_refuse(self):
        defaults = {"alpha": F(1, 2), "reference_caps": (F(0), F(1, 2)), "budgets": 2}
        invalids = {
            "alpha": (True, 0.5, F(-1), F(2)),
            "reference_caps": ([F(0)], (), (F(1, 2), F(0)), (F(0), True),
                               (F(0), F(2)), (F(-1),)),
            "budgets": (True, 0, -1, 2.0, transfer.MAX_BUDGETS + 1),
            "rate": (True, 1.0, F(-1)), "overhead": (False, 0.0, F(-1)),
            "domination": (True, 2.0, F(1, 2)), "excess": (False, 0.0, F(-1), F(2)),
        }
        for field, values in invalids.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(transfer.TransferError):
                        transfer.build_certificate(transfer.TransferSpec(**{**defaults, field: value}))
        with self.assertRaises(transfer.TransferError):
            transfer.build_certificate(transfer.TransferSpec(F(1, 2), (F(0),), 2))
        with self.assertRaises(transfer.TransferError):
            transfer.verify_certificate(self.spec, None)

    def test_bernoulli_endpoints_finite_domain_and_invalid_inputs(self):
        self.assertEqual(transfer.bernoulli_caps(F(0), 4, 2), (F(0),) * 3)
        self.assertEqual(transfer.bernoulli_caps(F(1), 4, 2), (F(0), F(1), F(1)))
        self.assertEqual(transfer.bernoulli_caps(F(1), 0, 2, 100), (F(0),) * 3)
        self.assertEqual(transfer.bernoulli_caps(F(1, 2), 2, 4),
                         (F(0), F(1, 2), F(3, 4), F(3, 4), F(3, 4)))
        for arguments in ((0.5, 2, 2), (True, 2, 2), (F(2), 2, 2),
                          (F(1, 2), True, 2), (F(1, 2), 2, -1),
                          (F(1, 2), 2, 2, False)):
            with self.assertRaises(transfer.TransferError):
                transfer.bernoulli_caps(*arguments)

    def test_cli_retains_unverified_premises_and_false_qualification(self):
        completed = subprocess.run([sys.executable, str(Path(transfer.__file__)), "--check"],
                                   capture_output=True, text=True, check=True, timeout=30)
        report = json.loads(completed.stdout)
        self.assertEqual(report["qualification"], "HOLD_NO_GO")
        self.assertFalse(report["actual_w1_cost_bound"])
        for certificate in report["fixtures"].values():
            self.assertFalse(certificate["premises_verified"])
            self.assertFalse(certificate["actual_w1_cost_bound"])
            self.assertFalse(certificate["production_activation"])


if __name__ == "__main__":
    unittest.main()
