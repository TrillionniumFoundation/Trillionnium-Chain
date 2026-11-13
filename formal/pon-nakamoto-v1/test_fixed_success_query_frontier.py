"""Independent small-policy and exact witness controls for the query frontier.

The policy enumerator below uses explicit oracle truth-table probabilities,
not the production frontier formula. At each observed history it considers
every address query, including repeats, and every permitted final output
subset. Randomized finite policies are convex mixtures of deterministic trees;
their optimal mean is obtained from a separately computed lower convex hull.
This checks tiny declared games, not coverage of actual W1 implementations.
"""
import copy
from fractions import Fraction
from functools import lru_cache
from itertools import combinations, product
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import fixed_success_query_frontier as frontier


def rational(value):
    return Fraction(value["numerator"], value["denominator"])


def explicit_prior(addresses, probability):
    result = []
    for bits in product((0, 1), repeat=addresses):
        mass = Fraction(1)
        for bit in bits:
            mass *= probability if bit else 1 - probability
        if mass:
            result.append((bits, mass))
    return tuple(result)


def enumerate_policy_pairs(prior, query_cap, free_outputs):
    """Return every attainable (success, mean paid queries) deterministic pair."""
    addresses = len(prior[0][0])

    @lru_cache(None)
    def visit(known, remaining):
        compatible = tuple((bits, mass) for bits, mass in prior
                           if all(value == -1 or bits[i] == value
                                  for i, value in enumerate(known)))
        mass = sum((weight for _, weight in compatible), Fraction(0))
        if not mass:
            return frozenset({(Fraction(0), Fraction(0))})
        unknown = tuple(i for i, value in enumerate(known) if value == -1)
        pairs = {(Fraction(0), Fraction(0))}  # Abort without an output.
        if 1 in known:
            pairs.add((Fraction(1), Fraction(0)))
        for size in range(min(free_outputs, len(unknown)) + 1):
            for subset in combinations(unknown, size):
                success = sum((weight for bits, weight in compatible
                               if any(bits[i] for i in subset)), Fraction(0)) / mass
                pairs.add((success, Fraction(0)))
        if not remaining:
            return frozenset(pairs)
        for address in range(addresses):
            if known[address] != -1:
                for success, cost in visit(known, remaining - 1):
                    pairs.add((success, 1 + cost))
                continue
            positive_mass = sum((weight for bits, weight in compatible
                                 if bits[address]), Fraction(0))
            chance = positive_mass / mass
            successors = []
            for bit in (0, 1):
                updated = list(known)
                updated[address] = bit
                successors.append(visit(tuple(updated), remaining - 1))
            for negative, positive in product(*successors):
                s0, c0 = negative
                s1, c1 = positive
                pairs.add(((1 - chance) * s0 + chance * s1,
                           1 + (1 - chance) * c0 + chance * c1))
        return frozenset(pairs)

    return visit((-1,) * addresses, query_cap)


def minimum_mixed_cost(pairs, target):
    """Minimize cost on the convex hull, allowing success greater than target."""
    best = {}
    for success, cost in pairs:
        best[success] = min(best.get(success, cost), cost)
    if max(best) < target:
        return None
    hull = []
    for point in sorted(best.items()):
        while len(hull) >= 2:
            a, b = hull[-2:]
            cross = ((b[0] - a[0]) * (point[1] - b[1])
                     - (b[1] - a[1]) * (point[0] - b[0]))
            if cross > 0:
                break
            hull.pop()
        hull.append(point)
    costs = [cost for success, cost in hull if success >= target]
    for left, right in zip(hull, hull[1:]):
        if left[0] <= target <= right[0]:
            mixture = (target - left[0]) / (right[0] - left[0])
            costs.append((1 - mixture) * left[1] + mixture * right[1])
    return min(costs)


class ExactFrontierTests(unittest.TestCase):
    def game(self, cap=11, addresses=32, free=0, probability=Fraction(1, 16),
             target=Fraction(1, 2)):
        return frontier.QueryExperiment(probability, target, cap, addresses, free)

    def checked(self, game):
        certificate = frontier.analyze(game)
        result = frontier.verify(game, certificate)
        self.assertTrue(result["verified"])
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertFalse(result["actual_w1_lower_bound"])
        self.assertFalse(result["native_admission_changed"])
        return certificate

    def test_fixed_half_success_distinguishes_expected_eight_and_cap_eleven(self):
        below = self.checked(self.game(cap=10))
        exact = self.checked(self.game(cap=11))
        self.assertEqual(below["status"], frontier.INFEASIBLE)
        self.assertIsNone(below["minimum_expected_paid_queries"])
        self.assertLess(rational(below["maximum_success_probability"]), Fraction(1, 2))
        self.assertGreater(rational(exact["maximum_success_probability"]), Fraction(1, 2))
        self.assertEqual(rational(exact["minimum_expected_paid_queries"]), 8)
        policy = exact["attaining_policy"]
        self.assertLess(rational(policy["paid_mode_probability"]), 1)
        self.assertGreater(rational(policy["paid_mode_expected_queries"]), 8)

    def test_one_final_guess_does_not_bill_a_virtual_check_to_the_producer(self):
        certificate = self.checked(self.game(cap=10, free=1))
        self.assertEqual(rational(certificate["minimum_expected_paid_queries"]), Fraction(112, 15))
        self.assertFalse(certificate["scope"]["virtual_final_checks_billed_to_producer"])
        self.assertEqual(rational(certificate["attaining_policy"]["mixture_success_probability"]), Fraction(1, 2))

    def test_enough_final_guesses_have_zero_paid_query_optimum(self):
        certificate = self.checked(self.game(cap=0, addresses=11, free=11))
        self.assertEqual(rational(certificate["minimum_expected_paid_queries"]), 0)
        self.assertEqual(rational(certificate["attaining_policy"]["paid_mode_probability"]), 0)
        self.assertGreater(rational(certificate["free_success_probability"]), Fraction(1, 2))

    def test_finite_domain_limits_success_even_when_query_cap_is_large(self):
        certificate = self.checked(self.game(cap=100, addresses=10))
        self.assertEqual(certificate["status"], frontier.INFEASIBLE)
        self.assertEqual(certificate["effective_caps"]["paid_fresh_queries"], 10)

    def test_free_outputs_reserve_only_addresses_that_really_exist(self):
        certificate = self.checked(self.game(cap=4, addresses=3, free=10,
                                             probability=Fraction(1, 2), target=Fraction(7, 8)))
        self.assertEqual(certificate["effective_caps"], {
            "reserved_unqueried_outputs": 3, "paid_fresh_queries": 0,
            "distinct_tested_or_output_addresses": 3})
        self.assertEqual(rational(certificate["minimum_expected_paid_queries"]), 0)

    def test_zero_and_one_probability_empty_domain_and_zero_target(self):
        for p, target, cap, addresses, free, expected in (
            (0, 0, 2, 3, 1, 0), (0, 1, 2, 3, 1, None),
            (1, 1, 1, 1, 0, 1), (1, Fraction(1, 2), 1, 1, 0, Fraction(1, 2)),
            (1, 1, 0, 1, 1, 0), (1, 1, 0, 0, 1, None),
            (Fraction(1, 2), 0, 0, 0, 0, 0),
            (Fraction(1, 2), 1, 3, 3, 0, None),
        ):
            with self.subTest(p=p, target=target, cap=cap, addresses=addresses, free=free):
                certificate = self.checked(self.game(cap, addresses, free, Fraction(p), Fraction(target)))
                if expected is None:
                    self.assertEqual(certificate["status"], frontier.INFEASIBLE)
                else:
                    self.assertEqual(rational(certificate["minimum_expected_paid_queries"]), expected)

    def test_exact_feasibility_boundary_has_no_float_tolerance(self):
        maximum = Fraction(3, 4)
        for target, status in ((maximum, frontier.FEASIBLE),
                               (maximum + Fraction(1, 10**30), frontier.INFEASIBLE),
                               (maximum - Fraction(1, 10**30), frontier.FEASIBLE)):
            certificate = self.checked(self.game(2, 2, 0, Fraction(1, 2), target))
            self.assertEqual(certificate["status"], status)

    def test_independent_verifier_does_not_call_frontier_constructor(self):
        game = self.game()
        certificate = frontier.analyze(game)
        with patch.object(frontier, "analyze", side_effect=AssertionError("constructor called")):
            self.assertTrue(frontier.verify(game, certificate)["verified"])

    def test_all_tiny_deterministic_trees_and_randomized_convex_hulls(self):
        checked = 0
        for addresses, cap, free, p in product(range(4), range(4), range(4),
                                                (Fraction(1, 4), Fraction(1, 2), Fraction(3, 4))):
            pairs = enumerate_policy_pairs(explicit_prior(addresses, p), cap, free)
            maximum = max(success for success, _ in pairs)
            targets = {Fraction(0), Fraction(1, 4), Fraction(1, 2), Fraction(3, 4),
                       Fraction(1), maximum, maximum / 2}
            for target in sorted(targets):
                with self.subTest(addresses=addresses, cap=cap, free=free, p=p, target=target):
                    independent_cost = minimum_mixed_cost(pairs, target)
                    certificate = self.checked(self.game(cap, addresses, free, p, target))
                    self.assertEqual(rational(certificate["maximum_success_probability"]), maximum)
                    if independent_cost is None:
                        self.assertEqual(certificate["status"], frontier.INFEASIBLE)
                    else:
                        self.assertEqual(rational(certificate["minimum_expected_paid_queries"]),
                                         independent_cost)
                    checked += 1
        self.assertGreater(checked, 1000)

    def test_fixed_mark_count_is_a_different_probability_law(self):
        # Exactly one of two addresses is marked; after one failed query the
        # other address is certain to be marked. Its marginal p=1/2 does not
        # make this law an independent Bernoulli oracle.
        fixed_count = (((0, 1), Fraction(1, 2)), ((1, 0), Fraction(1, 2)))
        fixed_pairs = enumerate_policy_pairs(fixed_count, 1, 1)
        iid_pairs = enumerate_policy_pairs(explicit_prior(2, Fraction(1, 2)), 1, 1)
        self.assertEqual(max(success for success, _ in fixed_pairs), 1)
        self.assertEqual(max(success for success, _ in iid_pairs), Fraction(3, 4))
        game = self.game(1, 2, 1, Fraction(1, 2), Fraction(1))
        certificate = self.checked(game)
        self.assertEqual(certificate["status"], frontier.INFEASIBLE)
        certificate["scope"]["independent_bernoulli_marks"] = False
        with self.assertRaisesRegex(frontier.QueryFrontierError, "^CERTIFICATE_SCOPE$"):
            frontier.verify(game, certificate)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.game = frontier.QueryExperiment(Fraction(1, 16), Fraction(1, 2), 11, 32)
        self.certificate = frontier.analyze(self.game)

    def reject(self, certificate, reason):
        with self.assertRaisesRegex(frontier.QueryFrontierError, "^" + reason + "$"):
            frontier.verify(self.game, certificate)

    def test_nonexact_probability_and_invalid_budgets_are_rejected(self):
        base = dict(probability=Fraction(1, 16), target_success=Fraction(1, 2),
                    query_cap=11, available_addresses=32, final_unqueried_outputs=0)
        for field, invalids in (
            ("probability", (False, 0.5, 1, Fraction(-1), Fraction(2))),
            ("target_success", (True, 0.5, 1, Fraction(-1), Fraction(2))),
            ("query_cap", (True, 1.0, -1, frontier.MAX_COUNT + 1)),
            ("available_addresses", (False, -1, frontier.MAX_COUNT + 1)),
            ("final_unqueried_outputs", (True, -1, frontier.MAX_COUNT + 1)),
        ):
            for invalid in invalids:
                with self.subTest(field=field, invalid=invalid):
                    values = {**base, field: invalid}
                    with self.assertRaises(frontier.QueryFrontierError):
                        frontier.QueryExperiment(**values)

    def test_implementation_size_limits_refuse_without_rounding(self):
        with self.assertRaisesRegex(frontier.QueryFrontierError, "^INPUT_RATIONAL_LIMIT$"):
            frontier.QueryExperiment(Fraction(1, 2**129), Fraction(1, 2), 1, 1)
        game = frontier.QueryExperiment(Fraction(1, 2**100), Fraction(1, 2), 100, 100)
        with self.assertRaisesRegex(frontier.QueryFrontierError, "^DERIVED_RATIONAL_LIMIT$"):
            frontier.analyze(game)

    def test_changed_experiment_and_digest_are_rejected(self):
        for field, value in (("query_cap", 12), ("available_addresses", 31),
                              ("final_unqueried_outputs", 1)):
            certificate = copy.deepcopy(self.certificate)
            certificate["experiment"][field] = value
            self.reject(certificate, "EXPERIMENT_BINDING")
        certificate = copy.deepcopy(self.certificate)
        certificate["experiment_sha256"] = "0" * 64
        self.reject(certificate, "EXPERIMENT_BINDING")

    def test_scope_cannot_promote_query_arithmetic_or_change_billing(self):
        changes = {
            "actual_w1_lower_bound": True,
            "virtual_final_checks_billed_to_producer": True,
            "hard_query_cap_is_wall_clock_deadline": True,
            "oracle_correlated_initial_state_or_public_help_covered": True,
            "quantum_algorithms_covered": True,
            "independent_bernoulli_marks": 1,
            "ideal_private_randomization": "fixed-32-bit-seed",
            "actual_classical_quantum_cost_points": "proved",
            "native_admission_changed": True,
            "production_activation": True,
        }
        for field, changed in changes.items():
            with self.subTest(field=field):
                certificate = copy.deepcopy(self.certificate)
                certificate["scope"][field] = changed
                self.reject(certificate, "CERTIFICATE_SCOPE")

    def test_cost_or_feasibility_cannot_be_upgraded(self):
        for expected in (Fraction(0), Fraction(7), Fraction(9)):
            certificate = copy.deepcopy(self.certificate)
            certificate["minimum_expected_paid_queries"] = frontier._wire(expected)
            self.reject(certificate, "EXPECTED_QUERY_LOWER_BOUND")
        certificate = copy.deepcopy(self.certificate)
        certificate["status"] = frontier.INFEASIBLE
        self.reject(certificate, "FEASIBLE_CERTIFICATE")
        game = frontier.QueryExperiment(Fraction(1, 16), Fraction(1, 2), 10, 32)
        impossible = frontier.analyze(game)
        impossible["status"] = frontier.FEASIBLE
        with self.assertRaisesRegex(frontier.QueryFrontierError, "^INFEASIBLE_CERTIFICATE$"):
            frontier.verify(game, impossible)

    def test_policy_mutations_are_rejected(self):
        for field, value, reason in (
            ("paid_mode_probability", frontier._wire(Fraction(0)), "POLICY_PROBABILITIES"),
            ("paid_mode_query_cap", 10, "POLICY_CAPS"),
            ("final_unqueried_output_cap", False, "POLICY_CAPS"),
            ("paid_mode_success_probability", frontier._wire(Fraction(1)), "PAID_MODE_SUCCESS"),
            ("paid_mode_expected_queries", frontier._wire(Fraction(8)), "PAID_MODE_QUERIES"),
            ("mixture_success_probability", frontier._wire(Fraction(1)), "MIXTURE_SUCCESS"),
            ("mixture_expected_paid_queries", frontier._wire(Fraction(7)), "MIXTURE_QUERIES"),
        ):
            with self.subTest(field=field):
                certificate = copy.deepcopy(self.certificate)
                certificate["attaining_policy"][field] = value
                self.reject(certificate, reason)

    def test_noncanonical_rationals_booleans_and_extra_fields_rejected(self):
        for value in ({"numerator": 16, "denominator": 2},
                      {"numerator": True, "denominator": 1},
                      {"numerator": 8, "denominator": 0}, 8.0):
            certificate = copy.deepcopy(self.certificate)
            certificate["minimum_expected_paid_queries"] = value
            self.reject(certificate, "EXPECTED_QUERIES")
        certificate = copy.deepcopy(self.certificate)
        certificate["approval"] = True
        self.reject(certificate, "CERTIFICATE_FIELDS")

    def test_json_duplicate_keys_floats_and_size_limit_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "certificate.json"
            for raw, reason in ((b'{"a":{"p":1,"p":2}}', "DUPLICATE_JSON_KEY"),
                                (b'{"p":0.5}', "NONINTEGER_JSON_NUMBER"),
                                (b'{"p":NaN}', "NONINTEGER_JSON_NUMBER"),
                                (b'[]', "CERTIFICATE_OBJECT"),
                                (b'\xff', "CERTIFICATE_JSON")):
                path.write_bytes(raw)
                with self.assertRaisesRegex(frontier.QueryFrontierError, "^" + reason + "$"):
                    frontier.load_certificate(path)
            path.write_bytes(b"{}" + b" " * (frontier.MAX_JSON_BYTES - 2))
            self.assertEqual(frontier.load_certificate(path), {})
            with path.open("ab") as stream:
                stream.write(b"\n")
            with self.assertRaisesRegex(frontier.QueryFrontierError, "^CERTIFICATE_TOO_LARGE$"):
                frontier.load_certificate(path)

    def test_cli_check_emits_exact_examples_and_retains_hold(self):
        result = subprocess.run([sys.executable, str(Path(frontier.__file__)), "--check"],
                                capture_output=True, text=True, check=True, timeout=30)
        report = json.loads(result.stdout)
        self.assertEqual(report["checked_examples"], 6)
        self.assertEqual(report["qualification"], "HOLD_NO_GO")
        self.assertFalse(report["actual_w1_lower_bound"])
        self.assertFalse(report["native_admission_changed"])
        self.assertTrue(all(row["verification"]["verified"] for row in report["examples"]))

    def test_cli_writes_once_and_verifies_the_same_fixed_experiment(self):
        command = [sys.executable, str(Path(frontier.__file__))]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "certificate.json"
            subprocess.run([*command, "--output", str(path)], check=True,
                           capture_output=True, text=True, timeout=30)
            original = path.read_bytes()
            verified = subprocess.run([*command, "--verify", str(path)], check=True,
                                      capture_output=True, text=True, timeout=30)
            self.assertTrue(json.loads(verified.stdout)["verified"])
            refused = subprocess.run([*command, "--output", str(path)],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(refused.returncode, 2)
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
