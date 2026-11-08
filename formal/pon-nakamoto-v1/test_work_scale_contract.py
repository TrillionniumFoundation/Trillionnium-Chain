"""Exact conditional controls; these tests do not establish W1 cost or finality."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import work_scale_contract as model
from work_scale_contract import (
    ConditionalEnvelope, Context, Scope, StepLaw, adaptive_crossing_probability,
    build_report, cost_point, reuse_counterexample, target_for_difficulty,
    toy_laws, verify_report,
)


HERE = Path(__file__).resolve().parent


def path_enumeration(law: StepLaw, gap: int, horizon: int) -> Fraction:
    """Independent first-passage sum over every complete outcome sequence."""
    total = Fraction(0)
    for path in product(law.outcomes, repeat=horizon):
        chance, position, crossed = Fraction(1), 0, False
        for increment, probability in path:
            chance *= probability
            position += increment
            crossed |= position >= gap
        if crossed:
            total += chance
    return total


def enumerate_policies(laws: tuple[StepLaw, ...], gap: int,
                       horizon: int) -> Fraction:
    """Enumerate all small time/gap policies, then propagate forward masses.

    This uses neither the model's backward recursion nor its exponential bound.
    The finite Markov state is sufficient for the stated law-menu experiment.
    """
    states, reachable = [], {gap}
    for tick in range(horizon):
        states.extend((tick, value) for value in sorted(reachable))
        reachable = {value - increment for value in reachable for law in laws
                     for increment, _ in law.outcomes if value - increment > 0}
    best = Fraction(0)
    for choices in product(range(len(laws)), repeat=len(states)):
        policy = dict(zip(states, choices))
        masses, crossed = {gap: Fraction(1)}, Fraction(0)
        for tick in range(horizon):
            following = {}
            for value, mass in masses.items():
                for increment, probability in laws[policy[tick, value]].outcomes:
                    remaining = value - increment
                    if remaining <= 0:
                        crossed += mass * probability
                    else:
                        following[remaining] = (following.get(remaining, Fraction(0))
                                                + mass * probability)
            masses = following
        best = max(best, crossed)
    return best


class ScopeAndCostTests(unittest.TestCase):
    def setUp(self):
        self.reference = target_for_difficulty(16)
        self.fixed = Scope("fixed-target", "shared-anchor", self.reference,
                           self.reference, self.reference)
        self.band = Scope("absolute-target-band", "shared-anchor", self.reference,
                          target_for_difficulty(256), self.reference)
        self.units = Scope("fixed-p-variable-units", "shared-anchor", self.reference,
                           self.reference, self.reference, 1, 256)

    def test_inclusive_target_and_floor_weight_are_exact(self):
        # 256/(48+1) is not an integer but has rational sqrt 16/7.
        point = cost_point(48, 3, bits=8)
        self.assertEqual(point.probability, Fraction(49, 256))
        self.assertEqual(point.difficulty, Fraction(256, 49))
        self.assertEqual(point.credited_work, 15)
        self.assertEqual(point.classical_winner_cost, Fraction(768, 49))
        self.assertEqual(point.classical_efficiency, Fraction(245, 256))
        self.assertNotEqual(point.classical_efficiency, 1)
        self.assertEqual(point.quantum_winner_cost, Fraction(48, 7))
        self.assertEqual(target_for_difficulty(16, bits=8), 15)
        self.assertEqual(cost_point(15, 1, bits=8).probability, Fraction(1, 16))

    def test_three_scopes_accept_both_forks_under_one_declared_anchor(self):
        for scope, alternative_target, alternative_units in (
            (self.fixed, self.reference, 1),
            (self.band, target_for_difficulty(256), 1),
            (self.units, self.reference, 256),
        ):
            rows = (Context("honest", "shared-anchor", self.reference, 1),
                    Context("private", "shared-anchor", alternative_target,
                            alternative_units))
            with self.subTest(policy=scope.policy):
                self.assertEqual(scope.check(rows), rows)
        self.assertEqual(self.band.difficulty_ratio(), 16)
        self.assertEqual(self.fixed.difficulty_ratio(), 1)

    def test_private_anchor_rebinding_is_refused_for_every_policy(self):
        for scope in (self.fixed, self.band, self.units):
            with self.subTest(policy=scope.policy):
                with self.assertRaisesRegex(ValueError, "ANCHOR_REBINDING"):
                    scope.check((Context("private", "private-local-anchor",
                                         self.reference, 1),))

    def test_band_checks_hard_and_easy_boundaries(self):
        for target in (self.band.hardest_target - 1, self.band.easiest_target + 1):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "OUTSIDE_ABSOLUTE_TARGET_BAND"):
                    self.band.check((Context("private", "shared-anchor", target, 1),))
        with self.assertRaisesRegex(ValueError, "TARGET_RANGE"):
            replace(self.band, hardest_target=self.band.easiest_target + 1)

    def test_fake_fixed_target_and_wrong_unit_policy_are_refused(self):
        for scope in (self.fixed, self.units):
            with self.subTest(policy=scope.policy):
                with self.assertRaisesRegex(ValueError, "TARGET_NOT_FIXED"):
                    replace(scope, hardest_target=target_for_difficulty(64))
                with self.assertRaisesRegex(ValueError, "OUTSIDE_ABSOLUTE_TARGET_BAND"):
                    scope.check((Context("private", "shared-anchor",
                                         target_for_difficulty(64), 1),))
        with self.assertRaisesRegex(ValueError, "UNITS_NOT_ONE"):
            replace(self.band, maximum_units=256)

    def test_zero_boolean_and_out_of_scope_units_are_refused(self):
        for units in (0, True, False, -1, 1.0):
            with self.subTest(units=units):
                with self.assertRaises(ValueError):
                    self.units.check((Context("private", "shared-anchor",
                                              self.reference, units),))
                with self.assertRaises(ValueError):
                    cost_point(self.reference, units)
        for units in (257,):
            with self.assertRaisesRegex(ValueError, "OUTSIDE_UNIT_RANGE"):
                self.units.check((Context("private", "shared-anchor",
                                          self.reference, units),))
        for change in ({"minimum_units": 0}, {"maximum_units": True},
                       {"minimum_units": 257}, {"bits": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(self.units, **change)
        with self.assertRaisesRegex(ValueError, "EMPTY_COMPARISON"):
            self.fixed.check(())

    def test_only_exact_rational_cost_examples_are_accepted(self):
        with self.assertRaisesRegex(ValueError, "NONINTEGRAL_TARGET"):
            target_for_difficulty(3)
        with self.assertRaisesRegex(ValueError, "NON_RATIONAL_SQUARE_ROOT"):
            cost_point(target_for_difficulty(2), 1)
        with self.assertRaisesRegex(ValueError, "NON_RATIONAL_SQUARE_ROOT"):
            cost_point(self.reference, 2, quantum_exponent=Fraction(1, 2))
        for change in ({"quantum_exponent": Fraction(3, 4)},
                       {"quantum_exponent": 0.5}, {"quantum_coefficient": Fraction(0)},
                       {"quantum_linear_tail": Fraction(-1, 16)}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                cost_point(self.reference, 1, **change)

    def test_linear_and_sublinear_unit_costs_have_different_scale(self):
        for alpha, expected in ((Fraction(1), Fraction(1)),
                                (Fraction(1, 2), Fraction(16))):
            with self.subTest(alpha=alpha):
                small = cost_point(self.reference, 1, quantum_exponent=alpha)
                large = cost_point(self.reference, 256, quantum_exponent=alpha)
                self.assertEqual(large.quantum_efficiency / small.quantum_efficiency,
                                 expected)
                self.assertEqual(large.classical_efficiency / small.classical_efficiency,
                                 1)

    def test_global_difficulty_band_has_square_root_scale_under_the_assumption(self):
        baseline = cost_point(self.reference, 1)
        harder = cost_point(target_for_difficulty(256), 1)
        self.assertEqual(harder.quantum_efficiency / baseline.quantum_efficiency, 4)
        self.assertEqual(harder.classical_efficiency / baseline.classical_efficiency, 1)

    def test_positive_linear_tail_does_not_make_finite_scale_neutral(self):
        costs = {u: cost_point(self.reference, u, quantum_exponent=Fraction(1, 2),
                               quantum_coefficient=Fraction(1, 4),
                               quantum_linear_tail=Fraction(1, 16)) for u in (1, 256)}
        self.assertEqual(costs[1].quantum_winner_cost, Fraction(17, 16))
        self.assertEqual(costs[256].quantum_winner_cost, 32)
        self.assertEqual(costs[256].quantum_efficiency / costs[1].quantum_efficiency,
                         Fraction(17, 2))

    def test_single_winner_linearity_does_not_control_cross_winner_reuse(self):
        self.assertEqual(reuse_counterexample(256, 1), 1)
        self.assertEqual(reuse_counterexample(1, 256), 1)
        self.assertEqual(reuse_counterexample(256, 256), Fraction(65536, 511))
        self.assertGreater(reuse_counterexample(256, 256), 128)
        for args in ((0, 1), (1, 0), (True, 1), (1, True)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                reuse_counterexample(*args)


class ConditionalTailTests(unittest.TestCase):
    def setUp(self):
        self.small, self.idle, self.burst = toy_laws()
        self.ordinary = ConditionalEnvelope((self.small, self.idle), Fraction(3, 2))
        self.with_bursts = ConditionalEnvelope((self.small, self.idle, self.burst),
                                               Fraction(17, 16))

    def test_equal_means_do_not_justify_transferring_the_tail_envelope(self):
        self.assertEqual(self.small.mean, Fraction(-1, 5))
        self.assertEqual(self.burst.mean, self.small.mean)
        self.assertEqual(self.small.pgf(Fraction(3, 2)), 1)
        self.assertGreater(self.burst.pgf(Fraction(3, 2)), 1)
        with self.assertRaisesRegex(ValueError, "CONDITIONAL_MOMENT_EXCEEDS_ONE"):
            ConditionalEnvelope((self.small, self.burst), Fraction(3, 2))
        self.assertLess(self.burst.pgf(Fraction(17, 16)), 1)
        actual = adaptive_crossing_probability((self.burst,), 8, 1)
        self.assertEqual(actual, Fraction(1, 20))
        self.assertGreater(actual, self.ordinary.crossing_bound(8))

    def test_bad_or_mutable_conditional_laws_are_refused(self):
        for outcomes in (list(self.small.outcomes), ([1, Fraction(1)],),
                         ((1, Fraction(1), 0),), ((True, Fraction(1)),),
                         ((1, Fraction(1, 2)), (1, Fraction(1, 2))),
                         ((1, Fraction(0)), (-1, Fraction(1))),
                         ((1, 0.4), (-1, 0.6)), ((1, Fraction(1, 2)),)):
            with self.subTest(outcomes=outcomes), self.assertRaises(ValueError):
                StepLaw("invalid", outcomes)
        for laws in ([], [self.small], (), (self.small, self.small)):
            with self.subTest(laws=laws), self.assertRaises(ValueError):
                ConditionalEnvelope(laws, Fraction(3, 2))
        for z in (Fraction(0), Fraction(1), 1.5, True):
            with self.subTest(z=z), self.assertRaises(ValueError):
                ConditionalEnvelope((self.small,), z)

    def test_exact_one_step_and_independent_path_enumeration(self):
        self.assertEqual(adaptive_crossing_probability((self.small,), 1, 1),
                         Fraction(2, 5))
        self.assertEqual(adaptive_crossing_probability((self.small,), 2, 1), 0)
        for law in (self.small, self.idle, self.burst):
            for horizon, gap in ((0, 1), (2, 1), (3, 2), (5, 4), (4, 8)):
                with self.subTest(law=law.name, horizon=horizon, gap=gap):
                    self.assertEqual(adaptive_crossing_probability((law,), gap, horizon),
                                     path_enumeration(law, gap, horizon))

    def test_adaptive_recursion_matches_all_small_markov_policies(self):
        for laws in ((self.small, self.idle), (self.small, self.burst)):
            for gap, horizon in ((1, 2), (2, 2), (2, 3)):
                with self.subTest(menu=[law.name for law in laws], gap=gap,
                                  horizon=horizon):
                    self.assertEqual(adaptive_crossing_probability(laws, gap, horizon),
                                     enumerate_policies(laws, gap, horizon))

    def test_multiple_adaptive_horizons_obey_the_assumed_anytime_bound(self):
        for envelope in (self.ordinary, self.with_bursts):
            for gap in (1, 2, 4, 8, 12):
                previous = Fraction(0)
                for horizon in (0, 1, 2, 4, 8, 12):
                    with self.subTest(z=envelope.z, gap=gap, horizon=horizon):
                        actual = adaptive_crossing_probability(envelope.laws, gap, horizon)
                        self.assertGreaterEqual(actual, previous)
                        self.assertLessEqual(actual, envelope.crossing_bound(gap))
                        previous = actual

    def test_inventory_margin_and_multiple_starts_are_charged(self):
        self.assertEqual(self.ordinary.crossing_bound(12, hidden_inventory=5,
                                                     network_margin=3),
                         self.ordinary.crossing_bound(4))
        self.assertEqual(self.ordinary.crossing_bound(8, hidden_inventory=5,
                                                     network_margin=3), 1)
        self.assertEqual(self.ordinary.crossing_bound(7, hidden_inventory=5,
                                                     network_margin=3), 1)
        self.assertEqual(self.ordinary.crossing_bound(20, attack_starts=100),
                         min(Fraction(1), 100 * Fraction(2, 3) ** 20))
        self.assertEqual(self.ordinary.crossing_bound(20, premise_failure=Fraction(1, 1000)),
                         Fraction(1, 1000) + Fraction(2, 3) ** 20)
        self.assertEqual(self.ordinary.crossing_bound(1, attack_starts=100), 1)

    def test_minimum_gaps_are_exact_and_previous_gap_fails(self):
        risk = Fraction(1, 1_000_000)
        for envelope, options, expected in (
            (self.ordinary, {}, 35),
            (self.ordinary, {"hidden_inventory": 5, "network_margin": 3}, 43),
            (self.ordinary, {"attack_starts": 100}, 46),
            (self.with_bursts, {}, 228),
        ):
            with self.subTest(z=envelope.z, options=options):
                self.assertEqual(envelope.minimum_gap(risk, **options), expected)
                self.assertLessEqual(envelope.crossing_bound(expected, **options), risk)
                self.assertGreater(envelope.crossing_bound(expected - 1, **options), risk)

    def test_invalid_inventory_risk_and_finite_search_are_refused(self):
        for options in ({"hidden_inventory": -1}, {"network_margin": True},
                        {"attack_starts": 0}, {"attack_starts": True},
                        {"premise_failure": Fraction(2)}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.ordinary.crossing_bound(10, **options)
        for risk in (Fraction(0), Fraction(1), 1e-6, True):
            with self.subTest(risk=risk), self.assertRaises(ValueError):
                self.ordinary.minimum_gap(risk)
        with self.assertRaisesRegex(ValueError, "FINITE_GAP_SEARCH_EXHAUSTED"):
            self.ordinary.minimum_gap(Fraction(1, 1_000_000), maximum=34)
        for gap, horizon in ((0, 1), (1, True), (1, 65), (4097, 1)):
            with self.subTest(gap=gap, horizon=horizon), self.assertRaises(ValueError):
                adaptive_crossing_probability((self.small,), gap, horizon)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.report = build_report()

    def test_report_keeps_all_real_world_qualification_closed(self):
        self.assertTrue(self.report["claims"])
        self.assertTrue(all(value is False for value in self.report["claims"].values()))
        self.assertTrue(all(value is None for value in self.report["unknown_resources"].values()))
        self.assertTrue(self.report["research_gate"].startswith("HOLD-"))
        self.assertEqual(self.report["abstract_crossing_examples"]["unit_jump_gap"], 35)
        policies = {row["policy"] for row in self.report["comparison"]}
        self.assertEqual(policies, set(model.POLICIES))

    def test_report_verifies_only_the_current_source_and_results(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "report.json"
            filename.write_text(json.dumps(self.report), encoding="utf-8")
            verify_report(filename)
            variants = []
            promoted = deepcopy(self.report)
            promoted["claims"]["common_prefix_qualified"] = True
            variants.append(promoted)
            changed = deepcopy(self.report)
            changed["abstract_crossing_examples"]["unit_jump_gap"] = 34
            variants.append(changed)
            wrong_source = deepcopy(self.report)
            wrong_source["source_sha256"]["work_scale_contract.py"] = "0" * 64
            variants.append(wrong_source)
            for altered in variants:
                filename.write_text(json.dumps(altered), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "REPORT_SOURCE_OR_RESULT_MISMATCH"):
                    verify_report(filename)
            filename.write_text(json.dumps(self.report), encoding="utf-8")
            with patch.object(model, "build_report", return_value=wrong_source):
                with self.assertRaisesRegex(ValueError, "REPORT_SOURCE_OR_RESULT_MISMATCH"):
                    verify_report(filename)

    def test_report_equality_preserves_boolean_and_integer_types(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "report.json"
            for field, replacement in (("claim", 0), ("gap", 35.0)):
                changed = deepcopy(self.report)
                if field == "claim":
                    changed["claims"]["common_prefix_qualified"] = replacement
                else:
                    changed["abstract_crossing_examples"]["unit_jump_gap"] = replacement
                filename.write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ValueError, "REPORT_SOURCE_OR_RESULT_MISMATCH"):
                        verify_report(filename)

    def test_duplicate_json_key_nonfinite_and_oversize_reports_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "report.json"
            payload = json.dumps(self.report)
            duplicate = payload[:-1] + ', "schema": ' + json.dumps(self.report["schema"]) + '}'
            filename.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
                verify_report(filename)
            filename.write_text('{"nonfinite": NaN}', encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_report(filename)
            filename.write_text(" " * (2 * 1024 * 1024 + 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "REPORT_TOO_LARGE"):
                verify_report(filename)

    def test_command_line_roundtrip_and_overwrite_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "report.json"
            command = [sys.executable, "-B", str(HERE / "work_scale_contract.py")]
            created = subprocess.run(command + ["--out", str(filename)], check=False,
                                     text=True, capture_output=True)
            self.assertEqual(created.returncode, 0, created.stderr)
            original = filename.read_bytes()
            checked = subprocess.run(command + ["--verify", str(filename)], check=False,
                                     text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            refused = subprocess.run(command + ["--out", str(filename)], check=False,
                                     text=True, capture_output=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("FileExistsError", refused.stderr)
            self.assertEqual(filename.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
