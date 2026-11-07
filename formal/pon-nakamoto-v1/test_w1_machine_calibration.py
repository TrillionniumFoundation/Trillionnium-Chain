"""Finite-sample confidence, scope, denominator and source-integrity controls.

All observation payloads in this file are synthetic test bytes. Their labels
exercise validation only and never establish that hardware executed anything.
"""
from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from math import comb
import unittest
from unittest.mock import patch

from test_w1_machine_architecture import MachineFixture
from w1_machine_calibration import (
    COMPONENTS, SAMPLE_SCHEMA, SAMPLING_PREMISE, confidence_power,
    finite_failure_upper, review_machine_calibration, strict_load,
    verify_machine_calibration, zero_fault_sample_requirement, _sqrt_upper,
)
from w1_quantum_oracle import canonical


class FiniteConfidenceTests(unittest.TestCase):
    def test_zero_faults_never_become_zero_probability(self):
        for n in (1, 16, 65536, 10**30):
            upper = finite_failure_upper(n, 0, Fraction(1, 20))
            self.assertGreater(upper, 0)
            self.assertEqual(upper, min(Fraction(1), Fraction(5, n)))

    def test_exact_finite_binomial_enumeration_covers_probability_grid(self):
        # Independently sum exact binomial probabilities of every bad interval.
        for n in (1, 2, 8, 32, 64):
            for alpha in (Fraction(1, 2), Fraction(1, 8), Fraction(1, 64)):
                for p in (Fraction(0), Fraction(1, 64), Fraction(1, 8),
                          Fraction(1, 2), Fraction(7, 8), Fraction(63, 64), Fraction(1)):
                    bad = sum((Fraction(comb(n, k)) * p**k * (1 - p)**(n - k)
                               for k in range(n + 1) if finite_failure_upper(n, k, alpha) < p), Fraction(0))
                    with self.subTest(n=n, alpha=alpha, p=p):
                        self.assertLessEqual(bad, alpha)

    def test_sqrt_rounds_outwards_with_exact_integer_arithmetic(self):
        for value in (Fraction(0), Fraction(1, 10**30), Fraction(2, 3), Fraction(3, 2)):
            upper = _sqrt_upper(value)
            self.assertGreaterEqual(upper * upper, value)
            if upper:
                self.assertLess((upper - Fraction(1, 1 << 96))**2, value)

    def test_direct_zero_tail_trial_requirement_is_explicitly_not_an_all_method_bound(self):
        rate, alpha = Fraction(1, 10**30), Fraction(1, 20)
        result = zero_fault_sample_requirement(rate, alpha)
        self.assertEqual(result["necessary_trials_lower_bound"], 95 * 10**28)
        self.assertEqual(result["sufficient_trials_for_this_bound"], 5 * 10**30)
        self.assertLessEqual(finite_failure_upper(result["sufficient_trials_for_this_bound"], 0, alpha), rate)
        zero = zero_fault_sample_requirement(Fraction(0), alpha)
        self.assertIsNone(zero["sufficient_trials_for_this_bound"])
        self.assertTrue(zero["zero_target_requires_nonstatistical_argument"])
        unit = zero_fault_sample_requirement(Fraction(1), alpha)
        self.assertEqual(unit["necessary_trials_lower_bound"], 0)
        self.assertEqual(unit["sufficient_trials_for_this_bound"], 0)
        self.assertFalse(unit["zero_target_requires_nonstatistical_argument"])

    def test_invalid_counts_and_confidence_never_coerce_boolean_or_float(self):
        for n, faults in ((0, 0), (True, 0), (1.0, 0), (1, True), (1, 2), (1, -1)):
            with self.subTest(n=n, faults=faults), self.assertRaises(ValueError):
                finite_failure_upper(n, faults, Fraction(1, 20))
        for alpha in (0, 0.05, Fraction(0), Fraction(1), Fraction(-1), Fraction(1, 1 << 257)):
            with self.assertRaises(ValueError):
                confidence_power(alpha)


class CalibrationObservationTests(MachineFixture):
    def setUp(self):
        self.record = self.build(schedule=((0, 0), (0, 1)), processors=1)
        self.kwargs = {"hardware_id": "synthetic-hardware-for-unit-test",
            "hardware_epoch": "test-epoch-1", "instrument_sha256": "1" * 64,
            "now_unix_seconds": 1000, "maximum_age_seconds": 100}

    def sample(self, component="host_calls", n=16):
        return {"schema": SAMPLE_SCHEMA,
            "target_binding_sha256": self.record["calibration_binding_sha256"],
            "hardware_id": self.kwargs["hardware_id"], "hardware_epoch": self.kwargs["hardware_epoch"],
            "instrument_sha256": self.kwargs["instrument_sha256"], "component": component,
            "unit": COMPONENTS[component][1], "execution_kind": COMPONENTS[component][2],
            "sampling_premise": SAMPLING_PREMISE, "started_at_unix_seconds": 950,
            "finished_at_unix_seconds": 999, "valid_until_unix_seconds": 1050,
            "predeclared_trials": n, "clock_threshold_ns": 100,
            "rows": [{"index": i, "event_id": f"{component}-synthetic-{i}",
                      "fault": False, "completed": True, "duration_ns": 10 + i}
                     for i in range(n)]}

    def review(self, samples=None, record=None, **kwargs):
        return review_machine_calibration(self.record if record is None else record,
            (self.domain,), {} if samples is None else samples, **(self.kwargs | kwargs))

    def test_missing_components_are_charged_worst_case_and_never_qualified(self):
        review = self.review()
        self.assertEqual(review["status"], "HOLD")
        self.assertEqual(set(review["missing_active_event_components"]), set(COMPONENTS))
        self.assertEqual(Fraction(**review["combined_risk_upper_if_sampling_and_transfer_premises_hold"]), 1)
        self.assertFalse(review["numerical_budget_comparison_passes"])
        self.assertTrue(all(value is False for value in review["claims"].values()))

    def test_failures_incomplete_attempts_and_overruns_keep_the_original_denominator(self):
        sample = self.sample()
        sample["rows"][0]["fault"] = True
        sample["rows"][1]["completed"] = False
        sample["rows"][2]["duration_ns"] = 101
        sample["rows"][3].update(fault=True, completed=False, duration_ns=102)
        report = self.review({"host_calls": canonical(sample)})
        row = next(x for x in report["components"] if x["component"] == "host_calls")
        obs = row["observation"]
        self.assertEqual(obs["trials"], 16)
        self.assertEqual(obs["faults_including_incomplete_and_clock_overruns"], 4)
        self.assertEqual(obs["incomplete_attempts"], 2)
        self.assertEqual(obs["clock_overruns"], 2)
        self.assertEqual(obs["duration_ns_sum"], sum(x["duration_ns"] for x in sample["rows"]))
        self.assertFalse(obs["sample_maximum_is_runtime_upper_bound"])
        self.assertFalse(obs["measurement_threshold_is_matched_execution_clock"])

    def test_confidence_is_added_once_and_execution_risk_uses_full_reserved_events(self):
        samples = {name: canonical(self.sample(name)) for name in COMPONENTS}
        review = self.review(samples)
        self.assertEqual(review["missing_active_event_components"], [])
        budget = Fraction(**review["original_machine_failure_budget"])
        self.assertEqual(Fraction(**review["calibration_confidence_failure_union"]), budget / 2)
        risk = Fraction(0)
        for row in review["components"]:
            amount = row["reserved_events"] * Fraction(**row["finite_sample_fault_upper"])
            risk += amount
            self.assertEqual(Fraction(**row["fault_union_contribution_if_transfer_premises_hold"]), amount)
        self.assertEqual(Fraction(**review["execution_fault_union_uncapped_if_transfer_premises_hold"]), risk)
        self.assertEqual(Fraction(**review["combined_risk_upper_if_sampling_and_transfer_premises_hold"]),
                         min(Fraction(1), risk + budget / 2))
        self.assertTrue(all(value is False for value in review["claims"].values()))
        self.assertEqual(verify_machine_calibration(review, self.record, (self.domain,), samples), review)

    def test_future_expired_stale_and_wrong_hardware_epochs_are_rejected(self):
        for field, value in (("hardware_epoch", "old-epoch"), ("hardware_id", "another-device"),
                             ("instrument_sha256", "2" * 64), ("target_binding_sha256", "3" * 64),
                             ("started_at_unix_seconds", 899), ("finished_at_unix_seconds", 1001),
                             ("valid_until_unix_seconds", 999)):
            sample = self.sample()
            sample[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.review({"host_calls": canonical(sample)})

    def test_wrong_units_simulation_and_classical_samples_cannot_cover_quantum_events(self):
        for field, value in (("unit", "nanoseconds"), ("execution_kind", "simulator"),
                             ("execution_kind", "physical-classical"),
                             ("component", "host_calls"), ("sampling_premise", "unknown")):
            sample = self.sample("initialization")
            sample[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.review({"initialization": canonical(sample)})

    def test_omitted_duplicate_reordered_and_noninteger_attempts_fail(self):
        for kind in ("omitted", "reused", "reordered", "float", "boolean", "extra"):
            sample = self.sample()
            if kind == "omitted":
                sample["rows"].pop()
            elif kind == "reused":
                sample["rows"][1]["event_id"] = sample["rows"][0]["event_id"]
            elif kind == "reordered":
                sample["rows"].reverse()
            elif kind == "float":
                sample["rows"][0]["duration_ns"] = 1.0
            elif kind == "boolean":
                sample["rows"][0]["index"] = False
            else:
                sample["omitted_failures"] = 2
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.review({"host_calls": json.dumps(sample).encode()})

    def test_inactive_factory_classes_do_not_invent_trials_or_confidence(self):
        record = self.build(schedule=((0, 0),), processors=1)
        review = self.review(record=record)
        inactive = [x for x in review["components"] if x["reserved_events"] == 0]
        self.assertEqual({x["component"] for x in inactive},
                         {"accepted_magic_state_service", "factory_attempts_exhausted"})
        for row in inactive:
            self.assertEqual(row["status"], "NO_EVENTS_IN_THIS_ALLOCATION")
            self.assertIsNone(row["zero_fault_sample_requirement"])
        self.assertEqual(Fraction(**review["calibration_confidence_failure_union"]), 0)

    def test_rehashed_machine_event_deletion_is_rejected_by_full_reconstruction(self):
        altered = deepcopy(self.record)
        altered["machine_record"]["envelope"]["events_all_processors"]["host_calls_including_reserved_proofs"] = 0
        altered["record_sha256"] = hashlib.sha256(canonical({k: v for k, v in altered.items() if k != "record_sha256"})).hexdigest()
        with self.assertRaisesRegex(ValueError, "REPLAY_MISMATCH"):
            self.review(record=altered)

    def test_rehashed_review_risk_or_claim_edits_do_not_verify(self):
        original = self.review()
        for kind in ("risk", "qualification"):
            changed = deepcopy(original)
            if kind == "risk":
                changed["combined_risk_upper_if_sampling_and_transfer_premises_hold"] = {"numerator": 0, "denominator": 1}
            else:
                changed["claims"]["physical_parameters_calibrated"] = True
            changed["record_sha256"] = hashlib.sha256(canonical({k: v for k, v in changed.items() if k != "record_sha256"})).hexdigest()
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "REPLAY_MISMATCH"):
                verify_machine_calibration(changed, self.record, (self.domain,), {})

    def test_source_change_during_review_is_not_accepted(self):
        with patch("w1_machine_calibration._sources", side_effect=[{"one": "1" * 64}, {"one": "2" * 64}]):
            with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
                self.review()

    def test_duplicate_keys_nonfinite_and_unknown_components_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":0.5}'):
            with self.assertRaises(ValueError):
                strict_load(raw)
        with self.assertRaisesRegex(ValueError, "COMPONENT_SET"):
            self.review({"unmetered_physical_guess": b"{}"})


if __name__ == "__main__":
    unittest.main()
