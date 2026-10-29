"""Independent vectors, causal counterexamples and honest model boundaries."""
from copy import deepcopy
from decimal import Decimal, localcontext
import json
from pathlib import Path
import unittest

import pon_risk_model_v1 as model


HERE = Path(__file__).resolve().parent


def suite():
    return model.load_json((HERE / "vectors/pon-risk-scenarios-v1.json").read_bytes())


def decimal_grover_success(nonce_bits, marked, iterations):
    """Independent 100-digit Chebyshev doubling; no asin/sin/cos or floats.

    P = (1 - T_(2*k+1)(1-2*M/N))/2. Doubling needs only O(log k)
    operations and keeps the test oracle practical at the allowed maximum k.
    """
    with localcontext() as context:
        context.prec = 100
        x = Decimal(1) - Decimal(2 * marked) / Decimal(1 << nonce_bits)
        left, right = Decimal(1), x
        for bit in bin(2 * iterations + 1)[2:]:
            middle = 2 * left * right - x
            if bit == '0':
                left, right = 2 * left * left - 1, middle
            else:
                left, right = middle, 2 * right * right - 1
        return (1 - left) / 2


def deterministic_fixture(delay):
    """Synthetic p=1 domain makes withholding/delivery causality exact."""
    config = suite()
    config["trials"] = 1
    config["horizon_slots"] = 20
    scenario = {
        "name": "frozen-release-prefix",
        "honest": [
            {"start": 0, "end": 7, "workers": 1, "cost": "generic"},
            {"start": 7, "end": 15, "workers": 0, "cost": "generic"},
            {"start": 15, "end": 20, "workers": 1, "cost": "generic"}],
        "private": [
            {"start": 0, "end": 7, "workers": 0, "cost": "generic"},
            {"start": 7, "end": 20, "workers": 1, "cost": "generic"}],
        "private_timestamp": "wall", "release_delay_slots": delay,
    }
    config["scenarios"] = [scenario]
    parameters = model.Parameters(model.U256, model.U256, 1000, 16, 10, 120, 6, 6)
    model.validate_suite(config)
    return config, scenario, parameters


class NativeArithmeticAgreement(unittest.TestCase):
    def test_shared_vectors_are_exact_checked_integer_rules(self):
        vectors = json.loads((HERE / "vectors/pon-risk-native-vectors-v1.json").read_text())
        self.assertEqual(vectors["schema"], "pon-risk-native-vectors-v1")
        self.assertEqual(len(vectors["retarget"]), 15)
        self.assertEqual(len(vectors["time"]), 8)
        for row in vectors["retarget"]:
            with self.subTest(row["name"]):
                args = (int(row["parent_target"], 16), row["first"], row["last"],
                        row["interval"], row["spacing"], int(row["pow_limit"], 16))
                if "error" in row:
                    with self.assertRaisesRegex(ValueError, row["error"]):
                        model.retarget(*args)
                else:
                    target = model.retarget(*args)
                    self.assertEqual(f'{target:064x}', row["target"])
                    self.assertEqual(f'{model.required_work(target):0128x}', row["required_work"])
        for row in vectors["time"]:
            with self.subTest(row["name"]):
                args = (row["candidate"], row["ancestors_parent_first"], row["now"], row["skew"])
                if "error" in row:
                    with self.assertRaisesRegex(ValueError, row["error"]):
                        model.check_time(*args)
                else:
                    model.check_time(*args)

    def test_512_bit_chainwork_does_not_saturate_or_wrap(self):
        self.assertEqual(model.add_work(model.U512 - 1, 1), model.U512)
        with self.assertRaises(ValueError):
            model.add_work(model.U512, 1)
        for value in (True, 0, -1, model.U256 + 1, 1.0):
            with self.assertRaises(ValueError):
                model.required_work(value)

    def test_retarget_uses_branch_local_genesis_and_fifteen_gaps(self):
        p = model.Parameters.installed()
        branch = model.Branch(p)
        for height in range(1, 16):
            branch.append(p.genesis + height, p.genesis + height * 10)
        expected = p.initial * 38 // 150
        self.assertEqual(branch.next_target(), expected)
        branch.append(p.genesis + 160, p.genesis + 160)
        self.assertEqual(branch.tip.target, expected)
        self.assertEqual(branch.tip.chainwork, 15 * model.required_work(p.initial) + model.required_work(expected))
        self.assertEqual(branch.retargets, 1)

    def test_invalid_time_cannot_mutate_synthetic_history(self):
        branch = model.Branch(model.Parameters.installed())
        before = branch.headers[:]
        with self.assertRaisesRegex(ValueError, "TIME"):
            branch.append(branch.tip.timestamp, branch.tip.timestamp)
        self.assertEqual(branch.headers, before)

    def test_timestamp_endpoint_policy_remains_admissible(self):
        p = model.Parameters.installed()
        branch = model.Branch(p)
        for height in range(1, 65):
            now = p.genesis + height * 10
            branch.append(branch.timestamp(now, "period_endpoints"), now)
        self.assertEqual(branch.retargets, 4)
        self.assertTrue(all(0 < header.target <= p.limit for header in branch.headers))

    def test_six_descendants_do_not_replace_the_required_work_threshold(self):
        p = model.Parameters.installed()
        branch = model.Branch(p)
        for height in range(1, 43):
            # First interval compresses; the next one reaches the slow clamp.
            # A transaction included at height 28 therefore receives several
            # cheaper descendants after the height-32 retarget.
            offset = height if height < 16 else (160 if height == 16 else height * 30)
            branch.append(p.genesis + offset, p.genesis + height * 100)
            if height == 34:
                self.assertEqual(branch.tip.height - 28, 6)
                self.assertFalse(branch.confirmed(28))
        self.assertTrue(branch.confirmed(28))


class CompleteResourceAccounting(unittest.TestCase):
    def test_setup_misses_and_winning_publication_all_reduce_the_available_budget(self):
        cost = suite()["costs"]["generic"]
        target = (1 << 255) - 1
        observed = model.opportunity(cost, 2, model.NANOSECONDS, target)
        # 1 second - 0.1 setup - 0.1 witness - 0.1 publication allows
        # two complete 0.25 second attempts per worker, not four per worker.
        self.assertEqual(observed["complete_attempts_budget"], 4)
        self.assertAlmostEqual(observed["success_probability"], 0.9375)
        no_publication_time = dict(cost, publication_ns=model.NANOSECONDS)
        self.assertEqual(model.opportunity(no_publication_time, 2, model.NANOSECONDS, target)
                         ["success_probability"], 0)

    def test_legal_heterogeneity_changes_opportunity_but_not_awarded_work(self):
        costs = suite()["costs"]
        target = (1 << 248) - 1
        ordinary = model.opportunity(costs["generic"], 1, model.NANOSECONDS, target)
        structured = model.opportunity(costs["structured"], 1, model.NANOSECONDS, target)
        self.assertGreater(structured["success_probability"], ordinary["success_probability"])
        self.assertEqual(model.required_work(target), 256)
        # A fabricated target hit has no model cost kind and cannot be counted
        # as an admissible legal solver in a valid input suite.
        invalid = dict(costs["generic"], kind="false_transcript")
        with self.assertRaises(ValueError):
            model.validate_cost(invalid)

    def test_exit_has_no_new_attempts_even_with_an_attractive_target(self):
        cost = suite()["costs"]["structured"]
        observed = model.opportunity(cost, 0, model.NANOSECONDS, model.U256)
        self.assertEqual(observed["success_probability"], 0)
        self.assertEqual(observed["complete_attempts_budget"], 0)
        self.assertEqual(observed["reserved_worker_wall_ns"], 0)

    def test_quantum_charges_complete_oracle_restart_and_classical_witness(self):
        cost = suite()["costs"]["quantum_hypothesis"]
        target = (1 << 252) - 1
        observed = model.opportunity(cost, 1, model.NANOSECONDS, target)
        self.assertEqual(observed["attempt_ns"], 150_000_000)
        self.assertEqual(observed["complete_attempts_budget"], 4)
        dearer = dict(cost, full_clean_oracle_and_diffusion_ns=450_000_000)
        expensive = model.opportunity(dearer, 1, model.NANOSECONDS, target)
        self.assertLess(expensive["success_probability"], observed["success_probability"])
        for key in ("full_clean_oracle_and_diffusion_ns", "measurement_check_restart_ns", "winning_witness_ns"):
            with self.subTest(key), self.assertRaises(ValueError):
                model.validate_cost(dict(cost, **{key: 0}))

    def test_grover_success_is_conditional_and_fixed_stop_can_overshoot(self):
        self.assertEqual(model.grover_success(8, 0, 17), 0)
        self.assertEqual(model.grover_success(8, 256, 17), 1)
        self.assertAlmostEqual(model.grover_success(8, 64, 0), 0.25)
        self.assertAlmostEqual(model.grover_success(8, 64, 1), 1)
        self.assertLess(model.grover_success(8, 192, 1), 1e-28)

    def test_nearly_full_64_bit_domain_retains_the_missing_marked_point(self):
        bits, marked, iterations = 64, (1 << 64) - 1, 1_000_000_000
        expected = decimal_grover_success(bits, marked, iterations)
        self.assertAlmostEqual(float(expected), 0.7983866285855264, delta=1e-15)
        self.assertAlmostEqual(model.grover_success(bits, marked, iterations),
                               float(expected), delta=1e-14)
        for marked in (1, 2, 3, 1024):
            with self.subTest(unmarked=marked):
                expected = decimal_grover_success(64, (1 << 64) - marked, iterations)
                self.assertAlmostEqual(model.grover_success(64, (1 << 64) - marked, iterations),
                                       float(expected), delta=1e-13)

    def test_high_phase_and_domain_boundaries_against_independent_decimal(self):
        for bits in (1, 2, 8, 32, 53, 64):
            domain = 1 << bits
            counts = {0, 1, domain // 4, domain // 2 - 1, domain // 2,
                      domain // 2 + 1, 3 * domain // 4, domain - 1, domain}
            for marked in counts:
                for iterations in (0, 1, 17, 999_999_999, 1_000_000_000):
                    with self.subTest(bits=bits, marked=marked, iterations=iterations):
                        actual = model.grover_success(bits, marked, iterations)
                        expected = float(decimal_grover_success(bits, marked, iterations))
                        self.assertGreaterEqual(actual, 0)
                        self.assertLessEqual(actual, 1)
                        # Large binary64 phases still have rounding error. This
                        # finite control is not a bound for all model inputs.
                        self.assertAlmostEqual(actual, expected, delta=1e-6)
            self.assertEqual(model.grover_success(bits, domain // 2, 1_000_000_000), 0.5)

    def test_grover_input_limits_remain_strict(self):
        for args in ((0, 0, 0), (65, 1, 0), (True, 1, 0), (1, -1, 0),
                     (1, 3, 0), (1, True, 0), (1, 1, -1),
                     (1, 1, 1_000_000_001), (1, 1, True), (1, 1, 0.0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                model.grover_success(*args)

    def test_empty_domain_and_unknown_occupancy_are_not_hidden(self):
        original = suite()["costs"]["quantum_hypothesis"]
        floor = dict(original, nonce_bits=8, occupancy_hypothesis="floor_mean")
        ceil = dict(floor, occupancy_hypothesis="ceil_mean")
        target = (1 << 246) - 1
        absent = model.opportunity(floor, 1, model.NANOSECONDS, target)
        present = model.opportunity(ceil, 1, model.NANOSECONDS, target)
        self.assertEqual(absent["marked_count_hypothesis"], 0)
        self.assertEqual(absent["success_probability"], 0)
        self.assertEqual(present["marked_count_hypothesis"], 1)
        self.assertGreater(present["success_probability"], 0)
        self.assertGreater(absent["independent_bernoulli_empty_domain_diagnostic"], 0.77)
        self.assertEqual(floor["iterations"], ceil["iterations"])


class WithholdingAndConfirmation(unittest.TestCase):
    def test_depth_and_required_work_confirmation_can_then_be_lost(self):
        config, scenario, parameters = deterministic_fixture(0)
        trial = model.run_trial(config, scenario, 0, True, parameters)
        self.assertEqual(trial["confirmed_slot"], 6)
        self.assertEqual(trial["reorg_slot"], 14)
        self.assertEqual(trial["honest_height"], 7)
        self.assertEqual(trial["private_height"], 8)

    def test_in_flight_offer_does_not_acquire_later_private_work_for_free(self):
        config, scenario, parameters = deterministic_fixture(2)
        trial = model.run_trial(config, scenario, 0, True, parameters)
        self.assertEqual(trial["confirmed_slot"], 6)
        self.assertIsNone(trial["reorg_slot"])
        self.assertEqual(trial["failed_release_attempts"], 2)
        self.assertGreater(int(trial["private_chainwork"]), int(trial["honest_chainwork"]))
        self.assertTrue(trial["confirmation_survived_only_to_horizon"])

    def test_equal_work_never_replaces_current_tip(self):
        config, scenario, parameters = deterministic_fixture(0)
        scenario["honest"] = scenario["private"] = [
            {"start": 0, "end": 20, "workers": 1, "cost": "generic"}]
        trial = model.run_trial(config, scenario, 0, True, parameters)
        self.assertEqual(trial["honest_chainwork"], trial["private_chainwork"])
        self.assertIsNone(trial["reorg_slot"])
        self.assertEqual(trial["release_attempts"], 0)

    def test_no_confirmation_and_finite_horizon_are_not_reported_as_finality(self):
        config = suite()
        config["trials"] = 2
        config["horizon_slots"] = 3
        config["scenarios"] = [config["scenarios"][0]]
        for actor in ("honest", "private"):
            config["scenarios"][0][actor] = [{"start": 0, "end": 3, "workers": 0, "cost": "generic"}]
        report = model.experiment(config)
        for result in report["results"]:
            self.assertEqual(result["no_confirmation_before_horizon"], 2)
            self.assertIsNone(result["reorg_after_confirmation_conditioned_on_observation"])
            self.assertGreater(result["reorg_after_confirmation_all_trials"]["wilson_95_high"], 0)
        for flag in ("production_activation", "changes_consensus_rules", "physical_quantum_oracle_measured",
                     "measured_costs_or_adversary_fraction", "public_network_qualification"):
            self.assertIs(report["boundaries"][flag], False)
        self.assertEqual(len(report["input_sha256"]), 64)

    def test_seed_is_reproducible_and_paired_before_native_first_retarget(self):
        config, scenario, parameters = deterministic_fixture(2)
        one = model.run_trial(config, scenario, 9, False, parameters)
        two = model.run_trial(config, scenario, 9, False, parameters)
        self.assertEqual(one, two)
        fixed = model.run_trial(config, scenario, 9, True, parameters)
        self.assertEqual(one, fixed)  # Neither branch reaches height 16 here.

    def test_fixed_target_clock_sensitivity_is_not_random_seed_noise(self):
        config = suite()
        ordinary = config["scenarios"][0]
        endpoints = deepcopy(ordinary)
        endpoints["name"] = "other-label-same-random-inputs"
        endpoints["private_timestamp"] = "period_endpoints"
        for trial in range(4):
            self.assertEqual(model.run_trial(config, ordinary, trial, True),
                             model.run_trial(config, endpoints, trial, True))


class InputAndEvidenceBoundaries(unittest.TestCase):
    def test_frozen_input_cannot_claim_native_measurements(self):
        config = suite()
        config["cost_provenance"] = "measured"
        with self.assertRaises(ValueError):
            model.validate_suite(config)

    def test_invalid_numbers_duplicate_keys_unknown_fields_and_schedule_gaps_fail(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.5}', b'{"a":Infinity}'):
            with self.subTest(raw), self.assertRaises(ValueError):
                model.load_json(raw)
        base = suite()
        for key, value in (("trials", True), ("seed", -1), ("slot_seconds", 0),
                           ("horizon_slots", 4097), ("unexpected", 1)):
            bad = deepcopy(base)
            bad[key] = value
            with self.subTest(key), self.assertRaises(ValueError):
                model.validate_suite(bad)
        bad = deepcopy(base)
        bad["scenarios"][0]["honest"][0]["start"] = 1
        with self.assertRaises(ValueError):
            model.validate_suite(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
