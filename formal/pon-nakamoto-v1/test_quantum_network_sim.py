"""Event and counterexample controls; no physical quantum qualification."""
from dataclasses import asdict, replace
from fractions import Fraction
import json
import math
from pathlib import Path
import tempfile
import unittest

from quantum_network_sim import (
    ASSUMPTIONS, Block, NetworkScenario, ParticipationShock, Simulator, TimestampPhase, Trial, WORK_MAX,
    checked_chainwork, grover_success, run_network_scenario, standard_network_scenarios,
)
from experiments.quantum_network_campaign import (
    canonical, cases_for, check_trace_arithmetic, digest, run_campaign, verify_campaign,
)


class ControlledRandom:
    def __init__(self, outcomes=(1.0,), delay=2.0):
        self.outcomes = list(outcomes)
        self.delay = delay
        self.rates = []

    def random(self):
        if len(self.outcomes) > 1:
            return self.outcomes.pop(0)
        return self.outcomes[0]

    def expovariate(self, rate):
        self.rates.append(rate)
        return self.delay

    def getrandbits(self, width):
        value = Fraction(self.random()) * (1 << width)
        return min((1 << width) - 1, value.numerator // value.denominator)


def idle(**changes):
    return NetworkScenario("controlled", classical_block_rate_at_initial_target=0,
                           quantum_initial_factor=0, **changes)


def append_block(sim, label, parent="prefix", stamp=None, miner="c0", probe=False):
    old = sim.blocks[parent]
    target = sim.target_for(parent)
    block = Block(label, parent, old.height + 1, old.timestamp + 10 if stamp is None else stamp,
                  target, old.chainwork + (1 << 256) // (target + 1), sim.profile, miner, probe)
    sim.register_block(block)
    return block


class FiniteGroverTests(unittest.TestCase):
    def test_finite_round_overshoot_and_parallel_measurements(self):
        self.assertAlmostEqual(grover_success(0.25, 0), 0.25)
        self.assertAlmostEqual(grover_success(0.25, 1), 1)
        self.assertAlmostEqual(grover_success(0.25, 2), 0.25)
        self.assertAlmostEqual(grover_success(0.25, 0, 3), 1 - 0.75 ** 3)
        self.assertEqual(grover_success(0.0, 100), 0)
        self.assertAlmostEqual(grover_success(1.0, 100), 1)

    def test_invalid_probability_and_iteration_inputs(self):
        for p, q, count in ((float("nan"), 0, 1), (1.1, 0, 1), (True, 1, 1),
                            (0.1, True, 1), (0.1, -1, 1), (0.1, 100_000_001, 1),
                            (0.1, 1, 0)):
            with self.subTest(p=p, q=q, count=count), self.assertRaises(ValueError):
                grover_success(p, q, count)

    def test_empty_and_full_marked_sets_are_exact_at_large_iteration_counts(self):
        for iterations in (0, 1, 87_366_946, 100_000_000):
            for processors in (1, 7, 1024):
                with self.subTest(iterations=iterations, processors=processors):
                    self.assertEqual(grover_success(0.0, iterations, processors), 0.0)
                    self.assertEqual(grover_success(1.0, iterations, processors), 1.0)

    def test_explicit_marked_fraction_and_missing_physics(self):
        self.assertTrue(ASSUMPTIONS["marked_fraction_assumed_equal_uniform_ticket_probability"])
        self.assertIsNone(ASSUMPTIONS["actual_w1_marked_count"])
        for name in ("logical_qubits", "logical_gate_count", "logical_gate_depth",
                     "physical_error_rate", "error_correction_overhead"):
            self.assertIsNone(ASSUMPTIONS[name])
        self.assertFalse(ASSUMPTIONS["security_theorem"])


class TailSamplingControls(unittest.TestCase):
    class TailBits:
        def __init__(self, draw):
            self.draw = draw
            self.widths = []

        def random(self):
            # A binary fraction below 2^-53 rounds to the zero atom when only
            # the first 53 random bits are retained. The later one is not zero.
            return 0.0

        def getrandbits(self, width):
            self.widths.append(width)
            return self.draw

    def trial(self, exponent, draw):
        sim = Simulator(NetworkScenario("rare_measurement",
            classical_block_rate_at_initial_target=0, quantum_fixed_iterations=0))
        sim.start()
        trial = replace(sim.active["q"], success_probability=math.ldexp(1.0, -exponent))
        sim.active["q"] = trial
        bits = self.TailBits(draw)
        sim.rngs["q"] = bits
        sim.now = trial.finishes
        sim._search_done("q", trial.serial)
        return sim, bits

    def test_tail_boundary_does_not_invent_a_winner_from_53_zero_bits(self):
        for exponent in (60, 256, 1074):
            with self.subTest(exponent=exponent):
                sim, bits = self.trial(exponent, 1)
                self.assertEqual(sim.counts["q"]["proofs_started"], 0)
                self.assertEqual(sim.counts["q"]["searches_failed"], 1)
                self.assertEqual(bits.widths, [exponent])

    def test_genuine_tail_winner_still_starts_a_paid_proof(self):
        sim, bits = self.trial(256, 0)
        self.assertEqual(sim.counts["q"]["proofs_started"], 1)
        self.assertEqual(sim.counts["q"]["searches_failed"], 0)
        self.assertEqual(bits.widths, [256])


class TipMeasurementControls(unittest.TestCase):
    class CountingRandom(ControlledRandom):
        def __init__(self, outcomes=(0.0, 1.0)):
            super().__init__(outcomes)
            self.widths = []

        def getrandbits(self, width):
            self.widths.append(width)
            return super().getrandbits(width)

    def simulation(self, **changes):
        case = NetworkScenario(
            "tip_measurement", duration_seconds=30,
            classical_block_rate_at_initial_target=0, quantum_fixed_iterations=8,
            quantum_prepare_seconds=1, quantum_iteration_seconds=1,
            quantum_measure_seconds=2, quantum_candidate_check_seconds=3,
            quantum_proof_seconds=4, quantum_processors=3,
            quantum_domain_size=8, quantum_domain_marked_count=1,
            quantum_domain_setup_seconds=1, quantum_clock_rounding="upward",
            quantum_tip_policy="measure-at-next-iteration")
        sim = Simulator(replace(case, **changes))
        sim.rngs["q"] = self.CountingRandom()
        sim.start()
        return sim

    def advance(self, sim, at):
        while sim.events and sim.events[0][0] <= at:
            self.assertTrue(sim.step())
        self.assertLessEqual(sim.now, at)
        sim.now = at

    def deliver(self, sim, at, name="competitor", parent="prefix"):
        block = append_block(sim, name, parent)
        sim._schedule(at, "delivery", ("q", block.block_id))
        self.advance(sim, at)
        return block

    def test_policy_is_explicit_and_rejects_ignored_private_branch_option(self):
        self.assertEqual(NetworkScenario("default").quantum_tip_policy, "restart")
        for changes in (dict(quantum_tip_policy="instant"),
                        dict(quantum_strategy="private-branch")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.simulation(**changes)
        sim = self.simulation(quantum_tip_policy="restart")
        original = sim.active["q"]
        block = self.deliver(sim, 4.25)
        self.assertNotEqual(sim.active["q"].serial, original.serial)
        self.assertEqual(sim.active["q"].parent, block.block_id)
        self.assertEqual(sim.counts["q"]["tip_measurements_requested"], 0)
        self.assertEqual(sim.counts["q"]["cancelled_on_tip"], 1)

    def test_incomplete_setup_or_preparation_restarts_and_retains_spent_cost(self):
        for at in (0.5, 1.5):
            with self.subTest(at=at):
                sim = self.simulation()
                original = sim.active["q"]
                block = self.deliver(sim, at)
                self.assertNotEqual(sim.active["q"].serial, original.serial)
                self.assertEqual(sim.active["q"].parent, block.block_id)
                self.assertEqual(sim.counts["q"]["wasted_search_seconds"], at)
                self.assertEqual(sim.domain_setup_seconds_charged, min(1, at))
                self.assertEqual(sim.counts["q"]["candidate_checks_started"], 0)
                self.assertEqual(sim.counts["q"]["tip_measurements_requested"], 0)
                self.assertEqual(sim.rngs["q"].widths, [])

    def test_prepared_boundary_whole_iteration_and_partial_iteration(self):
        for at, iterations, boundary in ((2, 0, 2), (4, 2, 4), (4.25, 3, 5)):
            with self.subTest(at=at):
                sim = self.simulation()
                original = sim.active["q"]
                self.deliver(sim, at)
                retained = sim.active["q"]
                self.assertEqual(retained.serial, original.serial)
                self.assertEqual(retained.started, original.started)
                self.assertEqual(retained.iterations, iterations)
                self.assertEqual(retained.finishes, boundary + 2 + 3)
                self.assertTrue(retained.tip_measurement_requested)
                self.assertEqual(retained.domain_id, original.domain_id)
                self.assertEqual(sim.counts["q"]["searches_started"], 1)
                self.assertEqual(sim.counts["q"]["searches_completed"], 0)
                self.assertEqual(sim.rngs["q"].widths, [])

    def test_fractional_boundaries_never_discard_partial_iteration(self):
        for at, iterations in ((0.3, 2), (math.nextafter(0.3, math.inf), 3)):
            with self.subTest(at=at):
                sim = self.simulation(quantum_prepare_seconds=0.1, quantum_domain_setup_seconds=0,
                                      quantum_iteration_seconds=0.1, quantum_measure_seconds=0.1,
                                      quantum_candidate_check_seconds=0.1, quantum_clock_rounding="nearest")
                self.deliver(sim, at)
                retained = sim.active["q"]
                self.assertEqual(retained.iterations, iterations)
                exact_boundary = Fraction(0.1) + iterations * Fraction(0.1)
                self.assertGreaterEqual(exact_boundary, Fraction(at))
                self.assertGreaterEqual(Fraction(retained.finishes), exact_boundary + 2 * Fraction(0.1))
                self.assertLess(Fraction(retained.finishes) - (exact_boundary + 2 * Fraction(0.1)),
                                Fraction(1, 10**14))

    def test_ongoing_readout_and_check_keep_one_original_measurement(self):
        for at in (10.5, 12.25):
            with self.subTest(at=at):
                sim = self.simulation()
                original = sim.active["q"]
                block = self.deliver(sim, at)
                retained = sim.active["q"]
                self.assertEqual(retained.iterations, original.iterations)
                self.assertEqual(retained.success_probability, original.success_probability)
                self.assertEqual(retained.finishes, original.finishes)
                self.deliver(sim, at + .25, "later", block.block_id)
                self.assertEqual(sim.active["q"], retained)
                self.assertEqual(sim.rngs["q"].widths, [])
                self.advance(sim, retained.finishes)
                self.assertEqual(len(sim.rngs["q"].widths), 1)
                self.assertEqual(sim.counts["q"]["tip_measurements_requested"], 1)
                self.assertEqual(sim.counts["q"]["candidate_checks_completed"], 3)

    def test_old_rounded_event_cannot_finish_retained_check_early(self):
        sim = self.simulation(quantum_fixed_iterations=1, quantum_prepare_seconds=.1,
                              quantum_domain_setup_seconds=.1, quantum_iteration_seconds=.1,
                              quantum_measure_seconds=.1, quantum_candidate_check_seconds=.1,
                              quantum_proof_seconds=.1, quantum_clock_rounding="nearest")
        original = sim.active["q"]
        self.deliver(sim, .4)
        retained = sim.active["q"]
        self.assertLess(Fraction(original.finishes), 5 * Fraction(.1))
        self.assertGreaterEqual(Fraction(retained.finishes), 5 * Fraction(.1))
        self.advance(sim, original.finishes)
        self.assertEqual(sim.counts["q"]["searches_completed"], 0)
        self.assertEqual(sim.rngs["q"].widths, [])
        self.advance(sim, retained.finishes)
        self.assertEqual(sim.counts["q"]["candidate_checks_completed"], 3)
        self.assertEqual(len(sim.rngs["q"].widths), 1)
        self.assertGreaterEqual(Fraction(sim.proofs["q"][2]),
                                Fraction(retained.finishes) + Fraction(.1))

    def test_old_header_target_and_domain_survive_a_retargeted_tip(self):
        sim = self.simulation()
        original = sim.active["q"]
        parent = "prefix"
        for index in range(16):
            parent = append_block(sim, f"fast{index}", parent,
                                  stamp=sim.blocks[parent].timestamp + 1).block_id
        self.assertNotEqual(sim.target_for(parent), original.target)
        sim._schedule(4.25, "delivery", ("q", parent))
        self.advance(sim, 4.25)
        retained = sim.active["q"]
        for key in ("parent", "target", "timestamp", "contains_probe", "domain_id"):
            self.assertEqual(getattr(retained, key), getattr(original, key))
        self.assertEqual(sim.domain_count, 1)
        self.assertAlmostEqual(retained.success_probability, grover_success(1 / 8, 3, 3))

    def test_duplicate_and_later_tips_do_not_remeasure_or_double_charge(self):
        sim = self.simulation()
        original = sim.active["q"]
        first = self.deliver(sim, 4.25)
        retained = sim.active["q"]
        sim._schedule(4.5, "delivery", ("q", first.block_id))
        later = self.deliver(sim, 4.75, "later", first.block_id)
        self.deliver(sim, 6, "latest", later.block_id)
        self.assertEqual(sim.active["q"], retained)
        self.assertEqual(sim.counts["q"]["tip_measurements_requested"], 1)
        self.assertEqual(sim.counts["q"]["cancelled_on_tip"], 0)
        self.advance(sim, 14)
        q = sim.counts["q"]
        self.assertEqual(q["logical_iterations_completed"], 9)
        self.assertEqual(q["search_seconds"], 10)
        self.assertEqual(q["candidate_checks_completed"], 3)
        self.assertEqual(q["candidate_check_processor_seconds"], 9)
        self.assertEqual(q["proof_seconds"], 4)
        self.assertEqual(q["stale_proofs_completed"], 1)
        self.assertEqual(len(sim.rngs["q"].widths), 1)
        created = [block for block in sim.blocks.values() if block.miner == "q"]
        self.assertEqual(len(created), 1)
        self.assertEqual((created[0].parent, created[0].target), (original.parent, original.target))
        self.advance(sim, original.finishes)
        self.assertEqual(q["proofs_started"], 1)
        self.assertEqual(len(sim.rngs["q"].widths), 1)
        self.assertGreaterEqual(sim.obsolete_events, 1)

    def test_horizon_retains_partial_candidate_check_and_no_free_proof(self):
        sim = self.simulation(duration_seconds=8)
        block = append_block(sim, "competitor")
        sim._schedule(4.25, "delivery", ("q", block.block_id))
        summary, _ = sim.run()
        q = summary["miners"]["q"]
        self.assertEqual(summary["observation_seconds"], 8)
        self.assertEqual(q["searches_censored"], 1)
        self.assertEqual(q["logical_iterations_completed"], 9)
        self.assertEqual(q["candidate_checks_completed"], 0)
        self.assertEqual(q["candidate_checks_censored"], 3)
        self.assertEqual(q["candidate_check_seconds"], 1)
        self.assertEqual(q["candidate_check_processor_seconds"], 3)
        self.assertEqual(q["proofs_started"], 0)
        self.assertEqual(sim.rngs["q"].widths, [])
        self.assertFalse(summary["tip_measurement_policy"]["profitability_or_security_claimed"])

    def test_failed_early_measurement_pays_all_checks_without_a_proof(self):
        sim = self.simulation(duration_seconds=10)
        sim.rngs["q"] = self.CountingRandom((1.0,))
        old_domain = sim.quantum_domain
        block = append_block(sim, "competitor")
        sim._schedule(4.25, "delivery", ("q", block.block_id))
        summary, _ = sim.run()
        q = summary["miners"]["q"]
        self.assertEqual(q["searches_failed"], 1)
        self.assertEqual(q["wasted_search_seconds"], 10)
        self.assertEqual(q["wasted_logical_iterations"], 9)
        self.assertEqual(q["candidate_check_processor_seconds"], 9)
        self.assertEqual(q["proofs_started"], 0)
        self.assertEqual(len(sim.rngs["q"].widths), 1)
        self.assertEqual(old_domain.completed_batches, 1)
        self.assertEqual(sim.domain_setup_seconds_charged, 1)

    def test_horizon_during_stale_proof_charges_actual_elapsed(self):
        sim = self.simulation(duration_seconds=12)
        block = append_block(sim, "competitor")
        sim._schedule(4.25, "delivery", ("q", block.block_id))
        summary, _ = sim.run()
        q = summary["miners"]["q"]
        self.assertEqual(q["proofs_started"], 1)
        self.assertEqual(q["proofs_censored"], 1)
        self.assertEqual(q["proof_seconds"], 2)
        self.assertEqual(q["candidate_check_processor_seconds"], 9)
        self.assertEqual(q["blocks_created"], 0)
        self.assertFalse(summary["native_w1_verified"])
        self.assertFalse(summary["security_theorem"])

    def test_shock_still_cancels_and_charges_retained_trial(self):
        sim = self.simulation(duration_seconds=12,
                              shocks=(ParticipationShock(4.75, 1, 0),))
        block = append_block(sim, "competitor")
        sim._schedule(4.25, "delivery", ("q", block.block_id))
        summary, _ = sim.run()
        q = summary["miners"]["q"]
        self.assertEqual(q["cancelled_on_shock"], 1)
        self.assertEqual(q["logical_iterations_completed"], 6)
        self.assertEqual(q["wasted_search_seconds"], 4.75)
        self.assertEqual(q["candidate_checks_started"], 0)
        self.assertEqual(q["proofs_started"], 0)
        self.assertEqual(sim.rngs["q"].widths, [])

    def test_conditional_resource_envelope_still_covers_shortened_trial(self):
        import quantum_oracle_resources as resources
        import quantum_resource_clock as clock

        case = replace(self.simulation().case, quantum_processors=2, quantum_fixed_iterations=100,
                       duration_seconds=2, propagation_seconds=.1,
                       max_events=100, max_blocks=20, max_trace_rows=3000)
        request = resources.example(True)
        binding = clock.bind_resource_clock(case, request, request.physical_models[0].name, 10**30)
        sim = Simulator(binding.scenario)
        sim.rngs["q"] = self.CountingRandom()
        sim.start()
        trial = sim.active["q"]
        prepared = Fraction(binding.scenario.quantum_prepare_seconds) + Fraction(trial.domain_setup_seconds)
        arrival = float(prepared + Fraction(3, 2) * Fraction(trial.iteration_seconds))
        self.deliver(sim, arrival)
        self.assertEqual(sim.active["q"].iterations, 2)
        summary, rows = sim.run()
        result = clock.audit_execution(binding, summary, rows)
        self.assertEqual(result["status"], "CONDITIONAL_RESOURCE_BOUND_OBSERVATION")
        self.assertTrue(result["whole_campaign_envelope_respected"])
        self.assertFalse(result["quantum_hardware_executed"])
        self.assertFalse(result["native_w1_verified"])


class ValidationTests(unittest.TestCase):
    def test_unavailable_backend_and_invalid_profiles_fail_closed(self):
        with self.assertRaisesRegex(NotImplementedError, "UNIMPLEMENTED"):
            Simulator(NetworkScenario("fda", policy="fast-daa-2026"))
        changes = [dict(profile="unknown"), dict(policy="sqrt-work"), dict(seed=True),
                   dict(duration_seconds=float("inf")), dict(max_events=0),
                   dict(max_blocks=10001), dict(quantum_processors=0),
                   dict(quantum_candidate_check_seconds=0), dict(quantum_strategy="hidden"),
                   dict(classical_block_rate_at_initial_target=1e-300),
                   dict(quantum_initial_factor=1e-300),
                   dict(confirmation_work_multiplier=0), dict(classical_shares=(0.8, 0.8)),
                   dict(shocks=(ParticipationShock(2, 1, 1), ParticipationShock(1, 1, 1)))]
        for patch in changes:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                replace(NetworkScenario("invalid"), **patch).validate()

    def test_checked_512_bit_credit(self):
        self.assertEqual(checked_chainwork(WORK_MAX - 1, 1), WORK_MAX)
        with self.assertRaisesRegex(OverflowError, "U512"):
            checked_chainwork(WORK_MAX, 1)
        for args in ((True, 1), (-1, 1), (1, WORK_MAX + 1)):
            with self.assertRaises(ValueError):
                checked_chainwork(*args)

    def test_targets_profiles_mtp_and_future_bound(self):
        sim = Simulator(idle())
        valid = append_block(sim, "valid", stamp=sim.base.timestamp - 1)
        self.assertEqual(sim.validate_block(valid), "admissible")
        for patch in (dict(target=valid.target + 1), dict(chainwork=valid.chainwork + 1),
                      dict(profile="different-genesis"), dict(timestamp=0), dict(height=True)):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                sim.validate_block(replace(valid, **patch))
        self.assertEqual(sim.validate_block(replace(valid, timestamp=sim.start_timestamp + 120)), "admissible")
        self.assertEqual(sim.validate_block(replace(valid, timestamp=sim.start_timestamp + 121)), "deferred-future")

    def test_equal_work_retains_tip_and_heavier_branch_reorgs(self):
        sim = Simulator(idle(confirmation_depth=1, confirmation_work_multiplier=1))
        a = append_block(sim, "a", probe=True)
        aa = append_block(sim, "aa", a.block_id)
        b = append_block(sim, "b", miner="q")
        bb = append_block(sim, "bb", b.block_id, miner="q")
        sim.receive("observer", aa.block_id)
        self.assertTrue(sim.probe_confirmed)
        sim.receive("observer", bb.block_id)
        self.assertEqual(sim.views["observer"].tip, aa.block_id)
        bbb = append_block(sim, "bbb", bb.block_id, miner="q")
        sim.receive("observer", bbb.block_id)
        self.assertEqual(sim.observer_max_reorg_depth, 2)
        self.assertEqual(sim.probe_confirmation_reversals, 1)

    def test_six_easy_descendants_do_not_confirm_a_hard_inclusion(self):
        sim = Simulator(idle())
        sim.now = 2000
        parent = "prefix"
        for offset in range(16):
            parent = append_block(sim, f"pre{offset}", parent,
                                  sim.blocks[parent].timestamp + 40, probe=offset == 15).block_id
        inclusion = parent
        for offset in range(6):
            parent = append_block(sim, f"easy{offset}", parent,
                                  sim.blocks[parent].timestamp + 40).block_id
        sim.receive("observer", parent)
        included, depth, credited, required = sim._probe(parent)
        self.assertTrue(included)
        self.assertEqual(depth, 6)
        self.assertEqual(sim._probe(inclusion)[1:3], (0, 0))
        self.assertLess(credited, required)
        self.assertFalse(sim.probe_confirmed)


class EventControls(unittest.TestCase):
    def test_private_search_ignores_public_tip_while_honest_search_restarts(self):
        for strategy, cancelled in (("honest-tip", 1), ("private-branch", 0)):
            case = NetworkScenario("restart", classical_block_rate_at_initial_target=0,
                                   quantum_strategy=strategy, quantum_fixed_iterations=10,
                                   quantum_iteration_seconds=1, quantum_prepare_seconds=0)
            sim = Simulator(case)
            sim.start()
            original = sim.active["q"].serial
            sim.now = 2
            block = append_block(sim, "other")
            sim.receive("q", block.block_id)
            self.assertEqual(sim.counts["q"]["cancelled_on_tip"], cancelled)
            self.assertEqual(sim.active["q"].serial == original, not cancelled)
            if not cancelled:
                self.assertEqual(sim.counts["q"]["private_public_tip_updates_ignored"], 1)

    def test_classical_clock_uses_target_probability_and_share(self):
        sim = Simulator(NetworkScenario("poisson", quantum_initial_factor=0))
        rng = ControlledRandom(delay=2)
        sim.rngs["c0"] = rng
        sim.start()
        self.assertAlmostEqual(rng.rates[0], 0.05)
        self.assertEqual(sim.active["c0"].finishes, 2)

    def test_winner_check_then_proof_then_delivery_are_distinct(self):
        case = NetworkScenario("stages", duration_seconds=10, classical_block_rate_at_initial_target=0,
                               quantum_fixed_iterations=0, quantum_prepare_seconds=0,
                               quantum_measure_seconds=1, quantum_candidate_check_seconds=2,
                               quantum_proof_seconds=3, propagation_seconds=4, probe_arrival_seconds=0)
        sim = Simulator(case)
        sim.rngs["q"] = ControlledRandom((0.0, 1.0))
        summary, rows = sim.run()
        self.assertEqual(next(r["at_seconds"] for r in rows if r["kind"] == "proof-start"), 3)
        self.assertEqual(next(r["at_seconds"] for r in rows if r["kind"] == "block"), 6)
        self.assertEqual(summary["probe"]["first_inclusion_seconds"], 10)
        q = summary["miners"]["q"]
        self.assertEqual(q["proofs_started"], 1)
        self.assertEqual(q["candidate_checks_completed"], 2)
        self.assertEqual(q["candidate_check_seconds"], 4)
        self.assertEqual(q["searches_failed"], 1)
        self.assertEqual(q["logical_iterations_completed"], 0)

    def test_failed_trials_charge_recheck_without_generating_proof(self):
        case = NetworkScenario("failed", duration_seconds=6, classical_block_rate_at_initial_target=0,
                               quantum_fixed_iterations=0, quantum_prepare_seconds=0,
                               quantum_measure_seconds=1, quantum_candidate_check_seconds=2)
        sim = Simulator(case)
        sim.rngs["q"] = ControlledRandom((1.0,))
        summary, _ = sim.run()
        q = summary["miners"]["q"]
        self.assertEqual(q["searches_failed"], 2)
        self.assertEqual(q["candidate_checks_completed"], 2)
        self.assertEqual(q["candidate_check_seconds"], 4)
        self.assertEqual(q["proofs_started"], 0)

    def test_horizon_censors_partial_search_and_candidate_check(self):
        case = NetworkScenario("partial", duration_seconds=3, classical_block_rate_at_initial_target=0,
                               quantum_fixed_iterations=0, quantum_prepare_seconds=0,
                               quantum_measure_seconds=1, quantum_candidate_check_seconds=10,
                               quantum_processors=3)
        summary, _ = run_network_scenario(case)
        q = summary["miners"]["q"]
        self.assertEqual(q["searches_completed"], 0)
        self.assertEqual(q["searches_censored"], 1)
        self.assertEqual(q["candidate_checks_censored"], 3)
        self.assertEqual(q["candidate_check_seconds"], 2)
        self.assertEqual(q["candidate_check_processor_seconds"], 6)
        self.assertEqual(q["proofs_started"], 0)
        self.assertEqual(summary["probe"]["right_censored_wait_seconds"], 2)

    def test_future_wait_does_not_spend_unobserved_horizon(self):
        sim = Simulator(idle(duration_seconds=2))
        trial = Trial(1, "q", "prefix", sim.start_timestamp + 200,
                      sim.target_for("prefix"), False, 0, 0, 0, 1, 0, 0.1)
        sim.proofs["q"] = (trial, 0, 0.1)
        sim.counts["q"]["proofs_started"] = 1
        sim._schedule(0.1, "proof", "q")
        summary, _ = sim.run()
        q = summary["miners"]["q"]
        self.assertEqual(q["blocks_created"], 0)
        self.assertEqual(q["future_waits_censored"], 1)
        self.assertAlmostEqual(q["future_timestamp_wait_seconds"], 1.9)
        self.assertAlmostEqual(q["future_timestamp_wait_scheduled_seconds"], 79.9)

    def test_private_future_parent_does_not_stop_descendant_search(self):
        case = NetworkScenario("privatefuture", duration_seconds=0.09,
                               classical_block_rate_at_initial_target=0,
                               quantum_strategy="private-branch", quantum_timestamp_mode="compressed",
                               private_timestamp_step=120, quantum_fixed_iterations=0,
                               quantum_prepare_seconds=0, quantum_measure_seconds=0.01,
                               quantum_candidate_check_seconds=0.01, quantum_proof_seconds=0,
                               probe_arrival_seconds=0, private_release_seconds=0.03,
                               propagation_seconds=0)
        sim = Simulator(case)
        sim.rngs["q"] = ControlledRandom((0.0,))
        summary, _ = sim.run()
        q = summary["miners"]["q"]
        self.assertEqual(q["blocks_created"], 4)
        self.assertEqual(q["private_future_blocks_created"], 3)
        self.assertEqual(q["searches_started"], 5)
        self.assertEqual(q["future_timestamp_wait_seconds"], 0)
        self.assertEqual(summary["observer_added_blocks"], 1)

    def test_deferred_bundle_adopts_prefix_then_descendant_at_exact_bound(self):
        sim = Simulator(idle(duration_seconds=200))
        a = append_block(sim, "a", stamp=sim.start_timestamp + 200, miner="q")
        b = append_block(sim, "b", parent=a.block_id, stamp=sim.start_timestamp + 201, miner="q")
        sim.receive("observer", a.block_id)
        sim.receive("observer", b.block_id)
        self.assertEqual(len(sim.deferred), 1)
        self.assertEqual(sim.views["observer"].tip, "prefix")
        sim.step()
        self.assertEqual(sim.now, 80)
        self.assertEqual(sim.views["observer"].tip, a.block_id)
        sim.step()
        self.assertEqual(sim.now, 81)
        self.assertEqual(sim.views["observer"].tip, b.block_id)
        self.assertFalse(sim.deferred)

    def test_private_timestamp_phase_boundaries(self):
        case = NetworkScenario("phases", duration_seconds=0.09,
                               classical_block_rate_at_initial_target=0,
                               quantum_strategy="private-branch", quantum_timestamp_mode="compressed",
                               private_timestamp_step=10,
                               private_timestamp_schedule=(TimestampPhase(2, 5), TimestampPhase(1, 20)),
                               quantum_fixed_iterations=0, quantum_prepare_seconds=0,
                               quantum_measure_seconds=0.01, quantum_candidate_check_seconds=0.01,
                               quantum_proof_seconds=0, probe_arrival_seconds=0)
        sim = Simulator(case)
        sim.rngs["q"] = ControlledRandom((0.0,))
        _, rows = sim.run()
        stamps = [sim.start_timestamp] + [r["timestamp"] for r in rows if r["kind"] == "block"]
        self.assertEqual([b-a for a, b in zip(stamps, stamps[1:])], [5, 5, 20, 10])

    def test_shock_cancels_active_trial_and_restart_has_new_clock(self):
        case = NetworkScenario("shock", duration_seconds=5, classical_block_rate_at_initial_target=0,
                               quantum_fixed_iterations=10, quantum_iteration_seconds=1,
                               shocks=(ParticipationShock(2, 0, 0), ParticipationShock(4, 0, 2)))
        summary, rows = run_network_scenario(case)
        q = summary["miners"]["q"]
        self.assertEqual(q["cancelled_on_shock"], 1)
        self.assertEqual(q["searches_started"], 2)
        self.assertEqual(q["searches_censored"], 1)
        starts = [r["at_seconds"] for r in rows if r["kind"] == "search-start"]
        self.assertEqual(starts, [0.0, 4.0])

    def test_unprocessed_zero_duration_proof_is_censored_at_event_limit(self):
        case = NetworkScenario("zero_proof", classical_block_rate_at_initial_target=0,
                               quantum_fixed_iterations=0, quantum_prepare_seconds=0,
                               quantum_measure_seconds=0.01, quantum_candidate_check_seconds=0.01,
                               quantum_proof_seconds=0, max_events=1)
        sim = Simulator(case)
        sim.rngs["q"] = ControlledRandom((0.0,))
        summary, _ = sim.run()
        q = summary["miners"]["q"]
        self.assertEqual(q["proofs_started"], 1)
        self.assertEqual(q["proofs_completed"], 0)
        self.assertEqual(q["proofs_censored"], 1)
        self.assertEqual(q["future_waits_censored"], 0)

    def test_resource_limits_and_seed_reproducibility(self):
        case = NetworkScenario("seeded", seed=919, duration_seconds=100)
        self.assertEqual(run_network_scenario(case), run_network_scenario(case))
        limited, _ = run_network_scenario(replace(case, max_events=1))
        self.assertEqual(limited["termination"], "event-limit")
        self.assertLessEqual(limited["events_processed"], 1)
        bounded, rows = run_network_scenario(replace(case, max_trace_rows=1))
        self.assertTrue(bounded["trace_limit_reached"])
        self.assertEqual(len(rows), 1)
        pending, _ = run_network_scenario(replace(case, max_pending_events=1))
        self.assertEqual(pending["termination"], "pending-event-limit")


class CampaignControls(unittest.TestCase):
    def test_fixed_tip_policy_pair_preserves_original_inventory_and_budgets(self):
        seeds = (4101, 4102, 4103)
        cases = cases_for(seeds)
        original = standard_network_scenarios()
        self.assertEqual(len(original), 10)
        self.assertEqual(len(cases), 36)
        for index, seed in enumerate(seeds):
            group = cases[12 * index:12 * (index + 1)]
            self.assertEqual(group[:10], [replace(case, seed=seed) for case in original])
            restart, measurement = group[-2:]
            first, second = asdict(restart), asdict(measurement)
            differences = {key for key in first if first[key] != second[key]}
            self.assertEqual(differences, {"name", "quantum_tip_policy"})
            self.assertEqual((restart.seed, measurement.seed), (seed, seed))
            self.assertEqual(restart.quantum_tip_policy, "restart")
            self.assertEqual(measurement.quantum_tip_policy, "measure-at-next-iteration")
            self.assertEqual(restart.duration_seconds, 300)
            self.assertIsNone(restart.quantum_domain_marked_count)
            self.assertEqual(restart.quantum_domain_trials_before_refresh, 0)
            for name in ("quantum_domain_setup_seconds", "quantum_prepare_seconds",
                         "quantum_iteration_seconds", "quantum_measure_seconds",
                         "quantum_candidate_check_seconds", "quantum_proof_seconds"):
                self.assertGreater(first[name], 0)
            restart.validate()
            measurement.validate()

    def test_fixed_pair_exercises_competing_tips_without_an_advantage_claim(self):
        restart, measurement = cases_for((4101,))[-2:]
        results = [run_network_scenario(case)[0] for case in (restart, measurement)]
        for summary in results:
            self.assertEqual(summary["termination"], "horizon")
            self.assertEqual(summary["observation_seconds"], 300)
            self.assertGreater(summary["miners"]["q"]["candidate_checks_completed"], 0)
            self.assertFalse(summary["security_theorem"])
            self.assertFalse(summary["quantum_hardware_executed"])
            self.assertFalse(summary["native_w1_verified"])
        self.assertGreater(results[0]["miners"]["q"]["cancelled_on_tip"], 0)
        self.assertGreater(results[1]["miners"]["q"]["tip_measurements_requested"], 0)
        self.assertFalse(results[1]["tip_measurement_policy"]["profitability_or_security_claimed"])

    def test_readback_replay_and_forged_qualification_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "campaign"
            result = run_campaign(out, ["unittest"], seeds=(4101,))
            self.assertEqual(result["runs"], 12)
            verification = verify_campaign(out)
            self.assertEqual(verification["result"], "SEEDED_REPLAY_AND_INTEGER_READBACK_PASS")
            self.assertEqual(verification["runs"], 12)
            with self.assertRaises(FileExistsError):
                run_campaign(out, ["unittest"], seeds=(4101,))
            report = json.loads((out / "report.json").read_text())
            original = canonical(report)
            manifest = json.loads((out / "manifest.json").read_text())
            original_manifest = canonical(manifest)
            dropped = report["observations"].pop()
            manifest["files_sha256"].pop(dropped["trace_file"])
            (out / "report.json").write_bytes(canonical(report))
            manifest["files_sha256"]["report.json"] = digest(out / "report.json")
            (out / "manifest.json").write_bytes(canonical(manifest))
            with self.assertRaisesRegex(ValueError, "MANIFEST_INVENTORY"):
                verify_campaign(out)
            for key, value in (("quantum_tip_policy", "restart"), ("quantum_prepare_seconds", .01)):
                report = json.loads(original)
                manifest = json.loads(original_manifest)
                report["observations"][-1]["parameters"][key] = value
                (out / "report.json").write_bytes(canonical(report))
                manifest["files_sha256"]["report.json"] = digest(out / "report.json")
                (out / "manifest.json").write_bytes(canonical(manifest))
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "SCENARIO_SUBSTITUTION"):
                    verify_campaign(out)
            (out / "manifest.json").write_bytes(original_manifest)
            report = json.loads(original)
            report["source"]["all_source_files_committed_at_head"] = not report["source"]["all_source_files_committed_at_head"]
            (out / "report.json").write_bytes(canonical(report))
            manifest = json.loads((out / "manifest.json").read_text())
            manifest["files_sha256"]["report.json"] = digest(out / "report.json")
            (out / "manifest.json").write_bytes(canonical(manifest))
            with self.assertRaisesRegex(ValueError, "SOURCE_COMMITMENT_CLAIM"):
                verify_campaign(out)
            report = json.loads(original)
            report["source"]["git_head"] = "0" * 40
            (out / "report.json").write_bytes(canonical(report))
            manifest["files_sha256"]["report.json"] = digest(out / "report.json")
            (out / "manifest.json").write_bytes(canonical(manifest))
            with self.assertRaisesRegex(ValueError, "SOURCE_HEAD"):
                verify_campaign(out)
            report = json.loads(original)
            report["assumptions"]["security_theorem"] = True
            (out / "report.json").write_bytes(canonical(report))
            manifest = json.loads((out / "manifest.json").read_text())
            manifest["files_sha256"]["report.json"] = digest(out / "report.json")
            (out / "manifest.json").write_bytes(canonical(manifest))
            with self.assertRaisesRegex(ValueError, "ASSUMPTION_SUBSTITUTION"):
                verify_campaign(out)

    def test_independent_readback_detects_integer_credit_mutation(self):
        _, rows = run_network_scenario(NetworkScenario("integrity", duration_seconds=100))
        check_trace_arithmetic(rows)
        index = next(i for i, row in enumerate(rows) if row["kind"] == "block")
        mutated = [dict(row) for row in rows]
        mutated[index]["chainwork"] = "1"
        with self.assertRaisesRegex(ValueError, "CHAINWORK"):
            check_trace_arithmetic(mutated)


class AdversarialPolicyControls(unittest.TestCase):
    def test_upward_mode_rounds_exact_stage_sum_and_search_and_proof_deadlines(self):
        case = NetworkScenario("upward", classical_block_rate_at_initial_target=0,
                               quantum_fixed_iterations=5, quantum_iteration_seconds=1 + 2**-52,
                               quantum_prepare_seconds=0.125, quantum_measure_seconds=0.5,
                               quantum_candidate_check_seconds=0.5, quantum_proof_seconds=1 + 2**-52,
                               quantum_domain_size=1, quantum_domain_marked_count=1,
                               quantum_domain_setup_seconds=0.25)
        exact = sum((Fraction.from_float(value) for value in (0.125, 0.5, 0.5, 0.25)), Fraction(0))
        exact += 5 * Fraction.from_float(case.quantum_iteration_seconds)
        nearest = Simulator(case)
        nearest.start()
        self.assertLess(Fraction.from_float(nearest.active["q"].finishes), exact)
        sim = Simulator(replace(case, quantum_clock_rounding="upward"))
        sim.now = 0.1
        sim.start()
        trial = sim.active["q"]
        self.assertGreaterEqual(Fraction.from_float(trial.finishes), Fraction.from_float(0.1) + exact)
        self.assertEqual(next(r for r in sim.trace if r["kind"] == "search-start")["clock_rounding"], "upward")
        sim.now = trial.finishes
        sim._search_done("q", trial.serial)
        _, started, finished = sim.proofs["q"]
        self.assertGreaterEqual(Fraction.from_float(finished),
                                Fraction.from_float(started) + Fraction.from_float(case.quantum_proof_seconds))
        self.assertEqual(sim.counts["q"]["logical_iterations_completed"], 5)

    def test_upward_mode_preserves_classical_clocks_and_rejects_unknown_mode(self):
        case = NetworkScenario("classical_rounding", quantum_initial_factor=0, duration_seconds=50)
        self.assertEqual(run_network_scenario(case),
                         run_network_scenario(replace(case, quantum_clock_rounding="upward")))
        with self.assertRaisesRegex(ValueError, "QUANTUM_CLOCK_ROUNDING"):
            replace(case, quantum_clock_rounding="downward").validate()

    def test_slow_effective_clock_after_permitted_speed_factor_is_censored(self):
        case = NetworkScenario("scaled_slow_clock", duration_seconds=10,
                               classical_block_rate_at_initial_target=0, quantum_initial_factor=1e-9,
                               quantum_iteration_seconds=1e30, quantum_trial_policy="bounded-throughput",
                               quantum_iteration_candidates=(1, 2), quantum_clock_rounding="upward")
        summary, rows = run_network_scenario(case)
        start = next(row for row in rows if row["kind"] == "search-start")
        self.assertGreater(start["iteration_seconds_upper"], 1e38)
        self.assertEqual(summary["termination"], "horizon")
        self.assertEqual(summary["miners"]["q"]["searches_censored"], 1)
        self.assertEqual(summary["miners"]["q"]["logical_iterations_completed"], 0)

    def test_persistent_zero_domain_freezes_header_and_charges_shared_setup_once(self):
        case = NetworkScenario("empty_domain", duration_seconds=10,
                               classical_block_rate_at_initial_target=0, quantum_processors=4,
                               quantum_fixed_iterations=0, quantum_prepare_seconds=0,
                               quantum_measure_seconds=0.5, quantum_candidate_check_seconds=0.5,
                               quantum_domain_size=16, quantum_domain_marked_count=0,
                               quantum_domain_setup_seconds=2)
        summary, rows = run_network_scenario(case)
        domains = [r for r in rows if r["kind"] == "quantum-domain"]
        starts = [r for r in rows if r["kind"] == "search-start"]
        self.assertEqual(len(domains), 1)
        self.assertEqual(len({r["domain_id"] for r in starts}), 1)
        self.assertEqual(len({r["timestamp"] for r in starts}), 1)
        self.assertEqual(starts[0]["domain_setup_seconds"], 2)
        self.assertTrue(all(r["domain_setup_seconds"] == 0 for r in starts[1:]))
        self.assertEqual(summary["adversarial"]["domain_setup_seconds_charged"], 2)
        self.assertEqual(summary["adversarial"]["domain_setup_processor_seconds_charged"], 8)
        self.assertEqual(summary["miners"]["q"]["searches_completed"], 8)
        self.assertEqual(summary["miners"]["q"]["candidate_checks_completed"], 32)
        self.assertEqual(summary["miners"]["q"]["proofs_started"], 0)

    def test_interrupted_domain_setup_resumes_paid_remaining_work(self):
        case = NetworkScenario("interrupted_setup", duration_seconds=4,
                               classical_block_rate_at_initial_target=0, quantum_fixed_iterations=0,
                               quantum_prepare_seconds=0, quantum_measure_seconds=0.5,
                               quantum_candidate_check_seconds=0.5, quantum_domain_size=16,
                               quantum_domain_marked_count=0, quantum_domain_setup_seconds=2,
                               shocks=(ParticipationShock(0.5, 1, 0), ParticipationShock(1, 1, 1)))
        summary, rows = run_network_scenario(case)
        starts = [r for r in rows if r["kind"] == "search-start"]
        self.assertEqual([r["domain_setup_seconds"] for r in starts], [2, 1.5, 0])
        self.assertEqual(len({r["domain_id"] for r in starts}), 1)
        self.assertEqual(summary["adversarial"]["domains_created"], 1)
        self.assertEqual(summary["adversarial"]["domain_setup_seconds_charged"], 2)
        self.assertEqual(summary["miners"]["q"]["searches_completed"], 1)
        self.assertEqual(summary["miners"]["q"]["candidate_checks_completed"], 1)

    def test_repeated_shocks_do_not_forgive_or_duplicate_domain_setup(self):
        case = NetworkScenario("repeated_setup_shocks", duration_seconds=4,
                               classical_block_rate_at_initial_target=0, quantum_fixed_iterations=0,
                               quantum_prepare_seconds=0, quantum_measure_seconds=0.5,
                               quantum_candidate_check_seconds=0.5, quantum_domain_size=16,
                               quantum_domain_marked_count=0, quantum_domain_setup_seconds=2,
                               shocks=(ParticipationShock(0.5, 1, 2), ParticipationShock(0.75, 1, 1)))
        summary, rows = run_network_scenario(case)
        starts = [r for r in rows if r["kind"] == "search-start"]
        self.assertEqual([r["domain_setup_seconds"] for r in starts], [2, 1.5, 1.25, 0, 0])
        self.assertEqual(summary["adversarial"]["domain_setup_seconds_charged"], 2)
        self.assertEqual(summary["miners"]["q"]["searches_completed"], 2)

    def test_parent_change_discards_only_unfinished_old_domain_setup(self):
        sim = Simulator(NetworkScenario("changed_setup_parent", duration_seconds=4,
                                        classical_block_rate_at_initial_target=0, quantum_fixed_iterations=0,
                                        quantum_prepare_seconds=0, quantum_measure_seconds=0.5,
                                        quantum_candidate_check_seconds=0.5, quantum_domain_size=16,
                                        quantum_domain_marked_count=0, quantum_domain_setup_seconds=2))
        sim.start()
        sim.now = 0.5
        block = append_block(sim, "new-parent")
        sim.receive("q", block.block_id)
        summary, rows = sim.run()
        domains = [r for r in rows if r["kind"] == "quantum-domain"]
        self.assertEqual(len(domains), 2)
        self.assertNotEqual(domains[0]["domain_id"], domains[1]["domain_id"])
        starts = [r for r in rows if r["kind"] == "search-start"]
        self.assertEqual([r["domain_setup_seconds"] for r in starts], [2, 2, 0])
        self.assertEqual(summary["adversarial"]["domain_setup_seconds_charged"], 2.5)
        self.assertEqual(summary["miners"]["q"]["searches_completed"], 1)

    def test_setup_remainder_uses_exact_elapsed_and_upward_conversion(self):
        sim = Simulator(NetworkScenario("setup_rounding", duration_seconds=4,
                                        classical_block_rate_at_initial_target=0, quantum_fixed_iterations=0,
                                        quantum_prepare_seconds=0, quantum_measure_seconds=0.5,
                                        quantum_candidate_check_seconds=0.5, quantum_domain_size=16,
                                        quantum_domain_marked_count=0, quantum_domain_setup_seconds=0.3,
                                        quantum_clock_rounding="upward"))
        sim.start()
        sim.now = 0.1
        sim._shock(ParticipationShock(sim.now, 1, 2))
        remaining = Fraction.from_float(0.3) - Fraction.from_float(0.1)
        self.assertGreaterEqual(Fraction.from_float(sim.active["q"].domain_setup_seconds), remaining)
        self.assertLess(Fraction.from_float(sim.active["q"].domain_setup_seconds), remaining + Fraction(1, 10**15))
        summary, _ = sim.run()
        self.assertAlmostEqual(summary["adversarial"]["domain_setup_seconds_charged"], 0.3)

    def test_refresh_is_after_measured_batches_and_pays_setup_again(self):
        case = NetworkScenario("refresh", duration_seconds=10,
                               classical_block_rate_at_initial_target=0, quantum_fixed_iterations=0,
                               quantum_prepare_seconds=0, quantum_measure_seconds=0.5,
                               quantum_candidate_check_seconds=0.5, quantum_domain_size=16,
                               quantum_domain_marked_count=0, quantum_domain_setup_seconds=2,
                               quantum_domain_trials_before_refresh=2)
        summary, rows = run_network_scenario(case)
        domains = [r for r in rows if r["kind"] == "quantum-domain"]
        self.assertEqual([r["at_seconds"] for r in domains], [0, 4, 8])
        self.assertEqual(len({r["domain_id"] for r in domains}), 3)
        self.assertEqual(summary["adversarial"]["domain_setup_seconds_charged"], 6)

    def test_sampled_shared_m_is_not_resampled_per_processor_or_retry(self):
        class EmptyTickets:
            calls = 0

            def getrandbits(self, bits):
                self.calls += 1
                return (1 << bits) - 1

        sim = Simulator(NetworkScenario("shared", duration_seconds=5,
                                        classical_block_rate_at_initial_target=0, quantum_processors=4,
                                        quantum_fixed_iterations=0, quantum_prepare_seconds=0,
                                        quantum_measure_seconds=0.5, quantum_candidate_check_seconds=0.5,
                                        quantum_domain_size=16))
        sim.domain_rng = EmptyTickets()
        summary, _ = sim.run()
        self.assertEqual(sim.domain_rng.calls, 16)
        self.assertEqual(summary["adversarial"]["zero_marked_domains"], 1)
        self.assertEqual(summary["miners"]["q"]["searches_failed"], 5)

    def test_trial_selection_never_receives_sampled_marked_count(self):
        class ConstantTickets:
            def __init__(self, marked):
                self.marked = marked

            def getrandbits(self, bits):
                return 0 if self.marked else (1 << bits) - 1

        case = NetworkScenario("hidden_m", classical_block_rate_at_initial_target=0,
                               quantum_trial_policy="bounded-throughput", quantum_iteration_candidates=tuple(range(9)),
                               quantum_domain_size=8, quantum_domain_trials_before_refresh=1,
                               quantum_domain_setup_seconds=0.1)
        choices, successes = [], []
        for marked in (False, True):
            sim = Simulator(case)
            sim.domain_rng = ConstantTickets(marked)
            sim.start()
            choices.append(sim.active["q"].iterations)
            successes.append(sim.active["q"].success_probability)
        self.assertEqual(choices[0], choices[1])
        self.assertEqual(successes, [0, 1])

    def test_optimizer_refuses_persistent_m_or_fixed_count_throughput_claim(self):
        case = NetworkScenario("bad_prior", quantum_trial_policy="bounded-throughput",
                               quantum_iteration_candidates=(0, 1), quantum_domain_size=8)
        for patch in ({}, dict(quantum_domain_trials_before_refresh=1, quantum_domain_marked_count=1),
                      dict(quantum_domain_trials_before_refresh=1, quantum_domain_size=65)):
            with self.assertRaises(ValueError):
                replace(case, **patch).validate()

    def test_branch_minimum_and_epoch_extremes_allow_valid_backward_timestamps(self):
        for mode in ("mtp-min", "retarget-extremes"):
            case = NetworkScenario("backward", duration_seconds=3,
                                   classical_block_rate_at_initial_target=0, quantum_strategy="private-branch",
                                   quantum_timestamp_mode=mode, quantum_fixed_iterations=0,
                                   quantum_domain_size=1, quantum_domain_marked_count=1,
                                   quantum_prepare_seconds=0, quantum_measure_seconds=0.1,
                                   quantum_candidate_check_seconds=0.1, quantum_proof_seconds=0)
            sim = Simulator(case)
            _, rows = sim.run()
            check_trace_arithmetic(rows)
            backwards = [b for b in sim.blocks.values() if b.parent is not None
                         and b.timestamp < sim.blocks[b.parent].timestamp]
            self.assertTrue(backwards, mode)
            self.assertTrue(all(sim.validate_block(b) == "admissible" for b in backwards))

    def test_adaptive_release_uses_only_miner_delivered_public_view(self):
        results = []
        for deliver_to_quantum in (False, True):
            sim = Simulator(idle(quantum_strategy="private-branch", private_release_policy="observed-work-lead"))
            public = "prefix"
            for index in range(3):
                public = append_block(sim, f"public{index}", public).block_id
            sim.receive("observer", public)
            if deliver_to_quantum:
                sim.receive("q", public)
            private = append_block(sim, "own", miner="q")
            sim.private_tip = private.block_id
            sim.private_wait_started = 0
            sim.receive("q", private.block_id, from_network=False)
            sim._maybe_adaptive_release("private-block")
            results.append(sim.adaptive_releases)
            self.assertEqual(sim.public_q_tip, public if deliver_to_quantum else "prefix")
            if not deliver_to_quantum:
                self.assertEqual(sim.views["observer"].tip, public)
                self.assertEqual(sim.last_published_private_tip, "own")
        self.assertEqual(results, [1, 0])

    def test_adaptive_release_defers_future_prefix_then_uses_local_timer(self):
        sim = Simulator(idle(duration_seconds=5, quantum_strategy="private-branch",
                             private_release_policy="observed-work-lead"))
        private = append_block(sim, "future", stamp=sim.start_timestamp + 121, miner="q")
        sim.private_tip = private.block_id
        sim.private_wait_started = 0
        sim.receive("q", private.block_id, from_network=False)
        sim._maybe_adaptive_release("private-block")
        self.assertEqual(sim.adaptive_releases, 0)
        sim.start()
        while sim.events and sim.events[0][0] <= 1:
            sim.step()
        self.assertEqual(sim.adaptive_releases, 1)
        self.assertEqual(sim.public_q_tip, "prefix")
        published = [r for r in sim.trace if r["kind"] == "publish"]
        self.assertEqual([r["at_seconds"] for r in published], [1])

    def test_explicit_timeout_can_release_without_work_advantage(self):
        sim = Simulator(idle(duration_seconds=5, quantum_strategy="private-branch",
                             private_release_policy="observed-work-lead", private_release_work_lead=100,
                             private_release_max_wait_seconds=2))
        private = append_block(sim, "own", miner="q")
        sim.private_tip = private.block_id
        sim.private_wait_started = 0
        sim._maybe_adaptive_release("private-block")
        self.assertEqual(sim.adaptive_releases, 0)
        sim.start()
        while sim.events and sim.events[0][0] <= 2:
            sim.step()
        self.assertEqual(sim.adaptive_releases, 1)
        release = [r for r in sim.trace if r["kind"] == "adaptive-release-check" and r["release"]][0]
        self.assertTrue(release["timed_out"])
        self.assertEqual(release["at_seconds"], 2)

    def test_fractional_private_timeout_uses_one_upward_deadline(self):
        sim = Simulator(idle(duration_seconds=1, quantum_strategy="private-branch",
                             private_release_policy="observed-work-lead", private_release_work_lead=100,
                             private_release_max_wait_seconds=0.1))
        sim.start()
        sim.now = 0.5
        private = append_block(sim, "own", miner="q")
        sim.private_tip = private.block_id
        sim.private_wait_started = sim.now
        sim._maybe_adaptive_release("private-block")
        exact = Fraction(0.5) + Fraction(0.1)
        deadline = math.nextafter(0.6, math.inf)
        self.assertLess(Fraction(0.6), exact)
        self.assertGreaterEqual(Fraction(deadline), exact)
        self.assertEqual(sim.adaptive_next_check, deadline)
        sim.now = 0.6
        sim._maybe_adaptive_release("public-message")
        self.assertEqual(sim.adaptive_releases, 0)
        self.assertEqual(sim.adaptive_next_check, deadline)
        self.assertTrue(sim.step())
        self.assertEqual(sim.now, deadline)
        self.assertEqual(sim.adaptive_releases, 1)
        self.assertEqual(sim.last_published_private_tip, private.block_id)
        releases = [r for r in sim.trace if r["kind"] == "adaptive-release-check" and r["release"]]
        self.assertEqual([(r["timed_out"], r["at_seconds"]) for r in releases], [(True, deadline)])
        sim._maybe_adaptive_release("duplicate-timer")
        self.assertEqual(sim.adaptive_releases, 1)

    def test_fractional_timeout_stays_unpublished_before_deadline_horizon(self):
        sim = Simulator(idle(duration_seconds=0.6, probe_arrival_seconds=0,
                             quantum_strategy="private-branch", private_release_policy="observed-work-lead",
                             private_release_work_lead=100, private_release_max_wait_seconds=0.1))
        sim.start()
        self.assertTrue(sim.step())  # Observe the probe before advancing the controlled clock.
        sim.now = 0.5
        private = append_block(sim, "own", miner="q")
        sim.private_tip, sim.private_wait_started = private.block_id, sim.now
        sim._maybe_adaptive_release("private-block")
        summary, rows = sim.run()
        self.assertEqual(summary["termination"], "horizon")
        self.assertEqual(summary["observation_seconds"], 0.6)
        self.assertEqual(sim.adaptive_releases, 0)
        self.assertEqual(sim.adaptive_next_check, math.nextafter(0.6, math.inf))
        self.assertFalse(any(r["kind"] == "publish" for r in rows))

    def test_slow_quantum_resource_clocks_censor_at_finite_horizon(self):
        case = NetworkScenario("slow_physics", duration_seconds=10,
                               classical_block_rate_at_initial_target=0,
                               quantum_iteration_seconds=1e25, quantum_prepare_seconds=1e24,
                               quantum_measure_seconds=1e23, quantum_candidate_check_seconds=1e22)
        summary, rows = run_network_scenario(case)
        self.assertEqual(summary["termination"], "horizon")
        self.assertEqual(summary["miners"]["q"]["searches_censored"], 1)
        self.assertEqual(summary["miners"]["q"]["logical_iterations_completed"], 0)
        self.assertEqual(summary["miners"]["q"]["proofs_started"], 0)
        self.assertGreater(rows[0]["scheduled_finish_seconds"], 1e25)


if __name__ == "__main__":
    unittest.main(verbosity=2)
