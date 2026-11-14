"""Event and counterexample controls; no physical quantum qualification."""
from dataclasses import replace
from fractions import Fraction
import json
import math
from pathlib import Path
import tempfile
import unittest

from quantum_network_sim import (
    ASSUMPTIONS, Block, NetworkScenario, ParticipationShock, Simulator, TimestampPhase, Trial, WORK_MAX,
    checked_chainwork, grover_success, run_network_scenario,
)
from experiments.quantum_network_campaign import (
    canonical, check_trace_arithmetic, digest, run_campaign, verify_campaign,
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

    def getrandbits(self, width):
        # Keep the existing controlled success/failure outcomes on the integer
        # sampler's valid [0, 2**width) support. This is not a PRNG model.
        point = Fraction(self.random()) * (1 << width)
        return min((1 << width) - 1, point.numerator // point.denominator)

    def expovariate(self, rate):
        self.rates.append(rate)
        return self.delay


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

    def test_explicit_marked_fraction_and_missing_physics(self):
        self.assertTrue(ASSUMPTIONS["marked_fraction_assumed_equal_uniform_ticket_probability"])
        self.assertIsNone(ASSUMPTIONS["actual_w1_marked_count"])
        for name in ("logical_qubits", "logical_gate_count", "logical_gate_depth",
                     "physical_error_rate", "error_correction_overhead"):
            self.assertIsNone(ASSUMPTIONS[name])
        self.assertFalse(ASSUMPTIONS["security_theorem"])


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
    def test_readback_replay_and_forged_qualification_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "campaign"
            result = run_campaign(out, ["unittest"], seeds=(4101,))
            self.assertEqual(result["runs"], 10)
            self.assertEqual(verify_campaign(out)["result"], "SEEDED_REPLAY_AND_INTEGER_READBACK_PASS")
            with self.assertRaises(FileExistsError):
                run_campaign(out, ["unittest"], seeds=(4101,))
            report = json.loads((out / "report.json").read_text())
            original = canonical(report)
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
