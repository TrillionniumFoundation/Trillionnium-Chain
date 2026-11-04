"""Event and counterexample controls; no physical quantum qualification."""
from dataclasses import replace
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
