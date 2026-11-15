"""Exact resource-clock phase accounting; no physical or consensus qualification."""
from dataclasses import replace
from fractions import Fraction
import unittest

from quantum_network_sim import NetworkScenario, Simulator, run_network_scenario


def scenario(*, iterations=5, measure=.2, processors=1, **changes):
    case = NetworkScenario(
        "candidate_check_phase", duration_seconds=10,
        classical_block_rate_at_initial_target=0, quantum_clock_rounding="upward",
        quantum_fixed_iterations=iterations, quantum_prepare_seconds=.1,
        quantum_iteration_seconds=.1, quantum_measure_seconds=measure,
        quantum_candidate_check_seconds=1, quantum_processors=processors,
        quantum_domain_size=1, quantum_domain_marked_count=0,
        quantum_domain_setup_seconds=.1)
    return replace(case, **changes)


def candidate_start(case):
    return (Fraction(case.quantum_prepare_seconds)
            + Fraction(case.quantum_domain_setup_seconds)
            + case.quantum_fixed_iterations * Fraction(case.quantum_iteration_seconds)
            + Fraction(case.quantum_measure_seconds))


class CandidateCheckClockTests(unittest.TestCase):
    def test_cancel_before_exact_readout_end_does_not_invent_check(self):
        case = scenario()
        sim = Simulator(case)
        sim.start()
        sim.now = .9
        self.assertLess(Fraction(sim.now), candidate_start(case))
        sim._cancel("q", "shock")
        q = sim.counts["q"]
        self.assertEqual(q["candidate_checks_started"], 0)
        self.assertEqual(q["candidate_checks_cancelled"], 0)
        self.assertEqual(q["candidate_check_seconds"], 0)

    def test_cancel_after_exact_readout_end_retains_started_check(self):
        case = scenario(iterations=7, measure=.1, processors=3)
        sim = Simulator(case)
        sim.start()
        sim.now = 1.0000000000000002
        expected = Fraction(sim.now) - candidate_start(case)
        self.assertGreater(expected, 0)
        sim._cancel("q", "shock")
        q = sim.counts["q"]
        self.assertEqual(q["candidate_checks_started"], 3)
        self.assertEqual(q["candidate_checks_cancelled"], 3)
        self.assertEqual(q["candidate_checks_completed"], 0)
        self.assertEqual(q["candidate_check_seconds"], float(expected))
        self.assertEqual(q["candidate_check_processor_seconds"], float(expected) * 3)

    def test_horizon_after_readout_retains_censored_check(self):
        case = scenario(iterations=7, measure=.1, processors=3,
                        duration_seconds=1.0000000000000002, probe_arrival_seconds=0)
        summary, _ = run_network_scenario(case)
        q = summary["miners"]["q"]
        self.assertEqual(summary["termination"], "horizon")
        self.assertEqual(q["candidate_checks_started"], 3)
        self.assertEqual(q["candidate_checks_censored"], 3)
        self.assertEqual(q["candidate_checks_completed"], 0)
        self.assertEqual(q["proofs_started"], 0)
        self.assertFalse(summary["security_theorem"])
        self.assertFalse(summary["release_ready"])

    def test_exact_binary_phase_boundary_has_no_positive_elapsed_check(self):
        case = scenario(quantum_prepare_seconds=.125, quantum_domain_setup_seconds=.125,
                        quantum_iteration_seconds=.125, quantum_measure_seconds=.125)
        sim = Simulator(case)
        sim.start()
        sim.now = float(candidate_start(case))
        self.assertEqual(Fraction(sim.now), candidate_start(case))
        sim._cancel("q", "shock")
        self.assertEqual(sim.counts["q"]["candidate_checks_started"], 0)
        self.assertEqual(sim.counts["q"]["candidate_check_seconds"], 0)

    def test_nonzero_search_start_is_included_in_elapsed_accounting(self):
        case = scenario(iterations=7, measure=.1, processors=2)
        sim = Simulator(case)
        sim.now = .5
        sim.start()
        trial = sim.active["q"]
        sim.now = 1.5000000000000002
        expected = Fraction(sim.now) - Fraction(trial.started) - candidate_start(case)
        self.assertGreater(expected, 0)
        sim._cancel("q", "shock")
        self.assertEqual(sim.counts["q"]["candidate_checks_started"], 2)
        self.assertEqual(sim.counts["q"]["candidate_check_seconds"], float(expected))

    def test_completed_failed_trial_pays_full_check_for_every_processor(self):
        case = scenario(processors=3)
        sim = Simulator(case)
        sim.start()
        trial = sim.active["q"]
        sim.now = trial.finishes
        sim._search_done("q", trial.serial)
        q = sim.counts["q"]
        self.assertEqual(q["candidate_checks_started"], 3)
        self.assertEqual(q["candidate_checks_completed"], 3)
        self.assertEqual(q["candidate_check_seconds"], 1)
        self.assertEqual(q["candidate_check_processor_seconds"], 3)
        self.assertEqual(q["proofs_started"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
