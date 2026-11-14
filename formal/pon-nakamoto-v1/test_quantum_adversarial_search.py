"""Independent small-state and optimization controls for conditional search."""
from dataclasses import replace
from fractions import Fraction
import itertools
import json
import math
from pathlib import Path
import tempfile
import unittest

from quantum_adversarial_search import (
    MAX_DOMAIN_SIZE, MAX_EXACT_BINOMIAL_SIZE, TrialCosts, batch_success,
    binomial_batch_success, binomial_weights, bounded_throughput_choice,
    finite_domain_success, sample_binary_probability, sample_marked_count,
)
from quantum_network_sim import NetworkScenario, run_network_scenario
from experiments.quantum_adversarial_campaign import (
    canonical, cases_for, check_native_periodic_arithmetic, digest, run_campaign, verify_campaign,
)
from experiments.quantum_network_campaign import check_trace_arithmetic, read_rows, write_rows


def exact_state_probability(size, marked_indices, iterations):
    """Rational amplitudes scaled by sqrt(size); explicit oracle + reflection."""
    amplitudes = [Fraction(1) for _ in range(size)]
    marked = set(marked_indices)
    for _ in range(iterations):
        amplitudes = [-a if i in marked else a for i, a in enumerate(amplitudes)]
        mean = sum(amplitudes) / size
        amplitudes = [2 * mean - a for a in amplitudes]
    return sum(amplitudes[i] ** 2 for i in marked) / size


def exact_two_amplitude_probability(p, iterations):
    """Repeated squaring of oracle/reflection on the two amplitude classes.

    Amplitudes are scaled by the uniform-state amplitude. This reference uses
    neither trigonometry nor a table of special periods. The tested rational
    fractions have bounded periodic entries, including at very large counts.
    """
    def product(left, right):
        return tuple(tuple(sum(left[i][k] * right[k][j] for k in range(2))
                           for j in range(2)) for i in range(2))

    operator = ((1 - 2 * p, 2 * (1 - p)), (-2 * p, 1 - 2 * p))
    total = ((Fraction(1), Fraction(0)), (Fraction(0), Fraction(1)))
    while iterations:
        if iterations & 1:
            total = product(operator, total)
        operator = product(operator, operator)
        iterations >>= 1
    marked_amplitude = sum(total[0])
    return p * marked_amplitude ** 2


class TicketWords:
    def __init__(self, values):
        self.values = iter(values)
        self.widths = []

    def getrandbits(self, width):
        self.widths.append(width)
        return next(self.values)


class RationalAngleControls(unittest.TestCase):
    def test_zero_iterations_preserve_the_input_fraction_exactly(self):
        for probability in (3 / 16, 5 / 16, math.nextafter(0.25, 0),
                            math.ldexp(3.0, -200), math.ldexp(1.0, -1074)):
            with self.subTest(probability=probability):
                self.assertEqual(batch_success(probability, 0), probability)

    def test_zero_iteration_parallel_measurements_match_positive_binomial_counts(self):
        # Count outcomes with at least one marked measurement directly. This
        # positive sum avoids both trigonometry and subtraction near one.
        for probability in (3 / 16, 5 / 16, math.ldexp(3.0, -200), math.ldexp(1.0, -1074)):
            marked, size = probability.as_integer_ratio()
            for processors in (1, 3, 64):
                accepted = sum(math.comb(processors, hits) * marked ** hits
                               * (size - marked) ** (processors - hits)
                               for hits in range(1, processors + 1))
                expected = float(Fraction(accepted, size ** processors))
                with self.subTest(probability=probability, processors=processors):
                    self.assertEqual(batch_success(probability, 0, processors), expected)
                if size == 16 and processors == 3:
                    literal_outcomes = sum(any(value < marked for value in row)
                                           for row in itertools.product(range(size), repeat=processors))
                    self.assertEqual(accepted, literal_outcomes)

    def test_two_class_reference_matches_full_small_state(self):
        for marked in (1, 2, 3):
            for iterations in range(18):
                self.assertEqual(exact_two_amplitude_probability(Fraction(marked, 4), iterations),
                                 exact_state_probability(4, range(marked), iterations))

    def test_special_fractions_and_parallel_batches_are_exact_at_large_counts(self):
        for marked in (1, 2, 3):
            p = Fraction(marked, 4)
            for iterations in (0, 1, 2, 3, 7, 16, 99_999_998, 99_999_999, 100_000_000):
                single = exact_two_amplitude_probability(p, iterations)
                for processors in (1, 2, 7, 53, 1024):
                    with self.subTest(p=p, iterations=iterations, processors=processors):
                        expected = float(1 - (1 - single) ** processors)
                        self.assertEqual(batch_success(float(p), iterations, processors), expected)
                        self.assertEqual(finite_domain_success(4, marked, iterations, processors), expected)

    def test_impossible_or_certain_measurements_do_not_draw_random_words(self):
        for iterations in (1, 100_000_000):
            for processors in (1, 1024):
                with self.subTest(iterations=iterations, processors=processors):
                    words = TicketWords([])
                    impossible = batch_success(0.75, iterations, processors)
                    certain = batch_success(0.25, iterations, processors)
                    self.assertEqual(impossible, 0.0)
                    self.assertEqual(certain, 1.0)
                    self.assertFalse(sample_binary_probability(words, impossible))
                    self.assertTrue(sample_binary_probability(words, certain))
                    self.assertEqual(words.widths, [])


class FiniteDomainControls(unittest.TestCase):
    def test_exact_amplitude_vectors_all_small_marked_counts(self):
        for size in (1, 2, 4, 8, 16):
            for marked in range(size + 1):
                for iterations in range(6):
                    expected = exact_state_probability(size, range(marked), iterations)
                    for processors in (1, 2, 4):
                        actual = finite_domain_success(size, marked, iterations, processors)
                        self.assertAlmostEqual(actual, float(1 - (1 - expected) ** processors), places=13)

    def test_exact_binomial_weights_and_no_solution_mass(self):
        p = Fraction(1, 16)
        weights = binomial_weights(16, p)
        self.assertEqual(sum(weights), 1)
        self.assertEqual(weights[0], Fraction(15, 16) ** 16)
        self.assertGreater(float(weights[0]), 0.35)
        self.assertLess(float(weights[0]), 0.36)
        self.assertEqual(sum(m * weight for m, weight in enumerate(weights)), 1)
        self.assertEqual(binomial_weights(4, Fraction(0)), (1, 0, 0, 0, 0))
        self.assertEqual(binomial_weights(4, Fraction(1)), (0, 0, 0, 0, 1))

    def test_enumerate_every_small_predicate_before_parallel_averaging(self):
        size, p, processors, iterations = 4, Fraction(1, 4), 3, 1
        total = Fraction(0)
        for bits in itertools.product((False, True), repeat=size):
            marked = [i for i, bit in enumerate(bits) if bit]
            single = exact_state_probability(size, marked, iterations)
            mass = p ** len(marked) * (1 - p) ** (size - len(marked))
            total += mass * (1 - (1 - single) ** processors)
        actual = binomial_batch_success(size, p, iterations, processors)
        self.assertAlmostEqual(actual, float(total), places=14)
        single_average = binomial_batch_success(size, p, iterations, 1)
        incorrectly_independent_domains = 1 - (1 - single_average) ** processors
        self.assertGreater(abs(actual - incorrectly_independent_domains), 0.1)
        # A shared zero-solution event remains impossible for every processor.
        self.assertLessEqual(actual, float(1 - (1 - p) ** size))

    def test_integer_ticket_sampler_uses_inclusive_boundary_once_per_domain(self):
        target = (1 << 200) + 17
        words = TicketWords([0, target, target + 1, (1 << 256) - 1])
        self.assertEqual(sample_marked_count(words, 4, target), 2)
        self.assertEqual(words.widths, [256] * 4)
        self.assertEqual(finite_domain_success(32, 0, 100_000_000, 1024), 0)
        self.assertEqual(finite_domain_success(32, 32, 100_000_000, 1024), 1)

    def test_domain_and_exact_binomial_limits_fail_explicitly(self):
        for args in ((0, 0, 1, 1), (4, 5, 1, 1), (4, True, 1, 1),
                     (MAX_DOMAIN_SIZE + 1, 1, 1, 1)):
            with self.assertRaises(ValueError):
                finite_domain_success(*args)
        with self.assertRaisesRegex(ValueError, "EXACT_BINOMIAL_SUPPORT"):
            binomial_weights(MAX_EXACT_BINOMIAL_SIZE + 1, Fraction(1, 16))
        with self.assertRaisesRegex(ValueError, "RATIONAL_PROBABILITY"):
            binomial_weights(4, 0.25)


class BoundedPolicyControls(unittest.TestCase):
    def setUp(self):
        self.costs = TrialCosts(0.02, 0.15, 0.01, 0.05, 1.0)

    def test_same_processor_budget_beats_first_peak(self):
        p = Fraction(1, 1_000_000)
        peak = round(math.pi / (4 * math.asin(math.sqrt(float(p)))) - 0.5)
        for processors, expected in ((1, 582), (4, 282), (16, 140)):
            choice = bounded_throughput_choice(p, tuple(range(peak + 1)), processors, self.costs)
            self.assertEqual(choice.iterations, expected)
            self.assertEqual(choice.processors, processors)
            self.assertFalse(choice.sampled_marked_count_used)
            self.assertFalse(choice.global_optimum_claimed)
            elapsed = 0.08 + 0.15 * expected
            single = math.sin((2 * expected + 1) * math.asin(math.sqrt(float(p)))) ** 2
            success = 1 - (1 - single) ** processors
            self.assertAlmostEqual(choice.measured_batch_seconds, elapsed)
            self.assertAlmostEqual(choice.processor_seconds_per_measured_batch, processors * elapsed)
            self.assertAlmostEqual(choice.expected_winners_per_second, success / (elapsed + success))
            peak_rate = batch_success(float(p), peak, processors) / (
                0.08 + 0.15 * peak + batch_success(float(p), peak, processors))
            self.assertGreater(choice.expected_winners_per_second, peak_rate)

    def test_independent_integer_grid_and_candidate_check_cost(self):
        candidates = tuple(range(64))
        p, processors = Fraction(1, 64), 4
        for check in (0.05, 10.0):
            costs = replace(self.costs, candidate_check_seconds=check)
            rates = []
            for k in candidates:
                single = math.sin((2 * k + 1) * math.asin(1 / 8)) ** 2
                success = 1 - (1 - single) ** processors
                elapsed = 0.02 + 0.15 * k + 0.01 + check
                rates.append(success / (elapsed + success))
            choice = bounded_throughput_choice(p, candidates, processors, costs)
            self.assertEqual(choice.iterations, max(candidates, key=lambda k: rates[k]))
            self.assertAlmostEqual(choice.expected_winners_per_second, max(rates))
        fast = bounded_throughput_choice(p, candidates, processors, self.costs)
        slow = bounded_throughput_choice(p, candidates, processors, replace(self.costs, candidate_check_seconds=10))
        self.assertNotEqual(fast.iterations, slow.iterations)

    def test_fresh_shared_domain_renewal_objective_includes_setup_and_single_proof(self):
        p, size, processors = Fraction(1, 16), 4, 3
        costs = replace(self.costs, domain_setup_seconds=2, proof_seconds=7)
        candidates = (0, 1, 2, 3)
        rates = []
        for k in candidates:
            success = Fraction(0)
            for bits in itertools.product((0, 1), repeat=size):
                marked = [i for i, bit in enumerate(bits) if bit]
                single = exact_state_probability(size, marked, k)
                success += p ** len(marked) * (1 - p) ** (size - len(marked)) * (1 - (1 - single) ** processors)
            duration = 2 + 0.02 + 0.15 * k + 0.01 + 0.05 + 7 * float(success)
            rates.append(float(success) / duration)
        choice = bounded_throughput_choice(p, candidates, processors, costs, finite_domain_size=size)
        self.assertEqual(choice.iterations, candidates[rates.index(max(rates))])
        self.assertAlmostEqual(choice.expected_winners_per_second, max(rates), places=14)

    def test_explicit_grid_and_zero_probability_tie_break(self):
        choice = bounded_throughput_choice(Fraction(0), (3, 8), 1, self.costs)
        self.assertEqual(choice.iterations, 3)
        self.assertEqual(choice.expected_winners_per_second, 0)
        self.assertEqual(choice.candidate_count, 2)
        for candidates in ((), (1, 0), (1, 1), (True,), (100_000_001,), tuple(range(4097))):
            with self.assertRaises(ValueError):
                bounded_throughput_choice(Fraction(1, 4), candidates, 1, self.costs)
        for patch in (dict(candidate_check_seconds=0), dict(measurement_seconds=float("nan")),
                      dict(iteration_seconds=-1), dict(prepare_seconds=True)):
            with self.assertRaises(ValueError):
                bounded_throughput_choice(Fraction(1, 4), (0, 1), 1, replace(self.costs, **patch))


class CampaignReadbackControls(unittest.TestCase):
    def test_integer_work_consistent_wrong_target_is_independently_rejected(self):
        case = NetworkScenario("native_target", duration_seconds=5,
                               classical_block_rate_at_initial_target=0, quantum_strategy="private-branch",
                               quantum_timestamp_mode="retarget-extremes", quantum_fixed_iterations=0,
                               quantum_prepare_seconds=0, quantum_measure_seconds=0.1,
                               quantum_candidate_check_seconds=0.1, quantum_proof_seconds=0,
                               quantum_domain_size=1, quantum_domain_marked_count=1)
        _, rows = run_network_scenario(case)
        result = check_native_periodic_arithmetic(rows, case)
        self.assertGreater(result["branch_retargets_checked"], 1)
        self.assertGreater(result["backward_adjacent_timestamps"], 0)
        index = next(i for i, row in enumerate(rows) if row["kind"] == "block")
        changed = [dict(row) for row in rows]
        target = int(changed[index]["target_hex"], 16)
        self.assertEqual((1 << 256) // (target + 1), (1 << 256) // (target + 2))
        changed[index]["target_hex"] = f"{target + 1:064x}"
        check_trace_arithmetic(changed)
        with self.assertRaisesRegex(ValueError, "NATIVE_REQUIRED_TARGET"):
            check_native_periodic_arithmetic(changed, case)

    def test_campaign_roundtrip_and_rehashed_forgery_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "observations"
            result = run_campaign(out, ["unittest"], seeds=(5101,), duration_seconds=10)
            self.assertEqual(result["runs"], 15)
            self.assertEqual(verify_campaign(out)["result"], "ADVERSARIAL_REPLAY_AND_NATIVE_ARITHMETIC_PASS")
            with self.assertRaises(FileExistsError):
                run_campaign(out, ["unittest"], seeds=(5101,), duration_seconds=10)
            original = (out / "report.json").read_bytes()
            original_manifest = (out / "manifest.json").read_bytes()

            def write_report(report):
                (out / "report.json").write_bytes(canonical(report))
                manifest = json.loads(original_manifest)
                manifest["files_sha256"]["report.json"] = digest(out / "report.json")
                (out / "manifest.json").write_bytes(canonical(manifest))

            report = json.loads(original)
            report["source"]["all_source_files_committed_at_head"] = not report["source"]["all_source_files_committed_at_head"]
            write_report(report)
            with self.assertRaisesRegex(ValueError, "SOURCE_COMMITMENT_CLAIM"):
                verify_campaign(out)
            report = json.loads(original)
            report["observations"][0]["parameters"]["quantum_processors"] = 8
            write_report(report)
            with self.assertRaisesRegex(ValueError, "SCENARIO_SUBSTITUTION"):
                verify_campaign(out)
            report = json.loads(original)
            report["bounded_search"]["global_attack_optimum_claimed"] = True
            write_report(report)
            with self.assertRaisesRegex(ValueError, "BOUNDED_SEARCH_SUBSTITUTION"):
                verify_campaign(out)
            report = json.loads(original)
            report["assumptions"]["security_theorem"] = True
            write_report(report)
            with self.assertRaisesRegex(ValueError, "ASSUMPTION_SUBSTITUTION"):
                verify_campaign(out)
            write_report(json.loads(original))
            record = next(r for r in json.loads(original)["observations"] if r["parameters"]["name"] == "finite_empty_persistent")
            trace = out / record["trace_file"]
            rows = read_rows(trace)
            domain = next(r for r in rows if r["kind"] == "quantum-domain")
            domain["marked_count"] = 1
            trace.unlink()
            write_rows(trace, rows)
            manifest = json.loads((out / "manifest.json").read_text())
            manifest["files_sha256"][record["trace_file"]] = digest(trace)
            (out / "manifest.json").write_bytes(canonical(manifest))
            with self.assertRaisesRegex(ValueError, "SEEDED_REPLAY_MISMATCH"):
                verify_campaign(out)

    def test_bounded_grid_rejects_unbounded_or_mixed_profile_claim(self):
        for seeds in ((), (1, 1), (True,), tuple(range(9))):
            with self.assertRaises(ValueError):
                cases_for(seeds)
        for duration in (float("nan"), float("inf"), 9, 3601, True):
            with self.assertRaises(ValueError):
                cases_for((1,), duration)
        with self.assertRaisesRegex(ValueError, "NATIVE_ARITHMETIC_PROFILE"):
            check_native_periodic_arithmetic([], NetworkScenario("asert", policy="asert-raw"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
