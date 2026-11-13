"""Independent full-predicate controls for the conditional finite policy model."""
from copy import deepcopy
from dataclasses import replace
from fractions import Fraction as F
from functools import lru_cache
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from quantum_posterior_policy import (
    MAX_BUDGET, MAX_DOMAIN_SIZE, MAX_FRACTION_BITS, Model, ResourceCosts,
    after_failure, batch_success, binomial_prior, example_model, parse_request,
    read_json, recheck_report, solve,
)


def exact_state(size, marked, iterations):
    """Explicit N amplitudes; independent of the two-amplitude recurrence."""
    state = [F(1) for _ in range(size)]
    for _ in range(iterations):
        flipped = [-x if i in marked else x for i, x in enumerate(state)]
        average = sum(flipped, F(0))/size
        state = [2*average - x for x in flipped]
    assert sum(x*x for x in state) == size
    return sum((state[i]**2 for i in marked), F(0))/size


def number(value):
    return F(value["numerator"], value["denominator"])


def explicit_predicate_optimum(model):
    """Enumerate every small predicate and every admissible failure schedule.

    A count prior is spread uniformly over bitsets of that count. Evolution
    uses the full amplitude vector for each bitset, not production posterior or
    probability helpers. Search all legal actions, without the production
    unchanged-belief refresh optimization, then compare success and spend.
    """
    n = model.domain_size
    assert n <= 4
    predicates = tuple(frozenset(i for i, bit in enumerate(bits) if bit)
                       for bits in itertools.product((False, True), repeat=n))
    multiplicities = [sum(len(x) == m for x in predicates) for m in range(n + 1)]
    initial = tuple(model.marked_count_prior[len(x)]/multiplicities[len(x)]
                    for x in predicates)
    success = {
        q: tuple(1 - (1 - exact_state(n, marked, q))**model.processors
                 for marked in predicates)
        for q in model.iteration_choices
    }
    c = model.costs

    @lru_cache(maxsize=None)
    def walk(budget, masses):
        best = (F(0), F(0))
        for q in model.iteration_choices:
            charge = model.processors*(c.state_prepare + c.oracle_iteration*q
                                       + c.readout + c.candidate_check)
            if charge + c.winner_proof > budget:
                continue
            won = sum((mass*chance for mass, chance in zip(masses, success[q])), F(0))
            lost = 1 - won
            child = walk(budget - charge, tuple(
                mass*(1 - chance)/lost for mass, chance in zip(masses, success[q]))) if lost else (0, 0)
            candidate = (won + lost*child[0], charge + won*c.winner_proof + lost*child[1])
            if candidate[0] > best[0] or (candidate[0] == best[0] and candidate[1] < best[1]):
                best = candidate
        if model.allow_refresh and budget >= c.domain_setup:
            child = walk(budget - c.domain_setup, initial)
            candidate = (child[0], child[1] + c.domain_setup)
            if candidate[0] > best[0] or (candidate[0] == best[0] and candidate[1] < best[1]):
                best = candidate
        return best

    if model.budget_units < c.domain_setup:
        return F(0), F(0)
    chance, spent = walk(model.budget_units - c.domain_setup, initial)
    return chance, spent + c.domain_setup if chance else F(0)


class ExactProbabilityControls(unittest.TestCase):
    def test_all_small_predicates_match_explicit_amplitude_vectors(self):
        for n in range(1, 6):
            for bits in itertools.product((False, True), repeat=n):
                marked = {i for i, bit in enumerate(bits) if bit}
                for q in range(6):
                    explicit = exact_state(n, marked, q)
                    for processors in (1, 2, 3):
                        self.assertEqual(batch_success(n, len(marked), q, processors),
                                         1 - (1 - explicit)**processors)

    def test_binomial_prior_matches_full_predicate_enumeration(self):
        n, p = 4, F(1, 4)
        masses = [F(0) for _ in range(n + 1)]
        for bits in itertools.product((False, True), repeat=n):
            m = sum(bits)
            masses[m] += p**m*(1 - p)**(n - m)
        self.assertEqual(binomial_prior(n, p), tuple(masses))
        self.assertEqual(masses[0], F(81, 256))

    def test_failure_changes_optimal_next_observation(self):
        prior = binomial_prior(4, F(1, 4))
        successes = tuple(batch_success(4, m, 1) for m in range(5))
        update = after_failure(prior, successes)
        self.assertEqual(update.success_probability, F(17, 32))
        self.assertEqual(update.posterior, (F(27, 40), F(0), F(9, 40), F(1, 10), F(0)))
        repeat = after_failure(update.posterior, successes)
        no_iteration = after_failure(update.posterior, tuple(F(m, 4) for m in range(5)))
        self.assertEqual(repeat.success_probability, F(9, 80))
        self.assertEqual(no_iteration.success_probability, F(3, 16))
        self.assertGreater(no_iteration.success_probability, repeat.success_probability)

    def test_persistent_domain_is_not_replaced_by_fresh_independent_trials(self):
        prior = binomial_prior(4, F(1, 4))
        successes = tuple(batch_success(4, m, 1) for m in range(5))
        first = after_failure(prior, successes)
        second = after_failure(first.posterior, successes)
        persistent = first.success_probability + first.failure_probability*second.success_probability
        refreshed = 1 - first.failure_probability**2
        self.assertEqual(persistent, F(299, 512))
        self.assertEqual(refreshed, F(799, 1024))
        self.assertGreater(refreshed - persistent, F(19, 100))

    def test_processors_share_marked_count_before_prior_average(self):
        prior = binomial_prior(4, F(1, 4))
        single = after_failure(prior, tuple(batch_success(4, m, 1) for m in range(5)))
        shared = after_failure(prior, tuple(batch_success(4, m, 1, 3) for m in range(5)))
        wrong = 1 - (1 - single.success_probability)**3
        self.assertNotEqual(shared.success_probability, wrong)
        self.assertLessEqual(shared.success_probability, 1 - prior[0])

    def test_impossible_failure_has_no_invented_posterior(self):
        update = after_failure((F(0), F(1)), (F(0), F(1)))
        self.assertEqual(update.failure_probability, 0)
        self.assertIsNone(update.posterior)
        empty = after_failure((F(1), F(0)), (F(0), F(1)))
        self.assertEqual(empty.posterior, (F(1), F(0)))

    def test_non_normalized_non_exact_and_impossible_inputs_fail(self):
        for prior in ((F(0), F(0)), (F(-1), F(2)), (0, 1), [F(0), F(1)]):
            with self.assertRaises(ValueError):
                after_failure(prior, (F(0), F(1)))
        for values in ((0, 0, 1, 1), (4, 5, 1, 1), (4, True, 1, 1),
                       (4, 1, -1, 1), (4, 1, 1, 0), (MAX_DOMAIN_SIZE + 1, 0, 1, 1)):
            with self.assertRaises(ValueError):
                batch_success(*values)
        with self.assertRaisesRegex(ValueError, "EXACT_FRACTION_LIMIT"):
            binomial_prior(1, F(1, 1 << MAX_FRACTION_BITS))


class BudgetPolicyControls(unittest.TestCase):
    def test_dynamic_program_matches_independent_exhaustive_predicate_solver(self):
        for n, p in ((1, F(1, 2)), (3, F(1, 3)), (4, F(1, 4))):
            for refresh in (False, True):
                for budget in (3, 7, 11):
                    case = Model(n, binomial_prior(n, p), (0, 1, 2), 1, budget,
                                 ResourceCosts(1, 0, 1, 1, 1, 1), refresh)
                    report = solve(case)
                    expected = explicit_predicate_optimum(case)
                    self.assertEqual(number(report["optimal_delivered_probability"]), expected[0])
                    self.assertEqual(number(report["expected_budget_spent"]), expected[1])

    def test_known_persistent_policy_switches_after_failure(self):
        report = solve(example_model(allow_refresh=False))
        self.assertEqual(number(report["optimal_delivered_probability"]), F(11089, 16384))
        self.assertEqual(number(report["expected_budget_spent"]), F(97735, 8192))
        path = report["chosen_policy_all_failures_path"]
        self.assertEqual([row.get("iterations") for row in path[:-1]], [1, 0, 0, 0, 0])
        self.assertEqual(path[-1]["action"], "stop")
        self.assertEqual(number(path[1]["conditional_success_probability"]), F(3, 16))

    def test_paid_refresh_beats_persistent_for_declared_budget(self):
        case = example_model()
        report = solve(case)
        self.assertEqual(number(report["optimal_delivered_probability"]), F(29393, 32768))
        self.assertEqual(number(report["expected_budget_spent"]), F(195377, 16384))
        path = report["chosen_policy_all_failures_path"]
        self.assertEqual([row["action"] for row in path],
                         ["measure", "refresh", "measure", "refresh", "measure", "stop"])
        self.assertEqual([row["remaining_budget"] for row in path], [18, 14, 12, 8, 6, 2])
        self.assertGreater(number(report["optimal_delivered_probability"]),
                           number(solve(replace(case, allow_refresh=False))["optimal_delivered_probability"]))

    def test_refresh_cost_changes_policy_and_is_never_free(self):
        cheap = example_model()
        costly = replace(cheap, costs=replace(cheap.costs, domain_setup=10))
        report = solve(costly)
        self.assertFalse(any(row["action"] == "refresh"
                             for row in report["chosen_policy_all_failures_path"]))
        self.assertEqual(report["initial_setup_units_charged"], 10)
        self.assertLess(number(report["optimal_delivered_probability"]),
                        number(solve(cheap)["optimal_delivered_probability"]))
        with self.assertRaisesRegex(ValueError, "COST_DOMAIN_SETUP"):
            solve(replace(cheap, costs=replace(cheap.costs, domain_setup=0)))

    def test_zero_iterations_still_pays_every_processor_readout_and_check(self):
        costs = ResourceCosts(2, 1, 1, 2, 3, 4)
        case = Model(1, (F(0), F(1)), (0,), 2, 18, costs, False)
        report = solve(case)
        self.assertEqual(number(report["optimal_delivered_probability"]), 1)
        self.assertEqual(number(report["expected_budget_spent"]), 18)
        self.assertEqual(report["chosen_policy_all_failures_path"][0]["charged_units"], 12)
        short = solve(replace(case, budget_units=17))
        self.assertEqual(number(short["optimal_delivered_probability"]), 0)
        self.assertEqual(short["initial_action"], "stop")

    def test_proof_is_paid_on_success_only_and_not_reserved_on_failure(self):
        # M=0 or M=1 with probability 1/2. After a failed zero-query batch,
        # M=0 is certain and stopping is optimal. Only one branch pays proof.
        case = Model(1, (F(1, 2), F(1, 2)), (0,), 1, 10,
                     ResourceCosts(2, 1, 1, 1, 1, 4), False)
        report = solve(case)
        self.assertEqual(number(report["optimal_delivered_probability"]), F(1, 2))
        self.assertEqual(number(report["expected_budget_spent"]), F(2 + 3 + 2))
        self.assertEqual(report["chosen_policy_all_failures_path"][1]["remaining_budget"], 5)
        self.assertEqual(report["chosen_policy_all_failures_path"][1]["action"], "stop")

    def test_pathwise_probability_and_cost_reconstruct_independently(self):
        for refresh in (False, True):
            case = example_model(allow_refresh=refresh)
            report = solve(case)
            chance, spent = F(0), F(report["initial_setup_units_charged"])
            reach = F(1)
            available = case.budget_units - report["initial_setup_units_charged"]
            for row in report["chosen_policy_all_failures_path"]:
                self.assertEqual(number(row["reach_probability"]), reach)
                self.assertEqual(row["remaining_budget"], available)
                if row["action"] == "stop":
                    continue
                charge = row["charged_units"]
                available -= charge
                spent += reach*charge
                if row["action"] == "measure":
                    probability = number(row["conditional_success_probability"])
                    chance += reach*probability
                    spent += reach*probability*case.costs.winner_proof
                    self.assertGreaterEqual(available, case.costs.winner_proof)
                    reach *= 1 - probability
            self.assertEqual(chance, number(report["optimal_delivered_probability"]))
            self.assertEqual(spent, number(report["expected_budget_spent"]))
            self.assertLessEqual(spent, case.budget_units)

    def test_empty_domain_stops_without_wasting_initial_setup(self):
        case = replace(example_model(), marked_count_prior=(F(1), F(0), F(0), F(0), F(0)))
        report = solve(case)
        self.assertEqual(number(report["optimal_delivered_probability"]), 0)
        self.assertEqual(number(report["expected_budget_spent"]), 0)
        self.assertEqual(report["initial_setup_units_charged"], 0)
        self.assertEqual(report["chosen_policy_all_failures_path"], [])

    def test_budget_monotonicity_and_persistent_no_solution_ceiling(self):
        case = example_model(allow_refresh=False)
        previous = F(0)
        for budget in range(0, 23):
            report = solve(replace(case, budget_units=budget))
            chance = number(report["optimal_delivered_probability"])
            self.assertGreaterEqual(chance, previous)
            self.assertLessEqual(chance, 1 - case.marked_count_prior[0])
            previous = chance

    def test_state_and_input_limits_refuse_without_partial_success_report(self):
        with self.assertRaisesRegex(ValueError, "EXACT_POLICY_STATE_LIMIT"):
            solve(example_model(), max_states=1)
        for patch in (dict(budget_units=MAX_BUDGET + 1), dict(budget_units=True),
                      dict(iteration_choices=(1, 0)), dict(iteration_choices=(0, 0)),
                      dict(processors=0), dict(allow_refresh=1)):
            with self.assertRaises(ValueError):
                solve(replace(example_model(), **patch))
        for name in ("readout", "candidate_check", "oracle_iteration"):
            with self.assertRaises(ValueError):
                solve(replace(example_model(), costs=replace(example_model().costs, **{name: 0})))


class ReportAndCliControls(unittest.TestCase):
    def test_request_roundtrip_and_exact_report_recomputation(self):
        case = example_model()
        self.assertEqual(parse_request(case.request()), case)
        report = solve(case)
        self.assertEqual(recheck_report(case, deepcopy(report)), report)

    def test_probability_policy_source_scope_and_type_forgery_refused(self):
        case = example_model()
        report = solve(case)
        mutations = []
        bad = deepcopy(report)
        bad["optimal_delivered_probability"] = {"numerator": 1, "denominator": 1}
        mutations.append(bad)
        bad = deepcopy(report)
        bad["chosen_policy_all_failures_path"][0]["iterations"] = 0
        mutations.append(bad)
        bad = deepcopy(report)
        bad["source_binding"]["quantum_posterior_policy.py_sha256"] = "0"*64
        mutations.append(bad)
        for changed in (True, 0):
            bad = deepcopy(report)
            bad["scope"]["whole_chain_quantum_qualified"] = changed
            mutations.append(bad)
        bad = deepcopy(report)
        bad["request"]["processors"] = True
        mutations.append(bad)
        for bad in mutations:
            with self.assertRaisesRegex(ValueError, "POSTERIOR_REPORT_MISMATCH"):
                recheck_report(case, bad)

    def test_strict_json_and_canonical_fractions(self):
        case = example_model()
        for patch in (dict(extra_security_claim=True), dict(processors=True)):
            bad = case.request()
            bad.update(patch)
            with self.assertRaises(ValueError):
                parse_request(bad)
        bad = case.request()
        bad["marked_count_prior"][0] = {"numerator": 162, "denominator": 512}
        with self.assertRaisesRegex(ValueError, "CANONICAL_FRACTION"):
            parse_request(bad)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"input.json"
            for raw in ('{"x":1,"x":2}', '{"x":1.0}', '{"x":NaN}'):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    read_json(path)
            path.write_text('{"payload": "1234567890"}')
            with self.assertRaisesRegex(ValueError, "JSON_BYTE_LIMIT"):
                read_json(path, limit=4)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO control")
    def test_nonregular_input_refused_before_blocking_open(self):
        script = Path(__file__).with_name("quantum_posterior_policy.py")
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp)/"untrusted.json"
            os.mkfifo(fifo)
            result = subprocess.run([sys.executable, str(script), "--request", str(fifo)],
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("REGULAR_JSON_FILE_REQUIRED", result.stderr)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "no-follow source open")
    def test_symbolic_link_input_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            regular, link = Path(tmp)/"regular.json", Path(tmp)/"link.json"
            regular.write_text(json.dumps(example_model().request()))
            link.symlink_to(regular)
            with self.assertRaises(OSError):
                read_json(link)

    def test_cli_replay_and_qualification_refusal(self):
        script = Path(__file__).with_name("quantum_posterior_policy.py")
        with tempfile.TemporaryDirectory() as tmp:
            request, report_path = Path(tmp)/"request.json", Path(tmp)/"report.json"
            request.write_text(json.dumps(example_model().request()))
            first = subprocess.run([sys.executable, str(script), "--request", str(request)],
                                   text=True, capture_output=True, timeout=20)
            self.assertEqual(first.returncode, 0, first.stderr)
            report_path.write_text(first.stdout)
            repeated = subprocess.run([sys.executable, str(script), "--request", str(request),
                                       "--verify", str(report_path)],
                                      text=True, capture_output=True, timeout=20)
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertEqual(repeated.stdout, first.stdout)
            refused = subprocess.run([sys.executable, str(script), "--example", "--require-qualified"],
                                     text=True, capture_output=True, timeout=20)
            self.assertEqual(refused.returncode, 3)
            self.assertIn("REFUSED_UNPROVED_NATIVE_QUANTUM_SECURITY", refused.stderr)
            self.assertFalse(json.loads(refused.stdout)["scope"]["quantum_work_lower_bound_proved"])


if __name__ == "__main__":
    unittest.main()
