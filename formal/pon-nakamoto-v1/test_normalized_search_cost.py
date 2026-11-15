"""Exact probability/cost controls; these are not W1 hardness experiments."""
from copy import deepcopy
from fractions import Fraction as F
import json
from pathlib import Path
import tempfile
import unittest

import normalized_search_cost as N


C = N.SamplingKind.CLASSICAL
Q = N.SamplingKind.QUANTUM
OK = N.OutcomeKind.SUCCESS
FAIL = N.OutcomeKind.FAILURE
ABANDON = N.OutcomeKind.ABANDON
CONTRACT = "finite-marked-event-v1"


def distribution(p, kind=C, success_contract=CONTRACT):
    return N.NormalizedSearch(kind, (("win", p), ("lose", 1 - p)), frozenset({"win"}), success_contract)


def cost(amount, unit="resource_units"):
    return N.Cost(F(amount), unit)


def search_unit(kind, predicate, *, preparation=0, membership=0, phase=0, uncompute=0, other=0):
    return N.SearchUnitCosts(kind, cost(preparation), cost(predicate), cost(membership),
                             cost(phase), cost(uncompute), cost(other))


def premises():
    return N.RenewalPremises(True, True, True)


def outcome(name, kind, probability, attempt, restart=0):
    return N.AttemptOutcome(name, kind, probability, cost(attempt), cost(restart))


def basic_task(name="task", proof=11):
    return N.RenewalTask(name, (
        outcome("win", OK, F(1, 4), 8),
        outcome("failed", FAIL, F(1, 2), 4, 2),
        outcome("abandoned", ABANDON, F(1, 4), 2, 6),
    ), cost(proof), "one valid winner with guaranteed proof completion")


class NormalizedSearchTests(unittest.TestCase):
    def test_classical_and_quantum_masses_define_the_same_marked_overlap(self):
        for kind in (C, Q):
            measure = N.NormalizedSearch(kind, (
                ("heavy", F(3, 4)), ("light", F(1, 8)), ("other", F(1, 8)),
            ), frozenset({"heavy", "light"}), CONTRACT)
            self.assertEqual(measure.success_probability, F(7, 8))
            self.assertNotEqual(measure.success_probability, F(2, 3))

    def test_masses_require_exact_fractions_and_normalization(self):
        for bad in (0.5, 1, True, "1/2"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                N.NormalizedSearch(C, (("a", bad), ("b", F(1, 2))), frozenset({"a"}), CONTRACT)
        for masses in ((("a", F(1, 4)), ("b", F(1, 4))),
                       (("a", F(1)), ("b", F(1))),
                       (("a", F(-1, 2)), ("b", F(3, 2)))):
            with self.subTest(masses=masses), self.assertRaises(ValueError):
                N.NormalizedSearch(C, masses, frozenset({"a"}), CONTRACT)

    def test_invalid_domains_and_missing_marked_labels_are_rejected(self):
        for masses, marked in (((), frozenset()),
                               ((("a", F(1, 2)), ("a", F(1, 2))), frozenset()),
                               ((("a", F(1)),), frozenset({"absent"})),
                               ((("a", F(1)),), {"a"})):
            with self.subTest(masses=masses, marked=marked), self.assertRaises(ValueError):
                N.NormalizedSearch(C, masses, marked, CONTRACT)

    def test_uniform_retention_is_not_the_normalized_success_ratio(self):
        domain = tuple(str(x) for x in range(8))
        restriction = N.uniform_restriction(domain, frozenset({"0", "1", "2", "3"}),
                                             frozenset({"0", "4"}))
        self.assertEqual(restriction.raw_domain_retention, F(1, 4))
        self.assertEqual(restriction.marked_retention, F(1, 4))
        self.assertEqual(restriction.baseline.success_probability, F(1, 2))
        self.assertEqual(restriction.restricted.success_probability, F(1, 2))
        self.assertEqual(restriction.success_ratio, F(1))

    def test_retaining_only_winners_does_not_make_f_the_winner_retention(self):
        restriction = N.uniform_restriction(tuple(str(x) for x in range(8)),
                                             frozenset({"0", "1"}), frozenset({"0"}), kind=Q)
        self.assertEqual(restriction.raw_domain_retention, F(1, 8))
        self.assertEqual(restriction.marked_retention, F(1, 2))
        self.assertEqual(restriction.restricted.success_probability, F(1))
        self.assertEqual(restriction.success_ratio, F(4))
        self.assertIn("not free", restriction.report()["restriction_cost"])

    def test_no_winners_is_a_valid_measure_but_not_a_finite_win_cost(self):
        empty = distribution(F(0))
        self.assertEqual(empty.success_probability, F(0))
        restriction = N.uniform_restriction(("x",), frozenset(), frozenset({"x"}))
        self.assertIsNone(restriction.marked_retention)
        self.assertIsNone(restriction.success_ratio)
        for first, second in ((empty, distribution(F(1, 2))),
                              (distribution(F(1, 2)), empty)):
            with self.assertRaisesRegex(ValueError, "ZERO_SUCCESS"):
                N.ideal_shortcut_comparison(first, second, a_classical=F(1), a_quantum=F(1))

    def test_restriction_rejects_duplicate_empty_and_foreign_subsets(self):
        for domain, retained in ((("a", "a"), frozenset({"a"})),
                                 (("a",), frozenset()),
                                 (("a",), frozenset({"outside"}))):
            with self.subTest(domain=domain, retained=retained), self.assertRaises(ValueError):
                N.uniform_restriction(domain, frozenset(), retained)

    def test_direct_restriction_constructor_cannot_disguise_a_nonuniform_measure(self):
        with self.assertRaisesRegex(ValueError, "UNIFORM_MASSES"):
            N.UniformRestriction(distribution(F(3, 4)), distribution(F(1, 2)))
        with self.assertRaisesRegex(ValueError, "INCONSISTENT"):
            N.UniformRestriction(distribution(F(1, 2)),
                                 N.NormalizedSearch(C, (("foreign", F(1)),), frozenset(), CONTRACT))

    def test_success_contract_is_required_validated_and_retained(self):
        self.assertEqual(distribution(F(1, 2)).report()["success_contract"], CONTRACT)
        for bad in ("", " ", True, None):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "SUCCESS_CONTRACT"):
                N.NormalizedSearch(C, (("a", F(1)),), frozenset({"a"}), bad)
        with self.assertRaises(TypeError):
            N.NormalizedSearch(C, (("a", F(1)),), frozenset({"a"}))

    def test_uniform_helper_preserves_explicit_contract_and_rejects_direct_mismatch(self):
        result = N.uniform_restriction(("a", "b"), frozenset({"a"}), frozenset({"a"}),
                                      success_contract="valid-complete-proof-v1")
        self.assertEqual(result.report()["success_contract"], "valid-complete-proof-v1")
        with self.assertRaisesRegex(ValueError, "SUCCESS_CONTRACT_MISMATCH"):
            N.UniformRestriction(distribution(F(1, 2)),
                                 distribution(F(1, 2), success_contract="precheck-only-v1"))


class IdealShortcutTests(unittest.TestCase):
    def test_user_counterexample_is_exact(self):
        result = N.ideal_shortcut_comparison(distribution(F(1, 4)), distribution(F(1, 16)),
                                             a_classical=F(2, 5), a_quantum=F(2, 5))
        self.assertEqual(result.success_ratio, F(1, 4))
        self.assertEqual(result.classical_relative_cost, F(8, 5))
        self.assertEqual(result.quantum_relative_cost, F(4, 5))
        self.assertGreater(result.classical_relative_cost, 1)
        self.assertLess(result.quantum_relative_cost, 1)

    def test_only_exact_square_roots_are_accepted(self):
        self.assertEqual(N.exact_square_root(F(4, 9)), F(2, 3))
        with self.assertRaisesRegex(ValueError, "IRRATIONAL"):
            N.ideal_shortcut_comparison(distribution(F(1, 2)), distribution(F(1, 4)),
                                        a_classical=F(1), a_quantum=F(1))
        for bad in (0.25, True, -1, F(-1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                N.exact_square_root(bad)

    def test_zero_cost_and_nonfraction_cost_ratios_are_rejected(self):
        for bad in (F(0), F(-1), 0.4, 1, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                N.ideal_shortcut_comparison(distribution(F(1, 2)), distribution(F(1, 8)),
                                            a_classical=bad, a_quantum=F(1))

    def test_direct_result_constructor_keeps_exact_model_guards(self):
        for values in ((F(1, 4), 0.0625, F(2, 5), F(2, 5)),
                       (F(0), F(1, 16), F(2, 5), F(2, 5)),
                       (F(1, 4), F(1, 16), F(0), F(2, 5)),
                       (F(1, 4), F(1, 8), F(1), F(1))):
            with self.subTest(values=values), self.assertRaises(ValueError):
                N.IdealShortcutComparison(*values, CONTRACT, CONTRACT)

    def test_cost_comparison_rejects_different_successful_events(self):
        baseline = distribution(F(1, 4))
        shortcut = distribution(F(1, 16), success_contract="only-cheap-precheck-v1")
        with self.assertRaisesRegex(ValueError, "SUCCESS_CONTRACT_MISMATCH"):
            N.ideal_shortcut_comparison(baseline, shortcut, a_classical=F(2, 5), a_quantum=F(2, 5))
        with self.assertRaisesRegex(ValueError, "SUCCESS_CONTRACT_MISMATCH"):
            N.compare_complete_search_units(
                baseline, shortcut, classical_baseline=search_unit(C, 10),
                classical_shortcut=search_unit(C, 4), quantum_baseline=search_unit(Q, 10),
                quantum_shortcut=search_unit(Q, 4))
        with self.assertRaisesRegex(ValueError, "SUCCESS_CONTRACT_MISMATCH"):
            N.IdealShortcutComparison(F(1, 4), F(1, 16), F(2, 5), F(2, 5),
                                       CONTRACT, "only-cheap-precheck-v1")
        with self.assertRaisesRegex(ValueError, "SUCCESS_CONTRACT"):
            N.IdealShortcutComparison(F(1, 4), F(1, 16), F(2, 5), F(2, 5), "", "")

    def test_preparation_and_uncomputation_can_reverse_apparent_advantage(self):
        baseline, shortcut = distribution(F(1, 4)), distribution(F(1, 16))
        kwargs = dict(classical_baseline=search_unit(C, 10), classical_shortcut=search_unit(C, 4),
                      quantum_baseline=search_unit(Q, 4, preparation=2, uncompute=4))
        omitted = N.compare_complete_search_units(
            baseline, shortcut, quantum_shortcut=search_unit(Q, 4), **kwargs)
        included = N.compare_complete_search_units(
            baseline, shortcut, quantum_shortcut=search_unit(Q, 4, preparation=1, uncompute=1), **kwargs)
        self.assertEqual(omitted.quantum_relative_cost, F(4, 5))
        self.assertEqual(included.quantum_relative_cost, F(6, 5))
        self.assertGreater(included.quantum_relative_cost, 1)

    def test_cost_units_and_categories_cannot_be_mixed(self):
        with self.assertRaisesRegex(ValueError, "MIXED_COST_UNITS"):
            N.SearchUnitCosts(Q, cost(0), cost(1, "seconds"), cost(0), cost(0), cost(1), cost(0))
        with self.assertRaisesRegex(ValueError, "SEARCH_UNIT_CATEGORY"):
            N.compare_complete_search_units(
                distribution(F(1, 2)), distribution(F(1, 8)),
                classical_baseline=search_unit(Q, 1), classical_shortcut=search_unit(C, 1),
                quantum_baseline=search_unit(Q, 1), quantum_shortcut=search_unit(Q, 1))

    def test_endpoint_is_explicitly_only_an_ideal_scaling_comparison(self):
        result = N.ideal_shortcut_comparison(distribution(F(1)), distribution(F(1, 4)),
                                             a_classical=F(1), a_quantum=F(1))
        self.assertEqual(result.quantum_relative_cost, F(2))
        self.assertTrue(any("endpoint" in line for line in result.report()["assumptions"]))


class StationaryRenewalTests(unittest.TestCase):
    def test_failure_abandon_and_restart_costs_are_all_unconditional(self):
        task = basic_task()
        result = N.stationary_renewal_cost(task, preparation=cost(7), premises=premises())
        # E[C] = 1/4*8 + 1/2*(4+2) + 1/4*(2+6) = 7; q=1/4.
        self.assertEqual(task.expected_attempt_cost.amount, F(7))
        self.assertEqual(task.repeated_cost_until_success.amount, F(28))
        self.assertEqual(result.total.amount, F(46))
        counts = {o["name"]: o["expected_occurrences_until_success"] for o in task.report()["outcomes"]}
        self.assertEqual(counts["failed"], {"numerator": 2, "denominator": 1})
        self.assertEqual(counts["abandoned"], {"numerator": 1, "denominator": 1})

    def test_increasing_failure_cost_changes_win_cost_without_changing_q(self):
        cheap = N.RenewalTask("a", (outcome("win", OK, F(1, 4), 4),
                                   outcome("fail", FAIL, F(3, 4), 2)), cost(0), "winner")
        costly = N.RenewalTask("b", (outcome("win", OK, F(1, 4), 4),
                                    outcome("fail", FAIL, F(3, 4), 6)), cost(0), "winner")
        self.assertEqual(cheap.success_probability, costly.success_probability)
        self.assertEqual(costly.repeated_cost_until_success.amount - cheap.repeated_cost_until_success.amount,
                         F(12))

    def test_post_win_proof_is_paid_once_not_per_attempt(self):
        with_proof = N.stationary_renewal_cost(basic_task(proof=11), preparation=cost(7), premises=premises())
        no_proof = N.stationary_renewal_cost(basic_task(proof=0), preparation=cost(7), premises=premises())
        self.assertEqual(with_proof.total.amount - no_proof.total.amount, F(11))
        self.assertEqual(with_proof.tasks[0].expected_attempt_cost, no_proof.tasks[0].expected_attempt_cost)
        self.assertNotEqual(with_proof.total.amount - no_proof.total.amount, F(44))

    def test_shared_preparation_is_paid_once_for_multiple_tasks(self):
        tasks = (basic_task("first"), basic_task("second"))
        shared = N.stationary_shared_campaign_cost(tasks, preparation=cost(7), premises=premises())
        two_cold = sum((N.stationary_renewal_cost(t, preparation=cost(7), premises=premises()).total.amount
                        for t in tasks), F(0))
        self.assertEqual(shared.total.amount, F(85))
        self.assertEqual(two_cold, F(92))
        self.assertEqual(shared.report()["preparation_charge_count"], 1)
        self.assertFalse(shared.report()["composition_lower_bound_proved"])

    def test_certain_success_has_one_attempt_and_no_restart(self):
        task = N.RenewalTask("certain", (outcome("win", OK, F(1), 5),), cost(3), "winner")
        result = N.stationary_renewal_cost(task, preparation=cost(2), premises=premises())
        self.assertEqual(result.total.amount, F(10))
        self.assertEqual(task.report()["expected_attempts"], {"numerator": 1, "denominator": 1})

    def test_q_zero_is_rejected_not_infinity_or_pass(self):
        with self.assertRaisesRegex(ValueError, "ZERO_SUCCESS"):
            N.RenewalTask("impossible", (outcome("fail", FAIL, F(1), 2, 3),), cost(4), "winner")

    def test_outcomes_must_be_a_normalized_distinct_partition(self):
        for outcomes in (
            (outcome("a", OK, F(1, 4), 2), outcome("b", FAIL, F(1, 4), 2)),
            (outcome("a", OK, F(3, 4), 2), outcome("b", FAIL, F(3, 4), 2)),
            (outcome("same", OK, F(1, 2), 2), outcome("same", FAIL, F(1, 2), 2)),
        ):
            with self.subTest(outcomes=outcomes), self.assertRaises(ValueError):
                N.RenewalTask("bad", outcomes, cost(0), "winner")

    def test_positive_probability_attempts_cannot_be_free(self):
        for kind in (OK, FAIL, ABANDON):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "ATTEMPT_COST"):
                outcome("free", kind, F(1), 0)

    def test_success_cannot_also_restart(self):
        with self.assertRaisesRegex(ValueError, "SUCCESS_CANNOT_RESTART"):
            outcome("contradiction", OK, F(1), 2, 3)

    def test_same_unit_required_across_attempts_proof_and_preparation(self):
        with self.assertRaisesRegex(ValueError, "MIXED_COST_UNITS"):
            N.AttemptOutcome("fail", FAIL, F(1, 2), cost(1, "seconds"), cost(1, "joules"))
        with self.assertRaisesRegex(ValueError, "MIXED_COST_UNITS"):
            N.RenewalTask("mixed", basic_task().outcomes, cost(5, "seconds"), "winner")
        with self.assertRaisesRegex(ValueError, "MIXED_COST_UNITS"):
            N.stationary_renewal_cost(basic_task(), preparation=cost(5, "seconds"), premises=premises())

    def test_history_state_or_interruptions_are_outside_this_formula(self):
        for flags in ((False, True, True), (True, False, True), (True, True, False), (1, True, True)):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "OUTSIDE_STATIONARY"):
                N.RenewalPremises(*flags)
        with self.assertRaisesRegex(ValueError, "EXPLICIT_RENEWAL"):
            N.stationary_renewal_cost(basic_task(), preparation=cost(1), premises=None)

    def test_costs_and_probabilities_reject_floats_bools_and_negative_values(self):
        for bad in (1.5, 1, True, "1", F(-1)):
            with self.subTest(cost=bad), self.assertRaises(ValueError):
                N.Cost(bad, "units")
        for bad in (0.5, 1, True, F(-1), F(3, 2)):
            with self.subTest(probability=bad), self.assertRaises(ValueError):
                N.AttemptOutcome("bad", OK, bad, cost(1), cost(0))

    def test_duplicate_task_ids_cannot_duplicate_expected_work(self):
        with self.assertRaisesRegex(ValueError, "DUPLICATE_TASK_NAME"):
            N.stationary_shared_campaign_cost((basic_task(), basic_task()),
                                              preparation=cost(7), premises=premises())

    def test_success_event_is_explicit_and_retained(self):
        task = basic_task()
        self.assertEqual(task.report()["success_event"], task.success_event)
        with self.assertRaisesRegex(ValueError, "SUCCESS_EVENT"):
            N.RenewalTask("missing", task.outcomes, cost(2), "")

    def test_reports_never_claim_w1_attack_or_resource_lower_bound(self):
        reports = (
            distribution(F(1, 4), Q).report(),
            N.uniform_restriction(("a", "b"), frozenset({"a"}), frozenset({"a"})).report(),
            N.ideal_shortcut_comparison(distribution(F(1, 4)), distribution(F(1, 16)),
                                        a_classical=F(2, 5), a_quantum=F(2, 5)).report(),
            basic_task().report(),
            N.stationary_renewal_cost(basic_task(), preparation=cost(7), premises=premises()).report(),
        )
        for report in reports:
            with self.subTest(model=report.get("model")):
                json.dumps(report, allow_nan=False)
                self.assertEqual(report["schema"], N.SCHEMA)
                for field in ("w1_quantum_attack_implemented", "quantum_state_preparation_implemented",
                              "global_cost_lower_bound_proved", "composition_lower_bound_proved",
                              "network_security_proved", "consensus_activation", "release_ready"):
                    self.assertIs(report[field], False)


class BoundedReportTests(unittest.TestCase):
    def test_fraction_input_and_accumulation_caps_apply_to_direct_apis(self):
        too_large = F(1 << N.MAX_FRACTION_BITS)
        too_precise = F(1, 1 << N.MAX_FRACTION_BITS)
        for construct in (
            lambda: N.Cost(too_large, "units"),
            lambda: distribution(too_precise),
            lambda: N.exact_square_root(too_large),
            lambda: N.AttemptOutcome("tiny", OK, too_precise, cost(1), cost(0)),
            lambda: N.IdealShortcutComparison(F(1, 4), F(1, 16), too_large, F(1), CONTRACT, CONTRACT),
        ):
            with self.subTest(construct=construct), self.assertRaisesRegex(ValueError, "FRACTION_BIT_LIMIT"):
                construct()
        boundary = F(1 << (N.MAX_FRACTION_BITS - 1))
        self.assertEqual(N.Cost(boundary, "units").amount, boundary)
        self.assertEqual(distribution(1 / boundary).success_probability, 1 / boundary)
        with self.assertRaisesRegex(ValueError, "FRACTION_BIT_LIMIT"):
            search_unit(Q, boundary, preparation=boundary)

    def test_fixed_report_is_deterministic_and_survives_saved_json_replay(self):
        first, second = N.build_report(), N.build_report()
        self.assertEqual(first, second)
        self.assertEqual(len(first["cases"]), 4)
        self.assertEqual(len(first["source_binding"]), 2)
        self.assertEqual(first["diagnostic_bounds"]["max_fraction_bits"], N.MAX_FRACTION_BITS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "normalized-search.json"
            path.write_text(json.dumps(first, sort_keys=True), encoding="utf-8")
            verification = N.verify_report(N.load_json(path))
        self.assertEqual(verification["verification"], "PASS")
        self.assertEqual(len(verification["case_ids"]), 4)
        self.assertFalse(verification["scope"]["global_cost_lower_bound_proved"])

    def test_report_recompute_rejects_flags_costs_contracts_source_and_type_changes(self):
        def mutate_flag(report):
            report["scope"]["global_cost_lower_bound_proved"] = True

        def mutate_false_to_integer(report):
            report["scope"]["w1_quantum_attack_implemented"] = 0

        def mutate_cost(report):
            report["cases"][1]["result"]["quantum_relative_cost"]["numerator"] = 3

        def mutate_contract(report):
            report["cases"][1]["input"]["shortcut"]["success_contract"] = "weaker-event-v1"

        def mutate_source(report):
            report["source_binding"][0]["sha256"] = "0" * 64

        def remove_case(report):
            report["cases"].pop()

        def mutate_nested_flag(report):
            report["cases"][3]["result"]["shared_campaign"]["network_security_proved"] = True

        original = N.build_report()
        for mutation in (mutate_flag, mutate_false_to_integer, mutate_cost, mutate_contract,
                         mutate_source, remove_case, mutate_nested_flag):
            modified = deepcopy(original)
            mutation(modified)
            with self.subTest(mutation=mutation.__name__), self.assertRaisesRegex(ValueError, "REPORT_"):
                N.verify_report(modified)

    def test_json_reader_rejects_duplicate_keys_floats_large_numbers_and_oversize(self):
        bad_documents = (
            '{"scope":{},"scope":{}}',
            '{"number":0.5}',
            '{"number":NaN}',
            '{"number":' + str(1 << N.MAX_FRACTION_BITS) + '}',
            ' ' * (N.MAX_JSON_BYTES + 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            for raw in bad_documents:
                path.write_text(raw, encoding="utf-8")
                with self.subTest(prefix=raw[:40]), self.assertRaises(ValueError):
                    N.load_json(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
