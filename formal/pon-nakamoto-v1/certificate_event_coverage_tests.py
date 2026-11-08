"""Adversarial EC1 tests over complete finite Execution records, not hardware."""
from __future__ import annotations

import copy
from dataclasses import replace
from fractions import Fraction as F
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import certificate_event_coverage as ec
import certificate_observability_models as co
import native_execution_certificate as native


class CompleteEventCoverageTests(unittest.TestCase):
    def setUp(self):
        self.law, self.cases = ec.two_confirmation_fixture()
        self.catalogue = ec.derive_event_catalogue(self.law, self.cases)
        self.allocations = ec.allocations_from_catalogue(self.catalogue)

    def test_automatically_derived_union_covers_both_sequential_confirmation_events(self):
        self.assertTrue(all(not case.document["comparisons"] for case in self.cases.values()))
        self.assertEqual(self.catalogue["derived_start_count"], 3)
        self.assertEqual(self.catalogue["derived_comparison_count"], 32)
        self.assertEqual(self.catalogue["failure_union_probability"], F(31, 256))
        checked = ec.check_event_coverage(self.law, self.cases, self.allocations, F(1, 8))
        bank = checked["same_joint_law_risk_bank"]
        self.assertEqual(bank["maximum_path_allowance_spent"], F(1, 8))
        self.assertEqual(bank["expected_allowance_spent"], F(1, 8))
        self.assertEqual(bank["failure_union_probability"], F(31, 256))
        self.assertTrue(checked["finite_declared_execution_event_coverage_verified"])
        for row in self.catalogue["starts"]:
            self.assertEqual(row["conditional_failure_probability"], F(1, 16))

    def test_old_bank_can_bound_the_first_event_while_omitting_the_second(self):
        first = tuple(a for a in self.allocations if a.start_history == ())
        old = co.check_predictable_risk_bank(self.law, tuple(
            co.Attempt(a.start_id, a.start_history, a.failure_leaves, a.allowance) for a in first), F(1, 16))
        self.assertEqual(old["failure_union_probability"], F(1, 16))
        self.assertGreater(self.catalogue["failure_union_probability"], old["failure_union_probability"])
        with self.assertRaisesRegex(ec.EventCoverageError, "CONFIRMATION_START_COVERAGE_MISMATCH"):
            ec.check_event_coverage(self.law, self.cases, first, F(1, 16))

    def test_omitting_a_failing_leaf_is_not_accepted_even_with_a_large_budget(self):
        original = next(a for a in self.allocations if not a.start_history)
        bad = replace(original, failure_leaves=original.failure_leaves[1:])
        allocations = tuple(bad if a.start_id == original.start_id else a for a in self.allocations)
        with self.assertRaisesRegex(ec.EventCoverageError, "FAILURE_EVENT_COVERAGE_MISMATCH"):
            ec.check_event_coverage(self.law, self.cases, allocations, F(1))

    def test_adding_a_nonfailing_leaf_is_also_a_mismatched_event(self):
        original = next(a for a in self.allocations if not a.start_history)
        missing = next(name for name in self.law.leaves if name not in original.failure_leaves)
        bad = replace(original, failure_leaves=original.failure_leaves + (missing,))
        allocations = tuple(bad if a.start_id == original.start_id else a for a in self.allocations)
        with self.assertRaisesRegex(ec.EventCoverageError, "FAILURE_EVENT_COVERAGE_MISMATCH"):
            ec.check_event_coverage(self.law, self.cases, allocations, F(1))

    def test_late_start_cannot_replace_the_original_confirmation_origin(self):
        original = next(a for a in self.allocations if not a.start_history)
        bad = replace(original, start_history=("first_hit",))
        allocations = tuple(bad if a.start_id == original.start_id else a for a in self.allocations)
        with self.assertRaisesRegex(ec.EventCoverageError, "START_HISTORY_MISMATCH"):
            ec.check_event_coverage(self.law, self.cases, allocations, F(1))

    def test_forging_future_history_labels_before_the_same_confirmation_is_refused(self):
        leaves, cases = [], {}
        for name, leaf in self.law.leaves.items():
            old = self.cases[name]
            cut1, cut2, end = old.history_cuts
            # The new first label reveals the future first outcome, although
            # every record through the first confirmation is still identical.
            path = ("unobserved_" + leaf.path[0],) + leaf.path
            leaves.append(co.Leaf(name, path, leaf.probability))
            cases[name] = ec.LeafExecution(old.document, (cut1 - 1, cut1, cut2, end))
        with self.assertRaisesRegex(ec.EventCoverageError, "HISTORY_SPLIT_NOT_OBSERVED"):
            ec.derive_event_catalogue(co.ProbabilityTree(tuple(leaves)), cases)

    def test_a_child_that_is_only_a_shorter_cut_of_another_is_not_a_record_split(self):
        # Both cases share their complete first-confirmation prefix.  Calling
        # the shorter one a separate outcome does not reveal a random event.
        chosen = [self.law.leaves["first_hit_second_miss"], self.law.leaves["first_hit_second_hit"]]
        leaves, cases = [], {}
        for index, leaf in enumerate(chosen):
            case = self.cases[leaf.name]
            cut1, cut2, end = case.history_cuts
            if index == 0:
                path, cuts = ("short", "later", "end"), (cut1 - 1, cut1, cut2, end)
            else:
                path, cuts = ("long", "end"), (cut1 - 1, cut2, end)
            leaves.append(co.Leaf(leaf.name, path, F(1, 2)))
            cases[leaf.name] = ec.LeafExecution(case.document, cuts)
        with self.assertRaisesRegex(ec.EventCoverageError, "HISTORY_SPLIT_NOT_OBSERVED"):
            ec.derive_event_catalogue(co.ProbabilityTree(tuple(leaves)), cases)

    def test_missing_confirmation_boundary_does_not_silently_move_its_origin(self):
        cases = {name: replace(case, history_cuts=(case.history_cuts[0] - 1,) + case.history_cuts[1:])
                 for name, case in self.cases.items()}
        with self.assertRaisesRegex(ec.EventCoverageError, "CONFIRMATION_HISTORY_BOUNDARY_MISSING"):
            ec.derive_event_catalogue(self.law, cases)

    def test_same_history_cell_requires_identical_actual_record_prefixes(self):
        cases = copy.deepcopy(self.cases)
        case = next(iter(cases.values()))
        # Header timestamps do not change this finite model's validity, but
        # this early descriptor is already part of the common record prefix.
        case.document["blocks"][0]["header_timestamp"] = 2
        with self.assertRaisesRegex(ec.EventCoverageError, "HISTORY_CELL_RECORD_PREFIX_MISMATCH"):
            ec.derive_event_catalogue(self.law, cases)

    def test_future_catalogue_entries_do_not_reveal_outcomes_before_they_are_used(self):
        first_cuts = {row["record_prefix_sha256"] for row in self.catalogue["starts"] if not row["start_history"]}
        self.assertEqual(len(first_cuts), 1)
        first_rival_weights = {next(block["weight"] for block in case.document["blocks"]
                                   if block["id"] == "first_rival") for case in self.cases.values()}
        self.assertEqual(first_rival_weights, {6, 8})

    def test_missing_or_extra_probability_leaf_execution_is_refused(self):
        for extra in (False, True):
            cases = dict(self.cases)
            if extra:
                cases["not_in_law"] = next(iter(cases.values()))
            else:
                cases.pop(next(iter(cases)))
            with self.subTest(extra=extra), self.assertRaisesRegex(
                    ec.EventCoverageError, "LEAF_EXECUTION_COVERAGE_MISMATCH"):
                ec.derive_event_catalogue(self.law, cases)

    def test_raw_execution_is_replayed_instead_of_accepting_a_verified_result(self):
        cases = dict(self.cases)
        name = next(iter(cases))
        cases[name] = ec.LeafExecution({"verified": True, "events_checked": 999}, (0, 1, 2))
        with self.assertRaisesRegex(native.CertificateError, "CERTIFICATE_FIELDS"):
            ec.derive_event_catalogue(self.law, cases)
        cases = copy.deepcopy(self.cases)
        cases[name].document["events"][28]["claim_confirmed"] = False
        with self.assertRaisesRegex(native.CertificateError, "CONFIRMATION_CLAIM_MISMATCH"):
            ec.derive_event_catalogue(self.law, cases)

    def test_transient_removal_restored_before_next_observation_is_still_covered(self):
        leaves, cases = [], {}
        for hit in (False, True):
            model = native.ModelBuilder("ec1_transient_removal")
            model.base()
            start = len(model.events)
            rival = model.block("transient", "g", 8 if hit else 6, "A")
            model.ready(8, rival)
            model.available(8, rival)
            model.select(8, rival)
            restored = model.block("restored", "a7", 2, "A")
            model.ready(9, restored)
            model.available(9, restored)
            model.select(9, restored)
            model.observe(10, "end")
            model.compare("end")
            doc = model.document()
            self.assertEqual(native.Execution(doc).report()["comparisons"][0]["outcome"],
                             "no_prefix_failure_in_this_pair")
            name = "hit" if hit else "miss"
            leaves.append(co.Leaf(name, (name,), F(1, 16) if hit else F(15, 16)))
            cases[name] = ec.LeafExecution(doc, (start, len(model.events)))
        catalogue = ec.derive_event_catalogue(co.ProbabilityTree(tuple(leaves)), cases)
        self.assertEqual(catalogue["failure_union_probability"], F(1, 16))
        failures = [comparison for comparison in catalogue["starts"][0]["comparisons"]["hit"]
                    if comparison["result"]["outcome"] == "prefix_failure_with_paid_deficit_witness"]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["later_view_kind"], "replayed_selection_cut")

    def test_incomplete_declared_execution_and_terminal_truncation_are_refused(self):
        cases = copy.deepcopy(self.cases)
        case = next(iter(cases.values()))
        case.document["scope"]["declared_no_missing_events"] = False
        with self.assertRaisesRegex(ec.EventCoverageError, "INCOMPLETE_DECLARED_EXECUTION"):
            ec.derive_event_catalogue(self.law, cases)
        cases = dict(self.cases)
        name = next(iter(cases))
        case = cases[name]
        cases[name] = replace(case, history_cuts=case.history_cuts[:-1] + (case.history_cuts[-1] - 1,))
        with self.assertRaisesRegex(ec.EventCoverageError, "TERMINAL_HISTORY_OMITS_EVENTS"):
            ec.derive_event_catalogue(self.law, cases)

    def test_boolean_cuts_duplicate_allocations_and_wrong_budget_are_refused(self):
        cases = dict(self.cases)
        name = next(iter(cases))
        cases[name] = replace(cases[name], history_cuts=(True,) + cases[name].history_cuts[1:])
        with self.assertRaisesRegex(ec.EventCoverageError, "HISTORY_CUT_ENCODING"):
            ec.derive_event_catalogue(self.law, cases)
        with self.assertRaisesRegex(ec.EventCoverageError, "DUPLICATE_OR_INVALID_START_ALLOCATION"):
            ec.check_event_coverage(self.law, self.cases, self.allocations + self.allocations[:1], F(1))
        with self.assertRaisesRegex(co.ObservabilityError, "PREDICTABLE_RISK_BUDGET_OVERSPENT"):
            ec.check_event_coverage(self.law, self.cases, self.allocations, F(1, 16))

    def test_allowance_is_checked_under_the_joint_law_without_a_theorem_label(self):
        allocations = tuple(replace(a, allowance=F(0)) for a in self.allocations)
        with self.assertRaisesRegex(co.ObservabilityError, "INVALID_CONDITIONAL_RISK_AT_START"):
            ec.check_event_coverage(self.law, self.cases, allocations, F(1))

    def test_cached_tree_nodes_and_self_asserted_qualification_are_not_trusted(self):
        self.law.nodes.clear()
        self.law.native_six_successor_risk_certified = True
        checked = ec.check_event_coverage(self.law, self.cases, self.allocations, F(1, 8))
        self.assertFalse(checked["native_six_successor_risk_certified"])
        self.assertIsNone(checked["native_six_successor_failure_probability"])
        for name, value in ec.UNATTESTED.items():
            self.assertEqual(checked[name], value)
            self.assertEqual(checked["event_catalogue"][name], value)

    def test_self_declared_physical_clock_and_native_origin_do_not_certify_reality(self):
        cases = copy.deepcopy(self.cases)
        for case in cases.values():
            case.document["provenance"]["origin"] = "observed_native"
            case.document["provenance"]["role"] = "unattested_native_record_conversion"
            case.document["clock"] = {"domain": "physical_monotonic", "unit": "ns",
                                      "binding_receipt": "caller-supplied-clock-label"}
        report = ec.check_event_coverage(self.law, cases, self.allocations, F(1, 8))
        self.assertFalse(report["physical_clock_authenticated"])
        self.assertFalse(report["native_runtime_attested"])
        self.assertFalse(report["all_world_events_authenticated"])
        self.assertFalse(report["actual_probability_law_authenticated"])


class JointInventoryProgressTests(unittest.TestCase):
    def test_same_marginals_have_zero_or_half_failure_after_execution_replay(self):
        summaries, risks = [], []
        for opposite in (False, True):
            law, cases = ec.inventory_progress_fixture(opposite)
            summaries.append(ec.inventory_progress_summary(law, cases))
            catalogue = ec.derive_event_catalogue(law, cases)
            risks.append(catalogue["failure_union_probability"])
            allocations = ec.allocations_from_catalogue(catalogue)
            report = ec.check_event_coverage(law, cases, allocations, F(int(opposite)))
            self.assertFalse(report["native_six_successor_risk_certified"])
            for row in catalogue["starts"]:
                for comparisons in row["comparisons"].values():
                    result = comparisons[0]["result"]
                    if result["outcome"] == "prefix_failure_with_paid_deficit_witness":
                        self.assertEqual(result["relative_initial_inventory_all_branches"], 8)
                        self.assertEqual(result["reference_growth"], 0)
                        self.assertEqual(result["new_adversarial_all_branch_weight"], 0)
        self.assertEqual(risks, [F(0), F(1, 2)])
        for key in ("inventory_marginal", "progress_marginal"):
            self.assertEqual(summaries[0][key], summaries[1][key])
        self.assertEqual(summaries[0]["inventory_marginal"],
                         ({"value": 0, "probability": F(1, 2)}, {"value": 8, "probability": F(1, 2)}))
        self.assertEqual(summaries[0]["progress_marginal"],
                         ({"value": 0, "probability": F(1, 2)}, {"value": 2, "probability": F(1, 2)}))


class RetainedEvidenceTests(unittest.TestCase):
    def test_evidence_contains_raw_records_exact_risks_and_refusals(self):
        evidence = ec.build_evidence()
        self.assertEqual(evidence["result"], "PASS")
        self.assertEqual(evidence["complete_event_risk_bank"]["event_catalogue"]["failure_union_probability"],
                         F(31, 256))
        self.assertEqual(len(evidence["raw_execution_family"]["executions"]), 4)
        self.assertEqual(set(evidence["negative_controls"]),
                         {"omitted_second_start", "omitted_failure_leaf", "late_start", "unobserved_future_label_split"})
        self.assertEqual(evidence["transient_selection_removal"]["complete_event_catalogue"]["failure_union_probability"],
                         F(1, 16))
        self.assertEqual(set(evidence["source_sha256"]), set(ec.SOURCE_FILES))
        self.assertFalse(evidence["native_program_executed_by_this_evidence_driver"])
        self.assertFalse(evidence["production_qualified"])

    def test_cli_retains_new_evidence_and_refuses_to_overwrite_it(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "new"
            command = [sys.executable, str(Path(ec.__file__)), "--write-evidence", str(target)]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            before = (target / "event-coverage.json").read_bytes()
            receipt = json.loads((target / "attempt.json").read_text())
            self.assertEqual(receipt["event_coverage_sha256"], ec.sha(before))
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(second.returncode, 2)
            self.assertIn("NEW_EVIDENCE_DIRECTORY_REQUIRED", second.stdout)
            self.assertEqual((target / "event-coverage.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
