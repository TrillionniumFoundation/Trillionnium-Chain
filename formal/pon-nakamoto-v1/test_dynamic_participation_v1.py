"""Benign lifecycle, missing-evidence and refusal checks for a declared model.

No test constructs a native packet or reproduces a consensus exploit.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import dynamic_participation_v1 as dynamic


HERE = Path(__file__).resolve().parent
SOURCE = "e2a02f9271b49f146e70806c8a66e161b5973971"


def event(time, kind, **data):
    return {"time": time, "kind": kind, **data}


def document(events=(), *, end=10):
    rows = copy.deepcopy(list(events))
    for index, row in enumerate(rows, 1):
        row["seq"] = index
    return {
        "schema": dynamic.SCHEMA, "source_commit": SOURCE,
        "clock_domain": "declared_model_ticks",
        "window": {"start": 0, "end": end, "complete_events_as_declared": True},
        "bounds": {"delta_pub": 1, "gamma": 2, "maximum_weight": 4},
        "initial": {"reference_score": 7, "resource_units": 1, "carry_in_tasks": [],
                    "active": [{"node": "h0", "generation": 1, "view_score": 7}]},
        "events": rows,
    }


def one_pacer_events():
    return [
        event(3, "bind", node="h0", generation=1, task="p0", parent_score=7, resource_units=2),
        event(4, "ready", task="p0", weight=2, provider_available=True, resource_units=3),
        event(4, "view", node="h0", generation=1, view_score=9),
    ]


def joined_events():
    return one_pacer_events() + [
        event(4, "join", node="h1", generation=1, view_score=7),
        event(4, "qualify", node="h1", generation=1),
        event(5, "view", node="h1", generation=1, view_score=9),
        event(7, "bind", node="h1", generation=1, task="p1", parent_score=9, resource_units=2),
        event(8, "ready", task="p1", weight=3, provider_available=True, resource_units=4),
        event(8, "view", node="h1", generation=1, view_score=12),
        event(9, "view", node="h0", generation=1, view_score=12),
    ]


def codes(report):
    return {row["code"] for row in report["violations"]}


class DynamicCohortTests(unittest.TestCase):
    def test_joined_members_inherit_progress_and_original_deadline(self):
        report = dynamic.audit_dynamic_participation(document(joined_events()))
        self.assertTrue(report["declared_contract_holds"])
        self.assertEqual(report["final_score_floor"], 12)
        self.assertEqual(report["paced_progress_credit"], 5)
        self.assertEqual(report["known_resource_units"], 12)
        self.assertEqual([row["deadline"] for row in report["pacers"]], [5, 9])
        self.assertEqual(report["final_active_nodes"], ["h0", "h1"])
        self.assertEqual(report["entry_or_carryover_credit_debt"], 0)

    def test_original_reference_does_not_meet_later_entry_floor(self):
        rows = one_pacer_events() + [
            event(6, "join", node="h1", generation=1, view_score=7),
            event(6, "qualify", node="h1", generation=1),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertFalse(report["declared_contract_holds"])
        self.assertIn("BOOTSTRAP_BELOW_CURRENT_FLOOR", codes(report))
        self.assertEqual(report["final_active_nodes"], ["h0"])

    def test_new_member_must_meet_already_pending_delivery_deadline(self):
        rows = one_pacer_events() + [
            event(4, "join", node="h1", generation=1, view_score=7),
            event(4, "qualify", node="h1", generation=1),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        failure = next(row for row in report["violations"]
                       if row["code"] == "INHERITED_DELIVERY_OR_RETENTION_DEFICIT")
        self.assertEqual((failure["node"], failure["time"], failure["required"]), ("h1", 5, 9))

    def test_timely_delivery_cannot_be_inferred_from_a_later_view(self):
        rows = one_pacer_events() + [
            event(4, "join", node="h1", generation=1, view_score=7),
            event(4, "qualify", node="h1", generation=1),
            event(6, "view", node="h1", generation=1, view_score=9),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertIn("INHERITED_DELIVERY_OR_RETENTION_DEFICIT", codes(report))

    def test_leaving_and_rejoining_preserves_task_generation_and_cost(self):
        rows = [
            event(3, "bind", node="h0", generation=1, task="old", parent_score=7, resource_units=3),
            event(4, "leave", node="h0", generation=1),
            event(5, "join", node="h0", generation=2, view_score=7),
            event(5, "qualify", node="h0", generation=2),
            event(5, "ready", task="old", weight=2, provider_available=True, resource_units=1),
            event(6, "charge", task="old", resource_units=4),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertTrue(report["declared_contract_holds"])
        self.assertEqual(report["paced_progress_credit"], 0)
        self.assertEqual(report["entry_or_carryover_credit_debt"], 2)
        self.assertEqual(report["task_accounts"]["old"]["generation"], 1)
        self.assertEqual(report["task_accounts"]["old"]["known_resource_units"], 8)
        self.assertEqual(report["known_resource_units"], 9)
        self.assertEqual(report["empty_cohort_intervals"], [{"start": 4, "end": 5}])

    def test_later_qualification_does_not_relabel_earlier_parent_binding(self):
        rows = [
            event(2, "join", node="h1", generation=1, view_score=7),
            event(3, "bind", node="h1", generation=1, task="early", parent_score=7, resource_units=2),
            event(4, "qualify", node="h1", generation=1),
            event(5, "ready", task="early", weight=2, provider_available=True, resource_units=1),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertFalse(report["task_accounts"]["early"]["qualified_at_binding"])
        self.assertEqual(report["entry_or_carryover_credit_debt"], 2)
        self.assertEqual(report["paced_progress_credit"], 0)

    def test_cancel_request_does_not_erase_late_output_or_resource(self):
        rows = [
            event(3, "bind", node="h0", generation=1, task="cancelled", parent_score=7, resource_units=2),
            event(4, "cancel", task="cancelled"),
            event(5, "ready", task="cancelled", weight=2, provider_available=True, resource_units=3),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertEqual(report["entry_or_carryover_credit_debt"], 2)
        self.assertEqual(report["known_resource_units"], 6)
        self.assertTrue(report["task_accounts"]["cancelled"]["cancel_requested"])
        self.assertTrue(report["task_accounts"]["cancelled"]["ready"])

    def test_cancellation_without_completion_stays_unresolved(self):
        rows = [
            event(3, "bind", node="h0", generation=1, task="pending", parent_score=7, resource_units=2),
            event(4, "cancel", task="pending"),
            event(5, "charge", task="pending", resource_units=3),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertEqual(report["uncompleted_tasks"], ["pending"])
        self.assertEqual(report["known_resource_units"], 6)
        self.assertEqual(report["total_ready_credit"], 0)

    def test_failed_task_costs_remain_without_inventing_success_credit(self):
        rows = [
            event(3, "bind", node="h0", generation=1, task="failed", parent_score=7, resource_units=2),
            event(4, "finish_without_output", task="failed", resource_units=3),
            event(5, "charge", task="failed", resource_units=4),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertEqual(report["known_resource_units"], 10)
        self.assertEqual(report["total_ready_credit"], 0)
        self.assertTrue(report["task_accounts"]["failed"]["failed"])

    def test_zero_participation_produces_no_growth_bound(self):
        report = dynamic.audit_dynamic_participation(document([event(1, "leave", node="h0", generation=1)]))
        self.assertTrue(report["declared_contract_holds"])
        self.assertEqual(report["empty_cohort_intervals"], [{"start": 1, "end": 10}])
        self.assertEqual(report["paced_progress_credit"], 0)
        self.assertIn("NO_PACED_PROGRESS_IN_DECLARED_WINDOW", report["qualification_refusals"])
        self.assertFalse(report["native_chain_growth_qualified"])
        self.assertIsNone(report["native_chain_growth_bound"])

    def test_view_retention_loss_is_not_hidden_by_reclassification(self):
        rows = one_pacer_events() + [event(6, "view", node="h0", generation=1, view_score=7)]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertIn("QUALIFIED_VIEW_RETENTION_REGRESSION", codes(report))
        self.assertIn("ACTIVE_VIEW_BELOW_FLOOR", codes(report))
        self.assertFalse(report["declared_contract_holds"])

    def test_known_better_parent_must_be_selected_to_count_progress(self):
        rows = one_pacer_events() + [
            event(7, "bind", node="h0", generation=1, task="old_parent", parent_score=7, resource_units=2),
            event(8, "ready", task="old_parent", weight=2, provider_available=True, resource_units=3),
        ]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertIn("QUALIFIED_PARENT_SELECTION_DEFICIT", codes(report))
        self.assertEqual(report["paced_progress_credit"], 2)
        self.assertEqual(report["entry_or_carryover_credit_debt"], 2)

    def test_censored_deadline_is_not_a_pass(self):
        report = dynamic.audit_dynamic_participation(document(one_pacer_events(), end=4))
        self.assertIn("DELIVERY_DEADLINE_CENSORED", codes(report))
        self.assertEqual(report["final_score_floor"], 7)
        self.assertFalse(report["declared_contract_holds"])

    def test_carry_in_remains_charged_and_never_becomes_fresh(self):
        doc = document([event(5, "ready", task="carry", weight=2, provider_available=True, resource_units=3)])
        doc["initial"]["carry_in_tasks"] = [{"task": "carry", "node": "h0", "generation": 1,
            "bound_at": 0, "parent_score": 7, "resource_units": 4}]
        report = dynamic.audit_dynamic_participation(doc)
        self.assertEqual(report["known_resource_units"], 8)
        self.assertEqual(report["entry_or_carryover_credit_debt"], 2)
        self.assertEqual(report["paced_progress_credit"], 0)
        self.assertIn("COMPLETION_BOUND_EXCEEDED", codes(report))

    def test_ready_credit_partition_is_exact_for_overlap_and_startup(self):
        rows = [
            event(1, "bind", node="h0", generation=1, task="startup", parent_score=7, resource_units=1),
            event(2, "ready", task="startup", weight=1, provider_available=True, resource_units=1),
        ] + one_pacer_events() + [
            event(5, "bind", node="h0", generation=1, task="unpaced", parent_score=9, resource_units=1),
            event(6, "ready", task="unpaced", weight=1, provider_available=True, resource_units=1),
        ]
        doc = document(rows)
        report = dynamic.audit_dynamic_participation(doc)
        raw_total = sum(row["weight"] for row in rows if row["kind"] == "ready")
        accounts = [report[name] for name in ("startup_honest_credit_debt", "entry_or_carryover_credit_debt",
                    "paced_progress_credit", "eligible_unpaced_credit", "unclassified_ready_credit")]
        self.assertEqual(raw_total, sum(accounts))
        self.assertEqual(accounts, [1, 0, 2, 1, 0])


class RefusalAndUnknownTests(unittest.TestCase):
    def test_unknown_bounds_are_not_zero_or_defaulted(self):
        doc = document(one_pacer_events())
        doc["bounds"]["gamma"] = None
        report = dynamic.audit_dynamic_participation(doc)
        self.assertFalse(report["declared_contract_holds"])
        self.assertEqual(report["unclassified_ready_credit"], 2)
        self.assertEqual(report["paced_progress_credit"], 0)
        self.assertIn("UNKNOWN_TIMING_OR_WEIGHT_BOUND", report["unknowns"])

    def test_unknown_cost_does_not_get_replaced_by_zero(self):
        doc = document(one_pacer_events())
        doc["events"][0]["resource_units"] = None
        report = dynamic.audit_dynamic_participation(doc)
        self.assertFalse(report["all_resource_charges_known"])
        self.assertFalse(report["task_accounts"]["p0"]["all_resource_charges_known"])
        self.assertEqual(report["known_resource_units"], 4)
        self.assertFalse(report["declared_contract_holds"])

    def test_unknown_clock_completeness_or_provider_never_qualifies(self):
        for change in ("clock", "coverage", "provider"):
            with self.subTest(change=change):
                doc = document(one_pacer_events())
                if change == "clock":
                    doc["clock_domain"] = "unknown"
                elif change == "coverage":
                    doc["window"]["complete_events_as_declared"] = False
                else:
                    doc["events"][1]["provider_available"] = None
                report = dynamic.audit_dynamic_participation(doc)
                self.assertFalse(report["declared_contract_holds"])
                self.assertEqual(report["qualification"], "HOLD_NO_GO")
                self.assertIsNone(report["native_six_successor_risk_bound"])

    def test_exceeded_weight_is_not_counted_as_paced_progress(self):
        doc = document(one_pacer_events())
        doc["events"][1]["weight"] = 5
        report = dynamic.audit_dynamic_participation(doc)
        self.assertIn("WEIGHT_BOUND_EXCEEDED", codes(report))
        self.assertEqual(report["paced_progress_credit"], 0)
        self.assertEqual(report["entry_or_carryover_credit_debt"], 5)

    def test_unknown_full_view_cannot_enter(self):
        rows = [event(1, "join", node="h1", generation=1, view_score=None),
                event(1, "qualify", node="h1", generation=1)]
        report = dynamic.audit_dynamic_participation(document(rows))
        self.assertIn("UNKNOWN_FULL_VIEW_SCORE", codes(report))
        self.assertEqual(report["final_active_nodes"], ["h0"])

    def test_unknown_unqualified_view_and_unfinished_parent_are_retained(self):
        doc = document([event(1, "join", node="h1", generation=1, view_score=None)])
        doc["initial"]["carry_in_tasks"] = [{"task": "unknown_parent", "node": "h0",
            "generation": 1, "bound_at": 0, "parent_score": None, "resource_units": 1}]
        report = dynamic.audit_dynamic_participation(doc)
        self.assertFalse(report["declared_contract_holds"])
        self.assertIn("UNKNOWN_FULL_VIEW_SCORE", report["unknowns"])
        self.assertIn("UNKNOWN_PARENT_SCORE", report["unknowns"])
        self.assertEqual(report["uncompleted_tasks"], ["unknown_parent"])

    def test_generations_and_task_identity_never_rewind(self):
        for rows, code in [
            ([event(1, "leave", node="h0", generation=1),
              event(2, "join", node="h0", generation=1, view_score=7)], "JOIN_GENERATION"),
            (one_pacer_events() + [event(6, "bind", node="h0", generation=1,
              task="p0", parent_score=9, resource_units=0)], "DUPLICATE_TASK"),
            (one_pacer_events() + [event(6, "ready", task="p0", weight=2,
              provider_available=True, resource_units=0)], "DUPLICATE_OR_TERMINAL_OUTPUT"),
        ]:
            with self.subTest(code=code), self.assertRaisesRegex(dynamic.ParticipationError, code):
                dynamic.audit_dynamic_participation(document(rows))

    def test_numbers_cannot_be_booleans_or_floats(self):
        for key, value in (("time", True), ("weight", True), ("resource_units", 1.5)):
            with self.subTest(key=key):
                doc = document(one_pacer_events())
                doc["events"][1][key] = value
                with self.assertRaises(dynamic.ParticipationError):
                    dynamic.audit_dynamic_participation(doc)

    def test_json_duplicates_and_nonfinite_values_refused(self):
        for body in ('{"a": 1, "a": 2}', '{"a": NaN}', '{"a": Infinity}'):
            with self.subTest(body=body), self.assertRaises(dynamic.ParticipationError):
                dynamic.strict_json(body)

    def test_oversized_json_integer_is_a_structured_refusal(self):
        with self.assertRaisesRegex(dynamic.ParticipationError, "JSON_INTEGER_RANGE"):
            dynamic.strict_json('{"n": ' + "9" * 5000 + '}')

    def test_unsigned_extra_qualification_field_is_not_accepted(self):
        doc = document()
        doc["native_common_prefix_qualified"] = True
        with self.assertRaisesRegex(dynamic.ParticipationError, "DOCUMENT_FIELDS"):
            dynamic.audit_dynamic_participation(doc)

    def test_every_numeric_native_claim_stays_unknown_on_good_trace(self):
        report = dynamic.audit_dynamic_participation(document(joined_events()))
        for name in ("native_six_successor_risk_bound", "native_common_prefix_failure_bound",
                     "native_chain_growth_bound", "native_chain_quality_bound"):
            self.assertIsNone(report[name])
        for name in ("native_common_prefix_qualified", "native_chain_growth_qualified",
                     "native_chain_quality_qualified", "physical_resource_cost_authenticated",
                     "production_activation"):
            self.assertIs(report[name], False)

    def test_cli_native_qualification_request_fails_even_after_finite_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "declared.json"
            path.write_text(json.dumps(document(joined_events())), encoding="utf-8")
            result = subprocess.run([sys.executable, str(HERE / "dynamic_participation_v1.py"),
                                     "--check", str(path), "--require-native-qualification"],
                                    capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertTrue(report["declared_contract_holds"])
        self.assertEqual(report["qualification"], "HOLD_NO_GO")


class BoundedCliInputTests(unittest.TestCase):
    def run_cli(self, path):
        result = subprocess.run(
            [sys.executable, str(HERE / "dynamic_participation_v1.py"),
             "--check", str(path)],
            capture_output=True, text=True, check=False, timeout=5,
        )
        self.assertEqual(result.stderr, "")
        return result.returncode, json.loads(result.stdout)

    def assert_refused(self, path, reason):
        code, report = self.run_cli(path)
        self.assertEqual(code, 2)
        self.assertEqual(report["check"], "REFUSED")
        self.assertIn(reason, report["reason"])
        self.assertEqual(report["qualification"], "HOLD_NO_GO")
        self.assertIsNone(report["native_six_successor_risk_bound"])

    def test_regular_cli_retains_the_original_finite_report(self):
        doc = document(joined_events())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "declared.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            code, report = self.run_cli(path)
        self.assertEqual(code, 0)
        self.assertEqual(report, dynamic.audit_dynamic_participation(doc))

    def test_exact_byte_ceiling_passes_and_one_excess_byte_refuses(self):
        doc = document(joined_events())
        encoded = json.dumps(doc).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "declared.json"
            path.write_bytes(encoded + b" " * (dynamic.MAX_INPUT_BYTES - len(encoded)))
            code, report = self.run_cli(path)
            self.assertEqual(code, 0)
            self.assertEqual(report, dynamic.audit_dynamic_participation(doc))
            with path.open("ab") as stream:
                stream.write(b" ")
            self.assert_refused(path, "nonregular/oversize source")

    def test_fifo_without_a_writer_is_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "declared.fifo"
            os.mkfifo(path)
            self.assert_refused(path, "nonregular/oversize source")

    def test_leaf_and_parent_symlink_aliases_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            path = real / "declared.json"
            path.write_text(json.dumps(document(joined_events())), encoding="utf-8")
            leaf = root / "linked.json"
            leaf.symlink_to(path)
            parent = root / "linked-directory"
            parent.symlink_to(real, target_is_directory=True)
            self.assert_refused(leaf, "symlink source refused")
            self.assert_refused(parent / path.name, "symlink source refused")

    def test_directory_and_missing_inputs_are_structured_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assert_refused(root, "nonregular/oversize source")
            self.assert_refused(root / "absent.json", "missing source")

    def test_invalid_utf8_remains_a_structured_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_bytes(b"\xff")
            self.assert_refused(path, "utf-8")


if __name__ == "__main__":
    unittest.main()
