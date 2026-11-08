"""Portable provenance, exact workload denominators and deadline-ledger controls."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w1_preprocessing_portfolio_campaign as campaign
from test_w1_quantum_oracle import fixture
from test_w1_preprocessing_portfolio import changed
from w1_native_bridge import FIXTURE_CLAIMS
from w1_preprocessing_portfolio import CAPACITIES, STRATEGIES, run_cell
from w1_quantum_oracle import Shape, canonical


def synthetic_fixture():
    """Metadata-only unit control, never passed off as an actual native run."""
    p = fixture(Shape(), nonce_bits=3)
    templates = (p, changed(p, parent=True))
    contexts = []
    for template in templates:
        rows = [{"nonce": nonce, "header_hex": template.header_for(nonce).hex(),
                 "native_winner": False, "complete_native_proof_generated": True,
                 "proof_sha256": "2" * 64, "proof_bytes": 49188, "trace": "3" * 64}
                for nonce in range(8)]
        contexts.append({"template_spec": template.spec(), "all_nonce_outcomes": rows})
    return {"contexts": contexts, "claims": dict(FIXTURE_CLAIMS),
        "native_source": {"git_head": "a" * 40, "binary_sha256": "b" * 64,
                          "source_sha256": {"unit-control-only": "c" * 64}}}


def timing_report(*, mode="full", limit=None, late=False):
    p = fixture(Shape(2, 1, 8, 2), nonce_bits=3)
    cell = run_cell((p,), ((0, 0),), "direct-ab", 0, max_stages=limit)
    admissions, timings = [], []
    wall, cpu = 10, 100
    for index, identity in enumerate(cell["completed_stages"]):
        if late and index == len(cell["completed_stages"]) - 1:
            wall = campaign.DEADLINE_NS - 3
        admissions.append({"identity": identity, "wall_elapsed_ns": wall, "allowed": True})
        row = {"identity": identity, "status": "COMPLETED", "error": None,
            "start_wall_elapsed_ns": wall + 1, "end_wall_elapsed_ns": wall + 5,
            "start_process_cpu_ns": cpu + 1, "end_process_cpu_ns": cpu + 3,
            "cpu_ns": 2, "wall_ns": 4}
        timings.append(row)
        wall, cpu = wall + 6, cpu + 4
    if cell["status"] == "CENSORED":
        wall = max(campaign.DEADLINE_NS, wall)
        admissions.append({"identity": cell["stopped_before"], "wall_elapsed_ns": wall, "allowed": False})
    end_wall, end_cpu = wall + 7, cpu + 5
    verifications = [row for row in timings if row["identity"][1] == "independent_full_relation_check"]
    return {"status": "COMPLETE_OBSERVATION", "failure": None, "strategy": "direct-ab",
        "capacity_payload_bytes": 0, "mode": mode,
        "deadline_ns": campaign.DEADLINE_NS if mode == "budgeted" else None,
        "cell": cell, "timings": timings, "admissions": admissions,
        "source_sha256_before": {"unit-control-only": "0" * 64},
        "native_fixture_sha256": "1" * 64, "plan": {"plan_sha256": "2" * 64},
        "timely_verified_attempt_indices": [row["identity"][0] for row in verifications
            if mode == "full" or row["end_wall_elapsed_ns"] <= campaign.DEADLINE_NS],
        "completed_verifications_after_deadline": [row["identity"][0] for row in verifications
            if mode == "budgeted" and row["end_wall_elapsed_ns"] > campaign.DEADLINE_NS],
        "process_observation": {"origin_scope": "observation-entry", "origin_wall_ns": 1000,
            "entry_wall_elapsed_ns": 0, "end_wall_elapsed_ns": end_wall,
            "observation_wall_ns": end_wall, "process_cpu_ns_at_entry": 100,
            "process_cpu_ns_at_end": end_cpu, "observation_cpu_ns": end_cpu - 100,
            "accounted_stage_cpu_ns": 2 * len(timings), "accounted_stage_wall_ns": 4 * len(timings),
            "other_observation_cpu_ns": end_cpu - 100 - 2 * len(timings),
            "other_observation_wall_ns": end_wall - 4 * len(timings),
            "process_high_water_rss_bytes_before": 10, "process_high_water_rss_bytes_after": 20,
            "overrun_after_deadline_ns": max(0, end_wall - campaign.DEADLINE_NS) if mode == "budgeted" else 0}}


def journal(report):
    events = [{"event": "run_started", "strategy": report["strategy"],
        "capacity_payload_bytes": report["capacity_payload_bytes"], "mode": report["mode"],
        "deadline_ns": report["deadline_ns"], "source_sha256": report["source_sha256_before"]},
        {"event": "plan_bound", "plan_sha256": report["plan"]["plan_sha256"],
         "native_fixture_sha256": report["native_fixture_sha256"], "planned_attempt_count": 28}]
    for index, admission in enumerate(report["admissions"]):
        events.append({"event": "stage_admission", **admission})
        if admission["allowed"]:
            row = report["timings"][index]
            events.extend([{"event": "stage_started", "identity": row["identity"],
                "wall_elapsed_ns": row["start_wall_elapsed_ns"], "process_cpu_ns": row["start_process_cpu_ns"]},
                {"event": "stage_terminal", **row}])
    events.append({"event": "run_terminal", "status": report["status"], "failure": report["failure"]})
    return b"".join(canonical(event) + b"\n" for event in events)


class WorkloadTests(unittest.TestCase):
    def test_original_16_and_extended_12_have_one_frozen_order_with_explicit_scope(self):
        fixture_record = synthetic_fixture()
        templates, schedule, plan = campaign.portfolio_plan(fixture_record)
        self.assertEqual(len(templates), 8)
        self.assertEqual(len(schedule), 28)
        self.assertEqual(schedule[:16], tuple((context, nonce) for nonce in range(8) for context in range(2)))
        self.assertEqual(schedule[16:], ((0, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0),
                                         (7, 0), (0, 1), (2, 1), (4, 1), (5, 1), (0, 0)))
        self.assertEqual(templates[0].a, templates[2].a)
        self.assertNotEqual(templates[0].header, templates[2].header)
        self.assertEqual(templates[3].target, 1)
        self.assertTrue(all(value == 0 for value in templates[5].a))
        self.assertTrue(all(not row["fresh_native_admission_claimed"] for row in plan["attempt_labels"]))
        self.assertFalse(plan["repeated_attempts_are_independent_queries"])
        self.assertFalse(plan["whole_proof_replay_cache_enumerated"])

    def test_changed_nonce_window_or_context_denominator_is_refused(self):
        for kind in ("context", "nonce"):
            data = synthetic_fixture()
            if kind == "context":
                data["contexts"].pop()
            else:
                for context in data["contexts"]:
                    context["template_spec"]["nonce_bits"] = 2
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                campaign.portfolio_plan(data)

    def test_matrix_has_32_unique_runs_no_performance_selected_repetitions(self):
        rows = campaign._matrix_contract()
        self.assertEqual(len(rows), 32)
        self.assertEqual(len({row["file"] for row in rows}), 32)
        self.assertEqual({(row["mode"], row["strategy"], row["capacity_payload_bytes"]) for row in rows},
                         {(mode, strategy, capacity) for mode in ("full", "budgeted")
                          for strategy in STRATEGIES for capacity in CAPACITIES})
        self.assertEqual(campaign.DEADLINE_NS, 4_000_000_000)


class PortableInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "portable.json"
        fixture_record = synthetic_fixture()
        with patch("w1_native_bridge.load_fixture", return_value=(fixture_record, "d" * 64, 32)):
            self.receipt = campaign.export_portable_input(Path("/unit-native-control"), self.path)

    def rewrite(self, record):
        record["record_sha256"] = campaign._hash({key: value for key, value in record.items() if key != "record_sha256"})
        self.path.write_bytes(canonical(record) + b"\n")
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_portable_export_requires_external_pin_and_does_not_claim_fresh_native_execution(self):
        loaded = campaign.load_portable_input(self.path, self.receipt["file_sha256"])
        self.assertEqual(loaded["native_provenance"]["frozen_implementation_commit"], "a" * 40)
        self.assertFalse(loaded["native_provenance"]["portable_consumer_reexecutes_native_admission"])
        self.assertFalse(loaded["native_provenance"]["native_node_executed_by_exporter"])
        self.assertEqual(loaded["preparation_observation"]["shared_input_preparations"], 1)
        with self.assertRaisesRegex(ValueError, "EXTERNAL_BYTE_PIN"):
            campaign.load_portable_input(self.path, None)
        with self.assertRaisesRegex(ValueError, "BYTE_PIN_MISMATCH"):
            campaign.load_portable_input(self.path, "0" * 64)

    def test_rehashed_source_plan_quantum_or_provenance_promotion_is_rejected(self):
        original = json.loads(self.path.read_bytes())
        for kind in ("source", "plan", "claim", "native_claim", "packet_count", "preparation"):
            record = deepcopy(original)
            if kind == "source":
                record["source_sha256"][next(iter(record["source_sha256"]))] = "0" * 64
            elif kind == "plan":
                record["plan"]["schedule"].pop()
            elif kind == "claim":
                record["claims"]["same_total_physical_resource_budget_proved"] = True
            elif kind == "native_claim":
                record["native_provenance"]["fixture_claims"]["quantum_hardware_executed"] = True
            elif kind == "packet_count":
                record["native_provenance"]["independently_checked_native_packet_records"] = 31
            else:
                record["preparation_observation"]["shared_input_preparations"] = 0
            pin = self.rewrite(record)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                campaign.load_portable_input(self.path, pin)

    def test_delegated_binding_is_explicit_and_full_loader_is_not_silently_substituted(self):
        with patch("w1_native_bridge.load_fixture", side_effect=AssertionError("full loader was invoked")):
            _, fixture_sha, binding = campaign._inputs(None, self.path, self.receipt["file_sha256"])
        self.assertEqual(fixture_sha, "d" * 64)
        self.assertEqual(binding["kind"], "SHA-pinned-portable-delegation")
        self.assertFalse(binding["full_native_inventory_checked_in_this_process"])
        self.assertFalse(binding["native_fixture_loader_executed_in_this_process"])
        with self.assertRaisesRegex(ValueError, "EXACTLY_ONE"):
            campaign._inputs(Path("/native"), self.path, self.receipt["file_sha256"])


class TimingAndJournalTests(unittest.TestCase):
    def test_valid_full_censored_and_late_completed_ledgers_keep_all_costs(self):
        for report in (timing_report(), timing_report(mode="budgeted", limit=6),
                       timing_report(mode="budgeted", late=True)):
            self.assertIsNone(campaign.validate_timing_ledger(report))
            self.assertIsNone(campaign.validate_journal(report, journal(report)))
        late = timing_report(mode="budgeted", late=True)
        self.assertEqual(late["timely_verified_attempt_indices"], [])
        self.assertEqual(late["completed_verifications_after_deadline"], [0])
        self.assertGreater(late["process_observation"]["overrun_after_deadline_ns"], 0)

    def test_missing_duplicate_reordered_or_fictitious_clock_rows_are_rejected(self):
        for kind in ("missing", "duplicate", "reverse", "clock", "bool-index", "overhead", "rss"):
            report = timing_report()
            if kind == "missing":
                report["timings"].pop()
            elif kind == "duplicate":
                report["timings"][-1] = deepcopy(report["timings"][0])
            elif kind == "reverse":
                report["timings"].reverse()
            elif kind == "clock":
                report["timings"][0]["cpu_ns"] = -1
            elif kind == "bool-index":
                report["timings"][1]["identity"] = [False, "input_binding"]
            elif kind == "overhead":
                report["process_observation"]["other_observation_cpu_ns"] = 0
            else:
                report["process_observation"]["process_high_water_rss_bytes_after"] = 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                campaign.validate_timing_ledger(report)

    def test_late_check_cannot_be_promoted_to_timely_delivery_or_omit_overrun(self):
        for kind in ("timely", "late", "overrun", "admission"):
            report = timing_report(mode="budgeted", late=True)
            if kind == "timely":
                report["timely_verified_attempt_indices"] = [0]
            elif kind == "late":
                report["completed_verifications_after_deadline"] = []
            elif kind == "overrun":
                report["process_observation"]["overrun_after_deadline_ns"] = 0
            else:
                report["admissions"][-1]["wall_elapsed_ns"] = campaign.DEADLINE_NS
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                campaign.validate_timing_ledger(report)

    def test_censoring_requires_a_deadline_refusal_and_preserves_unstarted_work(self):
        for kind in ("missing", "early", "allowed", "identity"):
            report = timing_report(mode="budgeted", limit=6)
            if kind == "missing":
                report["admissions"].pop()
            elif kind == "early":
                report["admissions"][-1]["wall_elapsed_ns"] = 1
            elif kind == "allowed":
                report["admissions"][-1]["allowed"] = True
            else:
                report["admissions"][-1]["identity"] = [1, "proof_product"]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                campaign.validate_timing_ledger(report)

    def test_truncated_reordered_or_partial_failure_journal_cannot_pass(self):
        report = timing_report(mode="budgeted", limit=6)
        raw = journal(report)
        lines = raw.splitlines(keepends=True)
        for damaged in (raw[:-1], b"".join(lines[:-1]), b"".join(lines[1:]),
                        b"".join(lines[:2] + [lines[3], lines[2]] + lines[4:])):
            with self.assertRaises(ValueError):
                campaign.validate_journal(report, damaged)
        failed = {"status": "FAILED", "plan": None}
        with self.assertRaisesRegex(ValueError, "RETAINS_FAILED"):
            campaign.validate_journal(failed, b'{"event":"stage_started"}\n')

    def test_failed_input_keeps_failure_and_does_not_claim_any_proof_work(self):
        events = []
        with patch.object(campaign, "_inputs", side_effect=ValueError("CONTROL_BAD_SOURCE")):
            report = campaign.observe(Path("/unused"), "direct-ab", 0, "full", progress=events.append)
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["failure"], {"type": "ValueError", "message": "CONTROL_BAD_SOURCE"})
        self.assertIsNone(report["cell"])
        self.assertEqual(report["timings"], [])
        self.assertEqual([event["event"] for event in events], ["run_started", "run_terminal"])
        self.assertTrue(all(value is False for value in report["claims"].values()))


if __name__ == "__main__":
    unittest.main()
