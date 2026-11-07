"""Lossless CPU stage accounting and native proof identity controls."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w1_preprocessing_cache_campaign as campaign
from test_w1_quantum_oracle import fixture
from w1_preprocessing_cache import execute_cache_comparison
from w1_quantum_oracle import Shape


def ledger(attempts=2):
    rows = [{"capacity_payload_bytes": capacity, "attempt_index": index, "stage": stage,
             "status": "COMPLETED", "error": None, "cpu_ns": 3, "wall_ns": 5}
            for capacity in campaign.CAPACITIES for index in range(attempts)
            for stage in ("producer", "independent_full_relation_check")]
    whole = {"cpu_ns": 3 * len(rows) + 11, "wall_ns": 5 * len(rows) + 17,
        "accounted_stage_cpu_ns": 3 * len(rows), "accounted_stage_wall_ns": 5 * len(rows),
        "other_observation_cpu_ns": 11, "other_observation_wall_ns": 17,
        "process_high_water_rss_bytes_before": 100, "process_high_water_rss_bytes_after": 200}
    return rows, whole


class TimingLedgerTests(unittest.TestCase):
    def test_complete_bijection_and_nonstage_overhead_are_charged(self):
        rows, whole = ledger()
        self.assertIsNone(campaign.validate_timing_ledger(rows, whole, 2))

    def test_missing_duplicate_reordered_and_wrong_capacity_rows_refused(self):
        for kind in ("missing", "duplicate", "reordered", "capacity", "stage"):
            rows, whole = ledger()
            if kind == "missing":
                rows.pop()
            elif kind == "duplicate":
                rows[-1] = deepcopy(rows[0])
            elif kind == "reordered":
                rows[0], rows[1] = rows[1], rows[0]
            elif kind == "capacity":
                rows[0]["capacity_payload_bytes"] = 1
            else:
                rows[0]["stage"] = "unaccounted_fast_oracle"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                campaign.validate_timing_ledger(rows, whole, 2)

    def test_failed_partial_negative_and_boolean_clocks_cannot_be_passed_as_complete(self):
        for key, value in (("status", "FAILED"), ("error", "timeout"), ("cpu_ns", -1),
                           ("wall_ns", True), ("attempt_index", False)):
            rows, whole = ledger()
            rows[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                campaign.validate_timing_ledger(rows, whole, 2)

    def test_omitted_overhead_or_rewound_rss_is_refused(self):
        for key, value in (("other_observation_cpu_ns", 0), ("accounted_stage_wall_ns", 0),
                           ("process_high_water_rss_bytes_after", 99)):
            rows, whole = ledger()
            whole[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                campaign.validate_timing_ledger(rows, whole, 2)

    def test_partial_started_journal_is_retained_but_not_a_successful_observation(self):
        raw = b'{"event":"stage_started"}\n'
        with self.assertRaisesRegex(ValueError, "NEEDS_COMPLETE"):
            campaign.validate_progress_journal({"status": "FAILED", "comparison": None}, raw)

    def test_journal_requires_each_start_terminal_pair_and_exact_declared_schedule(self):
        rows, _ = ledger()
        report = {"status": "PASS", "failure": None, "source_sha256_before": {},
            "native_fixture_sha256": "0" * 64, "comparison": {"schedule": [[0, 0], [0, 1]]}, "timings": rows}
        events = [{"event": "declared", "source_sha256": {}, "native_fixture_sha256": "0" * 64,
                   "schedule": [[0, 0], [0, 1]], "capacities_payload_bytes": list(campaign.CAPACITIES)}]
        for row in rows:
            events.append({"event": "stage_started", "capacity_payload_bytes": row["capacity_payload_bytes"],
                           "attempt_index": row["attempt_index"], "stage": row["stage"]})
            events.append({"event": "stage_terminal", **row})
        events.append({"event": "observation_terminal", "status": "PASS", "failure": None})
        raw = b"".join(campaign.canonical(value) + b"\n" for value in events)
        self.assertIsNone(campaign.validate_progress_journal(report, raw))
        for damaged in (raw[:-1], b"".join(campaign.canonical(value) + b"\n" for value in events[:-1]),
                        b"".join(campaign.canonical(value) + b"\n" for value in events[1:])):
            with self.assertRaises(ValueError):
                campaign.validate_progress_journal(report, damaged)

    def test_failed_input_observation_keeps_failure_and_never_claims_execution(self):
        events = []
        with patch("w1_native_bridge.load_fixture", side_effect=ValueError("CONTROL_BAD_SOURCE")):
            report = campaign.observe(Path("/unused-test-control"), progress=events.append)
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["failure"], {"type": "ValueError", "message": "CONTROL_BAD_SOURCE"})
        self.assertIsNone(report["comparison"])
        self.assertEqual(report["timings"], [])
        self.assertEqual(events, [{"event": "observation_terminal", "status": "FAILED", "failure": report["failure"]}])
        self.assertTrue(all(value is False for value in report["claims"].values()))


class NativeFixtureIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This is a source-control fixture, not an actual native admission. Its
        # producer relation is exercised, while this test isolates the required
        # identity comparisons that follow real load_fixture in the CLI.
        cls.template = fixture(Shape(), nonce_bits=1)
        cls.fixture = {"contexts": [{"template_spec": cls.template.spec(), "all_nonce_outcomes": []}]}
        cls.model = execute_cache_comparison((cls.template,), ((0, 0), (0, 1)), campaign.CAPACITIES)
        for attempt in cls.model["cells"][0]["attempts"]:
            cls.fixture["contexts"][0]["all_nonce_outcomes"].append({
                "nonce": attempt["nonce"], "header_hex": cls.template.header_for(attempt["nonce"]).hex(),
                "native_winner": attempt["outcome"] == "TARGET_HIT", "complete_native_proof_generated": True,
                "proof_sha256": attempt["proof_sha256"], "proof_bytes": attempt["proof_bytes"], "trace": attempt["trace"]})

    def test_nonce_major_plan_and_complete_proof_identity_bind_every_capacity(self):
        templates, schedule = campaign.native_plan(self.fixture)
        self.assertEqual(templates, (self.template,))
        self.assertEqual(schedule, ((0, 0), (0, 1)))
        reviewed = campaign.compare_native_proofs(self.model, self.fixture)
        self.assertEqual(reviewed["actual_native_fixture_proof_identities_checked"], 6)
        self.assertFalse(reviewed["same_packet_new_node_execution_claimed"])

    def test_wrong_proof_trace_verdict_and_header_are_refused(self):
        for field, value in (("proof_sha256", "0" * 64), ("trace", "0" * 64),
                             ("proof_bytes", 1), ("native_winner", False), ("header_hex", "00")):
            changed = deepcopy(self.fixture)
            changed["contexts"][0]["all_nonce_outcomes"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                campaign.compare_native_proofs(self.model, changed)

    def test_missing_duplicate_or_uncompleted_native_candidates_refused(self):
        for kind in ("missing", "duplicate", "incomplete"):
            changed = deepcopy(self.fixture)
            rows = changed["contexts"][0]["all_nonce_outcomes"]
            if kind == "missing":
                rows.pop()
            elif kind == "duplicate":
                rows[-1] = deepcopy(rows[0])
            else:
                rows[0]["complete_native_proof_generated"] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                campaign.compare_native_proofs(self.model, changed)

    def test_unbounded_native_nonce_window_rejected_before_schedule_materialization(self):
        changed = deepcopy(self.fixture)
        changed["contexts"][0]["template_spec"]["nonce_bits"] = 64
        with self.assertRaisesRegex(ValueError, "ATTEMPT_BUDGET"):
            campaign.native_plan(changed)


if __name__ == "__main__":
    unittest.main()
