#!/usr/bin/env python3
"""Independent reader fixtures; these do not claim that native work executed."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from check_growth_scale_observation import check, returned_stage


ACCOUNTS = (64, 1024, 16384)
HISTORY = (0, 16, 128)
SAMPLES = 8
OWNERS = ["11" * 32, "22" * 32, "33" * 32]
COUNTERS = (
    "context_checks", "header_ancestors", "full_work_checkpoints",
    "execution_checkpoints", "cow_account_node_checkpoints", "reorg_ancestors",
    "reorg_writes", "reorg_readbacks", "before_commit_checks",
)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def block(accounts, history, height):
    if height == 0:
        return digest(f"genesis-{accounts}")
    return digest(f"block-{accounts}-{history}-{height}")


def sql_rows(accounts, height):
    return {
        "blocks": height + 1, "growth_states": height + 1,
        "archive_nodes": 2 * accounts - 1 + 20 * height,
        "deltas": 4 * height, "events": height, "steps": int(height > 0),
    }


def working(height):
    rewards = min(height, 10)
    return {
        "keys": 4 + rewards, "canonical_bytes": 100 + 64 * rewards,
        "mandatory_owner_count": int(height > 0),
        "mandatory_owners": OWNERS[-1:] if height else [],
        "obligation_rows_by_prefix": {
            "reward:": rewards, "task:": 0, "quota:": 0, "escrow:": 0,
        },
    }


def disk():
    return {
        "file_bytes": {"native.sqlite": 4096, "native.sqlite-wal": 8192,
                       "native.sqlite-shm": 32768},
        "scope": "point sample; not peak disk, WAL, RSS or device memory",
    }


def stage(sample, parent_height, activation=False):
    counters = dict.fromkeys(COUNTERS, 0)
    if activation:
        wall, persistence, commit = 500, None, 400
        counters.update(reorg_ancestors=1, reorg_writes=1, reorg_readbacks=5,
                        before_commit_checks=1)
    else:
        wall, persistence, commit = 1000 + sample * 10, 700, 800
        counters.update(context_checks=2, header_ancestors=6 * min(parent_height, 16),
                        full_work_checkpoints=100, execution_checkpoints=20,
                        cow_account_node_checkpoints=20, before_commit_checks=1)
    return {
        "wall_ns": wall, "checkpoints": counters,
        "before_persistence_offset_ns": persistence,
        "before_commit_offset_ns": commit,
        "persistence_and_readback_wall_ns": None if activation else commit - persistence,
        "final_guard_and_sqlite_commit_wall_ns": wall - commit,
        "timing_scope": "inclusive wall time; offsets and nested intervals must not be summed",
    }


def fixture():
    """All native observer fields, independent of the reader implementation."""
    files = {
        "run.jsonl": [
            {
                "schema": "native-growth-fixed-owner-scale-observation-v1",
                "event": "run_started", "accounts": list(ACCOUNTS),
                "warmup_history_blocks": list(HISTORY),
                "measured_blocks_per_cohort": SAMPLES,
                "transaction": "one signed sender 0 to existing recipient 1, amount 1, consecutive nonce; miner 3",
                "declared_transaction_owners": OWNERS,
                "workers": 1, "work_search_attempt_limit": 4096,
                "fixture_scope": "preallocated dormant accounts; real empty maintenance warmup history; original 65,536 signed growth gate remains separate",
                "measurement_scope": "direct native Node only; no WAN, client confirmation, public admission qualification or throughput claim",
                "setup_reference_diagnostics_and_cancellation_excluded_from_native_stage_timings": True,
                "p99_ns": None, "wall_time_acceptance_gate": False, "completed": False,
            },
            {
                "event": "run_completed", "completed_cohorts": 9,
                "completed_measurements": 72,
                "actual_distinct_witness_owner_sets": [OWNERS],
                "fixed_witness_owner_set_observed": True, "p99_ns": None,
                "throughput_claim": False, "production_qualified": False,
            },
        ],
    }
    for accounts in ACCOUNTS:
        for history in HISTORY:
            rows = [{"event": "cohort_started", "accounts": accounts,
                     "warmup_history_blocks": history, "planned_measurements": SAMPLES}]
            rows.extend({"event": "warmup_started", "index": index,
                         "parent": block(accounts, history, index)} for index in range(history))
            rows.append({
                "event": "warmup_completed", "setup_wall_ns": 1000,
                "native_warmup_wall_ns": 1000 * history,
                "full_reference_warmup_wall_ns": 2000 * history,
                "network": digest("network"), "parameters": digest("parameters"),
                "genesis": block(accounts, history, 0),
                "sql_rows": sql_rows(accounts, history), "working": working(history),
                "disk_sample": disk(),
            })
            for sample in range(SAMPLES):
                height = history + sample
                rows.append({
                    "event": "measurement_started", "sample": sample,
                    "parent": block(accounts, history, height),
                    "history_blocks_before": height,
                })
                rows.append({
                    "event": "measurement_completed", "sample": sample,
                    "block": block(accounts, history, height + 1), "accounts": accounts,
                    "history_blocks_before": height, "history_blocks_after": height + 1,
                    "actual_witness_accounts": len(OWNERS), "actual_witness_owners": OWNERS,
                    "witness_bytes": 719, "witness_frontier_nodes": 8,
                    "packet_bytes": 50472, "full_work_proof_bytes": 49188,
                    "make_signed_packet_and_full_work_wall_ns": 3000,
                    "native_admission": stage(sample, height), "native_activation": stage(sample, height, True),
                    "admission_sql_total_changes": 26,
                    "activation_sql_total_changes": 5 if height else 4,
                    "retained_cow_nodes_added": 20, "retained_delta_rows_added": 4,
                    "sql_rows_before": sql_rows(accounts, height),
                    "sql_rows_after": sql_rows(accounts, height + 1),
                    "parent_working": working(height), "successor_working": working(height + 1),
                    "separate_successor_query": {"point_reads": 25, "witness_bytes": 719,
                                                  "expanded_witnesses_allocated": 0},
                    "complete_state_reference_and_diagnostics_wall_ns": 4000,
                    "complete_state_reference_equal": True, "active_generation": height + 1,
                    "disk_sample": disk(), "p99_ns": None,
                })
            rows.extend([
                {"event": "atomic_cancellation_started"},
                {"event": "atomic_cancellation_completed",
                 "error": "SCALE_OBSERVATION_BEFORE_COMMIT_CANCEL",
                 "all_sql_rows_equal": True, "active_generation_equal": True},
                {"event": "cold_reopen_started"},
                {
                    "event": "cohort_completed", "accounts": accounts,
                    "warmup_history_blocks": history, "measured_blocks": SAMPLES,
                    "successful_native_admissions": history + SAMPLES,
                    "deliberately_cancelled_admissions": 1, "failed_unexpected_admissions": 0,
                    "cold_reopens": 1, "cold_reopen_wall_ns": 5000,
                    "cold_complete_reference_equal": True,
                    "separate_post_open_journal_differential": {
                        "wall_ns": 6000, "typed_events": history + SAMPLES,
                        "semantic_events": history + SAMPLES, "latest_steps": 1,
                        "latest_events": 1, "peak_event_rows": 1,
                    },
                    "admission_median_interval_ns": [1030, 1040], "admission_max_ns": 1070,
                    "p99_ns": None, "disk_before_close": disk(), "disk_after_reopen": disk(),
                    "production_qualified": False,
                },
            ])
            files[f"cohort-a{accounts}-h{history}.jsonl"] = rows
    return files


def v2_stage(value):
    value = copy.deepcopy(value)
    value["before_commit_to_return_wall_ns"] = value.pop("final_guard_and_sqlite_commit_wall_ns")
    value["thread_cpu_ns"] = None
    value["process_cpu_ns"] = None
    value["timing_scope"] = (
        "inclusive wall time; offsets and nested intervals must not be summed; "
        "BeforeCommit-to-return includes the actual success or error return, not a durable-commit measurement"
    )
    return value


def return_receipt(*, purpose, sample, parent, target, operation, native, changes, error=None):
    return {
        "schema": "native-growth-stage-return-v1", "event": "native_stage_returned",
        "purpose": purpose, "sample": sample, "parent": parent, "block": target,
        "operation": operation, "accepted": error is None,
        "returned_block": target if error is None else None, "error": error, "error_code": None,
        "native_stage": copy.deepcopy(native), "sql_total_changes": changes,
    }


def fixture_v2():
    """Independent new producer shape, retaining the full historical fixture above."""
    files = fixture()
    first, last = files["run.jsonl"]
    first["schema"] = "native-growth-fixed-owner-scale-observation-v2"
    first.pop("setup_reference_diagnostics_and_cancellation_excluded_from_native_stage_timings")
    first.update({
        "setup_reference_diagnostics_and_journaling_excluded_from_native_stage_timings": True,
        "returned_native_stages_recorded_before_assertions": True,
        "cancelled_admission_timing_separate_from_successful_samples": True,
        "sql_total_changes_include_rolled_back_writes": True,
        "native_stage_return_schema": "native-growth-stage-return-v1",
        "native_stage_timing_scope": "wall only; no thread or process CPU measurement",
        "return_journal_scope": (
            "one flushed record per returned measured admission, activation and deliberate cancellation; "
            "journal IO is outside native stage timings but remains campaign cost; "
            "panic, kill and nonreturning calls have no invented return receipt"
        ),
    })
    last["returned_native_stages"] = 153
    for accounts in ACCOUNTS:
        for history in HISTORY:
            name = f"cohort-a{accounts}-h{history}.jsonl"
            rows = []
            cancelled = v2_stage(stage(1000, history + SAMPLES))
            for row in files[name]:
                if row["event"] == "measurement_completed":
                    sample = row["sample"]
                    for operation in ("admission", "activation"):
                        row[f"native_{operation}"] = v2_stage(row[f"native_{operation}"])
                        rows.append(return_receipt(
                            purpose="measurement", sample=sample,
                            parent=block(accounts, history, history + sample), target=row["block"],
                            operation=operation, native=row[f"native_{operation}"],
                            changes=row[f"{operation}_sql_total_changes"],
                        ))
                elif row["event"] == "atomic_cancellation_started":
                    row["parent"] = block(accounts, history, history + SAMPLES)
                elif row["event"] == "atomic_cancellation_completed":
                    rows.append(return_receipt(
                        purpose="atomic_cancellation", sample=None,
                        parent=block(accounts, history, history + SAMPLES),
                        target=block(accounts, history, history + SAMPLES + 1),
                        operation="admission", native=cancelled, changes=26,
                        error="SCALE_OBSERVATION_BEFORE_COMMIT_CANCEL",
                    ))
                    row["native_admission"] = copy.deepcopy(cancelled)
                    row["admission_sql_total_changes"] = 26
                elif row["event"] == "cohort_completed":
                    row["returned_native_stages"] = 17
                    row["cancelled_admission_wall_ns"] = cancelled["wall_ns"]
                rows.append(row)
            files[name] = rows
    return files


def fixture_v3():
    """Current producer structure; the retained v1/v2 fixtures stay unchanged."""
    files = fixture_v2()
    first = files["run.jsonl"][0]
    first["schema"] = "native-growth-fixed-owner-scale-observation-v3"
    first["header_window_contract"] = {
        "profile": "native-growth-single-header-window-v1",
        "complete_admission_windows": 3,
        "maximum_ancestor_headers_per_window": 16,
        "counter": "header_ancestors",
        "scope": "HeaderAncestor callbacks; excludes other SQL, epoch/schema checks, wall time and CPU",
    }
    for accounts in ACCOUNTS:
        for history in HISTORY:
            for row in files[f"cohort-a{accounts}-h{history}.jsonl"]:
                if row["event"] == "native_stage_returned" and row["operation"] == "admission":
                    height = history + (SAMPLES if row["sample"] is None else row["sample"])
                    row["native_stage"]["checkpoints"]["header_ancestors"] = 3 * min(height, 16)
                elif row["event"] == "measurement_completed":
                    row["native_admission"]["checkpoints"]["header_ancestors"] = (
                        3 * min(history + row["sample"], 16))
                elif row["event"] == "atomic_cancellation_completed":
                    row["native_admission"]["checkpoints"]["header_ancestors"] = (
                        3 * min(history + SAMPLES, 16))
    return files


class ObservationFiles(unittest.TestCase):
    make_fixture = staticmethod(fixture)
    historical_v1 = True
    historical_v2 = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-growth-reader-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "observations"
        self.root.mkdir()
        self.files = self.make_fixture()
        self.write()

    def write(self):
        for name, rows in self.files.items():
            (self.root / name).write_text("".join(json.dumps(row, separators=(",", ":")) + "\n"
                                                for row in rows), encoding="utf-8")

    def cohort(self, accounts=64, history=0):
        return self.files[f"cohort-a{accounts}-h{history}.jsonl"]

    def event(self, event, sample=None, accounts=64, history=0):
        return next(row for row in self.cohort(accounts, history)
                    if row["event"] == event and (sample is None or row.get("sample") == sample))

    def refused(self):
        self.write()
        with self.assertRaises((ValueError, KeyError, TypeError, OSError, UnicodeError)):
            self.read()

    def read(self):
        return check(self.root, historical_v1=self.historical_v1,
                     historical_v2=self.historical_v2)


class GrowthObservationReaderTests(ObservationFiles):

    def test_complete_fixture_accepts_all_seventy_two_samples_without_qualification(self):
        result = self.read()
        self.assertEqual(result["result"], "COMPLETE_LOCAL_OBSERVATION")
        self.assertEqual(result["measured_native_blocks"], 72)
        self.assertEqual(result["cancelled_admissions"], 9)
        self.assertEqual(result["cold_reopens"], 9)
        self.assertEqual(result["fixed_witness_owners"], OWNERS)
        self.assertEqual(len(result["files"]), 10)
        self.assertIsNone(result["p99_ns"])
        self.assertFalse(result["throughput_qualified"])
        self.assertFalse(result["production_activation"])

    def test_fixed_account_histories_cannot_change_native_context(self):
        for key in ("network", "parameters", "genesis"):
            for history in HISTORY[1:]:
                with self.subTest(key=key, history=history):
                    self.files = fixture()
                    self.event("warmup_completed", accounts=1024, history=history)[key] = digest(
                        f"changed-{key}-{history}")
                    self.refused()

    def test_distinct_account_counts_may_have_distinct_native_contexts(self):
        for accounts in ACCOUNTS:
            for history in HISTORY:
                warmup = self.event("warmup_completed", accounts=accounts, history=history)
                warmup["network"] = digest(f"network-{accounts}")
                warmup["parameters"] = digest(f"parameters-{accounts}")
                # The fixture already derives the same genesis per account count.
                self.assertEqual(warmup["genesis"], block(accounts, history, 0))
        self.write()
        result = self.read()
        self.assertEqual(result["completed_cohorts"], 9)
        self.assertEqual(result["measured_native_blocks"], 72)

    def test_missing_cohort_file_is_refused(self):
        (self.root / "cohort-a16384-h128.jsonl").unlink()
        with self.assertRaises(ValueError):
            self.read()

    def test_missing_sample_cannot_reduce_the_denominator(self):
        self.cohort().remove(self.event("measurement_completed", 7))
        self.refused()

    def test_duplicate_sample_is_refused(self):
        self.cohort().insert(4, copy.deepcopy(self.event("measurement_completed", 0)))
        self.refused()

    def test_reordered_start_completion_and_samples_are_refused(self):
        rows = self.cohort()
        rows[2], rows[3] = rows[3], rows[2]
        self.refused()

    def test_missing_warmup_or_incorrect_warmup_index_is_refused(self):
        self.event("warmup_started", accounts=1024, history=16)["index"] = 1
        self.refused()

    def test_cancelled_attempt_and_cold_reopen_cannot_be_omitted(self):
        for event in ("atomic_cancellation_started", "atomic_cancellation_completed", "cold_reopen_started"):
            with self.subTest(event=event):
                self.files = fixture()
                self.cohort().remove(self.event(event))
                self.refused()

    def test_reference_cancellation_and_cold_failures_are_refused(self):
        for event, key in (("measurement_completed", "complete_state_reference_equal"),
                           ("atomic_cancellation_completed", "all_sql_rows_equal"),
                           ("atomic_cancellation_completed", "active_generation_equal"),
                           ("cohort_completed", "cold_complete_reference_equal")):
            with self.subTest(event=event, key=key):
                self.files = fixture()
                self.event(event)[key] = False
                self.refused()

    def test_changed_or_duplicate_actual_owners_are_refused(self):
        for owners in (OWNERS[:2], [OWNERS[0], OWNERS[0], OWNERS[2]], list(reversed(OWNERS))):
            with self.subTest(owners=owners):
                self.files = fixture()
                done = self.event("measurement_completed", 4)
                done["actual_witness_owners"] = owners
                done["actual_witness_accounts"] = len(owners)
                self.refused()

    def test_uniform_invented_owner_set_cannot_hide_declared_transaction_or_mandatory_owners(self):
        for rows in self.files.values():
            for row in rows:
                if row.get("event") == "measurement_completed":
                    row["actual_witness_owners"] = ["44" * 32]
                    row["actual_witness_accounts"] = 1
        self.files["run.jsonl"][-1]["actual_distinct_witness_owner_sets"] = [["44" * 32]]
        self.refused()

    def test_mandatory_owner_must_be_covered_by_actual_witness(self):
        working = self.event("measurement_completed", 3)["parent_working"]
        working["mandatory_owners"] = ["44" * 32]
        self.refused()

    def test_booleans_cannot_impersonate_integer_fields_or_grid_values(self):
        for place in ("workers", "grid", "sample", "journal", "sql"):
            with self.subTest(place=place):
                self.files = fixture()
                if place == "workers":
                    self.files["run.jsonl"][0]["workers"] = True
                elif place == "grid":
                    self.files["run.jsonl"][0]["warmup_history_blocks"][0] = False
                elif place == "sample":
                    self.event("measurement_completed", 0)["sample"] = False
                elif place == "journal":
                    self.event("cohort_completed")["separate_post_open_journal_differential"]["peak_event_rows"] = True
                else:
                    self.event("measurement_completed", 0)["sql_rows_before"]["archive_nodes"] = True
                self.refused()

    def test_nonfinite_and_floating_json_are_refused_even_in_diagnostics(self):
        name = "cohort-a64-h0.jsonl"
        for token in ("1e309", "Infinity", "-Infinity", "Inf", "NaN", "1.0"):
            with self.subTest(token=token):
                self.files = fixture()
                self.event("measurement_completed", 0)["disk_sample"]["file_bytes"]["native.sqlite"] = "FLOAT_PLACEHOLDER"
                self.write()
                path = self.root / name
                path.write_bytes(path.read_bytes().replace(b'"FLOAT_PLACEHOLDER"', token.encode()))
                with self.assertRaises(ValueError):
                    self.read()

    def test_symlinked_file_and_directory_are_refused(self):
        path = self.root / "run.jsonl"
        target = Path(self.temp.name) / "retained-run.jsonl"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises((OSError, ValueError)):
            self.read()
        path.unlink()
        target.rename(path)
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            check(alias, historical_v1=self.historical_v1, historical_v2=self.historical_v2)

    def test_extra_file_and_trailing_event_are_refused(self):
        extra = self.root / "omitted-failure.jsonl"
        extra.write_text("{}\n")
        with self.assertRaises(ValueError):
            self.read()
        extra.unlink()
        self.cohort().append({"event": "unreported_failure"})
        self.refused()

    def test_duplicate_json_keys_and_missing_final_newline_are_refused(self):
        path = self.root / "run.jsonl"
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'"workers":1', b'"workers":1,"workers":1'))
        with self.assertRaises(ValueError):
            self.read()
        path.write_bytes(raw[:-1])
        with self.assertRaises(ValueError):
            self.read()

    def test_inconsistent_or_out_of_range_intervals_are_refused(self):
        for key, value in (("before_commit_offset_ns", 2000),
                           ("persistence_and_readback_wall_ns", 99),
                           ("final_guard_and_sqlite_commit_wall_ns", 201),
                           ("wall_ns", -1), ("wall_ns", 1 << 64)):
            with self.subTest(key=key, value=value):
                self.files = fixture()
                self.event("measurement_completed", 0)["native_admission"][key] = value
                self.refused()

    def test_cannot_claim_native_success_with_no_work_or_commit_checkpoints(self):
        for name in ("native_admission", "native_activation"):
            with self.subTest(stage=name):
                self.files = fixture()
                data = self.event("measurement_completed", 0)[name]
                data["checkpoints"] = dict.fromkeys(COUNTERS, 0)
                for key in ("before_persistence_offset_ns", "before_commit_offset_ns",
                            "persistence_and_readback_wall_ns", "final_guard_and_sqlite_commit_wall_ns"):
                    data[key] = None
                self.refused()

    def test_summary_median_max_and_planned_totals_are_recomputed(self):
        for place in ("median", "max", "cohort", "run", "p99"):
            with self.subTest(place=place):
                self.files = fixture()
                end = self.event("cohort_completed")
                if place == "median":
                    end["admission_median_interval_ns"] = [1, 2]
                elif place == "max":
                    end["admission_max_ns"] = 1
                elif place == "cohort":
                    end["successful_native_admissions"] -= 1
                elif place == "run":
                    self.files["run.jsonl"][-1]["completed_measurements"] = 71
                else:
                    end["p99_ns"] = 9999
                self.refused()

    def test_original_structural_limits_are_not_relaxed(self):
        for field, value in (("reads", 1024), ("cow", 4096), ("expanded", 1)):
            with self.subTest(field=field):
                self.files = fixture()
                done = self.event("measurement_completed", 0)
                if field == "reads":
                    done["separate_successor_query"]["point_reads"] = value
                elif field == "cow":
                    done["retained_cow_nodes_added"] = value
                else:
                    done["separate_successor_query"]["expanded_witnesses_allocated"] = value
                self.refused()

    def test_missing_required_native_diagnostics_are_refused(self):
        for key in ("block", "parent_working", "successor_working", "disk_sample",
                    "packet_bytes", "full_work_proof_bytes", "active_generation",
                    "retained_delta_rows_added", "admission_sql_total_changes"):
            with self.subTest(key=key):
                self.files = fixture()
                self.event("measurement_completed", 0).pop(key)
                self.refused()

    def test_repeated_or_unlinked_blocks_are_refused(self):
        for mutation in ("repeat", "unlinked", "malformed"):
            with self.subTest(mutation=mutation):
                self.files = fixture()
                if mutation == "repeat":
                    self.event("measurement_completed", 1)["block"] = self.event("measurement_completed", 0)["block"]
                elif mutation == "unlinked":
                    self.event("measurement_started", 1)["parent"] = "55" * 32
                else:
                    self.event("measurement_completed", 0)["block"] = "not-a-block"
                self.refused()

    def test_sql_deltas_history_and_generation_cannot_disagree_with_samples(self):
        for mutation in ("history", "cow", "deltas", "generation", "write_count"):
            with self.subTest(mutation=mutation):
                self.files = fixture()
                done = self.event("measurement_completed", 3)
                if mutation == "history":
                    for table in ("blocks", "growth_states", "events"):
                        done["sql_rows_before"][table] += 10
                        done["sql_rows_after"][table] += 10
                elif mutation == "cow":
                    done["sql_rows_after"]["archive_nodes"] += 1
                elif mutation == "deltas":
                    done["retained_delta_rows_added"] = 0
                elif mutation == "generation":
                    done["active_generation"] = 0
                else:
                    done["admission_sql_total_changes"] = 0
                self.refused()


class GrowthReturnedStageReaderTests(ObservationFiles):
    make_fixture = staticmethod(fixture_v2)
    historical_v1 = False
    historical_v2 = True

    def receipt(self, operation="admission", sample=0, purpose="measurement", accounts=64, history=0):
        return next(row for row in self.cohort(accounts, history)
                    if row["event"] == "native_stage_returned" and row["operation"] == operation
                    and row["purpose"] == purpose and row["sample"] == sample)

    def test_v2_retains_all_returns_and_keeps_cancellation_cost_outside_success_medians(self):
        result = self.read()
        self.assertEqual(result["schema"], "native-growth-fixed-owner-scale-readback-v2")
        self.assertFalse(result["historical_v1"])
        self.assertTrue(result["historical_v2"])
        self.assertIsNone(result["header_window_contract"])
        self.assertEqual(result["returned_native_stages"], 153)
        self.assertEqual(result["returned_native_outcomes"], {"accepted": 144, "rejected": 9})
        self.assertTrue(result["cancellation_stage_measurements_available"])
        self.assertFalse(result["native_stage_cpu_measurements_available"])
        self.assertEqual(result["measured_native_blocks"], 72)
        self.assertEqual(result["cancelled_admissions"], 9)
        for cohort in result["cohorts"]:
            self.assertEqual(cohort["cancelled_admission_wall_ns"], 11000)
            self.assertEqual(cohort["admission_median_interval_ns"], [1030, 1040])
            self.assertIsNone(cohort["p99_ns"])
        self.assertFalse(result["throughput_qualified"])
        self.assertFalse(result["production_activation"])

    def test_historical_v1_requires_explicit_mode_and_missing_return_timings_stay_unknown(self):
        self.files = fixture()
        self.write()
        with self.assertRaises(ValueError):
            check(self.root)
        historical = check(self.root, historical_v1=True)
        self.assertTrue(historical["historical_v1"])
        self.assertFalse(historical["cancellation_stage_measurements_available"])
        self.assertIsNone(historical["returned_native_stages"])
        self.assertIsNone(historical["returned_native_outcomes"])
        self.assertTrue(all(row["cancelled_admission_wall_ns"] is None for row in historical["cohorts"]))
        self.files = fixture_v2()
        self.write()
        with self.assertRaises(ValueError):
            check(self.root, historical_v1=True)

    def test_current_scope_cannot_silently_claim_old_success_only_timing(self):
        for key in (
                "setup_reference_diagnostics_and_journaling_excluded_from_native_stage_timings",
                "returned_native_stages_recorded_before_assertions",
                "cancelled_admission_timing_separate_from_successful_samples",
                "sql_total_changes_include_rolled_back_writes",
                "native_stage_return_schema", "native_stage_timing_scope", "return_journal_scope"):
            with self.subTest(key=key):
                self.files = fixture_v2()
                self.files["run.jsonl"][0][key] = False
                self.refused()
        self.files = fixture_v2()
        self.files["run.jsonl"][0]["setup_reference_diagnostics_and_cancellation_excluded_from_native_stage_timings"] = True
        self.refused()

    def test_erased_or_reordered_admission_and_activation_returns_are_refused(self):
        for mutation in ("erase_admission", "erase_activation", "duplicate", "reverse"):
            with self.subTest(mutation=mutation):
                self.files = fixture_v2()
                rows = self.cohort()
                admission = rows.index(self.receipt())
                if mutation == "erase_admission":
                    rows.pop(admission)
                elif mutation == "erase_activation":
                    rows.pop(admission + 1)
                elif mutation == "duplicate":
                    rows.insert(admission, copy.deepcopy(rows[admission]))
                else:
                    rows[admission], rows[admission + 1] = rows[admission + 1], rows[admission]
                self.refused()

    def test_native_return_identity_and_outcome_are_exact(self):
        mutations = (
            lambda row: row.update(schema="native-growth-stage-return-v0"),
            lambda row: row.update(operation="commit"),
            lambda row: row.update(purpose="atomic_cancellation"),
            lambda row: row.update(sample=False),
            lambda row: row.update(sample=1),
            lambda row: row.update(parent="55" * 32),
            lambda row: row.update(block="66" * 32),
            lambda row: row.update(returned_block="77" * 32),
            lambda row: row.update(accepted=1),
            lambda row: row.update(error="failure"),
            lambda row: row.update(error_code="PUBLIC_REQUEST_CANCELLED"),
            lambda row: row.update(sql_total_changes=True),
            lambda row: row.update(durable_commit_succeeded=True),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.files = fixture_v2()
                mutation(self.receipt())
                self.refused()

    def test_completed_sample_cannot_rewrite_already_returned_timings_or_sql_counts(self):
        for operation in ("admission", "activation"):
            for field in ("wall_ns", "sql_total_changes"):
                with self.subTest(operation=operation, field=field):
                    self.files = fixture_v2()
                    row = self.receipt(operation)
                    if field == "wall_ns":
                        row["native_stage"]["wall_ns"] += 1
                        row["native_stage"]["before_commit_to_return_wall_ns"] += 1
                    else:
                        row[field] += 1
                    self.refused()

    def test_unmeasured_stage_cpu_cannot_be_filled_with_zero_or_inferred_work(self):
        for key in ("thread_cpu_ns", "process_cpu_ns"):
            for value in (0, 1000):
                with self.subTest(key=key, value=value):
                    self.files = fixture_v2()
                    self.receipt()["native_stage"][key] = value
                    self.refused()

    def test_partial_failed_admission_retains_actual_cost_but_cannot_complete_campaign(self):
        row = self.receipt()
        row.update(accepted=False, returned_block=None,
                   error="PUBLIC_MUTATION_CPU_BUDGET", error_code="PUBLIC_MUTATION_CPU_BUDGET",
                   sql_total_changes=0)
        native = row["native_stage"]
        native.update(wall_ns=9123, before_persistence_offset_ns=None, before_commit_offset_ns=None,
                      persistence_and_readback_wall_ns=None, before_commit_to_return_wall_ns=None)
        native["checkpoints"] = dict.fromkeys(COUNTERS, 0)
        native["checkpoints"]["context_checks"] = 1
        validated = returned_stage(row, purpose="measurement", operation="admission", sample=0,
                                   parent=row["parent"], block=row["block"])
        self.assertEqual(validated["native_stage"]["wall_ns"], 9123)
        self.assertFalse(validated["accepted"])
        self.assertEqual(validated["sql_total_changes"], 0)
        self.assertIsNone(validated["native_stage"]["before_commit_to_return_wall_ns"])
        self.write()
        with self.assertRaisesRegex(ValueError, "unexpected admission failure"):
            self.read()
        retained = [json.loads(line) for line in (self.root / "cohort-a64-h0.jsonl").read_text().splitlines()]
        self.assertIn(row, retained)

    def test_activation_failure_keeps_prior_admission_return_and_remains_failure(self):
        admission = copy.deepcopy(self.receipt())
        activation = self.receipt("activation")
        activation.update(accepted=False, returned_block=None,
                          error="SCALE_OBSERVATION_ACTIVATION_CANCEL", error_code=None)
        validated = returned_stage(activation, purpose="measurement", operation="activation", sample=0,
                                   parent=activation["parent"], block=admission["block"])
        self.assertFalse(validated["accepted"])
        self.write()
        with self.assertRaisesRegex(ValueError, "unexpected activation failure"):
            self.read()
        retained = [json.loads(line) for line in (self.root / "cohort-a64-h0.jsonl").read_text().splitlines()]
        self.assertEqual(retained[retained.index(activation) - 1], admission)
        self.assertTrue(admission["accepted"])
        self.assertEqual(admission["returned_block"], activation["block"])

    def test_failure_receipt_requires_real_error_and_consistent_partial_checkpoints(self):
        for mutation in ("no_error", "bad_code", "false_returned_block", "missing_commit_offset"):
            with self.subTest(mutation=mutation):
                row = copy.deepcopy(self.receipt())
                row.update(accepted=False, returned_block=None, error="ROOT", error_code=None)
                if mutation == "no_error":
                    row["error"] = None
                elif mutation == "bad_code":
                    row["error_code"] = "not a typed code"
                elif mutation == "false_returned_block":
                    row["returned_block"] = row["block"]
                else:
                    row["native_stage"]["before_commit_offset_ns"] = None
                    row["native_stage"]["persistence_and_readback_wall_ns"] = None
                    row["native_stage"]["before_commit_to_return_wall_ns"] = None
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    returned_stage(row, purpose="measurement", operation="admission", sample=0,
                                   parent=row["parent"], block=row["block"])

    def test_all_nine_cancellations_need_their_own_return_and_timing(self):
        for accounts in ACCOUNTS:
            for history in HISTORY:
                with self.subTest(accounts=accounts, history=history):
                    self.files = fixture_v2()
                    row = self.receipt(sample=None, purpose="atomic_cancellation",
                                       accounts=accounts, history=history)
                    self.cohort(accounts, history).remove(row)
                    self.refused()
        for key in ("wall_ns", "checkpoints", "before_commit_offset_ns"):
            with self.subTest(key=key):
                self.files = fixture_v2()
                self.receipt(sample=None, purpose="atomic_cancellation")["native_stage"].pop(key)
                self.refused()

    def test_cancellation_cannot_be_a_success_or_misnamed_durable_commit_measurement(self):
        for mutation in ("success", "old_tail", "false_scope", "no_checkpoints", "sample", "parent"):
            with self.subTest(mutation=mutation):
                self.files = fixture_v2()
                row = self.receipt(sample=None, purpose="atomic_cancellation")
                native = row["native_stage"]
                if mutation == "success":
                    row.update(accepted=True, returned_block=row["block"], error=None)
                elif mutation == "old_tail":
                    native["final_guard_and_sqlite_commit_wall_ns"] = native.pop("before_commit_to_return_wall_ns")
                elif mutation == "false_scope":
                    native["timing_scope"] = "successful durable commit"
                elif mutation == "no_checkpoints":
                    native["checkpoints"] = dict.fromkeys(COUNTERS, 0)
                elif mutation == "sample":
                    row["sample"] = 8
                else:
                    row["parent"] = "55" * 32
                self.refused()

    def test_cancellation_return_cannot_disagree_with_atomic_readback_or_summary(self):
        for mutation in ("timing", "sql", "summary_time", "summary_count", "run_count"):
            with self.subTest(mutation=mutation):
                self.files = fixture_v2()
                cancel = self.event("atomic_cancellation_completed")
                end = self.event("cohort_completed")
                if mutation == "timing":
                    cancel["native_admission"]["wall_ns"] -= 1
                    cancel["native_admission"]["before_commit_to_return_wall_ns"] -= 1
                elif mutation == "sql":
                    cancel["admission_sql_total_changes"] -= 1
                elif mutation == "summary_time":
                    end["cancelled_admission_wall_ns"] -= 1
                elif mutation == "summary_count":
                    end["returned_native_stages"] -= 1
                else:
                    self.files["run.jsonl"][-1]["returned_native_stages"] -= 1
                self.refused()

    def test_deliberate_before_commit_cancellation_cannot_erase_rolled_back_write_cost(self):
        self.receipt(sample=None, purpose="atomic_cancellation")["sql_total_changes"] = 0
        self.event("atomic_cancellation_completed")["admission_sql_total_changes"] = 0
        self.refused()

    def test_deliberate_before_commit_cancellation_cannot_erase_ancestor_work(self):
        returned = self.receipt(sample=None, purpose="atomic_cancellation")
        returned["native_stage"]["checkpoints"]["header_ancestors"] = 0
        self.event("atomic_cancellation_completed")["native_admission"]["checkpoints"]["header_ancestors"] = 0
        self.refused()

    def test_cancelled_tail_is_not_a_ninth_successful_latency_sample(self):
        for mutation in ("median", "maximum"):
            with self.subTest(mutation=mutation):
                self.files = fixture_v2()
                end = self.event("cohort_completed")
                if mutation == "median":
                    end["admission_median_interval_ns"] = [1040, 1040]
                else:
                    end["admission_max_ns"] = end["cancelled_admission_wall_ns"]
                self.refused()


class GrowthSingleWindowReaderTests(ObservationFiles):
    make_fixture = staticmethod(fixture_v3)
    historical_v1 = False
    historical_v2 = False
    receipt = GrowthReturnedStageReaderTests.receipt

    def replace_ancestors(self, count, *, sample=0, purpose="measurement", accounts=64, history=0):
        row = self.receipt(sample=sample, purpose=purpose, accounts=accounts, history=history)
        row["native_stage"]["checkpoints"]["header_ancestors"] = count
        completed = self.event(
            "measurement_completed" if purpose == "measurement" else "atomic_cancellation_completed",
            sample=sample, accounts=accounts, history=history)
        completed["native_admission"]["checkpoints"]["header_ancestors"] = count

    def test_v3_retains_all_returns_with_exact_three_local_windows(self):
        result = self.read()
        self.assertEqual(result["schema"], "native-growth-fixed-owner-scale-readback-v3")
        self.assertFalse(result["historical_v1"])
        self.assertFalse(result["historical_v2"])
        self.assertEqual(result["header_window_contract"], self.files["run.jsonl"][0]["header_window_contract"])
        self.assertEqual(result["returned_native_stages"], 153)
        self.assertEqual(result["returned_native_outcomes"], {"accepted": 144, "rejected": 9})
        self.assertEqual(result["measured_native_blocks"], 72)
        self.assertEqual(result["cancelled_admissions"], 9)
        self.assertTrue(result["cancellation_stage_measurements_available"])
        self.assertFalse(result["native_stage_cpu_measurements_available"])
        self.assertFalse(result["throughput_qualified"])
        self.assertFalse(result["production_activation"])
        for cohort in result["cohorts"]:
            self.assertEqual(cohort["admission_median_interval_ns"], [1030, 1040])
            self.assertEqual(cohort["cancelled_admission_wall_ns"], 11000)
            self.assertIsNone(cohort["p99_ns"])

    def test_historical_v2_requires_explicit_mode_and_preserves_original_six_windows(self):
        self.files = fixture_v2()
        self.write()
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        with self.assertRaisesRegex(ValueError, "run context"):
            check(self.root)
        result = check(self.root, historical_v2=True)
        self.assertEqual(result["schema"], "native-growth-fixed-owner-scale-readback-v2")
        self.assertTrue(result["historical_v2"])
        self.assertIsNone(result["header_window_contract"])
        self.assertEqual(self.receipt(sample=1)["native_stage"]["checkpoints"]["header_ancestors"], 6)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.root.iterdir()})
        with self.assertRaises(ValueError):
            check(self.root, historical_v1=True, historical_v2=True)
        self.files = fixture_v3()
        self.write()
        with self.assertRaisesRegex(ValueError, "run context"):
            check(self.root, historical_v2=True)

    def test_v3_refuses_wrong_window_counts_in_every_account_history_cohort(self):
        for accounts in ACCOUNTS:
            for history in HISTORY:
                for sample in (0, SAMPLES - 1):
                    expected = 3 * min(history + sample, 16)
                    wrong = {0, expected + 1, 6 * min(history + sample, 16)} - {expected}
                    for count in wrong:
                        with self.subTest(accounts=accounts, history=history, sample=sample, count=count):
                            self.files = fixture_v3()
                            self.replace_ancestors(count, sample=sample, accounts=accounts, history=history)
                            self.write()
                            with self.assertRaisesRegex(ValueError, "exact native header window count"):
                                self.read()

    def test_v3_cancellation_cannot_retain_old_six_windows_or_erase_actual_work(self):
        for accounts in ACCOUNTS:
            for history in HISTORY:
                expected = 3 * min(history + SAMPLES, 16)
                for count in (0, expected + 1, 6 * min(history + SAMPLES, 16)):
                    with self.subTest(accounts=accounts, history=history, count=count):
                        self.files = fixture_v3()
                        self.replace_ancestors(count, sample=None, purpose="atomic_cancellation",
                                               accounts=accounts, history=history)
                        self.write()
                        with self.assertRaisesRegex(ValueError, "exact native header window count"):
                            self.read()

    def test_current_contract_cannot_change_window_size_counter_scope_or_number_types(self):
        for mutation in ("missing", "six", "window32", "boolean", "float", "counter",
                         "scope", "profile", "extra"):
            with self.subTest(mutation=mutation):
                self.files = fixture_v3()
                first = self.files["run.jsonl"][0]
                contract = first["header_window_contract"]
                if mutation == "missing":
                    first.pop("header_window_contract")
                elif mutation == "six":
                    contract["complete_admission_windows"] = 6
                elif mutation == "window32":
                    contract["maximum_ancestor_headers_per_window"] = 32
                elif mutation == "boolean":
                    contract["complete_admission_windows"] = True
                elif mutation == "float":
                    contract["complete_admission_windows"] = 3.0
                elif mutation == "counter":
                    contract["counter"] = "all_sql_reads"
                elif mutation == "scope":
                    contract["scope"] = "half of total SQL and latency"
                elif mutation == "profile":
                    contract["profile"] = "unbound"
                else:
                    contract["production_qualified"] = True
                self.refused()

    def test_relabelling_v2_as_v3_or_v3_as_v2_does_not_change_observed_counts(self):
        self.files = fixture_v2()
        first = self.files["run.jsonl"][0]
        first["schema"] = "native-growth-fixed-owner-scale-observation-v3"
        first["header_window_contract"] = fixture_v3()["run.jsonl"][0]["header_window_contract"]
        self.write()
        with self.assertRaisesRegex(ValueError, "exact native header window count"):
            self.read()
        self.files = fixture_v3()
        first = self.files["run.jsonl"][0]
        first["schema"] = "native-growth-fixed-owner-scale-observation-v2"
        first.pop("header_window_contract")
        self.write()
        with self.assertRaisesRegex(ValueError, "exact native header window count"):
            check(self.root, historical_v2=True)

    def test_v3_keeps_failed_cancelled_and_unobserved_returns_in_planned_denominator(self):
        for mutation in ("failed_admission", "failed_activation", "missing_return", "missing_cancellation"):
            with self.subTest(mutation=mutation):
                self.files = fixture_v3()
                if mutation in ("failed_admission", "failed_activation"):
                    operation = "admission" if mutation == "failed_admission" else "activation"
                    row = self.receipt(operation=operation)
                    row.update(accepted=False, returned_block=None, error="PUBLIC_REQUEST_DEADLINE",
                               error_code="PUBLIC_REQUEST_DEADLINE")
                elif mutation == "missing_return":
                    self.cohort().remove(self.receipt())
                else:
                    self.cohort().remove(self.receipt(sample=None, purpose="atomic_cancellation"))
                self.refused()


if __name__ == "__main__":
    unittest.main()
