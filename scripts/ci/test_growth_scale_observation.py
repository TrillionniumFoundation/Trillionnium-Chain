#!/usr/bin/env python3
"""Independent reader fixtures; these do not claim that native work executed."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from check_growth_scale_observation import check


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


class GrowthObservationReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-growth-reader-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "observations"
        self.root.mkdir()
        self.files = fixture()
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
            check(self.root)

    def test_complete_fixture_accepts_all_seventy_two_samples_without_qualification(self):
        result = check(self.root)
        self.assertEqual(result["result"], "COMPLETE_LOCAL_OBSERVATION")
        self.assertEqual(result["measured_native_blocks"], 72)
        self.assertEqual(result["cancelled_admissions"], 9)
        self.assertEqual(result["cold_reopens"], 9)
        self.assertEqual(result["fixed_witness_owners"], OWNERS)
        self.assertEqual(len(result["files"]), 10)
        self.assertIsNone(result["p99_ns"])
        self.assertFalse(result["throughput_qualified"])
        self.assertFalse(result["production_activation"])

    def test_missing_cohort_file_is_refused(self):
        (self.root / "cohort-a16384-h128.jsonl").unlink()
        with self.assertRaises(ValueError):
            check(self.root)

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
                    check(self.root)

    def test_symlinked_file_and_directory_are_refused(self):
        path = self.root / "run.jsonl"
        target = Path(self.temp.name) / "retained-run.jsonl"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises((OSError, ValueError)):
            check(self.root)
        path.unlink()
        target.rename(path)
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            check(alias)

    def test_extra_file_and_trailing_event_are_refused(self):
        extra = self.root / "omitted-failure.jsonl"
        extra.write_text("{}\n")
        with self.assertRaises(ValueError):
            check(self.root)
        extra.unlink()
        self.cohort().append({"event": "unreported_failure"})
        self.refused()

    def test_duplicate_json_keys_and_missing_final_newline_are_refused(self):
        path = self.root / "run.jsonl"
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'"workers":1', b'"workers":1,"workers":1'))
        with self.assertRaises(ValueError):
            check(self.root)
        path.write_bytes(raw[:-1])
        with self.assertRaises(ValueError):
            check(self.root)

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


if __name__ == "__main__":
    unittest.main()
