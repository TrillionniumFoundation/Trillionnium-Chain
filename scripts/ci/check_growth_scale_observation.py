#!/usr/bin/env python3
"""Validate every planned native growth observation, including cancellation.

This reader checks a bounded observation set, not execution attestation. Its
caller must separately require the exact native selector, successful process,
original workspace artifact and unchanged source/binary before and after.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ACCOUNTS = (64, 1024, 16384)
HISTORY = (0, 16, 128)
SAMPLES = 8
HEX = re.compile(r"[0-9a-f]{64}")
MAX_FILE_BYTES = 4 * 1024 * 1024
COUNTERS = {
    "context_checks", "header_ancestors", "full_work_checkpoints",
    "execution_checkpoints", "cow_account_node_checkpoints", "reorg_ancestors",
    "reorg_writes", "reorg_readbacks", "before_commit_checks",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def number(value):
    require(type(value) is int and 0 <= value <= (1 << 64) - 1, "unsigned integer")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def nonfinite(value):
    raise ValueError("nonfinite JSON: " + value)


def floating(value):
    raise ValueError("floating point is not part of this observation schema: " + value)


def read_rows(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE_BYTES,
                "observation must be a bounded regular file")
        raw = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
        fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                     value.st_mtime_ns, value.st_ctime_ns)
        require(fingerprint(info) == fingerprint(after), "observation changed while reading")
        require(len(raw) == info.st_size and raw.endswith(b"\n"), "incomplete observation file")
    rows = []
    for line in raw.splitlines():
        require(0 < len(line) <= 256 * 1024, "observation line limit")
        row = json.loads(line, object_pairs_hook=unique_object,
                         parse_constant=nonfinite, parse_float=floating)
        require(type(row) is dict, "observation object")
        rows.append(row)
    require(0 < len(rows) <= 1024, "observation record limit")
    return rows, {"file": path.name, "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest()}


def hash_id(value):
    require(type(value) is str and HEX.fullmatch(value), "hash identity")
    return value


def owners(value, allow_empty=False):
    require(type(value) is list and (value or allow_empty) and len(value) <= 256, "witness owner list")
    require(all(type(owner) is str and HEX.fullmatch(owner) for owner in value),
            "witness owner identity")
    require(value == sorted(set(value)), "duplicate or unordered witness owners")
    return tuple(value)


def stage(value, admission):
    require(type(value) is dict, "native stage")
    wall = number(value["wall_ns"])
    counters = value["checkpoints"]
    require(type(counters) is dict and set(counters) == COUNTERS, "checkpoint inventory")
    for count in counters.values():
        number(count)
    require(counters["before_commit_checks"] == 1, "native durable commit checkpoint")
    if admission:
        require(all(counters[key] > 0 for key in ("context_checks",
                    "full_work_checkpoints", "execution_checkpoints", "cow_account_node_checkpoints")),
                "complete native admission checkpoints")
    else:
        require(counters["reorg_ancestors"] == counters["reorg_writes"] == 1
                and counters["reorg_readbacks"] > 0, "native straight activation checkpoints")
    offsets = [value[key] for key in ("before_persistence_offset_ns", "before_commit_offset_ns")]
    for offset in offsets:
        if offset is not None:
            require(number(offset) <= wall, "stage offset outside inclusive wall time")
    persistence, commit = offsets
    require(commit is not None and (persistence is not None if admission else persistence is None),
            "native persistence/commit observation")
    require(not admission or persistence <= commit, "native persistence order")
    nested = value["persistence_and_readback_wall_ns"]
    tail = value["final_guard_and_sqlite_commit_wall_ns"]
    require(nested == (commit - persistence if persistence is not None and commit is not None
                       and commit >= persistence else None), "nested persistence interval")
    require(tail == (wall - commit if commit is not None else None), "commit tail interval")
    if nested is not None:
        number(nested)
    if tail is not None:
        number(tail)
    return wall


def working(value):
    require(type(value) is dict, "working partition observation")
    require(number(value["keys"]) > 0 and number(value["canonical_bytes"]) > 0,
            "complete bounded working partition")
    mandatory = owners(value["mandatory_owners"], allow_empty=True)
    require(number(value["mandatory_owner_count"]) == len(mandatory), "mandatory owner count")
    obligations = value["obligation_rows_by_prefix"]
    require(type(obligations) is dict and set(obligations) == {"reward:", "task:", "quota:", "escrow:"},
            "obligation observation inventory")
    require(sum(number(count) for count in obligations.values()) <= value["keys"], "obligation row count")
    return set(mandatory)


def disk(value):
    require(type(value) is dict, "disk point observation")
    sizes = value["file_bytes"]
    require(type(sizes) is dict and set(sizes) == {"native.sqlite", "native.sqlite-wal", "native.sqlite-shm"},
            "disk point file inventory")
    for size in sizes.values():
        number(size)


def sql_rows(value, height):
    require(type(value) is dict and set(value) == {"blocks", "growth_states", "archive_nodes", "deltas", "events", "steps"},
            "SQL table observation inventory")
    for count in value.values():
        number(count)
    require(value["blocks"] == value["growth_states"] == height + 1
            and value["events"] == height and value["steps"] == min(1, height)
            and value["archive_nodes"] > 0, "actual durable history rows")
    return value


def check(directory):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "observation directory")
    expected_files = {"run.jsonl"} | {
        f"cohort-a{accounts}-h{history}.jsonl" for accounts in ACCOUNTS for history in HISTORY
    }
    require({path.name for path in directory.iterdir()} == expected_files, "exact cohort file set")
    run, identity = read_rows(directory / "run.jsonl")
    require(len(run) == 2, "complete run start/end required")
    first, last = run
    require(first["schema"] == "native-growth-fixed-owner-scale-observation-v1"
            and first["event"] == "run_started" and last["event"] == "run_completed", "run context")
    require([number(value) for value in first["accounts"]] == list(ACCOUNTS)
            and [number(value) for value in first["warmup_history_blocks"]] == list(HISTORY)
            and number(first["measured_blocks_per_cohort"]) == SAMPLES
            and number(first["workers"]) == 1
            and number(first["work_search_attempt_limit"]) == 4096, "frozen native workload")
    require(first["wall_time_acceptance_gate"] is False and first["completed"] is False,
            "start cannot claim completion")
    require(first["setup_reference_diagnostics_and_cancellation_excluded_from_native_stage_timings"] is True,
            "native timing scope")
    declared_owners = first["declared_transaction_owners"]
    require(type(declared_owners) is list and len(declared_owners) == 3,
            "fixed transaction owner inventory")
    declared_owners = {hash_id(owner) for owner in declared_owners}
    require(len(declared_owners) == 3, "distinct transaction owners")
    require(first["p99_ns"] is None and last["p99_ns"] is None
            and last["throughput_claim"] is False and last["production_qualified"] is False,
            "unqualified scope")
    require(number(last["completed_cohorts"]) == 9
            and number(last["completed_measurements"]) == 72, "planned denominator")
    source_files, cohorts, owner_sets = [identity], [], set()
    contexts_by_accounts = {}
    for accounts in ACCOUNTS:
        for history in HISTORY:
            rows, identity = read_rows(directory / f"cohort-a{accounts}-h{history}.jsonl")
            source_files.append(identity)
            pos = 0

            def take(event):
                nonlocal pos
                require(pos < len(rows) and rows[pos].get("event") == event,
                        f"missing or reordered {event}")
                row = rows[pos]
                pos += 1
                return row

            start = take("cohort_started")
            require((number(start["accounts"]), number(start["warmup_history_blocks"]),
                     number(start["planned_measurements"])) == (accounts, history, SAMPLES),
                    "cohort context")
            for index in range(history):
                warmup_start = take("warmup_started")
                require(number(warmup_start["index"]) == index, "warmup denominator")
                hash_id(warmup_start["parent"])
            warmup = take("warmup_completed")
            context = tuple(hash_id(warmup[key]) for key in ("network", "parameters", "genesis"))
            require(contexts_by_accounts.setdefault(accounts, context) == context,
                    "fixed-account context changed across history cohorts")
            for key in ("setup_wall_ns", "native_warmup_wall_ns", "full_reference_warmup_wall_ns"):
                number(warmup[key])
            previous_rows = sql_rows(warmup["sql_rows"], history)
            previous_working = warmup["working"]
            working(previous_working)
            disk(warmup["disk_sample"])
            previous_block = warmup["genesis"] if history == 0 else None
            seen_blocks = set()
            times, query_reads, copied_nodes, witness_sizes = [], [], [], []
            for sample in range(SAMPLES):
                begun, done = take("measurement_started"), take("measurement_completed")
                require(number(begun["sample"]) == number(done["sample"]) == sample,
                        "missing or duplicated planned sample")
                require(number(begun["history_blocks_before"]) == history + sample
                        and number(done["history_blocks_before"]) == history + sample
                        and number(done["history_blocks_after"]) == history + sample + 1
                        and number(done["accounts"]) == accounts, "sample context")
                require(done["complete_state_reference_equal"] is True and done["p99_ns"] is None,
                        "complete state and unresolved p99")
                parent, block = hash_id(begun["parent"]), hash_id(done["block"])
                require(previous_block is None or parent == previous_block, "native block continuity")
                require(block != parent and block not in seen_blocks, "unique measured native blocks")
                seen_blocks.add(block)
                previous_block = block
                require(number(done["active_generation"]) == history + sample + 1,
                        "atomic active generation")
                current_owners = owners(done["actual_witness_owners"])
                require(number(done["actual_witness_accounts"]) == len(current_owners), "actual touched set")
                require(done["parent_working"] == previous_working, "working partition continuity")
                mandatory = working(done["parent_working"])
                working(done["successor_working"])
                require(set(current_owners) == declared_owners | mandatory, "complete actual mandatory touched set")
                previous_working = done["successor_working"]
                owner_sets.add(current_owners)
                times.append(stage(done["native_admission"], admission=True))
                stage(done["native_activation"], admission=False)
                ancestors = done["native_admission"]["checkpoints"]["header_ancestors"]
                require((ancestors == 0) == (history + sample == 0),
                        "actual bounded ancestor lookup scope")
                number(done["make_signed_packet_and_full_work_wall_ns"])
                number(done["complete_state_reference_and_diagnostics_wall_ns"])
                require(number(done["full_work_proof_bytes"]) == 49188, "complete original W1 proof width")
                witness = number(done["witness_bytes"])
                require(witness > 0 and number(done["packet_bytes"]) > 49188 + witness,
                        "complete packet and witness widths")
                number(done["witness_frontier_nodes"])
                query = done["separate_successor_query"]
                reads = number(query["point_reads"])
                require(number(query["witness_bytes"]) > 0, "complete successor witness")
                copied = number(done["retained_cow_nodes_added"])
                require(reads < 1024 and copied < 4096
                        and number(query["expanded_witnesses_allocated"]) == 0,
                        "original bounded witness/COW observation")
                query_reads.append(reads)
                copied_nodes.append(copied)
                witness_sizes.append(witness)
                before_rows = sql_rows(done["sql_rows_before"], history + sample)
                after_rows = sql_rows(done["sql_rows_after"], history + sample + 1)
                require(before_rows == previous_rows, "SQL history continuity")
                previous_rows = after_rows
                delta = number(done["retained_delta_rows_added"])
                require(after_rows["archive_nodes"] - before_rows["archive_nodes"] == copied
                        and after_rows["deltas"] - before_rows["deltas"] == delta,
                        "actual retained COW/delta changes")
                require(number(done["admission_sql_total_changes"]) >= copied + delta + 2
                        and number(done["activation_sql_total_changes"]) >= 4, "actual SQL changes")
                disk(done["disk_sample"])
                for table in ("blocks", "growth_states", "events"):
                    require(number(done["sql_rows_after"][table]) ==
                            number(done["sql_rows_before"][table]) + 1, "durable row denominator")
            take("atomic_cancellation_started")
            cancel = take("atomic_cancellation_completed")
            require(cancel["error"] == "SCALE_OBSERVATION_BEFORE_COMMIT_CANCEL"
                    and cancel["all_sql_rows_equal"] is True
                    and cancel["active_generation_equal"] is True, "atomic cancellation")
            take("cold_reopen_started")
            end = take("cohort_completed")
            require(pos == len(rows), "trailing cohort observations")
            require(number(end["accounts"]) == accounts and number(end["warmup_history_blocks"]) == history
                    and number(end["measured_blocks"]) == SAMPLES
                    and number(end["successful_native_admissions"]) == history + SAMPLES
                    and number(end["deliberately_cancelled_admissions"]) == 1
                    and number(end["failed_unexpected_admissions"]) == 0
                    and number(end["cold_reopens"]) == 1
                    and end["cold_complete_reference_equal"] is True, "complete cohort denominator")
            journal = end["separate_post_open_journal_differential"]
            for key in ("wall_ns", "latest_steps", "latest_events", "peak_event_rows"):
                number(journal[key])
            require(number(journal["typed_events"]) == number(journal["semantic_events"]) == history + SAMPLES,
                    "complete retained journal")
            sorted_times = sorted(times)
            require([number(value) for value in end["admission_median_interval_ns"]] == sorted_times[3:5]
                    and number(end["admission_max_ns"]) == sorted_times[-1]
                    and end["p99_ns"] is None and end["production_qualified"] is False,
                    "honest sample summary")
            disk(end["disk_before_close"])
            disk(end["disk_after_reopen"])
            cohorts.append({"accounts": accounts, "warmup_history_blocks": history,
                            "measured_blocks": SAMPLES, "admission_median_interval_ns": sorted_times[3:5],
                            "separate_query_point_reads_min_max": [min(query_reads), max(query_reads)],
                            "copied_nodes_min_max": [min(copied_nodes), max(copied_nodes)],
                            "witness_bytes_min_max": [min(witness_sizes), max(witness_sizes)],
                            "cold_reopen_wall_ns": number(end["cold_reopen_wall_ns"]), "p99_ns": None})
    require(len(owner_sets) == 1 and last["fixed_witness_owner_set_observed"] is True
            and [list(row) for row in sorted(owner_sets)] == last["actual_distinct_witness_owner_sets"],
            "fixed actual touched owners not demonstrated")
    return {"schema": "native-growth-fixed-owner-scale-readback-v1", "result": "COMPLETE_LOCAL_OBSERVATION",
            "completed_cohorts": 9, "measured_native_blocks": 72, "cancelled_admissions": 9,
            "cold_reopens": 9, "fixed_witness_owners": list(next(iter(owner_sets))),
            "cohorts": cohorts, "files": source_files, "p99_ns": None,
            "requires_separate_source_binary_and_native_exit_verification": True,
            "throughput_qualified": False, "public_network_ready": False, "production_activation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        result = check(args.directory)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        print(json.dumps({"result": "REFUSED", "error": str(error)}))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
