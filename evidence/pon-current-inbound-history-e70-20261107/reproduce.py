#!/usr/bin/env python3
"""Read pinned, failed e70 CI artifacts without executing their native binaries.

Prints deterministic diagnostic JSON. Exit zero means the reader verified its
inputs, never that the original acceptance tests passed. ZIPs are supplied by the
caller; this script does not fetch data, run workloads, or change acceptance rules.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import zipfile

HEAD = "e70f13448aad715286fb8eb56fc802b09db643a3"
TREE = "1fc19c44ab2d4b35672b25d0f4e4039b769cadea"
ARCHIVES = {
    "f0": ("e70-f0-original.zip", "85df3a7e3959ce6ff0f673837ca6ca6f0d6b92dfbfdeb062ea25f3d03baa2ae3", 42352433638, 13565944759),
    "campaign": ("e70-native-campaign-original.zip", "1e3db14094e171bbba436afa70769c5df4b7beb57db6336687e7b51189f18733", 42352433857, 13566067509),
    "history": ("e70-history-original.zip", "14bc8eb4d062ad5fbd8cb17d088dfaffae726e2a2dc6d18d0ea09467d1afd185", 42352433738, 13568123690),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def open_archive(directory, kind):
    filename, expected, _, _ = ARCHIVES[kind]
    path = directory / filename
    require(file_digest(path) == expected, f"{kind}: archive SHA256 mismatch")
    archive = zipfile.ZipFile(path)
    require(len(set(archive.namelist())) == len(archive.namelist()), "duplicate ZIP member")
    return archive


def read_json(archive, member):
    return json.loads(archive.read(member))


def checked_member(archive, member, expected):
    raw = archive.read(member)
    require(digest(raw) == expected, f"{member}: SHA256 mismatch")
    return raw


def take(record, *keys):
    return {key: record[key] for key in keys}


def stage_pair(phase):
    before = phase["client_native_history_arithmetic_before"]
    after = phase["client_native_history_arithmetic_after"]
    b = {row["stage"]: row["totals"] for row in before["stages"]}
    a = {row["stage"]: row["totals"] for row in after["stages"]}
    require(a.keys() == b.keys(), "stage set changed")
    delta = {stage: {key: a[stage][key] - b[stage][key] for key in a[stage]} for stage in a}
    require(all(value >= 0 for row in delta.values() for value in row.values()), "non-monotone stages")
    require(not before["stage_observation_failed"] and not after["stage_observation_failed"], "stage observation failed")
    return {"before": b, "after": a, "delta": delta,
            "scope": after["scope"], "nested_intervals_additive": False}


def f0_readback(directory):
    with open_archive(directory, "f0") as z:
        prepared = read_json(z, "prepared/prepared.json")
        result = read_json(z, "execution/results.json")
        require(result["head"] == prepared["head"] == HEAD, "F0 head mismatch")
        require(result["tree"] == prepared["tree"] == TREE, "F0 tree mismatch")
        checked_member(z, "prepared/prepared.json", result["prepared_sha256"])
        checked_member(z, "prepared/public_v3_multiprocess.bin", prepared["binary"]["sha256"])
        report = json.loads(checked_member(z, "execution/raw/report.json", result["report_sha256"]))
        finalization = read_json(z, "finalization/result.json")
        rounds = []
        for row in result["all_planned_rounds"]:
            row = dict(row)
            start, end = row["actual_started_ns"], row["actual_ended_ns"]
            row["actual_call_duration_ns"] = None if start is None or end is None else end - start
            rounds.append(row)
        require(len(rounds) == result["planned_confirmations"], "missing planned rounds")
        require(sum(row["four_second_slo_met"] for row in rounds) == result["four_second_slo_successes"], "SLO count mismatch")
        return {
            **take(result, "complete_success", "failure", "native_result_failure", "report_validation_failure",
                   "native_execution_observed", "controller_resources_complete", "planned_confirmations",
                   "planned_business_packet_exposures", "four_second_slo_successes", "inputs", "report_sha256"),
            "binary": prepared["binary"], "state_backend": report["state_backend"],
            "all_planned_rounds": rounds,
            "phases": [{"mode": phase["mode"], "client_stages": stage_pair(phase)} for phase in report["phases"]],
            "finalization": take(finalization, "complete_success", "all_services_known_empty"),
        }


def campaign_readback(directory):
    with open_archive(directory, "campaign") as z:
        result = read_json(z, "results.json")
        require(result["expected_head"] == HEAD and result["expected_tree"] == TREE, "campaign source mismatch")
        binary = result["binary"]
        require(binary["sha256_before"] == binary["sha256_after"], "campaign binary changed")
        checked_member(z, binary["retained"], binary["sha256_before"])
        runs = []
        for number in range(1, result["planned_complete_runs"] + 1):
            attempt = read_json(z, f"run-{number}-result.json")
            report = json.loads(checked_member(z, f"run-{number}-raw/report.json", attempt["report_sha256"]))
            runs.append({
                **take(attempt, "number", "complete_success", "original_criteria_met", "phase_startup_errors", "report_validation_failure", "report_sha256"),
                "process": take(attempt["step"], "returncode", "elapsed_ns", "command"),
                **take(report, "economics_complete", "finite_experiment_criteria_met", "best_observed_cold_legal_method", "scope"),
                "phases": [take(phase, "mode", "duration_seconds", "attacker_processes_requested", "finite_phase_criteria_met", "all_signed_rounds_confirmed_in_window", "receiver_client_state_equal", "observer_complete", "genuine_budget_depletion_observed", "full_work_accepted", "full_work_failed") for phase in report["phases"]],
            })
        return {**take(result, "complete_success", "failure", "planned_complete_runs", "state_backend", "original_inputs", "expected_resources", "scope"), "binary": binary, "runs": runs}


def database_readback(z, role):
    # Only copy the two known members. Never execute files or extract ZIP paths.
    member = f"history-native/long-history/{role}/native.sqlite"
    with tempfile.TemporaryDirectory(prefix="e70-retained-sqlite-") as directory:
        path = Path(directory) / "retained.sqlite"
        with z.open(member) as source, path.open("wb") as target:
            shutil.copyfileobj(source, target)
        db_hash = file_digest(path)
        connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            connection.execute("PRAGMA query_only = ON")
            count, low, high = connection.execute("SELECT count(*), min(height), max(height) FROM blocks").fetchone()
            active = connection.execute("SELECT a.singleton, lower(hex(a.tip)), a.generation, a.state_slot, b.height FROM active a LEFT JOIN blocks b ON b.id = a.tip").fetchall()
            pending = connection.execute("SELECT count(*) FROM reorg").fetchone()[0]
        finally:
            connection.close()
        require(file_digest(path) == db_hash, "read-only database bytes changed")
        return {"member": member, "sha256": db_hash, "bytes": path.stat().st_size,
                "retained_block_rows_including_genesis": count, "minimum_height": low, "maximum_height": high,
                "active_rows": [dict(zip(("singleton", "tip", "generation", "state_slot", "height"), row)) for row in active],
                "pending_reorg_rows": pending,
                "scope": "Offline immutable read of retained SQLite main-file bytes; no replay or crash-recovery claim."}


def history_readback(directory):
    with open_archive(directory, "history") as z:
        manifest = read_json(z, "history-native/manifest.json")
        source = manifest["source_before"]
        require(source == manifest["source_after"], "history source changed")
        require(source["commit"] == HEAD and source["tree"] == TREE, "history source mismatch")
        require(manifest["binary_before"] == manifest["binary_after"], "history binary metadata changed")
        checked_member(z, "history-native/preparation.json", manifest["preparation_sha256"])
        log = checked_member(z, "history-native/history.log", manifest["log"]["sha256"]).decode()
        resource_text = checked_member(z, "history-native/history-resources.txt", manifest["resources"]["sha256"]).decode()
        summary = json.loads(checked_member(z, "history-native/long-history/summary.json", manifest["summary_file"]["sha256"]))
        records = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
        def unique(schema):
            rows = [row for row in records if row.get("schema") == schema]
            require(len(rows) == 1, f"expected exactly one {schema}")
            return rows[0]
        server = unique("native-ancestry-public-server-exit-evidence-v1")
        sync = unique("native-ancestry-independent-sync-exit-evidence-v1")
        config = read_json(z, "history-native/long-history/config.json")
        packet_count = sum(bool(re.fullmatch(r"history-native/long-history/packets/[0-9]{5}\.bin", name)) for name in z.namelist())
        return {
            **take(manifest, "passed", "native_execution_authenticated", "named_execution", "whole_test_command_preserved", "compilation_in_native_measurement", "failures", "selector", "process"),
            "source": source, "binary_metadata": manifest["binary_before"],
            "binary_bytes_retained_in_this_zip": False,
            "config": config, "packet_members": packet_count, "summary": summary,
            "server_exit": server,
            "sync_exit": take(sync, "elapsed_ns", "sync_error", "failure_location"),
            "legacy_reorg_observation": sync["native_legacy_reorg_observation"],
            "resource_text": resource_text,
            "retained_databases": {role: database_readback(z, role) for role in ("confirmer", "validator")},
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_directory", type=Path)
    args = parser.parse_args()
    result = {
        "schema": "pon-e70-inbound-history-failed-artifact-readback-v1",
        "source": {"head": HEAD, "tree": TREE},
        "scope": "Read-only extraction of three original CI artifacts. Reader completion is not native acceptance, release qualification or production activation.",
        "artifacts": {kind: {"filename": row[0], "sha256": row[1], "run_id": row[2], "artifact_id": row[3]} for kind, row in ARCHIVES.items()},
        "f0": f0_readback(args.artifact_directory),
        "campaign": campaign_readback(args.artifact_directory),
        "history": history_readback(args.artifact_directory),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
