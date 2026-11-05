#!/usr/bin/env python3
"""Combine four independently verified, exact-source Node readbacks; no native runs."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": digest(raw)}


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
    return fingerprint(path)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--directory", required=True, type=Path)
parser.add_argument("--candidate", required=True)
parser.add_argument("--run-id", required=True, type=int)
parser.add_argument("--job-metadata", required=True, type=Path)
args = parser.parse_args()
directory = args.directory.resolve(strict=True)
metadata = json.loads(args.job_metadata.read_text())
assert metadata["candidate"] == args.candidate
raw = json.loads(metadata["tool_result"]["value"]["structuredContent"]["content"])
assert raw["total_count"] == len(raw["jobs"]) == 4
jobs = {row["id"]: row for row in raw["jobs"]}
lanes = []
records = []
readbacks = []
for lane in ("x64-head", "x64-merge", "arm64-head", "arm64-merge"):
    paths = sorted(directory.glob("pq-node-" + lane + "-*-readback.json"))
    assert len(paths) == 1, (lane, paths)
    path = paths[0]
    row = json.loads(path.read_text())
    assert row["candidate"] == args.candidate and row["run_id"] == args.run_id
    assert row["lane"] == lane and row["complete_974_registry_matched"] is True
    assert row["counts"] == {"pass": 951, "fail": 0, "original_ignored": 23, "measured": 0, "filtered": 0}
    assert len(row["unique_pass_names"]) == len(set(row["unique_pass_names"])) == 951
    assert len(row["ignored_names_and_reasons"]) == 23
    assert len(row["original43_named_controls"]) == 43
    assert all(control["executed_tests"] == 1 and control["result"] == "PASS"
               for control in row["original43_named_controls"])
    assert row["strict_clippy"]["exit_code"] == row["node_command"]["exit_code"] == 0
    job = jobs[row["job_id"]]
    assert job["head_sha"] == args.candidate and job["run_id"] == args.run_id
    assert job["status"] == "completed" and job["conclusion"] == "success"
    source = row["source"]
    expected_commit = args.candidate if lane.endswith("-head") else row["actual_merge"]
    assert source["tested_commit"] == expected_commit and source["tested_tree"] == row["tree"]
    raw_path = path.with_name(path.name.replace("-readback.json", "-original-records.json.gz"))
    readback_file = fingerprint(path)
    originals_file = fingerprint(raw_path)
    records.extend([readback_file, originals_file])
    lanes.append({
        "lane": lane, "job_id": job["id"], "job_started_at": job["started_at"],
        "job_completed_at": job["completed_at"], "job_status": job["status"],
        "job_conclusion": job["conclusion"], "artifact_id": row["artifact_id"],
        "artifact_bytes": row["artifact_bytes"], "artifact_sha256": row["artifact_sha256"],
        "source": source, "outer_summary": row["outer_summary"], "counts": row["counts"],
        "actual_compiler_profile": row["compiler_artifact"]["profile"],
        "original43_named_control_count": len(row["original43_named_controls"]),
        "strict_clippy_exit": row["strict_clippy"]["exit_code"],
        "readback": readback_file, "complete_original_records": originals_file,
        "native_elf_sha256": row["binary_sha256"], "native_elf_scope": row["binary_hash_scope"],
    })
    readbacks.append(row)

first = readbacks[0]
assert len({row["actual_merge"] for row in readbacks}) == len({row["tree"] for row in readbacks}) == 1
assert all(row["unique_pass_names"] == first["unique_pass_names"] for row in readbacks)
assert all(row["ignored_names_and_reasons"] == first["ignored_names_and_reasons"] for row in readbacks)
assert all([control["test"] for control in row["original43_named_controls"]]
           == [control["test"] for control in first["original43_named_controls"]] for row in readbacks)
assert all(row["frozen_registry"] == first["frozen_registry"] for row in readbacks)
registry = first["frozen_registry"]
assert digest(Path(registry["path"]).read_bytes()) == registry["sha256"]
observed = datetime.datetime.now(datetime.timezone.utc).isoformat()
scope = ("951 unique PASS names repeated on four exact source/architecture lanes. The original43 "
         "selectors overlap that population and are not added. Nested subprocess harness summaries "
         "are retained in per-lane records but not added. The three candidate diagnostic tests are "
         "included; all23 original ignored tests remain ignored. W1 History default-feature958 is "
         "a separate invocation profile. No results from a previous candidate are inherited.")
aggregate = {
    "schema": "exact-candidate-original-node-974-four-lane-terminal-readback-v1",
    "observed_utc": observed, "candidate": args.candidate, "actual_merge": first["actual_merge"],
    "tree": first["tree"], "run_id": args.run_id, "attempt": first["attempt"],
    "source_binding": fingerprint(directory / "source-binding.json"),
    "terminal_job_metadata": fingerprint(args.job_metadata),
    "same_951_unique_pass_names_all_four_lanes": True,
    "same_23_original_ignored_names_and_reasons_all_four_lanes": True,
    "same_43_original_selector_names_all_four_lanes": True,
    "registry_reference": {key: value for key, value in registry.items() if key != "registered"},
    "unique_pass_names_sha256": digest(("\n".join(first["unique_pass_names"]) + "\n").encode()),
    "original_ignored_names_and_reasons": first["ignored_names_and_reasons"], "lanes": lanes,
    "claims": {"four_original_full_node_lanes_pass": True, "four_original43_control_lanes_pass": True,
               "four_original_strict_clippy_commands_pass": True, "whole_workspace_pass": False,
               "nine_host_runtime_selectors_pass": False, "original_business_performance_acceptance_pass": False,
               "other_source_qualified": False, "whole_chain_pq_qualified": False,
               "release_or_activation_authorized": False},
    "counts_scope": scope, "reader": fingerprint(Path(__file__).resolve()),
}
aggregate_file = write_new(directory / "pq-original-node-four-lane-readback.json", aggregate)
handoff = {
    "schema": "exact-candidate-four-lane-node-small-handoff-v1", "observed_utc": observed,
    "candidate": args.candidate, "actual_merge": first["actual_merge"], "tree": first["tree"],
    "run_id": args.run_id, "aggregate": aggregate_file,
    "records": [row for row in records if "/pq-node-arm64-" in row["path"]],
    "previously_frozen_x64_handoff": fingerprint(directory / "pq-two-x64-terminal-handoff.json"),
    "new_file_scope": "Only the two newly completed ARM lane readbacks/original bundles and the four-lane aggregate/index are handed off here. Existing x64 files are referenced without rewriting or duplicating them.",
    "scope": scope,
    "metadata": fingerprint(args.job_metadata), "reader": fingerprint(Path(__file__).resolve()),
}
handoff_file = write_new(directory / "pq-original-node-four-lane-handoff.json", handoff)
print(json.dumps({"aggregate": aggregate_file, "handoff": handoff_file,
                  "lanes": [{key: row[key] for key in ("lane", "job_id", "artifact_id", "outer_summary")}
                            for row in lanes]}, indent=2))
