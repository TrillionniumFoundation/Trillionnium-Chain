#!/usr/bin/env python3
"""Read actual C1 records only; verify all nine Host selectors and preserve later abort."""
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

P = Path(__file__).resolve().parent
HEAD = "c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1"
MERGE = "7a3e125cb343bd85fb806aba87a21f99eac082de"
TREE = "30f59a8ec2abdc269bf91e228c58206b23add43d"
RUN = 41728500537
LIMITS = {"cpu.max": "25000 100000", "cpu.max.burst": "0", "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "256"}
TARGET = "public_submit_recovery"
ABORTED = "actual_equal_work_duplicate_ack_and_heavier_fork_do_not_advance_dependencies"
COMMAND = "cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def write_new(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
    return ref(path)


repo = Path("/workspace/scratch/b5a148b09b11/chain-six-axis")
source_path = "trillionnium/crates/trnm-pon-node/tests/public_submit_recovery.rs"
source_raw = subprocess.check_output(["git", "-C", str(repo), "show", HEAD + ":" + source_path])
source_blob = subprocess.check_output(["git", "-C", str(repo), "rev-parse", HEAD + ":" + source_path]).decode().strip()
registry = sorted(re.findall(r"(?m)^#\[test\]\nfn ([a-zA-Z0-9_]+)\(", source_raw.decode()))
assert len(registry) == len(set(registry)) == 24
meta_path = P / "20261103T234204327Z-baseline-final-full-jobs.json"
metadata = json.loads(meta_path.read_text())
assert metadata["candidate"] == HEAD
jobs = {row["id"]: row for row in json.loads(metadata["tool_result"]["value"]["structuredContent"]["content"])["jobs"]}
lanes = []
files = []
original_jobs = []
for lane, zip_lane, job_id, aid, commit in [
    ("head", "head", 126245171748, 13280768301, HEAD),
    ("actual-merge", "merge", 126245171763, 13280868776, MERGE),
]:
    readback_path = P / f"runtime-{lane}-{aid}-readback.json"
    originals_path = P / f"runtime-{lane}-{aid}-original-records.json.gz"
    readback = json.loads(readback_path.read_text())
    originals = json.loads(gzip.decompress(originals_path.read_bytes()))
    raw_records = {row["member"]: row for row in originals["records"]}
    assert len(raw_records) == originals["record_count"]
    for record in raw_records.values():
        raw = record["text"].encode()
        assert len(raw) == record["bytes"] and sha(raw) == record["sha256"]
    assert readback["candidate"] == HEAD and readback["source"] == commit and readback["tree"] == TREE
    assert readback["counts"] == {"native_pass": 9, "native_fail": 0, "native_incomplete": 0, "no_complete_manifest": 0}
    assert readback["rust_shard"]["status"] == "failed" and readback["rust_shard"]["exit_code"] == 101
    job = jobs[job_id]
    assert job["head_sha"] == HEAD and job["run_id"] == RUN
    assert job["status"] == "completed" and job["conclusion"] == "failure"
    steps = {row["number"]: row for row in job["steps"]}
    assert steps[9]["conclusion"] == "failure" and steps[10]["conclusion"] == "success"
    host_checks = []
    for observation in readback["public_fixture_observations"]:
        target, selector = observation["target"], observation["selector"]
        base = "public-fixtures/" + target + "/" + selector
        c = observation["controller"]
        process = observation["process"]
        binding = c["preparation_execution_binding"]
        before = json.loads(raw_records[base + "-host/inside-before.json"]["text"])
        after = json.loads(raw_records[base + "-host/outside-after.json"]["text"])
        assert observation["native_status"] == "PASS" and observation["manifest_passed"] is True
        assert observation["manifest_failures"] == [] and all(observation["integrity_checks"].values())
        assert observation["named_execution"]["executed_tests"] == 1 and observation["named_execution"]["result"] == "PASS"
        assert observation["named_execution"]["test"] == selector
        assert observation["native_execution_authenticated"] is True
        assert observation["runtime_limits_or_deadlines_changed"] is False
        assert process["started"] and process["reaped"] and process["supervisors_bound"]
        assert process["exit_code"] == 0 and process["failure"] is None and process["cleanup_errors"] == []
        assert not process["timed_out"] and process["supervisor_exit"] is None
        assert process["timeout_seconds"] == (120 if target == "architecture_delivery_compare" else None)
        assert observation["launch"]["passed"] is True and c["passed"] is True
        assert c["failure"] is None and c["final_host_errors"] == [] and c["cleanup"] == "already-collected"
        assert before["limits"] == after["limits"] == LIMITS
        assert after["counters"]["pids.current"] == "0" and "populated 0" in after["counters"]["cgroup.events"].splitlines()
        assert binding["source_commit"] == commit and binding["target"] == target and binding["selector"] == selector
        assert binding["binary_sha256"] == observation["binary"]["sha256"]
        assert binding["cli_binary_sha256"] == (observation["cli_binary"]["sha256"] if observation["cli_binary"] else None)
        assert binding["manifest_sha256"] == observation["manifest_sha256"]
        assert binding["performance_acceptance"] is False
        if target == "architecture_delivery_compare":
            report = raw_records[base + "/native/report.json"]
            assert binding["report_sha256"] == report["sha256"]
            assert binding["samples"] == 18 and binding["business_reader_passed"] is True and binding["business_reader_failure"] is None
        host_checks.append({
            "target": target, "selector": selector, "named_pass": True,
            "native_summary": observation["native_result_lines"][0],
            "native_binary": observation["binary"], "cli_binary": observation["cli_binary"],
            "source_identity": observation["source_before_after"],
            "controller_binding": binding, "original_limits_verified": LIMITS,
            "empty_after_verified": {"pids.current": after["counters"]["pids.current"], "cgroup.events": after["counters"]["cgroup.events"]},
            "cleanup": c["cleanup"], "native_timeout_seconds": process["timeout_seconds"],
        })
    script = raw_records["rust-shard.sh"]
    assert COMMAND in script["text"]
    assert 'export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"' in script["text"]
    workspace = raw_records["workspace-tests.log"]
    content = workspace["text"]
    start = content.index("     Running tests/public_submit_recovery.rs")
    terminal = content[start:]
    assert "running 24 tests" in terminal and "SIGABRT: process abort signal" in terminal
    assert "test result:" not in terminal, "aborted target must not have a fabricated final summary"
    named = re.findall(r"(?m)^test ([a-zA-Z0-9_]+) \.\.\. (.*)$", terminal)
    assert len(named) == len({name for name, status in named}) == 10
    passed = [name for name, status in named if status == "ok"]
    failed = [name for name, status in named if status == "FAILED"]
    incomplete = [name for name, status in named if status == ""]
    assert len(passed) == 6 and len(failed) == 3 and incomplete == [ABORTED]
    assert {name for name, status in named} <= set(registry)
    unobserved = sorted(set(registry) - {name for name, status in named})
    assert len(unobserved) == 14
    assert 'public_submit_recovery.rs:225:61' in terminal
    assert 'code: Some(OwnerReorgTerminationCpuRequired), kind: DependencyUnavailable, message: "OWNER_REORG_TERMINATION_CPU_REQUIRED"' in terminal
    assert 'left: Some("IO: Connection refused (os error 111)")' in terminal
    assert 'right: Some("SUBMIT_RECOVERY_STALE_BRANCH")' in terminal
    assert 'public_submit_recovery.rs:381:42' in terminal
    target_log = write_new(P / f"runtime-{lane}-public-submit-recovery.log", terminal.encode())
    files.extend([ref(readback_path), ref(originals_path), target_log])
    job_log_path = P / f"runtime-{zip_lane}-{job_id}-final-job.log"
    job_log = job_log_path.read_bytes()
    original_jobs.append({"lane": lane, "job_id": job_id, "file": job_log_path.name,
                          "bytes": len(job_log), "sha256": sha(job_log), "text": job_log.decode()})
    lanes.append({
        "lane": lane, "job_id": job_id, "source": commit, "tree": TREE,
        "job_started_at": job["started_at"], "job_completed_at": job["completed_at"],
        "native_step_started_at": steps[9]["started_at"], "native_step_completed_at": steps[9]["completed_at"],
        "artifact_id": aid, "artifact_bytes": readback["artifact_bytes"], "artifact_sha256": readback["artifact_sha256"],
        "readback": ref(readback_path), "full_original_records": ref(originals_path),
        "original_workspace_command": COMMAND, "original_script_sha256": script["sha256"],
        "workspace_log_bytes": workspace["bytes"], "workspace_log_sha256": workspace["sha256"],
        "rust_shard_exit_code": 101, "original_source_after_verified": True,
        "all_nine_host_selectors_pass": True, "host_selectors": host_checks,
        "public_submit_recovery": {
            "registered_tests": 24, "registered_names": registry, "pass_names": passed,
            "failed_names": failed, "started_then_process_aborted": incomplete,
            "unobserved_after_abort_names": unobserved, "final_libtest_summary": None,
            "target_log": target_log, "first_reported_failure_name": failed[0],
            "first_three_panic_details_available": False,
            "actual_error_target": ABORTED, "actual_error_source": "public_submit_recovery.rs:225:61",
            "actual_error": "Error { code: Some(OwnerReorgTerminationCpuRequired), kind: DependencyUnavailable, message: \"OWNER_REORG_TERMINATION_CPU_REQUIRED\", source: None, request_history_budget: false }",
            "followup_assertion_source": "public_submit_recovery.rs:1229:5",
            "actual_assertion_left": "IO: Connection refused (os error 111)", "actual_assertion_right": "SUBMIT_RECOVERY_STALE_BRANCH",
            "cleanup_panic_source": "public_submit_recovery.rs:381:42", "process_signal": "6/SIGABRT",
            "binary_sha256": None, "binary_hash_scope": "This target's ELF hash is not present in retained artifact records; do not substitute a Host-selector ELF hash.",
        },
    })

job_bundle = {"schema": "c1-runtime-two-lane-complete-original-job-logs-v1", "candidate": HEAD,
              "actual_merge": MERGE, "run_id": RUN, "records": original_jobs}
job_file = write_new(P / "runtime-two-lane-original-job-logs.json.gz", gzip.compress((json.dumps(job_bundle, indent=2) + "\n").encode(), mtime=0))
files.append(job_file)
now = datetime.datetime.now(datetime.timezone.utc).isoformat()
out = {
    "schema": "c1-runtime-nine-host-pass-later-workspace-abort-v1", "observed_utc": now,
    "candidate": HEAD, "actual_merge": MERGE, "tree": TREE, "run_id": RUN,
    "source_binding": ref(P / "source-binding.json"), "terminal_metadata": ref(meta_path),
    "public_submit_source": {"commit": HEAD, "path": source_path, "git_blob": source_blob, "bytes": len(source_raw), "sha256": sha(source_raw)},
    "profile_scope": {"original_command_uses_release": False, "actual_command": COMMAND,
                      "tracked_cargo_manifest": ref(P / "source-c5dd7c/trillionnium/Cargo.toml"),
                      "declared_trnm_pon_node_test_override": {"opt_level": 3, "debug_assertions": True, "overflow_checks": True},
                      "scope": "Original workspace cargo test command and tracked package test override retained. Per-fixture actual hosted ELF observations and build environment are in lane records. No compiler-artifact JSON is fabricated for this runtime artifact."},
    "lanes": lanes, "original_job_logs": job_file,
    "claims": {"all_nine_host_selectors_pass_in_both_c1_lanes": True, "evaluation_cpu_fixture_fix_observed_in_both_c1_lanes": True,
               "whole_workspace_pass": False, "public_submit_recovery_pass": False, "original_service_performance_acceptance_pass": False,
               "c2_or_future_source_runtime_qualified": False, "first_three_failed_tests_share_proven_cause": False,
               "release_or_activation_authorized": False},
    "counts_scope": "Nine unique original Host selector names executed independently in two exact source lanes. Later public_submit_recovery starts 24 registered tests but aborts after six named passes, three named failures and one entered selector; fourteen remain unobserved in each lane. No target-final summary exists. Architecture has 18 complete business-reader samples per lane while performance_acceptance remains false.",
    "reader": ref(Path(__file__).resolve()),
}
aggregate = write_new(P / "runtime-two-lane-terminal-readback.json", (json.dumps(out, indent=2) + "\n").encode())
handoff = {"schema": "c1-runtime-two-lane-terminal-small-handoff-v1", "observed_utc": now,
           "candidate": HEAD, "actual_merge": MERGE, "tree": TREE, "run_id": RUN,
           "aggregate": aggregate, "records": files, "metadata": ref(meta_path),
           "reader": ref(Path(__file__).resolve()), "scope": out["counts_scope"]}
handoff_file = write_new(P / "runtime-two-lane-terminal-handoff.json", (json.dumps(handoff, indent=2) + "\n").encode())
print(json.dumps({"aggregate": aggregate, "handoff": handoff_file, "original_job_logs": job_file,
                  "lanes": [{"lane": row["lane"], "nine_host_pass": row["all_nine_host_selectors_pass"],
                             "failed_names": row["public_submit_recovery"]["failed_names"],
                             "unobserved_count": len(row["public_submit_recovery"]["unobserved_after_abort_names"])} for row in lanes]}, indent=2))
