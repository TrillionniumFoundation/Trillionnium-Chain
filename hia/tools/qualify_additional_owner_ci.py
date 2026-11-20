"""Bind actual Peer, Payload metadata, Task and PQ execution to one exact CI source."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ("peer-unix", "payload-metadata", "task-store", "task-boundary", "pq-auth", "pq-candidate")
FALSE_SCOPES = ("whole_chain_native", "whole_package_retired", "node_integration_complete",
                "original_service_budget_qualified", "cross_target_qualified", "production_activation")
PQ_COUNTS = {"original_retained": 343, "original_doctests": 2, "native_original_pairs": 1609,
             "native_abi_calls": 24671, "exports": 55, "allocation_controls": 190,
             "actual_allocation_failures": 125, "lifetime_abi_calls": 1329, "parallel_readers": 8,
             "reader_integrity_controls": 49, "native_partitions": 6, "real_process_controls": 8,
             "native_execution_limit_seconds": 240, "single_cleanup_limit_seconds": 3}
PQ_FALSE_SCOPES = ("whole_chain_native", "whole_crypto_crate_ported", "openssl_owned_provider_ported",
                   "tuf_ported", "constant_time_qualified", "foreign_arbitrary_pointer_gate_qualified",
                   "register_stack_secret_erasure_qualified", "production_activation")
CANDIDATE_COUNTS = {"original_retained": 343, "original_doctests": 2, "explicit_original_methods": 12,
                    "exports": 25, "native_cases": 892, "native_abi_calls": 14680,
                    "alias_original_pairs": 2, "native_original_pairs": 894,
                    "allocation_controls": 186, "actual_allocation_failures": 109,
                    "lifetime_abi_calls": 992, "readonly_owner_shared_threads": 8,
                    "independent_post_owner_values": 132, "native_partitions": 3,
                    "reader_integrity_controls": 59, "real_process_controls": 8,
                    "native_execution_limit_seconds": 240, "single_cleanup_limit_seconds": 3}
CANDIDATE_METHODS = ("CandidateAlgorithm.name", "CandidateAlgorithm.public_key_bytes",
                     "CandidateAlgorithm.signature_bytes", "CandidateAlgorithm.nist_category",
                     "CandidateSigningKey.from_owned_seed", "CandidateSigningKey.algorithm",
                     "CandidateSigningKey.public_key", "CandidateSigningKey.sign",
                     "CandidateVerifier.from_pinned_raw", "CandidateVerifier.algorithm",
                     "CandidateVerifier.public_key", "CandidateVerifier.verify")


PAYLOAD_COUNTS = {"retained_outer_tests": 121, "retained_nested_executions": 2,
                  "codec_pairs": 4472, "wire_priority_pairs": 8, "replay_pairs": 840,
                  "primitive_native_calls": 5320, "runtime_paired_native_calls": 10640,
                  "runtime_boundary_calls": 21, "readonly_queries": 48, "incremental_histories": 8,
                  "allocator_shapes": 857, "allocator_abi_calls": 2827, "actual_allocation_failures": 840,
                  "allocator_threads": 8, "parallel_abi_calls": 256, "loader_views": 8,
                  "public_histories": 48, "public_paired_calls": 492, "syscall_histories": 61,
                  "syscall_paired_calls": 488, "crash_histories": 14, "real_successful_syscall_cuts": 28,
                  "boundary_histories": 32, "boundary_paired_calls": 201, "small_wal_cases": 11,
                  "small_wal_native_calls": 18, "small_wal_original_cases": 9,
                  "large_wal_cases": 15, "large_wal_native_calls": 23, "large_wal_original_cases": 13,
                  "maximum_authenticated_records": 176602}
PAYLOAD_GROUPS = ("primitives", "runtime", "allocations", "views", "public", "syscalls", "crash", "boundaries",
                  "wal-small", "wal-large", "wal-maximum-replay", "wal-maximum-index")
PAYLOAD_METHODS = ("open", "path", "head_path", "namespace", "last_hash", "record_count", "accepted_frame_count",
                   "contains_session", "latest_generation", "verify_bound_endpoint_identity", "admit", "lookup_exact_v1")
PAYLOAD_FALSE_SCOPES = ('whole_payload_owner_qualified', 'payload_body_store_qualified', 'external_recovery_owner_qualified', 'whole_peer_package_retired', 'whole_chain_native', 'production_activation', 'original_service_budget_qualified', 'foreign_pointer_ownership_or_concurrent_arena_qualified', 'runtime_host_proxy', 'rust_or_interpreter_fallback', 'full_host_dependency_closure_claimed')
PAYLOAD_LIMITS = {'compiler_seconds': 30, 'compiler_functions': 128, 'compiler_blocks': 1536, 'compiler_ops': 8192, 'compiler_blocks_per_function': 256, 'native_seconds': 240, 'cleanup_seconds': 3, 'cleanup_windows': 1, 'process_observations': 4096, 'original_service_seconds': 4}
PAYLOAD_CONTROL_METHODS = (
    'test_actual_escaped_descendant_is_reaped',
    'test_actual_escaped_descendant_times_out',
    'test_actual_native_owner_times_out',
    'test_actual_normal_owned_child',
    'test_actual_public_close_has_one_cleanup_window',
    'test_actual_stopped_trace_child_cleanup',
    'test_allocation_failure_cannot_be_faked_by_count',
    'test_compiler_profile_cannot_exceed_8192_ops',
    'test_complete_source_byte_mutation_is_refused',
    'test_crash_cut_cannot_claim_power_failure',
    'test_crash_cut_cannot_substitute_an_injected_action',
    'test_duplicate_json_status_is_refused',
    'test_eight_thread_roster_cannot_shrink',
    'test_failed_report_cannot_be_promoted',
    'test_infinite_elapsed_time_is_refused',
    'test_injected_syscall_roster_cannot_shrink',
    'test_linked_ancestor_is_refused',
    'test_maximum_index_cannot_borrow_another_round',
    'test_missing_evidence_member_is_refused',
    'test_missing_native_group_is_refused',
    'test_modified_evidence_bytes_are_refused',
    'test_native_group_command_substitution_is_refused',
    'test_native_primitive_pair_count_cannot_shrink',
    'test_new_owned_source_member_is_refused',
    'test_original_dependency_profile_mutation_is_refused',
    'test_original_diagnostic_event_addition_is_refused',
    'test_original_diagnostic_event_deletion_is_refused',
    'test_original_diagnostic_event_reordering_is_refused',
    'test_original_diagnostic_response_code_substitution_is_refused',
    'test_original_git_blob_mutation_is_refused',
    'test_public_history_names_cannot_be_substituted',
    'test_published_head_read_cannot_target_a_temporary_file',
    'test_retained_path_traversal_is_refused',
    'test_retained_symlink_is_refused',
    'test_runtime_guard_failure_is_refused',
    'test_service_four_second_overclaim_is_refused',
    'test_single_cleanup_budget_cannot_be_renewed',
    'test_unchanged_240_second_limit_is_enforced',
    'test_wal_corrupt_history_cannot_be_reported_as_replay',
    'test_wal_partitions_cannot_duplicate_a_native_call',
    'test_wal_partitions_cannot_omit_maximum_index',
)


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(path):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode), "Regular retained input required: " + str(path))
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(stamp(before) == stamp(opened) == stamp(after) == stamp(path.lstat()), "Input changed")
    return {"bytes": before.st_size, "sha256": digest}


def read(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, "Duplicate report key")
            value[key] = item
        return value
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def write(path, value):
    with Path(path).open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def directory(path):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path and ROOT not in path.parents and path != ROOT,
         "Runner-owned output outside the checkout required")
    return path


def peer_summary(report, independent):
    need(report.get("schema") == "trnm.hia.peer-unix-qualification.v1"
         and report.get("status") == "PASS" and report.get("source_inputs_stable") is True
         and report.get("retained_original_tests", {}).get("outer_tests") == 121
         and report.get("integrity_controls", {}).get("count") == 18
         and set(report.get("groups", {})) == {"codec", "client", "client-owner", "cli", "daemon",
                                               "storage-faults", "syscall-faults"}
         and independent.get("status") == "PASS", "Incomplete actual Peer Unix gate")


def pq_summary(report, independent, head, tree):
    need(report.get("schema") == "trnm.hia.pq-public-qualification.v2"
         and report.get("status") == "PASS" and report.get("source_unchanged_during_tests") is True
         and independent.get("status") == "PASS", "Incomplete supervised public PQ gate")
    need(all(type(independent.get(name)) is int and independent[name] == count
             for name, count in PQ_COUNTS.items()), "Incomplete public PQ original/native/control roster")
    for value in (report, independent):
        need(value.get("source_commit_observed") == head and value.get("source_tree_observed") == tree
             and value.get("source_dirty_observed") == "", "PQ evidence is not from this clean committed head")
        limits = value.get("limits", {})
        need(set(limits) == set(PQ_FALSE_SCOPES) | {"live_pointer_const_and_exclusive_budget_contract_required"}
             and all(limits.get(name) is False for name in PQ_FALSE_SCOPES)
             and limits.get("live_pointer_const_and_exclusive_budget_contract_required") is True,
             "PQ component evidence was promoted beyond its qualified scope")
    sources = report.get("source_inputs")
    need(type(sources) is dict and sources and all(type(name) is str and name
             and not Path(name).is_absolute() and ".." not in Path(name).parts
             and Path(name).as_posix() == name and "\\" not in name and "\0" not in name
             and type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest)
             for name, digest in sources.items()),
         "Missing or malformed PQ source closure")
    digest = hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode()).hexdigest()
    need(independent.get("source_files") == len(sources)
         and independent.get("source_set_sha256") == report.get("source_set_sha256") == digest,
         "PQ reader and execution belong to different source graphs")


def candidate_summary(report, independent, head, tree):
    need(report.get("schema") == "trnm.hia.candidate-public-qualification.v1"
         and report.get("status") == "PASS" and report.get("source_unchanged_during_tests") is True
         and report.get("provider_inputs_unchanged_after_original") is True
         and report.get("provider_inputs_unchanged_after_all_execution") is True
         and report.get("full_host_dependency_closure_claimed") is False
         and independent.get("status") == "PASS", "Incomplete supervised Candidate gate")
    need(all(type(independent.get(name)) is int and independent[name] == count
             for name, count in CANDIDATE_COUNTS.items()), "Incomplete Candidate original/native/control roster")
    need(all(type(report.get(name)) is int and report[name] == CANDIDATE_COUNTS[name]
             for name in ("native_cases", "native_abi_calls", "alias_original_pairs", "native_original_pairs"))
         and type(report.get("case_count")) is int and report["case_count"] == CANDIDATE_COUNTS["native_cases"]
         and type(report.get("original_mode_signatures_accepted_under_their_own_modes")) is int
         and report["original_mode_signatures_accepted_under_their_own_modes"] == 12
         and report.get("original_method_roster") == list(CANDIDATE_METHODS),
         "Candidate execution omitted actual methods, modes or comparisons")
    for value in (report, independent):
        need(value.get("source_commit_observed") == head and value.get("source_tree_observed") == tree
             and value.get("source_dirty_observed") == "", "Candidate evidence is not from this clean committed head")
        limits = value.get("limits", {})
        need(set(limits) == set(PQ_FALSE_SCOPES) | {"live_pointer_const_contract_required"}
             and all(limits.get(name) is False for name in PQ_FALSE_SCOPES)
             and limits.get("live_pointer_const_contract_required") is True,
             "Candidate evidence was promoted beyond its qualified scope")
    sources = report.get("source_inputs")
    need(type(sources) is dict and sources and all(type(name) is str and name and name != "."
             and not Path(name).is_absolute() and ".." not in Path(name).parts
             and Path(name).as_posix() == name and "\\" not in name and "\0" not in name
             and type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest)
             for name, digest in sources.items()), "Missing or malformed Candidate source closure")
    digest = hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode()).hexdigest()
    need(type(independent.get("source_files")) is int and independent["source_files"] == len(sources)
         and independent.get("source_set_sha256") == report.get("source_set_sha256") == digest,
         "Candidate reader and execution belong to different source graphs")
    image = report.get("production_image")
    need(type(image) is dict and image == independent.get("production_image")
         and set(image) == {"path", "retained", "bytes", "sha256"}
         and type(image["path"]) is str and Path(image["path"]).is_absolute()
         and image["retained"] == "native/candidate-owned.so"
         and type(image["bytes"]) is int and image["bytes"] > 0
         and type(image["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", image["sha256"]),
         "Candidate reader and execution used different production images")



def payload_summary(report, independent, head, tree):
    schema = "trnm.hia.payload-metadata-qualification.v1"
    need(report.get("schema") == schema and report.get("status") == "PASS"
         and report.get("source_inputs_stable") is True
         and report.get("complete_original_tests_preserved") is True
         and report.get("original_tests_rerun_in_this_qualification") is True
         and report.get("public_observer_links_unchanged_original") is True
         and report.get("private_observer_append_only_test_hook") is True
         and type(report.get("metadata_owner_public_methods_qualified")) is int
         and report["metadata_owner_public_methods_qualified"] == 12
         and report.get("failure") is None and report.get("traceback") is None,
         "Incomplete actual Payload metadata qualification")
    need(set(independent) == {"schema", "status", "elapsed_ns", "retained_entries"}
         and independent.get("schema") == schema and independent.get("status") == "PASS"
         and type(report.get("elapsed_ns")) is int and 0 < report["elapsed_ns"] <= 1_200_000_000_000
         and type(report.get("retained_entries")) is int and report["retained_entries"] > 0
         and all(type(independent.get(name)) is int and independent[name] == report[name]
                 for name in ("elapsed_ns", "retained_entries")),
         "Payload independent reader did not complete this exact retained report")
    need(report.get("lineage") == {"head": head, "tree": tree, "dirty": False}
         and report["lineage"]["dirty"] is False,
         "Payload metadata evidence is not from this clean committed head")
    limits = report.get("limits")
    need(type(limits) is dict and limits == PAYLOAD_LIMITS
         and all(type(value) is int for value in limits.values())
         and all(report.get(name) is False for name in PAYLOAD_FALSE_SCOPES),
         "Payload metadata deadlines or unqualified scope changed")
    need(type(report.get("groups")) is dict and set(report["groups"]) == set(PAYLOAD_GROUPS),
         "Incomplete or substituted Payload metadata native groups")
    retained = report.get("retained_tests", {})
    need(type(retained) is dict and all(type(retained.get(name)) is int and retained[name] == count
             for name, count in (("outer_tests", 121), ("child_reexecutions", 2))),
         "Complete unchanged original Peer tests were not retained")
    production = report.get("production_readback", {})
    need(type(production) is dict and production.get("schema") == "trnm.hia.payload-metadata-production-readback.v1"
         and production.get("status") == "PASS" and production.get("public_methods") == list(PAYLOAD_METHODS)
         and production.get("prior_execution_reused") is False
         and production.get("same_round_maximum_replay_index_original") is True
         and all(production.get(name) is False for name in PAYLOAD_FALSE_SCOPES)
         and all(type(production.get(name)) is int and production[name] == count
                 for name, count in PAYLOAD_COUNTS.items()),
         "Payload metadata original/native/lifetime/WAL roster is incomplete or overstated")
    controls = report.get("integrity_controls", {})
    need(type(controls) is dict, "Missing Payload metadata integrity controls")
    actual = controls.get("actual", {})
    need(controls.get("status") == "PASS" and type(controls.get("tests")) is int
         and controls["tests"] == 41 and controls.get("methods") == list(PAYLOAD_CONTROL_METHODS)
         and type(actual) is dict
         and set(actual) == {"normal", "descendant", "deadline", "native-blocked", "public-close", "ptrace-cleanup"}
         and all(type(row) is dict and row.get("family_reaped") is True for row in actual.values()),
         "Payload metadata requires all 41 controls and six actual process lifetimes")
    sources = report.get("source_inputs")
    need(type(sources) is dict and sources and all(type(name) is str and name and name != "."
         and not Path(name).is_absolute() and ".." not in Path(name).parts and Path(name).as_posix() == name
         and "\\" not in name and "\0" not in name and type(value) is dict
         and set(value) == {"bytes", "sha256"} and type(value.get("bytes")) is int and value["bytes"] >= 0
         and type(value.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
         for name, value in sources.items()), "Missing or malformed Payload metadata source closure")
    digest = hashlib.sha256((json.dumps(sources, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True) + "\n").encode()).hexdigest()
    need(report.get("source_set_sha256") == digest, "Payload metadata source graph was substituted")


def run(component, root, rust_bin):
    root = directory(root)
    observation = root / "observations"
    need(observation.is_dir(), "Missing independently initialized observation directory")
    qualified = root / ("q" if component in ("peer-unix", "payload-metadata") else "qualification")
    need(not qualified.exists(), "A fresh component output is required")
    if component in ("peer-unix", "payload-metadata"):
        platform = {"peer-unix": "peer_lease_unix", "payload-metadata": "peer_payload"}[component]
        commands = [("qualification", [sys.executable, "-B", "-m",
                     "hia.platform." + platform + ".qualify", "run", "--output", str(qualified)]),
                    ("readback", [sys.executable, "-B", "-m", "hia.platform." + platform + ".qualify",
                     "readback", "--input", str(qualified)])]
    elif component in ("pq-auth", "pq-candidate"):
        need(rust_bin is not None and rust_bin.resolve(strict=True) == rust_bin,
             "Canonical original Rust toolchain directory required")
        platform = {"pq-auth": "pq_auth", "pq-candidate": "pq_candidate"}[component]
        commands = [("qualification", [sys.executable, "-I", "-S", "-B",
                     str(ROOT / "hia/platform" / platform / "qualify.py"), "--output", str(qualified),
                     "--rust-bin", str(rust_bin), "--provider-receipt",
                     str(root / "provider-receipts/pq-provider/provider.json"),
                     "--provider-environment", str(root / "provider.env")]),
                    ("readback", [sys.executable, "-I", "-S", "-B",
                     str(ROOT / "hia/platform" / platform / "readback.py"), "--report", str(qualified)])]
    else:
        need(rust_bin is not None and rust_bin.resolve(strict=True) == rust_bin,
             "Canonical original Rust toolchain directory required")
        commands = [("qualification", [sys.executable, "-B", str(ROOT / "hia/tools/qualify_task_ci.py"),
                     "--component", component, "--output", str(qualified), "--rust-bin", str(rust_bin)])]
    result = {"schema": "trnm.hia.additional-owner-process.v1", "component": component,
              "status": "FAIL", "stages": [], **{name: False for name in FALSE_SCOPES}}
    write(observation / "run-intent.json", {
        "schema": "trnm.hia.additional-owner-intent.v1", "component": component,
        "commands": [{"name": name, "argv": argv, "cwd": str(ROOT)} for name, argv in commands],
        "outer_deadline_owner": "GitHub Actions job timeout-minutes: 20",
        "component_deadlines_replaced": False,
        "final_observation_guaranteed_after_runner_termination": False,
    })
    try:
        qualified_report = None
        for name, argv in commands:
            started = time.monotonic_ns()
            row = {"name": name, "argv": argv, "cwd": str(ROOT), "started": False,
                   "exit_code": None, "failure": None,
                   "interpreter": {"path": str(Path(argv[0]).resolve(strict=True)),
                                   **identity(Path(argv[0]).resolve(strict=True))}}
            result["stages"].append(row)
            write(observation / (name + ".intent.json"), row)
            try:
                if name == "readback":
                    row["qualification_report_before"] = identity(qualified / "report.json")
                    need(row["qualification_report_before"] == qualified_report,
                         "Qualification report changed before independent readback")
                with (observation / (name + ".stdout.raw")).open("xb") as stdout, \
                        (observation / (name + ".stderr.raw")).open("xb") as stderr:
                    row["started"] = True
                    child = subprocess.run(argv, cwd=ROOT, stdout=stdout, stderr=stderr)
                row["exit_code"] = child.returncode
                need(child.returncode == 0, "Actual component process failed: " + name)
                row["qualification_report_after"] = identity(qualified / "report.json")
                if name == "readback":
                    need(row["qualification_report_after"] == qualified_report,
                         "Qualification report changed during independent readback")
                else:
                    qualified_report = row["qualification_report_after"]
            except BaseException as error:
                row["failure"] = repr(error)
                raise
            finally:
                row["elapsed_ns"] = time.monotonic_ns() - started
                for stream in ("stdout", "stderr"):
                    path = observation / (name + "." + stream + ".raw")
                    if path.exists():
                        row[stream] = identity(path)
                write(observation / (name + ".receipt.json"), row)
        result["status"] = "PASS"
    finally:
        write(observation / "process.json", result)
    return result


def bind(component, root, rust_bin):
    root = directory(root)
    observation = root / "observations"
    expected = os.environ["TRNM_EXPECTED_SOURCE_SHA"]
    need(re.fullmatch(r"[0-9a-f]{40}", expected), "Exact CI head required")
    git = lambda *args: subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT)
    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    need(head == expected, "Current CI head differs")
    before, after = (read(observation / name) for name in ("source-before.json", "source-after.json"))
    need(before == after and before["kind"] == "head"
         and before["tested_commit"] == before["candidate"] == head
         and before["tested_tree"] == tree and before["tracked_worktree_verified"] is True,
         "Whole committed source before/after qualification differs")
    process = read(observation / "process.json")
    stages = ["qualification", "readback"] if component in ("peer-unix", "payload-metadata", "pq-auth", "pq-candidate") else ["qualification"]
    need(process["schema"] == "trnm.hia.additional-owner-process.v1"
         and process["component"] == component and process["status"] == "PASS"
         and [row["name"] for row in process["stages"]] == stages
         and all(process.get(name) is False for name in FALSE_SCOPES), "Failed or foreign execution")
    qualified_path = root / ("q" if component in ("peer-unix", "payload-metadata") else "qualification")
    if component in ("peer-unix", "payload-metadata"):
        platform = {"peer-unix": "peer_lease_unix", "payload-metadata": "peer_payload"}[component]
        expected_commands = {
            "qualification": [sys.executable, "-B", "-m", "hia.platform." + platform + ".qualify",
                              "run", "--output", str(qualified_path)],
            "readback": [sys.executable, "-B", "-m", "hia.platform." + platform + ".qualify",
                         "readback", "--input", str(qualified_path)],
        }
    elif component in ("pq-auth", "pq-candidate"):
        need(rust_bin is not None and rust_bin.resolve(strict=True) == rust_bin,
             "The actual original Rust directory must remain explicit")
        platform = {"pq-auth": "pq_auth", "pq-candidate": "pq_candidate"}[component]
        expected_commands = {
            "qualification": [sys.executable, "-I", "-S", "-B",
                              str(ROOT / "hia/platform" / platform / "qualify.py"), "--output", str(qualified_path),
                              "--rust-bin", str(rust_bin), "--provider-receipt",
                              str(root / "provider-receipts/pq-provider/provider.json"),
                              "--provider-environment", str(root / "provider.env")],
            "readback": [sys.executable, "-I", "-S", "-B",
                         str(ROOT / "hia/platform" / platform / "readback.py"), "--report", str(qualified_path)],
        }
    else:
        need(rust_bin is not None and rust_bin.resolve(strict=True) == rust_bin,
             "The actual original Rust directory must remain explicit")
        expected_commands = {"qualification": [sys.executable, "-B", str(ROOT / "hia/tools/qualify_task_ci.py"),
                             "--component", component, "--output", str(qualified_path),
                             "--rust-bin", str(rust_bin)]}
    for row in process["stages"]:
        need(read(observation / (row["name"] + ".receipt.json")) == row,
             "Independently retained stage receipt differs")
        need(row["started"] is True and type(row["exit_code"]) is int and row["exit_code"] == 0
             and row["failure"] is None and row["cwd"] == str(ROOT)
             and row["argv"] == expected_commands[row["name"]], "Actual stage failed or its command differs")
        need(row.get("qualification_report_after") == identity(qualified_path / "report.json")
             and (row["name"] != "readback"
                  or row.get("qualification_report_before") == row["qualification_report_after"]),
             "Current qualification differs from the actually executed and read report")
        interpreter = Path(row["interpreter"]["path"])
        need(interpreter == Path(sys.executable).resolve(strict=True)
             and identity(interpreter) == {k: row["interpreter"][k] for k in ("bytes", "sha256")},
             "Actual qualification interpreter changed")
        for stream in ("stdout", "stderr"):
            need(identity(observation / (row["name"] + "." + stream + ".raw")) == row[stream],
                 "Complete actual process stream changed")
    qualification = qualified_path
    report = read(qualification / "report.json")
    need(report["status"] == "PASS", "The component gate did not pass")
    if component == "peer-unix":
        independent = read(observation / "readback.stdout.raw")
        peer_summary(report, independent)
        inputs = {str(ROOT / name): row for name, row in report["source_inputs"].items()}
    elif component == "payload-metadata":
        independent = read(observation / "readback.stdout.raw")
        payload_summary(report, independent, head, tree)
        inputs = {str(ROOT / name): row for name, row in report["source_inputs"].items()}
    elif component in ("pq-auth", "pq-candidate"):
        independent = read(observation / "readback.stdout.raw")
        (pq_summary if component == "pq-auth" else candidate_summary)(report, independent, head, tree)
        need(independent.get("qualification_report_sha256") == identity(qualification / "report.json")["sha256"],
             "Independent crypto reader belongs to a different qualification report")
        inputs = {str(ROOT / name): {"bytes": identity(ROOT / name)["bytes"], "sha256": digest}
                  for name, digest in report["source_inputs"].items()}
    else:
        need(report["component"] == component and report["finalized"] is True
             and report["source_before"] == report["source_after"], "Incomplete Task source-bound gate")
        inputs = report["source_before"]
    committed = {}
    for name, wanted in inputs.items():
        path = Path(name)
        if not path.is_absolute():
            path = ROOT / path
        if not path.is_relative_to(ROOT):
            continue
        relative = path.relative_to(ROOT).as_posix()
        need(path.resolve(strict=True) == path and identity(path) == wanted,
             "Qualified checkout input differs: " + relative)
        raw = git("cat-file", "blob", "HEAD:" + relative)
        need({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} == wanted,
             "Qualified input is not this exact Git blob: " + relative)
        committed[relative] = wanted
    need(committed, "The executed component has no committed source closure")
    required = ["hia/tools/qualify_additional_owner_ci.py", ".github/workflows/hia-native-migration.yml",
                "scripts/ci/verify_ci_source.py", "scripts/project-preflight.sh"]
    if component in ("task-store", "task-boundary"):
        required.append("hia/tools/qualify_task_ci.py")
    elif component == "payload-metadata":
        required.extend(("hia/platform/peer_payload/qualify.py", "hia/platform/peer_payload/readback.py",
                         "hia/platform/peer_payload/contract.py", "hia/platform/peer_payload/build.py",
                         "hia/platform/peer_payload/original.py", "hia/platform/peer_payload/readback_observations.py",
                         "hia/platform/peer_payload/control_readback.py", "hia/platform/peer_payload/test_qualification.py",
                         "hia/platform/peer_lease_unix/process.py", "hia/platform/peer_lease_unix/original_build.py",
                         "hia/platform/peer_lease_unix/readback.py", "scripts/w1_owned_process_collector_v1.py"))
    elif component == "pq-auth":
        required.extend(("hia/platform/pq_auth/qualify.py", "hia/platform/pq_auth/readback.py",
                         "hia/platform/pq_auth/qualification/contract.py",
                         "hia/platform/pq_auth/qualification/supervision.py",
                         "hia/platform/pq_auth/qualification/supervision_controls.py",
                         "scripts/ci/prepare_pq_provider.sh"))
    elif component == "pq-candidate":
        required.extend(("hia/platform/pq_candidate/qualify.py", "hia/platform/pq_candidate/readback.py",
                         "hia/platform/pq_candidate/qualification/contract.py",
                         "hia/platform/pq_candidate/qualification/integrity.py",
                         "hia/platform/pq_auth/qualification/contract.py",
                         "hia/platform/pq_auth/qualification/supervision.py",
                         "hia/platform/pq_auth/qualification/supervision_controls.py",
                         "hia/tools/ml_dsa_original.py", "hia/tools/qualify_ml_dsa.py",
                         "scripts/ci/prepare_pq_provider.sh"))
    readers = {}
    for name in required:
        raw = git("cat-file", "blob", "HEAD:" + name)
        readers[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        need(identity(ROOT / name) == readers[name], "CI driver differs from this commit")
    tool_files = {}
    tools = [row["interpreter"] for row in process["stages"]]
    if component == "peer-unix":
        tools.extend(read(qualification / "original/build.json")["tools"].values())
    elif component == "payload-metadata":
        tools.extend(read(qualification / "original/complete/build.json")["tools"].values())
    elif component in ("pq-auth", "pq-candidate"):
        tools.extend(report["tools"].values())
    captured = root / "ci-inputs"
    captured.mkdir(mode=0o700)
    for row in tools:
        source = Path(row["path"])
        wanted = {key: row[key] for key in ("bytes", "sha256")}
        need(identity(source) == wanted, "Actual qualification tool changed before capture")
        target = captured / wanted["sha256"]
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(source.read_bytes())
        need(identity(target) == identity(source) == wanted, "Tool capture changed")
        tool_files[str(source)] = {**wanted, "captured": str(target.relative_to(root))}
    result = {"schema": "trnm.hia.additional-owner-ci-binding.v1", "status": "PASS", "component": component,
              "head": head, "tree": tree, "run_id": os.environ["GITHUB_RUN_ID"],
              "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "job": os.environ["GITHUB_JOB"],
              "process": identity(observation / "process.json"),
              "qualification": identity(qualification / "report.json"),
              "tool_files": tool_files, "full_host_dependency_closure_claimed": False,
              "committed_source_inputs": committed, "ci_reader_sources": readers,
              "source_set_sha256": hashlib.sha256(json.dumps(committed, sort_keys=True,
                  separators=(",", ":")).encode()).hexdigest(), **{name: False for name in FALSE_SCOPES}}
    write(observation / "binding.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("run", "bind"))
    parser.add_argument("--component", choices=COMPONENTS, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--rust-bin", type=Path)
    args = parser.parse_args()
    result = (run(args.component, args.root, args.rust_bin) if args.phase == "run"
              else bind(args.component, args.root, args.rust_bin))
    print(json.dumps({key: result[key] for key in ("schema", "status", "component")}, sort_keys=True))


if __name__ == "__main__":
    main()
