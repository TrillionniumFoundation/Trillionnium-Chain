#!/usr/bin/env python3
"""Join fixed-source native observations without promoting build-only results."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re


TARGETS = {
    "lib": "unittests src/lib.rs",
    "pool_mining": "tests/pool_mining.rs",
    "architecture_delivery_compare": "tests/architecture_delivery_compare.rs",
}
SUMMARY = re.compile(
    r"test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; "
    r"([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; "
    r"finished in ([0-9]+(?:\.[0-9]+)?)s"
)
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
RUNNING = re.compile(r"^\s*Running (.+?) \((.+)\)\s*$")
TEST = re.compile(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. (.+)$")
FIXED_ROSTER_SHA256 = "65bacc4498148df53662ce46147f285aa272090960606fd38eb2c68148f13500"


def load(path):
    raw = path.read_bytes()
    return json.loads(raw), {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def verify_original(record):
    material = {}
    for prefix in ("receipt", "log"):
        raw = Path(record[prefix + "_path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != record[prefix + "_sha256"]:
            raise ValueError(f"original {prefix} differs from observation")
        if prefix == "log" and len(raw) != record["log_bytes"]:
            raise ValueError("original log length differs from observation")
        material[prefix] = raw
    receipt = json.loads(material["receipt"])
    original_log_name = receipt.get("log_file")
    if (not isinstance(original_log_name, str) or Path(original_log_name).name != original_log_name
            or Path(record["log_path"]).resolve()
            != (Path(record["receipt_path"]).resolve().parent / original_log_name).resolve()
            or record["log_sha256"] != receipt.get("log_sha256")
            or record["log_bytes"] != receipt.get("log_bytes")):
        raise ValueError("derived log identity differs from the original receipt binding")
    status_key = "build_status" if "build_status" in record else "status"
    exit_key = "build_exit_code" if "build_exit_code" in record else "exit_code"
    if (receipt.get("schema") != "trnm-pq-native-command-v1"
            or receipt.get("status") not in ("command_succeeded", "command_failed")
            or type(receipt.get("exit_code")) is not int
            or (receipt["status"] == "command_succeeded") != (receipt["exit_code"] == 0)
            or record[status_key] != receipt["status"]
            or record[exit_key] != receipt["exit_code"]):
        raise ValueError("derived status differs from the original completed receipt")
    for key in ("argv", "cwd", "environment"):
        if record[key] != receipt[key]:
            raise ValueError(f"derived {key} differs from the original receipt")
    if (record["source"] != receipt.get("before")
            or record["source"] != receipt.get("after")
            or record["source"].get("tracked_worktree_verified") is not True):
        raise ValueError("derived source differs from original before/after checks")
    return material["log"].decode("utf-8", errors="replace").splitlines()


def verify_execution_lines(record, log_lines):
    replay = []
    for number, raw_line in enumerate(log_lines, 1):
        line = ANSI.sub("", raw_line)
        match = RUNNING.fullmatch(line)
        if match:
            replay.append({"cargo_target": match[1], "cargo_running_line": number,
                           "cargo_logged_path": match[2],
                           "observed_test_lines": [], "observed_summary_lines": []})
        elif replay:
            test = TEST.fullmatch(line)
            if test:
                replay[-1]["observed_test_lines"].append({
                    "line": number, "name": test[1], "outcome_text": test[2]})
            elif line.startswith("test result:"):
                replay[-1]["observed_summary_lines"].append({"line": number, "text": line})
    keys = ("cargo_target", "cargo_running_line", "cargo_logged_path",
            "observed_test_lines", "observed_summary_lines")
    projected = [{key: row[key] for key in keys} for row in record["executions"]]
    if projected != replay:
        raise ValueError("derived Cargo/test/summary lines differ from original log replay")
    for row in record["executions"]:
        logged = Path(row["cargo_logged_path"])
        resolved = (logged if logged.is_absolute() else Path(record["cwd"]) / logged).resolve()
        if str(resolved) != row["elf"]["path"]:
            raise ValueError("derived ELF path differs from the original Cargo Running path")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre", type=Path, required=True)
    parser.add_argument("--post", type=Path, required=True)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    pre, pre_ref = load(args.pre)
    post, post_ref = load(args.post)
    roster, roster_ref = load(args.roster)
    if roster_ref["sha256"] != FIXED_ROSTER_SHA256:
        raise ValueError("new-test roster differs from the audited fixed-source artifact")
    if (pre["schema"] != "chain-pre-execution-executable-observation-v1"
            or post["schema"] != "chain-post-command-executable-observation-v1"
            or roster["schema"] != "chain-fixed-source-new-native-test-roster-v1"):
        raise ValueError("unexpected observation schema")
    for field in ("source_commit", "source_tree"):
        if pre[field] != post[field] or pre[field] != roster[field]:
            raise ValueError("cross-source observation inputs")
    if pre["executed_tests"] != 0 or pre["native_tests_passed_by_build_only"] != 0:
        raise ValueError("build-only observation must retain zero executed/passed tests")
    verify_original(pre)
    if (pre["source"]["tested_commit"] != pre["source_commit"]
            or pre["source"]["tested_tree"] != pre["source_tree"]):
        raise ValueError("build-only raw receipt belongs to another source")
    pre_targets = {row["cargo_target"]: row for row in pre["executables"]}
    if len(pre["executables"]) != 3 or set(pre_targets) != set(TARGETS.values()):
        raise ValueError("pre-execution target set differs from original three targets")
    by_target = defaultdict(list)
    commands, summaries, primary_summaries = [], [], []
    for receipt in post["receipts"]:
        log_lines = verify_original(receipt)
        verify_execution_lines(receipt, log_lines)
        if (receipt["source"]["tested_commit"] != pre["source_commit"]
                or receipt["source"]["tested_tree"] != pre["source_tree"]):
            raise ValueError("post receipt belongs to another source")
        commands.append({key: receipt[key] for key in
                         ("receipt_path", "receipt_sha256", "log_path", "log_sha256",
                          "log_bytes", "status", "exit_code", "argv")})
        for position, execution in enumerate(receipt["executions"]):
            by_target[execution["cargo_target"]].append(execution)
            target_summaries = []
            for row in execution["observed_summary_lines"]:
                match = SUMMARY.fullmatch(row["text"])
                parsed = None if match is None else {
                    "status": match[1], "passed": int(match[2]), "failed": int(match[3]),
                    "ignored": int(match[4]), "measured": int(match[5]),
                    "filtered_out": int(match[6]), "elapsed_seconds_text": match[7],
                }
                observation = {"target": execution["cargo_target"],
                               "log_path": receipt["log_path"], **row, "parsed": parsed}
                summaries.append(observation)
                target_summaries.append(observation)
            next_line = (receipt["executions"][position + 1]["cargo_running_line"] - 1
                         if position + 1 < len(receipt["executions"]) else len(log_lines))
            declared = None
            for line in log_lines[execution["cargo_running_line"]:next_line]:
                match = re.fullmatch(r"running ([0-9]+) tests?", ANSI.sub("", line).strip())
                if match:
                    declared = int(match[1])
                    break
            last = target_summaries[-1] if target_summaries else None
            parsed = last["parsed"] if last else None
            count_matches = (parsed is not None and declared is not None
                             and sum(parsed[key] for key in
                                     ("passed", "failed", "ignored", "measured")) == declared)
            primary_summaries.append({
                "target": execution["cargo_target"], "log_path": receipt["log_path"],
                "primary_declared_tests": declared, "last_observed_summary": last,
                "last_summary_counts_match_primary_declaration": count_matches,
                "earlier_nested_or_intermediate_summary_count": max(0, len(target_summaries) - 1),
            })
    bindings = []
    for target in sorted(set(pre_targets) | set(by_target)):
        before = pre_targets.get(target)
        after = by_target.get(target, [])
        comparable = before is not None and len(after) == 1
        equal = comparable and all(before["elf"][key] == after[0]["elf"][key]
                                   for key in ("path", "sha256", "bytes"))
        bindings.append({
            "target": target, "pre": before["elf"] if before else None,
            "post": [row["elf"] for row in after],
            "post_invocations": len(after), "path_sha256_and_length_equal": equal,
            "file_identity_equal": comparable and all(
                before["elf"][key] == after[0]["elf"][key]
                for key in ("device", "inode", "mode", "mtime_ns", "ctime_ns")),
        })
    coverage = []
    roster_ids = {(row["target"], row["test"]) for row in roster["new_tests"]}
    if (len(roster["new_tests"]) != 37 or len(roster_ids) != 37
            or Counter(row["target"] for row in roster["new_tests"])
            != {"lib": 24, "pool_mining": 2, "architecture_delivery_compare": 11}):
        raise ValueError("fixed-source new-test roster is not the audited 37 entries")
    for required in roster["new_tests"]:
        target = TARGETS[required["target"]]
        found = [line for invocation in by_target.get(target, [])
                 for line in invocation["observed_test_lines"]
                 if line["name"] == required["test"]]
        if not found:
            result = "not_observed"
        elif len(found) != 1:
            result = "ambiguous_multiple_lines"
        elif found[0]["outcome_text"] == "ok":
            result = "observed_pass"
        elif found[0]["outcome_text"] == "FAILED":
            result = "observed_failure"
        elif found[0]["outcome_text"].startswith("ignored"):
            result = "observed_ignored"
        else:
            result = "nonstandard_outcome_text"
        coverage.append({"target": required["target"], "test": required["test"],
                         "source": required["source"], "result": result, "log_lines": found})
    result = {
        "schema": "chain-fixed-source-native-observation-summary-v1",
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": pre["source_commit"], "source_tree": pre["source_tree"],
        "input_observations": {"pre": pre_ref, "post": post_ref, "roster": roster_ref},
        "build_only_executed_tests": 0, "build_only_native_pass_count": 0,
        "native_commands": commands, "primary_harness_summaries": primary_summaries,
        "all_harness_summary_observations": summaries,
        "new_test_roster_size": 37,
        "new_test_outcome_counts": dict(Counter(row["result"] for row in coverage)),
        "new_test_observations": coverage, "pre_post_executable_bindings": bindings,
        "all_three_pre_post_path_sha256_length_equal": (
            len(bindings) == 3 and all(row["path_sha256_and_length_equal"] for row in bindings)),
        "exec_time_attestation": False, "independent_deployment_qualified": False,
        "whole_chain_quantum_security_qualified": False,
        "scope": "original native outcomes plus named new-test and local pre/post byte observations",
    }
    output = args.output.resolve()
    if any(output.is_relative_to(Path(row["cwd"])) for row in post["receipts"]):
        raise ValueError("write derived observations outside source")
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(output), "new_test_outcome_counts": result["new_test_outcome_counts"],
                      "all_three_pre_post_path_sha256_length_equal": result["all_three_pre_post_path_sha256_length_equal"]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
