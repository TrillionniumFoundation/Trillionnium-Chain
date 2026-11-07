#!/usr/bin/env python3
"""Seal a precise remainder diagnosis and a compact actual union summary.

This only reads frozen source/evidence and writes new sibling diagnostics.
Earlier conservative classifications remain retained. No tests or source fixes.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path("/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2")
TOOLS = ROOT / "recovery-evidence-tools"
SOURCE = ROOT / "chain-source-bounded"
COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
UNION_SHA = "e858131ad9b7e9e0ceb83a57d5c2bb665adbac6b395fedacd59f2d8a3e6ddde2"
LOG_SHA = "eae7dc4120c3fdfe32fea20a563bc6df929b944107c74fba59cdfeae80c35e3e"
V1_SHA = "775f6d170d3d67bd19c7f752013a730d892d157cf02d7af55353ee3f9e56baa4"
SUMMARY_SHA = "36f17f8123241259fb76012b8cf70c550c4d7a0a833641bddefc4d037859bf1a"
CPU_TEST = "test_full_transaction_pages_use_byte_limits_and_recover_all_native_state"
READY_TEST = "actual_pinned_peer_cli_follows_native_blocks_and_closes_shared_owner"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, expected=None):
    raw = path.read_bytes()
    assert expected is None or sha(raw) == expected, str(path)
    return raw, {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def load(path, expected=None):
    raw, identity = read(path, expected)
    return json.loads(raw), identity


def write(name, raw):
    path = TOOLS / name
    with path.open("xb") as stream:
        stream.write(raw)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def write_json(name, data):
    return write(name, (json.dumps(data, sort_keys=True, indent=2) + "\n").encode())


def rows(raw, first, last):
    lines = raw.splitlines(keepends=True)
    assert 1 <= first <= last <= len(lines)
    return [{"line": n, "text": lines[n - 1].decode().rstrip("\r\n"),
             "raw_line_including_newline_sha256": sha(lines[n - 1])}
            for n in range(first, last + 1)]


def git_identity():
    def git(*args):
        return subprocess.check_output(
            ["/usr/bin/git", "--no-replace-objects", *args], cwd=SOURCE).decode()
    identity = {"commit": git("rev-parse", "HEAD").strip(),
                "tree": git("rev-parse", "HEAD^{tree}").strip(),
                "status": git("status", "--porcelain=v1", "-z", "--untracked-files=all")}
    assert identity == {"commit": COMMIT, "tree": TREE, "status": ""}
    return identity


def main():
    before = git_identity()
    union, union_id = load(TOOLS / "node-cross-run-coverage-v1.json", UNION_SHA)
    v1, v1_id = load(TOOLS / "node-failure-classification-v1/failure-classification.json", V1_SHA)
    summary, summary_id = load(TOOLS / "node-union-finalization-v1/coverage-summary.json", SUMMARY_SHA)
    inventory, inventory_id = load(TOOLS / "node-target-inventory-recovery-v1.json",
        "e7e2f7e0717cfaa4dc1278f0ef0bec449796c7a738def2fb093ea8b2a38300e5")
    log, log_id = read(ROOT / "build-receipts/remaining-node-690f710c-v1/remaining-node.log", LOG_SHA)
    assert union["source_commit"] == COMMIT and union["source_tree"] == TREE
    assert union["qualification"] is False and union["errors"] == []
    assert v1["total_failed"] == 15 and v1["unresolved_failed_test_count"] == 0
    cases = [dict(row) for row in v1["cases"] if row["run"] == "remainder"]
    assert len(cases) == 7
    source_files, source_extracts = {}, {}
    for name, spans in (
            ("native_node", ((1350, 1419), (1429, 1432))),
            ("public_pool_cli", ((571, 585), (642, 670), (696, 722)))):
        target = [t for t in inventory["targets"] if t["name"] == name and t["kind"] == ["test"]]
        assert len(target) == 1
        raw, identity = read(SOURCE / target[0]["source"], target[0]["source_sha256"])
        source_files[name] = identity
        source_extracts[name] = [{"first_line": first, "last_line": last,
                                 "lines": rows(raw, first, last)} for first, last in spans]
    specific_log = {
        "cpu_import_then_captured_panic": rows(log, 116, 122),
        "same_test_inherited_kernel_marker": rows(log, 333, 338),
        "reader_eof_and_receiver_disconnected": rows(log, 345, 352),
    }
    assert "PUBLIC_MUTATION_CPU_BUDGET" in specific_log["cpu_import_then_captured_panic"][3]["text"]
    assert specific_log["same_test_inherited_kernel_marker"][3]["text"] == (
        "test " + READY_TEST + " ... PUBLIC_HOST_KERNEL_PARENT")
    assert "Option::unwrap()" in specific_log["reader_eof_and_receiver_disconnected"][3]["text"]
    assert "Disconnected" in specific_log["reader_eof_and_receiver_disconnected"][7]["text"]
    for case in cases:
        ev = case["capture_evidence"]
        assert ev is not None
        start, end = ev["block_byte_span"]["start_inclusive"], ev["block_byte_span"]["end_exclusive"]
        assert sha(log[start:end]) == ev["block_sha256"]
        case["prior_v1_classification"] = case["classification"]
        if case["test_name"] == CPU_TEST:
            case.update(
                classification="native_cpu_budget_refused_during_complete_page_import",
                classification_scope="direct retained error plus exact frozen call site",
                confirmed=[
                    "The first retained panic at native_node.rs:1407 unwraps imported for a complete final history page; the actual error is PublicMutationCpuBudget / PUBLIC_MUTATION_CPU_BUDGET.",
                    "The frozen source calls the actual ingress::sync_from socket API at line1405; line1407 expects the complete page result to equal tip.",
                    "The later Any panic at line1432 is result.unwrap() on the catch_unwind result after stop and server cleanup; it is not the server join failure.",
                ],
                uncertainty=[
                    "The trace does not uniquely identify the internal CPU reserve/checkpoint/activation refusal point or a cost-reducing fix.",
                    "This is a distinct test from the original library history-page failure; its detailed budget cause is not transferred.",
                    "The later root equality, receiver height and cold-reopen assertions were not reached successfully.",
                ],
                refined_raw_evidence="cpu_import_then_captured_panic",
                source_evidence="native_node")
        elif case["test_name"] == READY_TEST:
            case.update(
                classification="receiver_readiness_failure_with_same_test_kernel_marker",
                classification_scope="direct same-test marker and failure sequence; emitter attribution remains limited",
                confirmed=[
                    "The actual single-threaded libtest progress line336 names this test and prints PUBLIC_HOST_KERNEL_PARENT before FAILED.",
                    "The reader thread panics at public_pool_cli.rs:582 because lines.next() is None: no first stdout readiness line was received by that reader.",
                    "The parent test then panics at line722 with Disconnected while waiting on receiver_rx; the receiver readiness channel closed.",
                    "Frozen source line722 is the receiver readiness wait. Both source and receiver children inherit stderr, so the inline marker is retained outside the captured panic block.",
                ],
                uncertainty=[
                    "The inherited stderr marker does not carry a child process identity; the retained record does not uniquely assign that marker to source versus receiver.",
                    "No child terminal status or separate phase trace is retained here to prove that the kernel guard was the sole cause of receiver readiness loss.",
                    "The original v1 classification omitted this inline marker because it inspected only the later captured panic block; it remains retained, not rewritten.",
                ],
                refined_raw_evidence=["same_test_inherited_kernel_marker",
                                      "reader_eof_and_receiver_disconnected"],
                source_evidence="public_pool_cli")
        else:
            assert case["classification"] == "host_kernel_prerequisite_reported"
    counts = {}
    for case in cases:
        counts[case["classification"]] = counts.get(case["classification"], 0) + 1
    assert counts == {"host_kernel_prerequisite_reported": 5,
                      "native_cpu_budget_refused_during_complete_page_import": 1,
                      "receiver_readiness_failure_with_same_test_kernel_marker": 1}
    after = git_identity()
    assert before == after
    assert read(TOOLS / "node-cross-run-coverage-v1.json")[1] == union_id
    assert read(ROOT / "build-receipts/remaining-node-690f710c-v1/remaining-node.log")[1] == log_id
    inputs = {"union": union_id, "initial_classification": v1_id,
              "full_coverage_summary": summary_id, "inventory": inventory_id,
              "remainder_raw_log": log_id, "frozen_source_files": source_files}
    diagnosis = {
        "schema": "pon-node-remainder-failure-diagnosis-v2",
        "source_commit": COMMIT, "source_tree": TREE, "source_before": before, "source_after": after,
        "inputs": inputs, "cases": cases, "case_count": 7, "counts_by_classification": counts,
        "raw_line_evidence": specific_log, "frozen_source_extracts": source_extracts,
        "original_eight_failures_retained": True, "union_counts_changed": False,
        "earlier_classification_file_rewritten": False,
        "qualification": False, "fixed": False, "tests_started": False,
        "source_modified": False, "cpu_deadline_guard_or_os_modified": False,
        "scope": "Precision refinement of two conservative v1 cases from actual retained bytes and frozen source. Counts and original failures are unchanged.",
    }
    diagnosis_id = write_json("remainder-failure-diagnosis-v2.json", diagnosis)
    md = [
        "# Remainder run: seven actual failed tests",
        "",
        "Source " + COMMIT + ", tree " + TREE + ". Qualification remains false. No source or guard fix was made.",
        "",
        "The seven failures are: five direct primary-panic PUBLIC_HOST_KERNEL_PARENT reports, one direct CPU-budget refusal during complete-page import, and one receiver-readiness failure accompanied by a same-test inherited kernel-parent marker.",
        "",
        "| Test | Actual retained failure | Attribution boundary |",
        "|---|---|---|",
    ]
    for case in cases:
        clean = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
        md.append("| " + " | ".join(clean(s) for s in (
            case["test_name"], " ".join(case["confirmed"]), " ".join(case["uncertainty"]))) + " |")
    md.extend([
        "",
        "## Two refined cases",
        "",
        "The native_node full-transaction-pages case first failed at native_node.rs:1407 on PublicMutationCpuBudget. The later line1432 Any panic rethrows the captured panic after cleanup. It is not a separate server join failure. No unique internal CPU refusal stage is identified.",
        "",
        "The public_pool_cli pinned-peer case has PUBLIC_HOST_KERNEL_PARENT on its own progress line336, outside the captured failure block. The reader then encounters EOF before its first stdout line at source line582; the receiver readiness wait reports Disconnected at line722. Both CLI children inherit stderr, so the marker's exact emitting process and sole causal role are not established.",
        "",
        "V1 remains retained as a conservative initial extraction. V2 adds the earlier CPU panic and the inline stderr marker without changing the 91-target union, replacing original failures, or manufacturing missing original source-after/completion receipts.",
        "",
    ])
    md_id = write("remainder-failure-diagnosis-v2.md", "\n".join(md).encode())
    compact = {
        "schema": "pon-node-cross-run-compact-summary-v1",
        "source_commit": summary["source_commit"], "source_tree": summary["source_tree"],
        "union": union_id, "full_summary": summary_id,
        "original_job": summary["original_job"], "remainder_job": summary["remainder_job"],
        "original_terminal_state": summary["original_terminal"]["state"],
        "original_terminal_exit": summary["original_terminal"]["exit_code"],
        "remainder_terminal_state": summary["remainder_terminal"]["state"],
        "remainder_terminal_exit": summary["remainder_terminal"]["exit_code"],
        "remainder_native_cargo_exit_code": summary["remainder_native_cargo_exit_code"],
        "inventory_target_count": 91, "original_assignment_count": 30, "remainder_assignment_count": 61,
        "completed_target_count": 91, "all_targets_have_unambiguous_complete_summary": True,
        "uncovered_or_ambiguous_targets": [], "errors": union["errors"],
        "original_completed_target_totals": summary["original_completed_target_totals"],
        "remainder_completed_target_totals": summary["remainder_completed_target_totals"],
        "cross_run_completed_target_totals": summary["cross_run_completed_target_totals"],
        "native_five_targets": [{"name": r["name"], "run": r["run"], "status": r["status"],
                                 "counts": r["counts"]} for r in summary["native_five_targets"]],
        "original_source_after_present": summary["original_source_after_present"],
        "remainder_source_after_present": summary["remainder_source_after_present"],
        "remainder_source_before_after_identical": summary["remainder_source_before_after_identical"],
        "qualification": False, "single_complete_cargo_gate": False,
        "controlled_run_qualification_passed": False,
        "original_failures_superseded": False, "nested_summaries_added_to_totals": False,
        "union_field_paths": {
            "source_commit": "$.source_commit", "source_tree": "$.source_tree",
            "original_job": "$.original_run.provenance.job_id",
            "original_terminal_job": "$.original_run.terminal.job_id",
            "remainder_job": "$.remainder_run.provenance.job_id",
            "remainder_terminal_job": "$.remainder_run.terminal.job_id",
            "errors": "$.errors", "qualification": "$.qualification",
            "single_complete_cargo_gate": "$.single_complete_cargo_gate",
            "coverage_complete": "$.all_targets_have_unambiguous_complete_summary",
            "completed_target_count": "$.completed_target_count",
            "totals": "$.cross_run_completed_target_totals",
        },
        "remainder_diagnosis": diagnosis_id,
    }
    compact_id = write_json("node-cross-run-compact-summary-v1.json", compact)
    _, script_id = read(Path(__file__))
    manifest_id = write_json("native-evidence-closeout-v1.json", {
        "schema": "pon-native-evidence-closeout-v1", "observed_unix_seconds": time.time(),
        "script": script_id, "artifacts": [diagnosis_id, md_id, compact_id], "inputs": inputs,
        "source_before": before, "source_after": after, "source_unchanged": True,
        "original_or_remainder_receipts_modified": False, "union_modified": False,
        "qualification": False, "tests_started": False})
    print(json.dumps({"manifest": manifest_id, "compact_summary": compact_id,
                      "diagnosis": diagnosis_id, "markdown": md_id, "counts": counts,
                      "qualification": False}, sort_keys=True))


if __name__ == "__main__":
    main()
