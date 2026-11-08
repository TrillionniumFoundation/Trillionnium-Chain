#!/usr/bin/env python3
"""Render actual completed cross-run Node coverage; never a qualification gate.

Requires an already recorded union diagnostic. No tests or live log reads.
Creates CSV, JSON, Markdown, and a hash manifest in a new output directory.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
FIELDS = ("passed", "failed", "ignored", "measured", "filtered_out")
NATIVE = ("no_gain_fees", "funded_service_contract", "native_demand_evidence",
          "native_task_operation_v2", "native_active_anchor")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fact(path, raw):
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write(out, name, raw):
    path = out / name
    with path.open("xb") as stream:
        stream.write(raw)
    return fact(path, raw)


def write_json(out, name, value):
    return write(out, name, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def count_rows(rows):
    summaries = [row["summary"] for row in rows if row["summary"] is not None]
    for row in summaries:
        require(all(type(row.get(k)) is int and row[k] >= 0 for k in FIELDS),
                "invalid strict summary integer")
    return {key: sum(row[key] for row in summaries) for key in FIELDS}


def table(rows):
    lines = [
        "| # | Kind | Target | Run | Status | Passed | Failed | Ignored | Measured | Filtered |",
        "|---:|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for index, row in enumerate(rows, 1):
        values = ["—" if row["summary"] is None else str(row["summary"][k]) for k in FIELDS]
        lines.append("| " + " | ".join([
            str(index), row["kind"], row["name"], row["run"], row["status"], *values]) + " |")
    return "\n".join(lines)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--union", required=True, type=Path)
    cli.add_argument("--output-directory", required=True, type=Path)
    cli.add_argument("--original-diagnosis", action="append", type=Path, default=[])
    args = cli.parse_args()
    raw = args.union.read_bytes()
    data = json.loads(raw)
    require(data.get("schema") == "pon-node-cross-run-coverage-diagnostic-recovery-v1"
            and data.get("result") == "COVERAGE_DIAGNOSTIC_RECORDED"
            and data.get("qualification") is False
            and data.get("single_complete_cargo_gate") is False
            and data.get("errors") == [], "requires coherent non-qualifying union diagnostic")
    require(data.get("source_commit") == COMMIT and data.get("source_tree") == TREE,
            "wrong frozen source")
    coverage = data["coverage"]
    require(len(coverage) == 91 and type(data["inventory_target_count"]) is int
            and data["inventory_target_count"] == 91, "coverage is not 91 inventory targets")
    seen, rows = set(), []
    for original in coverage:
        target = original["target"]
        key = canonical([target["kind"][0], target["name"], target["source"]]).decode()
        require(original["target_key"] == key and key not in seen, "canonical duplicate target")
        seen.add(key)
        require(original["assigned_run"] in ("original", "remainder"), "unknown run")
        summary = original["counted_summary"]
        require(type(original["counted_once"]) is bool
                and original["counted_once"] == (summary is not None), "counted flag differs")
        if summary is not None:
            require(original["status"] in ("completed_passed", "completed_with_failures"),
                    "non-complete target has summary")
            provenance = original["summary_provenance"]
            require(provenance["target_key"] == key and provenance["target"] == target
                    and provenance["source_commit"] == COMMIT and provenance["source_tree"] == TREE,
                    "summary frozen provenance mismatch")
        rows.append({"key": key, "kind": target["kind"][0], "name": target["name"],
                     "source": target["source"], "source_sha256": target["source_sha256"],
                     "run": original["assigned_run"], "status": original["status"],
                     "summary": summary, "provenance": original["summary_provenance"],
                     "original_status": original["original_observation_status"],
                     "qualification": False})
    totals = count_rows(rows)
    require(totals == data["cross_run_completed_target_totals"], "rendered union totals mismatch")
    require(sum(row["summary"] is not None for row in rows) == data["completed_target_count"],
            "completed count mismatch")
    native = []
    for name in NATIVE:
        matches = [row for row in rows if row["kind"] == "test" and row["name"] == name]
        require(len(matches) == 1, "missing or ambiguous native target: " + name)
        native.append(matches[0])
    original_totals = count_rows([row for row in rows if row["run"] == "original"])
    remainder_totals = count_rows([row for row in rows if row["run"] == "remainder"])
    require(original_totals == data["original_completed_target_totals"]
            and remainder_totals == data["remainder_completed_target_totals"],
            "per-run count mismatch")
    diagnoses = []
    for path in args.original_diagnosis:
        body = path.read_bytes()
        diagnoses.append(fact(path, body))
    args.output_directory.mkdir()
    out = args.output_directory
    inputs = {"union": fact(args.union, raw), "original_diagnosis_artifacts": diagnoses,
              "renderer": fact(Path(__file__), Path(__file__).read_bytes())}
    native_totals = count_rows(native)
    brief = {
        "schema": "pon-native-five-target-cross-run-observation-v1",
        "source_commit": COMMIT, "source_tree": TREE, "inputs": inputs,
        "targets": native, "completed_native_target_count": sum(r["summary"] is not None for r in native),
        "native_target_count": 5, "totals": native_totals,
        "qualification": False, "single_complete_cargo_gate": False,
        "scope": "Actual five target summaries selected by the union's fixed per-target assignment. No original failed observation is replaced.",
    }
    outputs = []
    outputs.append(write_json(out, "native-five-targets.json", brief))
    outputs.append(write_json(out, "node-91-targets.json", {
        "schema": "pon-node-91-target-cross-run-observation-v1",
        "source_commit": COMMIT, "source_tree": TREE, "inputs": inputs,
        "rows": rows, "totals": totals, "original_totals": original_totals,
        "remainder_totals": remainder_totals, "qualification": False,
        "single_complete_cargo_gate": False,
    }))
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("ordinal", "kind", "name", "source", "run", "status", *FIELDS,
                     "job_id", "log_sha256", "segment_start_byte", "segment_end_byte",
                     "summary_start_byte", "summary_end_byte", "qualification"))
    for i, row in enumerate(rows, 1):
        summary, p = row["summary"], row["provenance"]
        counts = ["" if summary is None else summary[key] for key in FIELDS]
        evidence = ([""] * 6 if p is None else [
            p["job_id"], p["raw_log"]["sha256"],
            p["segment_byte_span"]["start_inclusive"], p["segment_byte_span"]["end_exclusive"],
            p["summary_byte_span"]["start_inclusive"], p["summary_byte_span"]["end_exclusive"]])
        writer.writerow((i, row["kind"], row["name"], row["source"], row["run"], row["status"],
                         *counts, *evidence, "false"))
    outputs.append(write(out, "node-91-targets.csv", stream.getvalue().encode()))
    failed = [row for row in rows if row["summary"] is not None and row["summary"]["failed"] > 0]
    incomplete = [row for row in rows if row["summary"] is None]
    md = [
        "# Node coverage diagnostic on frozen 690f710c",
        "",
        "**Qualification remains false.** This report counts complete target summaries across two independent Cargo invocations. The original failures and timeout remain retained.",
        "",
        "Source commit: " + COMMIT + ". Tree: " + TREE + ".",
        "",
        "## Actual counts",
        "",
        "| Scope | Passed | Failed | Ignored | Measured | Filtered |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, result in (("Original complete targets", original_totals),
                         ("Remainder complete targets", remainder_totals),
                         ("Cross-run complete targets", totals)):
        md.append("| " + name + " | " + " | ".join(str(result[k]) for k in FIELDS) + " |")
    md.extend([
        "",
        "Completed targets: " + str(data["completed_target_count"]) + " / 91. Missing or ambiguous targets: " + str(len(incomplete)) + ". Ignored tests are excluded from passed counts. No nested harness or partial test-case count is included.",
        "",
        "The original process ended by native timeout 124 and has no source-after snapshot. A later snapshot does not repair that missing provenance. The remainder native Cargo exit was " + str(data["remainder_run"]["native_cargo_exit_code"]) + "; its host terminal state was " + str(data["remainder_run"]["terminal"]["state"]) + ".",
        "",
        "## Five native targets",
        "",
        table(native),
        "",
        "These rows retain their source run and raw-log provenance. Passing these five targets does not change any original failure or qualify the whole Node suite.",
        "",
        "## Failed targets",
        "",
        table(failed) if failed else "No complete target with a nonzero failed count was attributable. This statement does not qualify interrupted or missing targets.",
        "",
        "Failure causes require retained per-test evidence. Diagnostic files supplied with this report are listed by exact hash in its manifest; they are not inferred from target names.",
        "",
        "## All 91 targets",
        "",
        table(rows),
        "",
        "The CSV and JSON retain canonical source paths and raw-log byte intervals. The original partial model_composition_v4 observation is preserved in the union and excluded from sums; only its preassigned remainder invocation can contribute a complete summary.",
        "",
        "This report establishes controlled execution observations and counting coverage only. It is not independent customer demand, external-funding independence, physical model gain, production installation, or a single successful Cargo gate.",
        "",
    ])
    outputs.append(write(out, "node-coverage-report.md", "\n".join(md).encode()))
    manifest = {"schema": "pon-node-coverage-report-files-v1", "inputs": inputs,
                "artifacts": outputs, "qualification": False,
                "tests_started": False, "node_live_log_read": False,
                "completed_target_count": data["completed_target_count"],
                "native_completed_target_count": brief["completed_native_target_count"]}
    manifest_id = write_json(out, "manifest.json", manifest)
    print(json.dumps({"manifest": manifest_id, "artifacts": outputs, "totals": totals,
                      "native_totals": native_totals, "qualification": False}, sort_keys=True))


if __name__ == "__main__":
    main()
