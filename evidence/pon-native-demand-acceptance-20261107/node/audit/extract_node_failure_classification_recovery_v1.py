#!/usr/bin/env python3
"""Extract actual per-test failures after the bound two-run coverage audit.

Original diagnoses retain their documented uncertainty. New remainder cases
are classified by explicit retained error markers, never by an inferred shared
cause. No tests, source edits, guard changes or live-log reads.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
ORIGINAL_DIAGNOSIS_SHA = "99dddd4fe1ec2249b02bd20da57b4a1a62803d7d108769be7e23ec4dbf6ea358"
FIELDS = ("passed", "failed", "ignored", "measured", "filtered_out")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path, expected=None):
    import os
    path = Path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read()
        after = os.fstat(stream.fileno())
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(key(before) == key(after) and len(raw) == before.st_size, "file changed during read")
    identity = {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}
    require(expected is None or identity["sha256"] == expected, "artifact hash mismatch: " + str(path))
    return raw, identity


def write(out, name, raw):
    path = out / name
    with path.open("xb") as stream:
        stream.write(raw)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def write_json(out, name, value):
    return write(out, name, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def span_bytes(raw, span):
    start, end = span["start_inclusive"], span["end_exclusive"]
    require(type(start) is int and type(end) is int and 0 <= start <= end <= len(raw),
            "invalid strict byte interval")
    return raw[start:end]


def line_at(raw, offset):
    return raw[:offset].count(b"\n") + 1


def new_classification(block, primary):
    inspected = primary if primary else block
    if "PUBLIC_HOST_KERNEL_PARENT" in inspected:
        return ("host_kernel_prerequisite_reported", "The retained primary panic context contains PUBLIC_HOST_KERNEL_PARENT.",
                "No guard was changed. A missing fixed parent observed separately does not reconstruct per-process membership at the original event.")
    if "PUBLIC_MUTATION_CPU_BUDGET" in inspected or "PublicMutationCpuBudget" in inspected:
        return ("native_cpu_budget_reported", "The retained primary panic context contains the native CPU budget refusal.",
                "No unique expensive phase or instantaneous reserve allowance is inferred.")
    if any(marker in inspected for marker in (
            "PQ_WITNESS_DEADLINE", "PQ_WITNESS_UNAVAILABLE", "PQ_WITNESS")):
        return ("witness_error_reported", "The retained primary panic context contains an explicit PQ witness error.",
                "The exact cause and chronology require the retained phase evidence; no original-test cause is transferred.")
    if any(marker in inspected for marker in ("FRAME_EOF", "Connection reset", "Broken pipe", "broken pipe")):
        return ("transport_symptom_reported", "The retained primary panic context contains a transport symptom.",
                "A transport symptom alone does not identify a witness, deadline, kernel prerequisite, or child crash.")
    if "PUBLIC_HOST_KERNEL_PARENT" in block:
        return ("host_kernel_marker_in_failed_capture", "PUBLIC_HOST_KERNEL_PARENT is present in the captured failure block.",
                "The primary panic context does not directly identify it as the unique cause.")
    if "assertion" in inspected or "assertion" in block:
        return ("assertion_failure_unclassified", "An assertion failed in the retained test capture.",
                "No unique cause is assigned from an assertion alone.")
    return ("unclassified_failure", "The complete target summary reports a failed test; retained capture is referenced.",
            "No unique cause is established by this extractor.")


def extract_failed_names(segment, summary_relative, expected_count):
    prefix = segment[:summary_relative]
    matches = list(re.finditer(rb"(?m)^failures:\r?$", prefix))
    require(matches, "no outer failure-name list before counted summary")
    last = matches[-1]
    raw_names = prefix[last.end():].decode("utf-8").splitlines()
    names = [name.strip() for name in raw_names if name.strip()]
    require(len(names) == expected_count and len(set(names)) == len(names),
            "outer failure-name count/uniqueness differs from counted summary")
    require(all(re.fullmatch(r"[A-Za-z0-9_:]+", name) for name in names),
            "noncanonical outer test name in failure list")
    return names, last.start()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--union", required=True, type=Path)
    cli.add_argument("--union-sha256", required=True)
    cli.add_argument("--original-diagnosis", required=True, type=Path)
    cli.add_argument("--output-directory", required=True, type=Path)
    args = cli.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.union_sha256) is not None, "invalid union hash")
    raw, union_id = read(args.union, args.union_sha256)
    union = json.loads(raw)
    require(union.get("schema") == "pon-node-cross-run-coverage-diagnostic-recovery-v1"
            and union.get("result") == "COVERAGE_DIAGNOSTIC_RECORDED"
            and union.get("qualification") is False
            and union.get("single_complete_cargo_gate") is False
            and union.get("errors") == [], "requires coherent bound union diagnostic")
    require(union["source_commit"] == COMMIT and union["source_tree"] == TREE, "wrong frozen source")
    ending = union["remainder_run"]["terminal"]
    require(ending.get("job_id") == "1a1b6b4fa87-12894-60d"
            and ending.get("state") in ("succeeded", "failed", "cancelled", "timed_out")
            and ending.get("terminal_publication_confirmed") is True
            and ending.get("output_complete") is True and ending.get("output_durable") is True,
            "no retained real remainder ending")
    diagnosis_raw, diagnosis_id = read(args.original_diagnosis, ORIGINAL_DIAGNOSIS_SHA)
    original_diagnosis = json.loads(diagnosis_raw)
    require(original_diagnosis["source_commit"] == COMMIT
            and original_diagnosis["source_tree"] == TREE, "original diagnosis source")
    originals = {row["test_name"]: row for row in original_diagnosis["failures"]}
    require(len(originals) == len(original_diagnosis["failures"]) == 8,
            "original diagnosis must retain eight distinct failed tests")
    logs, log_ids = {}, {}
    for run in ("original", "remainder"):
        declared = union[run + "_run"]["provenance"]["raw_log"]
        logs[run], log_ids[run] = read(declared["path"], declared["sha256"])
        require(type(declared["bytes"]) is int and declared["bytes"] == len(logs[run]),
                "raw log bytes mismatch")
    old_lines = logs["original"].splitlines(keepends=True)
    for row in originals.values():
        require(row["fixed"] is False, "original diagnosis reclassified as fixed")
        for observation in row["original_panic"]:
            number = observation["line"]
            require(type(number) is int and 1 <= number <= len(old_lines), "panic line out of range")
            observed = old_lines[number - 1]
            require(sha(observed) == observation["raw_line_including_newline_sha256"]
                    and observed.decode("utf-8").rstrip("\r\n") == observation["text"],
                    "original diagnosis raw panic line differs")
    cases, unresolved_targets, errors, seen_original = [], [], [], set()
    for row in union["coverage"]:
        summary = row["counted_summary"]
        if summary is None or summary["failed"] == 0:
            continue
        require(type(summary["failed"]) is int and summary["failed"] > 0, "invalid failed count")
        run = row["assigned_run"]
        provenance = row["summary_provenance"]
        raw_log = logs[run]
        segment_span = provenance["segment_byte_span"]
        segment = span_bytes(raw_log, segment_span)
        summary_raw = span_bytes(raw_log, provenance["summary_byte_span"])
        require(summary_raw.decode("utf-8").rstrip("\r\n") == summary["raw"],
                "counted summary raw bytes differ")
        summary_relative = provenance["summary_byte_span"]["start_inclusive"] - segment_span["start_inclusive"]
        try:
            names, failure_list_start = extract_failed_names(segment, summary_relative, summary["failed"])
        except ValueError as failure:
            unresolved_targets.append({"target": row["target"], "run": run,
                                       "counted_failed": summary["failed"], "reason": str(failure),
                                       "provenance": provenance})
            continue
        headers = {}
        for name in names:
            pattern = rb"(?m)^---- " + re.escape(name.encode()) + rb" (?:stdout|stderr) ----\r?$"
            matches = list(re.finditer(pattern, segment[:failure_list_start]))
            headers[name] = matches
        starts = sorted(match.start() for matches in headers.values() for match in matches)
        for name in names:
            matches = headers[name]
            evidence, block, primary = None, "", ""
            if len(matches) == 1:
                start = matches[0].start()
                later = [value for value in starts if value > start]
                end = min(later + [failure_list_start])
                block_bytes = segment[start:end]
                block = block_bytes.decode("utf-8")
                global_start = segment_span["start_inclusive"] + start
                global_end = segment_span["start_inclusive"] + end
                panic_lines = []
                local_offset = 0
                for line in block_bytes.splitlines(keepends=True):
                    text = line.decode("utf-8").rstrip("\r\n")
                    if "panicked at" in text or "PUBLIC_HOST_KERNEL_PARENT" in text:
                        panic_lines.append({
                            "line": line_at(raw_log, global_start + local_offset),
                            "text": text, "raw_line_including_newline_sha256": sha(line)})
                    if ("thread '" + name + "'") in text and "panicked at" in text:
                        # Classification uses the actual matching test panic tail,
                        # not all earlier fixture refusals in the captured output.
                        primary = block_bytes[local_offset:].decode("utf-8")
                    local_offset += len(line)
                evidence = {
                    "log": log_ids[run],
                    "block_byte_span": {"start_inclusive": global_start, "end_exclusive": global_end},
                    "block_bytes": len(block_bytes), "block_sha256": sha(block_bytes),
                    "first_line": line_at(raw_log, global_start),
                    "panic_or_kernel_marker_lines": panic_lines,
                    "matching_test_panic_found": bool(primary),
                }
            case = {
                "run": run, "target_key": row["target_key"], "target": row["target"],
                "test_name": name, "provenance": provenance, "capture_evidence": evidence,
                "capture_header_count": len(matches), "fixed": False, "qualification": False,
            }
            if run == "original":
                require(name in originals and name not in seen_original,
                        "original failed test lost, duplicated or absent from sealed diagnosis: " + name)
                seen_original.add(name)
                source = originals[name]
                case.update(classification=source["classification"],
                            classification_scope="sealed original read-only diagnosis",
                            confirmed=source["confirmed"], uncertainty=source["uncertainty"],
                            original_diagnosis_id=source["id"],
                            original_panic=source["original_panic"],
                            original_observations=source["observations"])
            else:
                classification, observed, uncertainty = new_classification(block, primary)
                if evidence is None:
                    classification, observed, uncertainty = (
                        "capture_attribution_unresolved",
                        "The final complete target failure list names this failed test.",
                        "A unique retained capture block could not be attributed; no cause is assigned.")
                case.update(classification=classification,
                            classification_scope="explicit retained marker or unclassified symptom; no source repair",
                            confirmed=[observed], uncertainty=[uncertainty],
                            primary_panic_tail_excerpt=primary[:3000] if primary else None,
                            primary_excerpt_truncated=len(primary) > 3000)
            cases.append(case)
    require(seen_original == set(originals), "not all eight original failures retained")
    total_failed = union["cross_run_completed_target_totals"]["failed"]
    unresolved_count = sum(row["counted_failed"] for row in unresolved_targets)
    require(len(cases) + unresolved_count == total_failed,
            "per-test classification plus unresolved count differs from union failure count")
    categories = {}
    for case in cases:
        group = categories.setdefault(case["run"], {})
        group[case["classification"]] = group.get(case["classification"], 0) + 1
    for run in logs:
        _, again = read(log_ids[run]["path"])
        require(again == log_ids[run], "sealed raw log changed during extraction")
    args.output_directory.mkdir()
    out = args.output_directory
    inputs = {"union": union_id, "original_diagnosis": diagnosis_id, "logs": log_ids}
    report = {
        "schema": "pon-node-cross-run-failure-classification-v1", "source_commit": COMMIT,
        "source_tree": TREE, "inputs": inputs, "cases": cases,
        "case_count": len(cases), "unresolved_target_captures": unresolved_targets,
        "unresolved_failed_test_count": unresolved_count, "total_failed": total_failed,
        "counts_by_run_and_classification": categories, "errors": errors,
        "qualification": False, "fixed": False, "source_modified": False,
        "cpu_or_deadline_or_guard_modified": False,
        "scope": "All original failures retained. New causes remain marker observations unless separately established; no shared-cause inference.",
    }
    result_id = write_json(out, "failure-classification.json", report)
    def clean(value):
        return str(value).replace("|", "\\|").replace("\n", " ")
    lines = [
        "# Cross-run Node failure classification",
        "",
        "Qualification remains false. No failure is fixed or superseded by this report.",
        "",
        "Frozen source: " + COMMIT + "; tree: " + TREE + ".",
        "",
        "Counted failed tests: " + str(total_failed) + ". Attributed test names: " + str(len(cases))
        + ". Failed tests in unresolved capture structures: " + str(unresolved_count) + ".",
        "",
        "| Run | Test | Classification | Retained observation | Uncertainty |",
        "|---|---|---|---|---|",
    ]
    for case in cases:
        lines.append("| " + " | ".join(clean(value) for value in (
            case["run"], case["test_name"], case["classification"],
            " ".join(case["confirmed"]), " ".join(case["uncertainty"]))) + " |")
    lines.extend([
        "",
        "Original categories and uncertainties come from the hash-bound sealed diagnosis; each original panic line was rechecked against its raw line hash. New remainder categories describe explicit retained error markers or symptoms. They do not transfer a cause from a different test.",
        "",
        "Every case retains canonical target identity, run/job/command/source provenance, raw log hash and byte span. The JSON includes exact marker/panic lines with raw-line hashes. Missing or ambiguous capture structures are not assigned a cause.",
        "",
    ])
    md_id = write(out, "failure-classification.md", "\n".join(lines).encode())
    _, own = read(__file__)
    manifest_id = write_json(out, "manifest.json", {
        "schema": "pon-node-failure-classification-files-v1", "script": own, "inputs": inputs,
        "artifacts": [result_id, md_id], "qualification": False, "tests_started": False,
        "node_live_log_read": False})
    print(json.dumps({"manifest": manifest_id, "result": result_id, "markdown": md_id,
                      "total_failed": total_failed, "classified": len(cases),
                      "unresolved": unresolved_count, "categories": categories,
                      "qualification": False}, sort_keys=True))


if __name__ == "__main__":
    main()
