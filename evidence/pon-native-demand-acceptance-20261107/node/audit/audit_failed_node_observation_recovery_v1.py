#!/usr/bin/env python3
"""Independent failure/partial-coverage auditor; qualification is ALWAYS false.

This new recovery tool does not run or import the success parser and does not
modify the original recorder, source, job, or logs. Wait for either the original
result.json or a retained, terminal native H process_status JSON for the exact
job. A running status is not an ending receipt. No live log is read by the
not-ready path. Output is create-only.

Usage:
  --run-dir PATH --inventory PATH --capture-receipt PATH --run-recorder PATH
  --output PATH [--terminal-status PATH]

--terminal-status is the exact decoded native status JSON retained from H
process_status (not a hand-written success/timeout declaration). It is mandatory
when the original recorder never reached result.json, e.g. host timeout.
An after-source snapshot missing at termination is reported missing, never
manufactured from the before snapshot or from a later current checkout.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys

EXPECTED_COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
EXPECTED_TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
EXPECTED_RECORDER_SHA256 = "049c64cf32927bcd16a82059707a468c91d6fc9be7d7abc9047bb3efcd2d8123"
EXPECTED_JOB = "1a1b6390138-12894-305"
FIELDS = ("passed", "failed", "ignored", "measured", "filtered_out")
RUN_FIELDS = ("passed", "failed", "ignored", "measured")
HEADER = re.compile(r"^ {5}Running (?P<label>.+?) \((?P<executable>/[^()\r\n]+)\)$")
START = re.compile(r"(?<!\S)running (?P<count>[0-9]+) tests?(?!\S)")
SUMMARY = re.compile(
    r"test result: (?P<status>ok|FAILED)\. (?P<passed>[0-9]+) passed; "
    r"(?P<failed>[0-9]+) failed; (?P<ignored>[0-9]+) ignored; "
    r"(?P<measured>[0-9]+) measured; (?P<filtered_out>[0-9]+) filtered out; "
    r"finished in (?P<seconds>[0-9]+(?:\.[0-9]+)?)s")
OLD_SUMMARY = re.compile(
    r"test result: (\w+)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;")
CARGO_ARGS = ["test", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
              "-p", "trnm-pon-node", "--all-targets", "--all-features", "--no-fail-fast",
              "--", "--test-threads=1"]
PREFIX = "trillionnium/crates/trnm-pon-node/"
MAX_BYTES = 64 * 1024 * 1024

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def read(path):
    path = Path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > MAX_BYTES:
            raise ValueError("input exceeds 64 MiB: " + str(path))
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    ident = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if ident(before) != ident(after) or len(raw) != before.st_size:
        raise ValueError("input changed during read: " + str(path))
    return raw, {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def read_json(path):
    raw, identity = read(path)
    return json.loads(raw), identity


def error(errors, code, **details):
    errors.append({"code": code, **details})


def require(errors, condition, code, **details):
    if not condition:
        error(errors, code, **details)
    return bool(condition)


def natural(value):
    return type(value) is int and value >= 0


def exact_natural(value, expected):
    return natural(value) and value == expected


def finite_number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_artifact(errors, actual, declared, label):
    return require(errors,
                   exact_natural(declared.get("bytes"), actual["bytes"])
                   and actual["sha256"] == declared.get("sha256"),
                   "ARTIFACT_IDENTITY_MISMATCH", artifact=label,
                   actual=actual, declared=declared)


def total(rows):
    return {field: sum(row[field] for row in rows) for field in FIELDS}


def executed(row):
    return sum(row[field] for field in RUN_FIELDS)


def pos(row):
    return row["line"], row["column"]


def event(number, line, match, start=False):
    value = {"line": number, "column": match.start() + 1, "raw": line,
             "whole_line": not line[:match.start()].strip() and not line[match.end():].strip()}
    if start:
        value["count"] = int(match["count"])
    else:
        value.update({field: int(match[field]) for field in FIELDS})
        value.update(status=match["status"], elapsed_seconds=match["seconds"])
    return value


def expected_targets(inventory, metadata, manifest, errors):
    require(errors, inventory.get("schema") == "pon-complete-node-target-inventory-recovery-v1",
            "INVENTORY_SCHEMA")
    require(errors, inventory.get("source_commit") == EXPECTED_COMMIT
            and inventory.get("source_tree") == EXPECTED_TREE, "INVENTORY_FROZEN_IDENTITY")
    packages = [p for p in metadata["packages"] if p["name"] == "trnm-pon-node"]
    if not require(errors, len(packages) == 1, "METADATA_NODE_PACKAGE_COUNT"):
        return {}
    sources = {row["path"]: row for row in manifest["materialized"]}
    observed = []
    for target in packages[0]["targets"]:
        absolute = target["src_path"]
        marker = "/" + PREFIX
        if not require(errors, absolute.count(marker) == 1, "METADATA_TARGET_SOURCE", path=absolute):
            continue
        relative = PREFIX + absolute.split(marker, 1)[1]
        require(errors, type(target.get("test")) is bool
                and (target.get("harness") is None or type(target["harness"]) is bool),
                "METADATA_TARGET_BOOLEAN_TYPES", target=relative)
        row = {"name": target["name"], "kind": target["kind"], "test": target["test"],
               "harness": target.get("harness"), "source": relative,
               "source_sha256": sources.get(relative, {}).get("sha256"),
               "required_features": target.get("required-features", [])}
        require(errors, row["source_sha256"] is not None, "TARGET_MISSING_FROM_SOURCE_MANIFEST",
                target=relative)
        observed.append(row)
    declared_targets = inventory.get("targets")
    require(errors, isinstance(declared_targets, list) and all(
        isinstance(row, dict) and type(row.get("test")) is bool
        and (row.get("harness") is None or type(row["harness"]) is bool)
        for row in declared_targets), "INVENTORY_TARGET_BOOLEAN_TYPES")
    require(errors, observed == declared_targets, "INVENTORY_METADATA_TARGETS_DIFFER")
    require(errors, len(observed) == 91 and exact_natural(inventory.get("target_count"), 91),
            "COMPLETE_TARGET_COUNT", observed=len(observed), recorded=inventory.get("target_count"))
    counts = {kind: sum(t["kind"] == [kind] for t in observed)
              for kind in ("lib", "bin", "test", "example")}
    declared_counts = inventory.get("kind_counts")
    require(errors, counts == {"lib": 1, "bin": 1, "test": 69, "example": 20}
            and isinstance(declared_counts, dict) and set(declared_counts) == set(counts)
            and all(exact_natural(declared_counts[key], value) for key, value in counts.items()),
            "TARGET_KIND_COUNTS", observed=counts)
    require(errors, exact_natural(inventory.get("workspace_members"), len(metadata["workspace_members"]))
            and exact_natural(inventory.get("resolved_packages"), len(metadata["packages"])),
            "INVENTORY_GRAPH_COUNT_TYPES")
    result = {}
    for target in observed:
        kind, source = target["kind"], target["source"]
        if not require(errors, kind in (["lib"], ["bin"], ["test"], ["example"])
                       and target.get("harness") is not False, "UNSUPPORTED_TARGET", target=target):
            continue
        relative = source[len(PREFIX):]
        if not require(errors, relative.endswith(".rs") and ".." not in PurePosixPath(relative).parts,
                       "INVALID_TARGET_SOURCE", target=target):
            continue
        label = relative if kind == ["test"] else "unittests " + relative
        require(errors, label not in result, "DUPLICATE_INVENTORY_TARGET", label=label)
        result[label] = target
    return result



def terminal_status(path):
    if path is None:
        return None, None, False
    value, identity = read_json(path)
    terminal = (
        isinstance(value, dict) and value.get("job_id") == EXPECTED_JOB
        and value.get("audit_recorded") is True
        and value.get("state") in ("succeeded", "failed", "cancelled", "timed_out")
        and value.get("terminal_publication_confirmed") is True
        and value.get("output_complete") is True
        and value.get("output_durable") is True
        and (value.get("exit_code") is None or type(value["exit_code"]) is int)
    )
    return value, identity, terminal


def diagnose_segment(header, body, expected, target_dir, last):
    problems, starts, summaries, skip_markers, failed_test_lines = [], [], [], [], []
    for number, line in body:
        if "\x1b" in line or "\x00" in line:
            error(problems, "CONTROL_BYTES_IN_HARNESS_OUTPUT", line=number)
        starts.extend(event(number, line, match, True) for match in START.finditer(line))
        matches = list(SUMMARY.finditer(line))
        for match in matches:
            row = event(number, line, match)
            summaries.append(row)
            require(problems, (row["status"] == "ok") == (row["failed"] == 0),
                    "SUMMARY_STATUS_COUNTS_DISAGREE", line=number)
        if "test result:" in line and not matches:
            error(problems, "MALFORMED_SUMMARY", line=number, raw=line)
        if len(matches) > 1:
            error(problems, "MULTIPLE_SUMMARIES_ON_LINE", line=number)
        if re.search(r"\b(?:[0-9]+\s+skipped|skipped(?:\s|:)|SKIP(?:PED)?(?:\s|:))", line):
            skip_markers.append({"line": number, "raw": line})
        if re.search(r"^test .* \.\.\. FAILED$", line):
            failed_test_lines.append({"line": number, "raw": line,
                                      "scope": "unattributed raw test line; not added as a count"})
    target = expected.get(header["label"])
    if require(problems, target is not None, "UNKNOWN_TARGET_HEADER", label=header["label"]):
        exe = PurePosixPath(header["executable"])
        names = {target["name"], target["name"].replace("-", "_")}
        require(problems, any(re.fullmatch(re.escape(name) + r"-[0-9a-f]{16}", exe.name)
                              for name in names), "EXECUTABLE_NAME_TARGET_MISMATCH")
        sub = "examples" if target["kind"] == ["example"] else "deps"
        require(problems, exe.parent == PurePosixPath(target_dir) / "debug" / sub
                and ".." not in exe.parts, "EXECUTABLE_DIRECTORY_MISMATCH")
    first = starts[0] if starts else None
    final = summaries[-1] if summaries else None
    if first:
        require(problems, first["whole_line"], "OUTER_RUNNING_NOT_WHOLE_LINE")
    same_size = ([s for s in starts[1:] if s["count"] == first["count"]]
                 if first else [])
    require(problems, not same_size, "PARENT_CHILD_SUMMARY_ATTRIBUTION_AMBIGUOUS",
            same_sized_nested_starts=same_size)
    possible_outer = bool(
        first and final and final["whole_line"] and pos(final) > pos(first)
        and executed(final) == first["count"] and final["filtered_out"] == 0
        and not any(pos(s) > pos(final) for s in starts)
    )
    prior = summaries[:-1] if possible_outer else summaries
    remaining = list(starts[1:])
    nested_candidates = []
    for row in prior:
        candidates = [s for s in remaining if pos(s) < pos(row) and s["count"] == executed(row)]
        annotated = {**row, "included_in_completed_target_totals": False,
                     "matched_nested_running": None,
                     "attribution": "provisional nested observation"}
        if candidates:
            chosen = max(candidates, key=pos)
            remaining.remove(chosen)
            annotated["matched_nested_running"] = chosen
        else:
            annotated["attribution"] = "unattributed summary"
            if possible_outer:
                error(problems, "EARLIER_SUMMARY_NOT_ATTRIBUTABLE_TO_NESTED_START", line=row["line"])
        nested_candidates.append(annotated)
    complete = possible_outer and not problems
    if problems:
        status = "ambiguous_or_inconsistent"
    elif complete:
        status = "completed_with_failures" if final["failed"] else "completed_passed"
    elif last:
        status = "incomplete_at_termination"
    else:
        status = "terminated_without_summary_before_next_target"
    return {
        "header": header, "target": target, "status": status, "first_running": first,
        "all_summary_observations": summaries,
        "completed_top_level_summary": final if complete else None,
        "last_summary_candidate": final,
        "was_in_progress_at_log_end": bool(last and not complete),
        "currently_running": False,
        "currently_running_note": "Audit requires an ending receipt; this is historical state at log end.",
        "nested_summary_candidates": nested_candidates,
        "nested_running_headers": starts[1:], "nested_starts_without_matched_summary": remaining,
        "unclosed_child_note": "Intentional crash/SIGKILL children need not print summaries; no pass inferred.",
        "ignored_count": final["ignored"] if complete else None,
        "skipped": None, "skip_note": "Rust libtest has no skipped summary field.",
        "unclassified_skip_markers": skip_markers, "failed_test_lines_not_counted": failed_test_lines,
        "attribution_problems": problems, "qualification": False,
    }


def audit(args, ending, ending_identity, terminal_confirmed):
    errors, identities = [], {}
    run = args.run_dir
    result = None
    if (run / "result.json").is_file():
        result, identities["result"] = read_json(run / "result.json")
        require(errors, result.get("schema") == "pon-native-complete-node-execution-v1"
                and type(result.get("exit_code")) is int, "NATIVE_RESULT_SCHEMA_OR_EXIT")
    if ending is not None:
        identities["host_terminal_status"] = ending_identity
        require(errors, terminal_confirmed, "HOST_STATUS_NOT_CONFIRMED_TERMINAL")
    if result is None and not terminal_confirmed:
        raise ValueError("no confirmed ending receipt")
    started, identities["started"] = read_json(run / "started.json")
    env, identities["environment"] = read_json(run / "environment.json")
    before, identities["source_before"] = read_json(run / "source-before.json")
    after = None
    if (run / "source-after.json").is_file():
        after, identities["source_after"] = read_json(run / "source-after.json")
    inventory, identities["inventory"] = read_json(args.inventory)
    capture, identities["capture"] = read_json(args.capture_receipt)
    metadata_name = inventory["metadata"]["path"]
    if Path(metadata_name).name != metadata_name:
        raise ValueError("metadata artifact must be sibling basename")
    metadata, identities["metadata"] = read_json(args.inventory.parent / metadata_name)
    validate_artifact(errors, identities["metadata"], inventory["metadata"], "metadata")
    validate_artifact(errors, identities["inventory"], capture["inventory"], "captured inventory")
    validate_artifact(errors, identities["metadata"], capture["metadata"], "captured metadata")
    require(errors, capture.get("schema") == "pon-node-inventory-capture-recovery-v1"
            and exact_natural(capture.get("exit_code"), 0)
            and capture.get("source_unchanged") is True, "CAPTURE_INVALID")
    for side in ("source_before", "source_after"):
        require(errors, capture.get(side) == {"commit": EXPECTED_COMMIT, "tree": EXPECTED_TREE,
                                              "status": ""}, "CAPTURE_SOURCE_IDENTITY", side=side)
    for key in ("started", "environment", "source_before"):
        validate_artifact(errors, identities[key], inventory["run_inputs"][key], "inventory " + key)
        validate_artifact(errors, identities[key], capture["run_inputs"][key], "capture " + key)
    _, identities["run_recorder"] = read(args.run_recorder)
    validate_artifact(errors, identities["run_recorder"], inventory["run_inputs"]["run_recorder"],
                      "actual recorder versus inventory")
    validate_artifact(errors, identities["run_recorder"], capture["run_inputs"]["run_recorder"],
                      "actual recorder versus capture")
    require(errors, identities["run_recorder"]["sha256"] == EXPECTED_RECORDER_SHA256,
            "ACTUAL_RECORDER_HASH")
    before_sha = sha(canonical(before))
    identities["source_before"]["canonical_sha256"] = before_sha
    require(errors, before.get("head") == EXPECTED_COMMIT and before.get("tree") == EXPECTED_TREE,
            "BEFORE_SOURCE_IDENTITY")
    require(errors, started.get("source_sha256") == before_sha
            and inventory.get("source_before_canonical_sha256") == before_sha
            and started.get("expected_commit") == EXPECTED_COMMIT, "STARTED_SOURCE_BINDING")
    source_after_matches = None
    if after is not None:
        after_sha = sha(canonical(after))
        identities["source_after"]["canonical_sha256"] = after_sha
        source_after_matches = before == after
        require(errors, after.get("head") == EXPECTED_COMMIT and after.get("tree") == EXPECTED_TREE,
                "AFTER_SOURCE_IDENTITY")
        if result is not None:
            require(errors, result.get("source_after_sha256") == after_sha, "RESULT_AFTER_SOURCE_HASH")
    if result is not None:
        require(errors, result.get("source_before_sha256") == before_sha, "RESULT_BEFORE_SOURCE_HASH")
        require(errors, after is not None and source_after_matches is True
                and result.get("source_unchanged") is True, "RESULT_SOURCE_NOT_UNCHANGED")
        require(errors, result.get("command") == started.get("command"), "RESULT_STARTED_COMMAND")
    expected_command = [str(PurePosixPath(env["RUSTC"]).parent / "cargo")] + CARGO_ARGS
    require(errors, started.get("command") == expected_command, "STARTED_COMMAND_NOT_COMPLETE_GATE")
    for key, value in {"RUST_TEST_THREADS": "1", "CARGO_TERM_COLOR": "never",
                       "CARGO_BUILD_JOBS": "2"}.items():
        require(errors, env.get(key) == value, "ENVIRONMENT_GATE_SETTING", key=key)

    # This read is reachable only after a native result or confirmed host ending.
    raw, identities["log"] = read(run / "complete-node.log")
    text = raw.decode("utf-8", errors="strict")
    native_log_bound = False
    if result is not None:
        native_log_bound = require(
            errors, exact_natural(result.get("log_bytes"), len(raw))
            and result.get("log_sha256") == sha(raw), "RESULT_LOG_BINDING")
    expected = expected_targets(inventory, metadata, before, errors)
    sections, headers, body, preamble = [], [], [], []
    header = None
    for number, line in enumerate(text.splitlines(), 1):
        match = HEADER.fullmatch(line)
        if match:
            if header is not None:
                sections.append((header, body))
            header = {"line": number, "raw": line, **match.groupdict()}
            headers.append(header)
            body = []
        else:
            if re.match(r"^\s*Running\s", line):
                error(errors, "MALFORMED_CARGO_TARGET_HEADER", line=number, raw=line)
            if header is not None:
                body.append((number, line))
            elif START.search(line) or "test result:" in line:
                preamble.append({"line": number, "raw": line})
    if header is not None:
        sections.append((header, body))
    require(errors, not preamble, "HARNESS_OUTPUT_BEFORE_CARGO_HEADER", events=preamble)
    segments = [diagnose_segment(h, b, expected, env["CARGO_TARGET_DIR"], i == len(sections) - 1)
                for i, (h, b) in enumerate(sections)]
    grouped = {}
    for index, segment in enumerate(segments):
        grouped.setdefault(segment["header"]["label"], []).append(index)
    coverage, completed = [], []
    for label, target in expected.items():
        indexes = grouped.get(label, [])
        if not indexes:
            row = {"label": label, "target": target, "status": "not_observed_started",
                   "summary": None, "segment_indexes": [],
                   "note": "No Cargo Running header in retained log; not an inference about all possible effects."}
        elif len(indexes) > 1:
            row = {"label": label, "target": target, "status": "duplicate_headers_unqualified",
                   "summary": None, "segment_indexes": indexes}
        else:
            segment = segments[indexes[0]]
            row = {"label": label, "target": target, "status": segment["status"],
                   "summary": segment["completed_top_level_summary"], "segment_indexes": indexes}
            if row["summary"] is not None:
                completed.append(row["summary"])
        row["qualification"] = False
        coverage.append(row)
    unexpected = sorted(set(grouped) - set(expected))
    require(errors, not unexpected, "UNEXPECTED_CARGO_TARGETS", labels=unexpected)
    duplicate_executables = len({h["executable"] for h in headers}) != len(headers)
    require(errors, not duplicate_executables, "DUPLICATE_CARGO_EXECUTABLE")
    observed_statuses = {}
    for row in coverage:
        observed_statuses[row["status"]] = observed_statuses.get(row["status"], 0) + 1
    old_rows = [list(row) for row in OLD_SUMMARY.findall(text)]
    old = {"passed": sum(int(row[1]) for row in old_rows),
           "failed": sum(int(row[2]) for row in old_rows),
           "ignored": sum(int(row[3]) for row in old_rows), "test_summary_count": len(old_rows)}
    if result is not None:
        require(errors, result.get("test_summaries") == old_rows, "RECORDER_SUMMARY_LIST_MISMATCH")
        for key, value in old.items():
            require(errors, exact_natural(result.get(key), value),
                    "RECORDER_NESTED_INCLUSIVE_AGGREGATE_MISMATCH", field=key)
    sqlite = []
    if result is not None:
        for row in result.get("sqlite_build_outputs", []):
            name = row.get("retained", "")
            if not require(errors, re.fullmatch(
                    r"sqlite-trnm-sqlite-io-boundary-[0-9a-f]{16}\.txt", name) is not None,
                    "SQLITE_RETAINED_NAME", name=name):
                continue
            witness, identity = read(run / name)
            match = sha(witness) == row.get("sha256")
            require(errors, match, "SQLITE_RETAINED_HASH", name=name)
            sqlite.append({**identity, "matches_native_result": match,
                           "qualified_marker": b"cargo:rustc-cfg=trnm_sqlite_layout_witness\n" in witness,
                           "unqualified_marker": b"UNQUALIFIED:" in witness})
    # Re-read the log at the end: a stable single read is insufficient if a writer
    # resumes during the analysis. Do not manufacture finality for such a file.
    _, final_log_identity = read(run / "complete-node.log")
    require(errors, final_log_identity == identities["log"], "LOG_CHANGED_DURING_AUDIT")
    _, auditor_identity = read(__file__)
    coherent = not errors
    all_targets_completed = len(completed) == len(expected) and not unexpected
    return {
        "schema": "pon-node-failed-observation-inventory-recovery-v1",
        "kind": "failure_or_partial_coverage_diagnostic",
        "result": "DIAGNOSTIC_RECORDED" if coherent else "DIAGNOSTIC_WITH_BINDING_ERRORS",
        "qualification": False, "controlled_run_qualification_passed": False,
        "independent_acceptance": False, "production_activation": False,
        "auditor": auditor_identity, "inputs": identities, "binding_integrity": coherent,
        "ending": {"original_native_result_present": result is not None,
                   "original_native_exit_code": None if result is None else result.get("exit_code"),
                   "host_terminal_status_present": ending is not None,
                   "host_terminal_confirmed": terminal_confirmed,
                   "host_status": ending, "expected_job_id": EXPECTED_JOB,
                   "readiness_checked_before_log_read": True},
        "raw_log_evidence": {
            "bound_to_original_native_result": native_log_bound,
            "observed_stable_after_host_or_native_ending": True,
            "newline_terminated": raw.endswith(b"\n"),
            "scope": "If no native result exists, this is a new post-termination byte/hash "
                     "observation, not a recovered or invented original closing receipt."},
        "source": {"commit": EXPECTED_COMMIT, "tree": EXPECTED_TREE,
                   "before_present": True, "after_present": after is not None,
                   "available_before_after_snapshots_identical": source_after_matches,
                   "original_result_source_unchanged":
                       None if result is None else result.get("source_unchanged"),
                   "missing_after_not_replaced_with_current_checkout": True},
        "inventory_target_count": len(expected), "cargo_header_count": len(headers),
        "coverage_by_status": observed_statuses, "coverage": coverage,
        "all_inventory_targets_have_unambiguous_completion": all_targets_completed,
        "uncovered_or_ambiguous_targets": [
            row["label"] for row in coverage if row["summary"] is None],
        "completed_target_totals": total(completed) if coherent else None,
        "raw_parsed_completed_candidates_only": total(completed),
        "completed_target_count": len(completed),
        "totals_scope": "Only individually unambiguous completed Cargo top-level targets; "
                        "never a total for unstarted or interrupted targets, and never qualification.",
        "unexpected_targets": unexpected, "target_headers": headers, "segments": segments,
        "original_naive_nested_inclusive_totals_observed": old,
        "original_naive_totals_used_as_top_level": False,
        "nested_summaries_added_to_completed_totals": False,
        "nested_filtered_out_added_to_top_level": False,
        "skipped_classification": {
            "rust_libtest_explicit_skipped_count": None,
            "ignored_kept_separate_and_not_passes": True,
            "unclassified_skip_markers": [m for s in segments for m in s["unclassified_skip_markers"]]},
        "sqlite_retained_observations": sqlite,
        "sqlite_index_available_from_original_result": result is not None,
        "source_or_original_recorder_or_job_modified": False,
        "original_log_or_result_rewritten": False, "tests_started": False,
        "errors": errors,
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--run-dir", required=True, type=Path)
    cli.add_argument("--inventory", required=True, type=Path)
    cli.add_argument("--capture-receipt", required=True, type=Path)
    cli.add_argument("--run-recorder", required=True, type=Path)
    cli.add_argument("--terminal-status", type=Path)
    cli.add_argument("--output", required=True, type=Path)
    args = cli.parse_args()
    try:
        ending, ending_identity, ready = terminal_status(args.terminal_status)
        native_present = (args.run_dir / "result.json").is_file()
        if not native_present and not ready:
            print(json.dumps({"result": "NOT_READY_NO_CONFIRMED_ENDING",
                              "qualification": False, "raw_log_read": False, "output_created": False}))
            return 2
        report = audit(args, ending, ending_identity, ready)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as failure:
        report = {"schema": "pon-node-failed-observation-inventory-recovery-v1",
                  "result": "DIAGNOSTIC_INPUT_ERROR", "qualification": False,
                  "controlled_run_qualification_passed": False,
                  "completed_target_totals": None,
                  "errors": [{"code": "INPUT_OR_AUDITOR_ERROR", "type": type(failure).__name__,
                              "message": str(failure)}],
                  "original_log_or_result_rewritten": False, "production_activation": False}
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    try:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    except OSError as failure:
        print(json.dumps({"result": "OUTPUT_REFUSED", "message": str(failure),
                          "qualification": False}), file=sys.stderr)
        return 2
    print(json.dumps({"result": report["result"], "qualification": False,
                      "output": str(args.output), "bytes": len(encoded), "sha256": sha(encoded),
                      "coverage_by_status": report.get("coverage_by_status"),
                      "completed_target_totals": report.get("completed_target_totals"),
                      "error_count": len(report["errors"])}, sort_keys=True))
    # 0 means that a diagnostic was recorded coherently; qualification remains false.
    return 0 if report["result"] == "DIAGNOSTIC_RECORDED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
