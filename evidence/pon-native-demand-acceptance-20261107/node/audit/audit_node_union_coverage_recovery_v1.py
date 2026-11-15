#!/usr/bin/env python3
"""Count independent Node target coverage across a failed run and a remainder run.

Never a success qualification and never a reconstructed single Cargo invocation.
Requires an actual retained terminal H status for the remainder job BEFORE any
test-log read. Uses pinned, previously reviewed failure-attribution helper bytes.
Every target is assigned beforehand to original-complete or remainder selection.
Creates one new diagnostic; original files are read-only.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import types

ROOT = Path("/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2")
TOOLS = ROOT / "recovery-evidence-tools"
ORIGINAL = ROOT / "build-receipts/complete-node-690f710c-v1"
REMAINDER = ROOT / "build-receipts/remaining-node-690f710c-v1"
COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
ORIGINAL_JOB = "1a1b6390138-12894-305"
REMAINDER_JOB = "1a1b6b4fa87-12894-60d"
AUDIT_SHA = "d906a690639ee78b6b38e1a97e27904e1a1b7a540f9206cadbde03aa40adbc70"
HELPER_SHA = "3add13fa42e47103c90d6e35c98c7be0accccc739963bad26aabcb8c930900cf"
INVENTORY_SHA = "e7e2f7e0717cfaa4dc1278f0ef0bec449796c7a738def2fb093ea8b2a38300e5"
ORIGINAL_TERMINAL_SHA = "1ad19471b75c6b97570592289ebabe6bd1d486dca60d6bcb794a9dd40137e949"
SELECTION_SHA = "9bd89ad1849745b3be329094de6a37571fb680307b868dea2375d3526812cb46"
FIELDS = ("passed", "failed", "ignored", "measured", "filtered_out")
COMPLETE = ("completed_passed", "completed_with_failures")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def require(value, message):
    if not value:
        raise ValueError(message)


def natural(value):
    return type(value) is int and value >= 0


def artifact_equal(actual, declared):
    return (natural(declared.get("bytes")) and actual["bytes"] == declared["bytes"]
            and actual["sha256"] == declared.get("sha256"))


def read(path, expected=None):
    import os
    path = Path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(before.st_size <= 64 * 1024 * 1024, "input exceeds 64 MiB: " + str(path))
        raw = stream.read()
        after = os.fstat(stream.fileno())
    stat_id = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(stat_id(before) == stat_id(after) and len(raw) == before.st_size,
            "file changed during read: " + str(path))
    identity = {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}
    require(expected is None or identity["sha256"] == expected, "unexpected bytes: " + str(path))
    return raw, identity


def read_json(path, expected=None):
    raw, identity = read(path, expected)
    return json.loads(raw), identity


def terminal(path, job):
    value, identity = read_json(path)
    require(value.get("job_id") == job and value.get("audit_recorded") is True
            and value.get("state") in ("succeeded", "failed", "cancelled", "timed_out")
            and value.get("terminal_publication_confirmed") is True
            and value.get("output_complete") is True and value.get("output_durable") is True
            and (value.get("exit_code") is None or type(value["exit_code"]) is int),
            "not a confirmed durable terminal status for " + job)
    return value, identity


def target_key(target):
    # Canonical identity is kind + name + frozen source path, never binary basename.
    return canonical([target["kind"][0], target["name"], target["source"]]).decode()


def sum_rows(rows):
    for row in rows:
        require(all(natural(row.get(k)) for k in FIELDS), "invalid strict summary integers")
    return {key: sum(row[key] for row in rows) for key in FIELDS}


def load_helper():
    path = TOOLS / "audit_failed_node_observation_recovery_v1.py"
    raw, identity = read(path, HELPER_SHA)
    module = types.ModuleType("pinned_node_failed_observation_helper")
    module.__file__ = str(path)
    # Only imports and function definitions execute. The __main__ entry is false.
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module, identity


def parse_run(helper, raw, expected, target_dir):
    lines, offsets, cursor = [], [], 0
    chunks = raw.split(b"\n")
    if chunks and chunks[-1] == b"":
        chunks.pop()
    for index, chunk in enumerate(chunks):
        terminated = index < len(chunks) - 1 or raw.endswith(b"\n")
        offsets.append(cursor)
        lines.append(chunk.decode("utf-8", errors="strict").removesuffix("\r"))
        cursor += len(chunk) + int(terminated)
    require(cursor == len(raw), "raw byte/line accounting differs")
    sections, body, current, header_lines, problems = [], [], None, [], []
    for number, line in enumerate(lines, 1):
        match = helper.HEADER.fullmatch(line)
        if match:
            if current is not None:
                sections.append((current, body))
            current = {"line": number, "raw": line, **match.groupdict()}
            header_lines.append(number)
            body = []
        else:
            if re.match(r"^\s*Running\s", line):
                problems.append({"code": "MALFORMED_CARGO_HEADER", "line": number, "raw": line})
            if current is None:
                if helper.START.search(line) or "test result:" in line:
                    problems.append({"code": "HARNESS_EVENT_BEFORE_CARGO_HEADER",
                                     "line": number, "raw": line})
            else:
                body.append((number, line))
    if current is not None:
        sections.append((current, body))
    segments = []
    for index, (header, body) in enumerate(sections):
        row = helper.diagnose_segment(
            header, body, expected, target_dir, index == len(sections) - 1)
        start = offsets[header["line"] - 1]
        end = offsets[sections[index + 1][0]["line"] - 1] if index + 1 < len(sections) else len(raw)
        row["segment_byte_span"] = {"start_inclusive": start, "end_exclusive": end}
        summary = row["completed_top_level_summary"]
        if summary is not None:
            n = summary["line"] - 1
            row["summary_byte_span"] = {
                "start_inclusive": offsets[n],
                "end_exclusive": offsets[n + 1] if n + 1 < len(offsets) else len(raw),
            }
        else:
            row["summary_byte_span"] = None
        segments.append(row)
    grouped = {}
    for index, row in enumerate(segments):
        grouped.setdefault(row["header"]["label"], []).append(index)
    extra = sorted(set(grouped) - set(expected))
    if extra:
        problems.append({"code": "UNSELECTED_CARGO_TARGETS", "labels": extra})
    executables = [row["header"]["executable"] for row in segments]
    if len(executables) != len(set(executables)):
        problems.append({"code": "DUPLICATE_CARGO_EXECUTABLE"})
    coverage = {}
    for name, target in expected.items():
        indexes = grouped.get(name, [])
        if not indexes:
            row = {"label": name, "target": target, "status": "not_observed_started",
                   "summary": None, "segment_indexes": []}
        elif len(indexes) > 1:
            row = {"label": name, "target": target, "status": "duplicate_headers_unqualified",
                   "summary": None, "segment_indexes": indexes}
            problems.append({"code": "DUPLICATE_CARGO_TARGET", "label": name})
        else:
            segment = segments[indexes[0]]
            row = {"label": name, "target": target, "status": segment["status"],
                   "summary": segment["completed_top_level_summary"],
                   "segment_indexes": indexes}
        coverage[name] = row
    return {"coverage": coverage, "segments": segments, "problems": problems,
            "raw_line_count": len(lines), "header_count": len(sections)}


def validate_target_list(selection, expected, audit):
    require(selection.get("schema") == "pon-node-remaining-target-selection-v1"
            and selection.get("source_commit") == COMMIT and selection.get("source_tree") == TREE
            and selection.get("qualification") is False
            and selection.get("same_single_cargo_run") is False, "selection schema/identity")
    for key, value in (("inventory_target_count", 91), ("selected_target_count", 61),
                       ("previous_completed_target_count", 30)):
        require(type(selection.get(key)) is int and selection[key] == value,
                "selection strict count: " + key)
    old = {row["label"]: row for row in audit["coverage"]}
    selected = selection["selected"]
    names = [row["label"] for row in selected]
    require(len(names) == len(set(names)) == 61, "selection duplicates or wrong size")
    wanted = [name for name in expected if old[name]["summary"] is None]
    require(names == wanted, "selection is not exact original-uncompleted partition")
    for row in selected:
        require(row["target"] == expected[row["label"]]
                and row["reason"] == old[row["label"]]["status"]
                and row["original_summary"] is None, "selected frozen target/reason mismatch")
    previous = [{"label": row["label"], "status": row["status"], "summary": row["summary"]}
                for row in audit["coverage"] if row["summary"] is not None]
    require(selection["previous_completed"] == previous,
            "selection replaced or omitted original complete target")
    require(selection["original_completed_target_totals"] == audit["completed_target_totals"],
            "selection lost original failures")
    args = []
    kinds = {"lib": 0, "bin": 0, "test": 0, "example": 0}
    for row in selected:
        target = row["target"]
        require(target["kind"] in (["test"], ["example"]), "unexpected remaining target kind")
        kind = target["kind"][0]
        kinds[kind] += 1
        args.extend(("--test" if kind == "test" else "--example", target["name"]))
    require(kinds == {"lib": 0, "bin": 0, "test": 41, "example": 20},
            "remaining kind partition changed")
    require(set(selection["selected_kind_counts"]) == set(kinds)
            and all(type(selection["selected_kind_counts"][k]) is int
                    and selection["selected_kind_counts"][k] == v for k, v in kinds.items()),
            "invalid strict kind counts")
    require(selection["cargo_target_args"] == args, "target argv selection mismatch")
    return {name: expected[name] for name in names}, args


def run_provenance(run_id, job, command, log, before_sha, after_sha, after_present):
    return {"run_id": run_id, "job_id": job, "command": command, "raw_log": log,
            "source_commit": COMMIT, "source_tree": TREE,
            "source_before_canonical_sha256": before_sha,
            "source_after_canonical_sha256": after_sha,
            "source_after_present": after_present}


def provenance_for(row, parsed, provenance):
    require(len(row["segment_indexes"]) == 1, "completed target lacks exactly one segment")
    segment = parsed["segments"][row["segment_indexes"][0]]
    return {**provenance, "target_key": target_key(row["target"]),
            "target": row["target"], "cargo_header": segment["header"],
            "segment_byte_span": segment["segment_byte_span"],
            "summary_byte_span": segment["summary_byte_span"]}


def main(args, remainder_terminal, terminal_identity):
    inputs, warnings, problems = {}, [], []
    helper, inputs["failure_attribution_helper"] = load_helper()
    audit, inputs["original_failure_audit"] = read_json(
        TOOLS / "original-node-failed-inventory-v1.json", AUDIT_SHA)
    require(audit["binding_integrity"] is True and audit["qualification"] is False
            and audit["result"] == "DIAGNOSTIC_RECORDED" and audit["errors"] == [],
            "original audit not a bound failure observation")
    inventory, inputs["inventory"] = read_json(
        TOOLS / "node-target-inventory-recovery-v1.json", INVENTORY_SHA)
    capture, inputs["inventory_capture"] = read_json(TOOLS / "inventory-capture-recovery-v1.json")
    require(artifact_equal(inputs["inventory"], capture["inventory"]), "capture inventory hash")
    metadata_name = inventory["metadata"]["path"]
    require(Path(metadata_name).name == metadata_name, "inventory metadata path")
    metadata, inputs["original_metadata"] = read_json(TOOLS / metadata_name)
    require(artifact_equal(inputs["original_metadata"], inventory["metadata"]), "metadata hash")
    original_terminal, inputs["original_terminal"] = terminal(
        TOOLS / "original-node-terminal-status.json", ORIGINAL_JOB)
    require(inputs["original_terminal"]["sha256"] == ORIGINAL_TERMINAL_SHA,
            "original terminal identity differs")
    inputs["remainder_terminal"] = terminal_identity
    old_before, inputs["original_source_before"] = read_json(ORIGINAL / "source-before.json")
    old_started, inputs["original_started"] = read_json(ORIGINAL / "started.json")
    old_env, inputs["original_environment"] = read_json(ORIGINAL / "environment.json")
    old_before_sha = sha(canonical(old_before))
    require(old_before_sha == inventory["source_before_canonical_sha256"]
            == old_started["source_sha256"], "original source binding")
    expected = helper.expected_targets(inventory, metadata, old_before, problems)
    require(not problems and len(expected) == 91, "91-target metadata/source validation")
    for key, name in (("started", "original_started"), ("environment", "original_environment"),
                      ("source_before", "original_source_before")):
        require(artifact_equal(inputs[name], inventory["run_inputs"][key]), "original " + key)
    old_after, old_after_sha = None, None
    if (ORIGINAL / "source-after.json").is_file():
        old_after, inputs["original_source_after"] = read_json(ORIGINAL / "source-after.json")
        old_after_sha = sha(canonical(old_after))
    require((old_after is not None) == audit["source"]["after_present"],
            "original after availability differs from sealed audit")
    if old_after is None:
        warnings.append({"code": "ORIGINAL_SOURCE_AFTER_ABSENT",
                         "note": "The original timed-out run has no after snapshot. Later snapshots cannot repair it."})
    original_log, inputs["original_log"] = read(ORIGINAL / "complete-node.log")
    require(artifact_equal(inputs["original_log"], audit["inputs"]["log"]), "original sealed raw hash")
    original_parse = parse_run(helper, original_log, expected, old_env["CARGO_TARGET_DIR"])
    problems.extend(original_parse["problems"])
    old_rows = {row["label"]: row for row in audit["coverage"]}
    require(set(old_rows) == set(expected), "original audit target coverage")
    for name, row in original_parse["coverage"].items():
        require(row["target"] == old_rows[name]["target"]
                and row["status"] == old_rows[name]["status"]
                and row["summary"] == old_rows[name]["summary"],
                "sealed original target attribution differs: " + name)

    selection, inputs["remainder_selection"] = read_json(REMAINDER / "selection.json", SELECTION_SHA)
    selected, target_args = validate_target_list(selection, expected, audit)
    require(artifact_equal(inputs["original_failure_audit"], selection["original_audit"])
            and artifact_equal(inputs["original_terminal"], selection["original_terminal"]),
            "selection original evidence binding")
    started, inputs["remainder_started"] = read_json(REMAINDER / "started.json")
    before, inputs["remainder_source_before"] = read_json(REMAINDER / "source-before.json")
    env, inputs["remainder_environment"] = read_json(REMAINDER / "environment.json")
    before_sha = sha(canonical(before))
    require(before == old_before and before_sha == old_before_sha
            and started["source_sha256"] == before_sha, "remainder before does not match frozen original source")
    require(env == old_env, "recorded build environment differs")
    require(started.get("schema") == "pon-native-remaining-node-start-v1"
            and started.get("qualification") is False
            and started.get("expected_commit") == COMMIT and started.get("expected_tree") == TREE,
            "remainder started schema/source")
    require(artifact_equal(inputs["remainder_selection"], started["selection"]),
            "started selection hash")
    command = [str(Path(env["RUSTC"]).parent / "cargo"), "test", "--locked", "--offline",
               "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node",
               *target_args, "--all-features", "--no-fail-fast", "--", "--test-threads=1"]
    require(started["command"] == selection["command"] == command, "remainder exact argv mismatch")
    for key in ("RUST_TEST_THREADS", "CARGO_BUILD_JOBS", "CARGO_TERM_COLOR"):
        require(env[key] == {"RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "2",
                             "CARGO_TERM_COLOR": "never"}[key], "gate environment differs")
    graph, inputs["remainder_graph"] = read_json(REMAINDER / "cargo-graph.json")
    new_metadata, inputs["remainder_metadata"] = read_json(REMAINDER / "cargo-metadata.json")
    require(artifact_equal(inputs["remainder_metadata"], graph["metadata"])
            and artifact_equal(inputs["remainder_graph"], started["graph"])
            and new_metadata == metadata and graph["identical_to_inventory_metadata"] is True,
            "new actual metadata graph not identical")
    require(type(graph.get("exit_code")) is int and graph["exit_code"] == 0,
            "new metadata exit code")
    for key, n in (("workspace_members", len(metadata["workspace_members"])),
                   ("resolved_packages", len(metadata["packages"])), ("node_inventory_targets", 91)):
        require(type(graph.get(key)) is int and graph[key] == n, "strict graph count: " + key)
    _, inputs["remainder_recorder"] = read(
        TOOLS / "run_remaining_node_gate_recovery_v1.py")
    require(artifact_equal(inputs["remainder_recorder"], started["recorder"]),
            "actual remainder recorder hash differs")
    _, inputs["original_recorder"] = read(ROOT / "run_remote_node_gate.py")
    require(artifact_equal(inputs["original_recorder"], inventory["run_inputs"]["run_recorder"]),
            "actual original recorder hash differs")
    provider, inputs["provider"] = read_json(ROOT / "build-receipts/pq-provider/provider.json")
    require(provider["result"] == "PREPARED_AND_SMOKE_VERIFIED"
            and type(provider["exit_code"]) is int and provider["exit_code"] == 0
            and provider["version"] == "3.5.9", "provider result/strict exit")
    require(artifact_equal(inputs["provider"], started["inputs"]["provider"]), "provider receipt changed")
    for item in started["provider_artifacts"]:
        _, identity = read(item["path"])
        require(artifact_equal(identity, item), "provider backend artifact changed")
    _, cli_identity = read(env["TRNM_PQ_OPENSSL"])
    require(artifact_equal(cli_identity, started["provider_cli"])
            and cli_identity["sha256"] == env["TRNM_PQ_OPENSSL_SHA256"], "provider CLI changed")
    versions, inputs["remainder_toolchain"] = read_json(REMAINDER / "toolchain.json")
    old_versions, inputs["original_toolchain"] = read_json(ORIGINAL / "toolchain.json")
    require(versions == old_versions
            and artifact_equal(inputs["remainder_toolchain"], started["toolchain"]),
            "toolchain/kernel binding differs")
    for name, key in (("source-before.json", "source_before"), ("environment.json", "environment")):
        actual = inputs["remainder_source_before" if key == "source_before" else "remainder_environment"]
        require(artifact_equal(actual, started[key]), "started artifact " + name)
    result, after, after_sha = None, None, None
    if (REMAINDER / "result.json").is_file():
        result, inputs["remainder_result"] = read_json(REMAINDER / "result.json")
        require(result.get("schema") == "pon-native-remaining-node-execution-v1"
                and type(result.get("exit_code")) is int
                and result.get("qualification") is False
                and result.get("controlled_run_qualification_passed") is False
                and result.get("same_single_cargo_run_as_original") is False,
                "remainder result schema/strict exit/qualification boundary")
        require(result["command"] == command and result["source_before_sha256"] == before_sha,
                "result command/source binding")
        require(artifact_equal(inputs["remainder_started"], result["started"])
                and artifact_equal(inputs["remainder_selection"], result["selection"]),
                "result started/selection binding")
        require(artifact_equal(inputs["remainder_recorder"], result["recorder_before"])
                and artifact_equal(inputs["remainder_recorder"], result["recorder_after"])
                and result["recorder_unchanged"] is True and result["changed_inputs"] == [],
                "result input/recorder identity changed")
    if (REMAINDER / "source-after.json").is_file():
        after, inputs["remainder_source_after"] = read_json(REMAINDER / "source-after.json")
        after_sha = sha(canonical(after))
        require(after.get("head") == COMMIT and after.get("tree") == TREE, "remainder after source identity")
    if result is not None:
        require(result["source_after_sha256"] == after_sha, "result after-source hash")
        require(type(result["source_unchanged"]) is bool
                and result["source_unchanged"] == (after is not None and before == after),
                "result source unchanged boolean")
        if after is not None:
            require(artifact_equal(inputs["remainder_source_after"], result["source_after"]),
                    "result source after artifact")
    if after is None:
        warnings.append({"code": "REMAINDER_SOURCE_AFTER_ABSENT",
                         "note": "No later current-checkout snapshot is substituted."})
    elif before != after:
        problems.append({"code": "REMAINDER_SOURCE_CHANGED"})
    if result is None:
        warnings.append({"code": "REMAINDER_NATIVE_RESULT_ABSENT",
                         "note": "Only newly observed stable raw bytes after confirmed host termination are available."})
    remaining_log, inputs["remainder_log"] = read(REMAINDER / "remaining-node.log")
    if result is not None:
        require(artifact_equal(inputs["remainder_log"], result["log"]), "result raw log binding")
    remainder_parse = parse_run(helper, remaining_log, selected, env["CARGO_TARGET_DIR"])
    problems.extend(remainder_parse["problems"])

    sqlite = []
    if result is not None:
        require(isinstance(result["sqlite_build_outputs"], list), "SQLite output list type")
        for row in result["sqlite_build_outputs"]:
            retained = row["retained"]
            path = Path(retained["path"])
            require(path.parent == REMAINDER and re.fullmatch(
                r"sqlite-trnm-sqlite-io-boundary-[0-9a-f]{16}\.txt", path.name) is not None,
                    "SQLite witness path outside run")
            raw, identity = read(path)
            require(artifact_equal(identity, retained), "SQLite witness hash")
            qualified = b"cargo:rustc-cfg=trnm_sqlite_layout_witness\n" in raw
            unqualified = b"UNQUALIFIED:" in raw
            require(type(row["qualified"]) is bool and type(row["unqualified"]) is bool
                    and row["qualified"] is qualified and row["unqualified"] is unqualified,
                    "SQLite marker booleans disagree")
            sqlite.append({"artifact": identity, "qualified_marker": qualified,
                           "unqualified_marker": unqualified})
        if not sqlite or not all(row["qualified_marker"] and not row["unqualified_marker"] for row in sqlite):
            warnings.append({"code": "REMAINDER_SQLITE_QUALIFICATION_NOT_ESTABLISHED"})
        expected_wrapper = result["exit_code"] if result["exit_code"] != 0 else (
            0 if result["source_unchanged"] and result["recorder_unchanged"]
            and result["changed_inputs"] == [] and sqlite
            and all(row["qualified_marker"] and not row["unqualified_marker"] for row in sqlite) else 3)
        if remainder_terminal["state"] not in ("timed_out", "cancelled"):
            require(remainder_terminal["exit_code"] == expected_wrapper % 256,
                    "host wrapper exit disagrees with native recorder rule")
    original_provenance = run_provenance(
        "original", ORIGINAL_JOB, old_started["command"], inputs["original_log"],
        old_before_sha, old_after_sha, old_after is not None)
    remainder_provenance = run_provenance(
        "remainder", REMAINDER_JOB, command, inputs["remainder_log"],
        before_sha, after_sha, after is not None)
    union, summaries, failure_targets = [], [], []
    original_keys, remainder_keys = set(), set()
    for name, target in expected.items():
        original_row = original_parse["coverage"][name]
        from_original = old_rows[name]["summary"] is not None
        if from_original:
            row, parsed, provenance, assigned = original_row, original_parse, original_provenance, "original"
            original_keys.add(target_key(target))
        else:
            row = remainder_parse["coverage"][name]
            parsed, provenance, assigned = remainder_parse, remainder_provenance, "remainder"
            remainder_keys.add(target_key(target))
        entry = {
            "target_key": target_key(target), "target": target, "label": name,
            "assigned_run": assigned, "status": row["status"],
            "counted_summary": row["summary"], "counted_once": row["summary"] is not None,
            "summary_provenance": None,
            "original_observation_status": original_row["status"],
            "original_observation_excluded_from_totals": not from_original,
            "original_observation_exclusion_reason": None if from_original else
                "No unambiguous complete original target summary; retain raw observation and use the preassigned remainder run.",
            "qualification": False,
        }
        if row["summary"] is not None:
            entry["summary_provenance"] = provenance_for(row, parsed, provenance)
            summaries.append(row["summary"])
            if row["summary"]["failed"]:
                failure_targets.append({"target_key": entry["target_key"],
                                        "run": assigned, "failed": row["summary"]["failed"],
                                        "provenance": entry["summary_provenance"]})
        union.append(entry)
    require(len(original_keys) == 30 and len(remainder_keys) == 61
            and not original_keys.intersection(remainder_keys)
            and len(original_keys.union(remainder_keys)) == 91, "union canonical target partition")
    original_summaries = [row["summary"] for row in original_parse["coverage"].values()
                          if row["summary"] is not None]
    require(sum_rows(original_summaries) == audit["completed_target_totals"],
            "original complete failures lost")
    remaining_summaries = [row["summary"] for row in remainder_parse["coverage"].values()
                           if row["summary"] is not None]
    for parsed in (original_parse, remainder_parse):
        for segment in parsed["segments"]:
            for problem in segment["attribution_problems"]:
                warnings.append({"code": "SEGMENT_ATTRIBUTION_REFUSED",
                                 "target": segment["header"]["label"], "problem": problem})
    for path, identity in ((ORIGINAL / "complete-node.log", inputs["original_log"]),
                           (REMAINDER / "remaining-node.log", inputs["remainder_log"])):
        _, current = read(path)
        require(current == identity, "raw log changed during union audit")
    attribution_complete = len(summaries) == 91 and not problems
    _, own_identity = read(__file__)
    return {
        "schema": "pon-node-cross-run-coverage-diagnostic-recovery-v1",
        "result": "COVERAGE_DIAGNOSTIC_RECORDED" if not problems else "COVERAGE_DIAGNOSTIC_WITH_BINDING_OR_STRUCTURE_ERRORS",
        "kind": "cross_run_failed_observation_coverage", "qualification": False,
        "controlled_run_qualification_passed": False, "single_complete_cargo_gate": False,
        "original_failures_superseded": False, "original_timeout_reclassified": False,
        "independent_acceptance": False, "production_activation": False,
        "auditor": own_identity, "inputs": inputs,
        "source_commit": COMMIT, "source_tree": TREE,
        "inventory_target_count": 91, "original_assignment_count": 30,
        "remainder_assignment_count": 61, "completed_target_count": len(summaries),
        "all_targets_have_unambiguous_complete_summary": attribution_complete,
        "coverage": union,
        "uncovered_or_ambiguous_targets": [row["target_key"] for row in union if not row["counted_once"]],
        "original_completed_target_totals": sum_rows(original_summaries),
        "remainder_completed_target_totals": sum_rows(remaining_summaries),
        "cross_run_completed_target_totals": sum_rows(summaries) if not problems else None,
        "totals_scope": "At most one unambiguous complete Cargo target summary per canonical inventory target. This is diagnostic coverage across two invocations, not one successful test run.",
        "completed_failure_targets": failure_targets,
        "any_completed_test_failure_observed": bool(failure_targets),
        "original_run": {"terminal": original_terminal, "provenance": original_provenance,
                         "source_after_missing_not_repaired_by_remainder": old_after is None,
                         "segments": original_parse["segments"]},
        "remainder_run": {"terminal": remainder_terminal, "provenance": remainder_provenance,
                          "native_result_present": result is not None,
                          "native_cargo_exit_code": None if result is None else result["exit_code"],
                          "native_log_bound": result is not None,
                          "source_after_present": after is not None,
                          "source_before_after_identical": None if after is None else before == after,
                          "segments": remainder_parse["segments"]},
        "nested_summaries_added_to_totals": False, "nested_filtered_added_to_totals": False,
        "incomplete_test_case_lines_added_to_totals": False,
        "ignored_kept_separate_and_not_passes": True,
        "rust_libtest_skipped_summary_count": None,
        "raw_failed_and_skip_lines": {
            run: {"failed_lines": [r for s in parsed["segments"] for r in s["failed_test_lines_not_counted"]],
                  "unclassified_skip_markers": [r for s in parsed["segments"] for r in s["unclassified_skip_markers"]]}
            for run, parsed in (("original", original_parse), ("remainder", remainder_parse))},
        "sqlite_remainder_retained_witnesses": sqlite,
        "errors": problems, "warnings": warnings,
        "original_or_remainder_receipts_rewritten": False, "tests_started": False,
    }


def entry():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--remainder-terminal-status", required=True, type=Path)
    cli.add_argument("--output", required=True, type=Path)
    args = cli.parse_args()
    try:
        ending, ending_identity = terminal(args.remainder_terminal_status, REMAINDER_JOB)
    except (OSError, ValueError, TypeError, KeyError) as failure:
        print(json.dumps({"result": "NOT_READY_NO_CONFIRMED_REMAINDER_ENDING",
                          "qualification": False, "raw_test_logs_read": False,
                          "output_created": False, "message": str(failure)}))
        return 2
    try:
        report = main(args, ending, ending_identity)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as failure:
        report = {"schema": "pon-node-cross-run-coverage-diagnostic-recovery-v1",
                  "result": "COVERAGE_DIAGNOSTIC_INPUT_ERROR", "qualification": False,
                  "controlled_run_qualification_passed": False, "single_complete_cargo_gate": False,
                  "cross_run_completed_target_totals": None, "production_activation": False,
                  "errors": [{"type": type(failure).__name__, "message": str(failure)}]}
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    with args.output.open("xb") as stream:
        stream.write(encoded)
    print(json.dumps({"result": report["result"], "qualification": False,
                      "output": str(args.output), "bytes": len(encoded), "sha256": sha(encoded),
                      "completed_target_count": report.get("completed_target_count"),
                      "cross_run_completed_target_totals": report.get("cross_run_completed_target_totals"),
                      "error_count": len(report["errors"])}))
    return 0 if report["result"] == "COVERAGE_DIAGNOSTIC_RECORDED" else 2


if __name__ == "__main__":
    raise SystemExit(entry())
