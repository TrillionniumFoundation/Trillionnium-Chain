#!/usr/bin/env python3
"""Desktop recovery v3 adds actual original recorder artifact verification.

Recovery v1/v2 are retained unchanged; inaccessible scratch bytes were not recovered.

Read final retained evidence only; do not run Cargo/tests or change source/jobs.
Do not invoke before run-dir/result.json and source-after.json exist. An output
file is create-only. The original recorder's nested-inclusive totals are retained
as a comparison and are never rewritten.

Required:
  --run-dir PATH --inventory PATH --capture-receipt PATH --provider PATH --run-recorder PATH --output PATH

The metadata named by the inventory must be beside that inventory. Inventory is
created by capture_node_inventory_recovery_v1.py from actual locked Cargo metadata.
A PASS qualifies only the retained top-level harness count, source/environment
bindings, and retained SQLite layout witness for this controlled run. It does not
authenticate arbitrary print statements or establish independent business value.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys

VERSION = "desktop-recovery-v3"
EXPECTED_RECORDER_SHA256 = "049c64cf32927bcd16a82059707a468c91d6fc9be7d7abc9047bb3efcd2d8123"
EXPECTED_COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
EXPECTED_TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
RECOVERY_NOTE = ("New desktop recovery v3 derived from retained H v2; "
                 "v1/v2 are retained unchanged. Original recorder bytes are explicitly verified.")
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


def parse_segment(header, body, expected, target_dir, errors):
    local, starts, summaries, skip_markers = [], [], [], []
    for number, line in body:
        if "\x1b" in line or "\x00" in line:
            error(local, "CONTROL_BYTES_IN_HARNESS_OUTPUT", line=number)
        starts.extend(event(number, line, m, True) for m in START.finditer(line))
        matches = list(SUMMARY.finditer(line))
        for match in matches:
            row = event(number, line, match)
            summaries.append(row)
            require(local, (row["status"] == "ok") == (row["failed"] == 0),
                    "SUMMARY_STATUS_COUNTS_DIFFER", line=number)
        if "test result:" in line and not matches:
            error(local, "MALFORMED_SUMMARY", line=number, raw=line)
        if len(matches) > 1:
            error(local, "MULTIPLE_SUMMARIES_ON_LINE", line=number)
        if re.search(r"\b(?:[0-9]+\s+skipped|skipped(?:\s|:)|SKIP(?:PED)?(?:\s|:))", line):
            skip_markers.append({"line": number, "raw": line, "counted_as_top_level": False})

    target = expected.get(header["label"])
    if require(local, target is not None, "UNEXPECTED_CARGO_TARGET", label=header["label"]):
        exe = PurePosixPath(header["executable"])
        names = {target["name"], target["name"].replace("-", "_")}
        require(local, any(re.fullmatch(re.escape(name) + r"-[0-9a-f]{16}", exe.name)
                           for name in names), "EXECUTABLE_TARGET_MISMATCH", executable=str(exe))
        sub = "examples" if target["kind"] == ["example"] else "deps"
        require(local, exe.parent == PurePosixPath(target_dir) / "debug" / sub
                and ".." not in exe.parts, "EXECUTABLE_DIRECTORY_MISMATCH", executable=str(exe))

    first = starts[0] if starts else None
    final = summaries[-1] if summaries else None
    nested_rows = summaries[:-1] if summaries else []
    require(local, first is not None, "MISSING_OUTER_RUNNING")
    if first:
        require(local, first["whole_line"], "OUTER_RUNNING_NOT_WHOLE_LINE", line=first["line"])
    require(local, final is not None, "MISSING_OUTER_SUMMARY")
    if final:
        require(local, final["whole_line"], "FINAL_SUMMARY_NOT_WHOLE_LINE", line=final["line"])
        if first:
            require(local, pos(final) > pos(first), "SUMMARY_BEFORE_OUTER_RUNNING")
            require(local, first["count"] == executed(final), "OUTER_COUNT_MISMATCH",
                    running=first["count"], summary_executed=executed(final))
        require(local, final["filtered_out"] == 0, "OUTER_FILTERED_NONZERO",
                filtered_out=final["filtered_out"])
        require(local, not any(pos(row) > pos(final) for row in starts),
                "RUNNING_AFTER_FINAL_SUMMARY")

    remaining = list(starts[1:])
    nested = []
    for row in nested_rows:
        candidate = [s for s in remaining if pos(s) < pos(row) and s["count"] == executed(row)]
        record = {**row, "included_in_top_level_totals": False, "matched_running": None}
        if candidate:
            chosen = max(candidate, key=pos)
            remaining.remove(chosen)
            record["matched_running"] = chosen
        else:
            error(local, "NESTED_SUMMARY_WITHOUT_MATCHING_START", line=row["line"])
        nested.append(record)
    if final and first:
        # Never erase a same-sized child by greedily matching an earlier summary.
        # With no process-tagged output, a later child result can impersonate the
        # outer result even after the real outer result was printed. Refuse all
        # same-sized child starts conservatively; do not relax this to make a log pass.
        ambiguous = [s for s in starts[1:] if pos(first) < pos(s) < pos(final)
                     and s["count"] == first["count"]]
        require(local, not ambiguous, "FINAL_SUMMARY_AMBIGUOUS_WITH_CHILD", starts=ambiguous)
    errors.extend({"target": header["label"], **item} for item in local)
    return {
        "header": header, "target": target, "first_running": first,
        "candidate_outer_summary": final, "counting_valid": not local, "errors": local,
        "nested_summaries": nested, "nested_totals_excluded": total(nested),
        "nested_summary_attribution_verified": not local,
        "attribution_policy": "Any same-sized nested start is ambiguous without independent "
                              "process identity; greedy prior matches cannot remove that ambiguity.",
        "nested_running_headers": starts[1:], "unmatched_nested_running": remaining,
        "unmatched_nested_note": "Actual crash/SIGKILL children may have no summary; no pass inferred.",
        "skip_markers_unclassified": skip_markers,
    }


def analyze(args):
    errors, identities = [], {}
    run = args.run_dir
    # Read the terminal receipt first. Never interpret a live log as completed.
    result, identities["result"] = read_json(run / "result.json")
    require(errors, result.get("schema") == "pon-native-complete-node-execution-v1", "RESULT_SCHEMA")
    require(errors, type(result.get("exit_code")) is int, "RESULT_EXIT_MISSING")
    started, identities["started"] = read_json(run / "started.json")
    env, identities["environment"] = read_json(run / "environment.json")
    before, identities["source_before"] = read_json(run / "source-before.json")
    after, identities["source_after"] = read_json(run / "source-after.json")
    toolchain, identities["toolchain"] = read_json(run / "toolchain.json")
    inventory, identities["inventory"] = read_json(args.inventory)
    capture, identities["inventory_capture"] = read_json(args.capture_receipt)
    provider, identities["provider"] = read_json(args.provider)
    metadata_name = inventory["metadata"]["path"]
    if Path(metadata_name).name != metadata_name:
        raise ValueError("metadata artifact must be a sibling basename")
    metadata, identities["metadata"] = read_json(args.inventory.parent / metadata_name)
    validate_artifact(errors, identities["metadata"], inventory["metadata"], "metadata")
    validate_artifact(errors, identities["inventory"], capture["inventory"], "captured inventory")
    validate_artifact(errors, identities["metadata"], capture["metadata"], "captured metadata")
    require(errors, capture.get("schema") == "pon-node-inventory-capture-recovery-v1"
            and exact_natural(capture.get("exit_code"), 0) and capture.get("source_unchanged") is True,
            "INVENTORY_CAPTURE_INVALID")
    for side in ("source_before", "source_after"):
        require(errors, capture.get(side) == {"commit": EXPECTED_COMMIT, "tree": EXPECTED_TREE,
                                              "status": ""}, "CAPTURE_SOURCE_IDENTITY", side=side)
    expected_metadata_command = [
        started["command"][0], "metadata", "--locked", "--offline", "--manifest-path",
        "trillionnium/Cargo.toml", "--all-features", "--format-version", "1"]
    require(errors, capture.get("command") == expected_metadata_command, "CAPTURE_METADATA_COMMAND")
    for key in ("started", "environment", "source_before"):
        validate_artifact(errors, identities[key], inventory["run_inputs"][key],
                          "inventory run input " + key)
        validate_artifact(errors, identities[key], capture["run_inputs"][key],
                          "capture run input " + key)
    _, identities["run_recorder"] = read(args.run_recorder)
    validate_artifact(errors, identities["run_recorder"], inventory["run_inputs"]["run_recorder"],
                      "actual recorder versus inventory")
    validate_artifact(errors, identities["run_recorder"], capture["run_inputs"]["run_recorder"],
                      "actual recorder versus capture")
    require(errors, identities["run_recorder"]["sha256"] == EXPECTED_RECORDER_SHA256,
            "ORIGINAL_RUN_RECORDER_ACTUAL_HASH")
    for name, value in (("before", before), ("after", after)):
        digest = sha(canonical(value))
        identities["source_" + name]["canonical_sha256"] = digest
        require(errors, value.get("head") == EXPECTED_COMMIT and value.get("tree") == EXPECTED_TREE,
                "RUN_SOURCE_IDENTITY", which=name)
        require(errors, digest == result.get("source_" + name + "_sha256"),
                "RUN_SOURCE_DIGEST_MISMATCH", which=name)
        require(errors, isinstance(value.get("materialized"), list) and bool(value["materialized"]),
                "SOURCE_ENTRIES_MISSING", which=name)
        require(errors, all(isinstance(row, dict) and natural(row.get("bytes"))
                            for row in value.get("materialized", [])),
                "SOURCE_ENTRY_BYTE_COUNT_TYPES", which=name)
        omitted = value.get("omitted_historical_archive_blobs", [])
        require(errors, isinstance(omitted, list) and all(
            row["path"].startswith(("evidence/", "qualification/")) for row in omitted),
            "UNPERMITTED_SOURCE_OMISSION", which=name)
    require(errors, before == after and result.get("source_unchanged") is True,
            "RUN_SOURCE_CHANGED")
    source_sha = sha(canonical(before))
    require(errors, started.get("source_sha256") == source_sha
            and inventory.get("source_before_canonical_sha256") == source_sha,
            "STARTED_SOURCE_DIGEST")
    require(errors, started.get("expected_commit") == EXPECTED_COMMIT, "STARTED_COMMIT")
    expected_command = [str(PurePosixPath(env["RUSTC"]).parent / "cargo")] + CARGO_ARGS
    require(errors, result.get("command") == started.get("command") == expected_command,
            "RUN_COMMAND_NOT_COMPLETE_GATE")
    require(errors, finite_number(started.get("started_unix_seconds"))
            and started["started_unix_seconds"] > 0
            and finite_number(result.get("started_unix_seconds"))
            and started["started_unix_seconds"] == result["started_unix_seconds"],
            "RUN_START_TIME_MISMATCH")
    for key, value in {"CARGO_BUILD_JOBS": "2", "RUST_TEST_THREADS": "1",
                       "CARGO_TERM_COLOR": "never", "OPENSSL_STATIC": "1",
                       "OPENSSL_NO_VENDOR": "1", "OPENSSL_CONF": "/dev/null",
                       "TRNM_PQ_OPENSSL_VERSION": "3.5.9"}.items():
        require(errors, env.get(key) == value, "RUN_ENVIRONMENT_MISMATCH", key=key)
    require(errors, Path(env["RUSTC"]).is_absolute()
            and Path(env["CARGO_TARGET_DIR"]).is_absolute(), "RUN_ENVIRONMENT_PATH")
    require(errors, str(toolchain.get("rustc", "")).startswith("rustc 1.95.0 ")
            and str(toolchain.get("cargo", "")).startswith("cargo 1.95.0 "),
            "RECORDED_TOOLCHAIN_VERSION")
    require(errors, provider.get("result") == "PREPARED_AND_SMOKE_VERIFIED"
            and provider.get("version") == "3.5.9" and exact_natural(provider.get("exit_code"), 0),
            "PROVIDER_PREPARATION_INVALID")
    for env_key, provider_key in (("TRNM_PQ_OPENSSL", "cli_executable"),
                                  ("TRNM_PQ_OPENSSL_SHA256", "cli_sha256"),
                                  ("OPENSSL_DIR", "install_prefix")):
        require(errors, env.get(env_key) == provider.get(provider_key),
                "PROVIDER_ENVIRONMENT_BINDING", key=env_key)
    require(errors, env.get("OPENSSL_MODULES") == provider.get("openssl_modules")
            and env.get("OPENSSL_CONF") == provider.get("openssl_conf"),
            "PROVIDER_MODULE_CONFIGURATION")
    provider_artifacts = []
    for row in provider.get("native_backend_inputs", []):
        _, identity = read(row["path"])
        validate_artifact(errors, identity, row, "actual provider artifact")
        provider_artifacts.append(identity)
    require(errors, bool(provider_artifacts), "PROVIDER_NATIVE_INPUTS_MISSING")

    raw, identities["log"] = read(run / "complete-node.log")
    require(errors, exact_natural(result.get("log_bytes"), len(raw)) and sha(raw) == result.get("log_sha256"),
            "FINAL_LOG_IDENTITY")
    text = raw.decode("utf-8", errors="strict")
    require(errors, raw.endswith(b"\n"), "LOG_NOT_NEWLINE_TERMINATED")
    sqlite = []
    rows = result.get("sqlite_build_outputs")
    require(errors, isinstance(rows, list) and bool(rows), "SQLITE_QUALIFICATION_MISSING")
    seen_sqlite = set()
    for row in rows or []:
        name = row.get("retained", "")
        if not require(errors, re.fullmatch(r"sqlite-trnm-sqlite-io-boundary-[0-9a-f]{16}\.txt", name)
                       is not None and name not in seen_sqlite, "SQLITE_RETAINED_NAME", name=name):
            continue
        seen_sqlite.add(name)
        witness, identity = read(run / name)
        qualified = b"cargo:rustc-cfg=trnm_sqlite_layout_witness\n" in witness
        unqualified = b"UNQUALIFIED:" in witness
        require(errors, sha(witness) == row.get("sha256"), "SQLITE_RETAINED_HASH", name=name)
        require(errors, qualified and not unqualified and row.get("qualified") is True
                and row.get("unqualified") is False, "SQLITE_LAYOUT_UNQUALIFIED", name=name)
        sqlite.append({**identity, "actual_qualified_marker": qualified,
                       "actual_unqualified_marker": unqualified})
    require(errors, "trnm SQLite I/O boundary UNQUALIFIED:" not in text,
            "SQLITE_UNQUALIFIED_WARNING_IN_RAW_LOG")

    expected = expected_targets(inventory, metadata, before, errors)
    headers, sections, body, preamble = [], [], [], []
    current = None
    for number, line in enumerate(text.splitlines(), 1):
        match = HEADER.fullmatch(line)
        if match:
            if current is not None:
                sections.append((current, body))
            current = {"line": number, "raw": line, **match.groupdict()}
            headers.append(current)
            body = []
        else:
            if re.match(r"^\s*Running\s", line):
                error(errors, "MALFORMED_CARGO_RUNNING_HEADER", line=number, raw=line)
            if current is not None:
                body.append((number, line))
            elif START.search(line) or "test result:" in line:
                preamble.append({"line": number, "raw": line})
    if current is not None:
        sections.append((current, body))
    require(errors, not preamble, "HARNESS_OUTPUT_WITHOUT_CARGO_HEADER", events=preamble)
    labels = [row["label"] for row in headers]
    missing = sorted(set(expected) - set(labels))
    unexpected = sorted(set(labels) - set(expected))
    duplicates = sorted({name for name in labels if labels.count(name) != 1})
    require(errors, not missing, "MISSING_TARGET_HEADERS", targets=missing)
    require(errors, not unexpected, "UNEXPECTED_TARGET_HEADERS", targets=unexpected)
    require(errors, not duplicates, "DUPLICATE_TARGET_HEADERS", targets=duplicates)
    require(errors, len({h["executable"] for h in headers}) == len(headers),
            "DUPLICATE_TOP_LEVEL_EXECUTABLE")
    segments = [parse_segment(h, b, expected, env["CARGO_TARGET_DIR"], errors) for h, b in sections]
    observed = [s["candidate_outer_summary"] for s in segments
                if s["counting_valid"] and s["candidate_outer_summary"] is not None]
    nested = [{**row, "cargo_target": segment["header"]["label"]}
              for segment in segments for row in segment["nested_summaries"]]
    old_rows = [list(row) for row in OLD_SUMMARY.findall(text)]
    old = {"passed": sum(int(row[1]) for row in old_rows),
           "failed": sum(int(row[2]) for row in old_rows),
           "ignored": sum(int(row[3]) for row in old_rows),
           "test_summary_count": len(old_rows)}
    require(errors, result.get("test_summaries") == old_rows, "RECORDER_SUMMARY_LIST_CHANGED")
    for key, value in old.items():
        require(errors, exact_natural(result.get(key), value), "RECORDER_ORIGINAL_TOTAL_CHANGED", key=key)
    complete = not errors and len(observed) == len(expected) == len(headers)
    totals = total(observed) if complete else None
    if complete and result["exit_code"] == 0 and totals["failed"] != 0:
        error(errors, "ZERO_CARGO_EXIT_WITH_FAILED_OUTER_TEST")
        complete, totals = False, None
    passed = complete and result["exit_code"] == 0 and all(row["status"] == "ok" for row in observed)
    _, parser = read(__file__)
    return {
        "schema": "pon-complete-node-top-level-counts-recovery-v3",
        "recovery_version": VERSION, "recovery_provenance": RECOVERY_NOTE, "parser": parser,
        "result": "PASS" if passed else ("TEST_FAILURE" if complete else "INCOMPLETE_OR_INVALID"),
        "inputs": identities, "source_commit": EXPECTED_COMMIT, "source_tree": EXPECTED_TREE,
        "top_level_counting_complete": complete, "controlled_run_qualification_passed": passed,
        "top_level_totals": totals, "observed_valid_segment_totals_only": total(observed),
        "target_headers": headers, "expected_target_count": len(expected),
        "target_header_count": len(headers), "missing_targets": missing,
        "unexpected_targets": unexpected, "duplicate_targets": duplicates,
        "segments": segments, "nested_summaries": nested,
        "nested_summary_count": len(nested), "nested_totals_excluded": total(nested),
        "nested_filtered_out_included_in_top_level": False,
        "skipped_classification": {
            "libtest_explicit_skipped_field": None,
            "ignored_are_not_passes": True,
            "non_libtest_skip_markers_are_unclassified_not_added": True,
            "markers": [row for s in segments for row in s["skip_markers_unclassified"]],
        },
        "original_recorder_nested_inclusive_totals_unchanged": old,
        "sqlite_retained_witnesses": sqlite, "provider_actual_artifacts": provider_artifacts,
        "original_recorder_rewritten": False, "original_result_rewritten": False,
        "original_log_rewritten": False, "source_or_job_modified": False, "tests_started": False,
        "errors": errors, "independent_customer": False, "independent_operator": False,
        "physical_model_efficacy": False, "production_activation": False,
        "authority_boundary": "Controlled owner receipts and byte comparisons. A text parser "
                              "cannot authenticate arbitrary printed claims or independent demand.",
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--run-dir", required=True, type=Path)
    cli.add_argument("--inventory", required=True, type=Path)
    cli.add_argument("--capture-receipt", required=True, type=Path)
    cli.add_argument("--provider", required=True, type=Path)
    cli.add_argument("--run-recorder", required=True, type=Path)
    cli.add_argument("--output", required=True, type=Path)
    args = cli.parse_args()
    if not (args.run_dir / "result.json").is_file() or not (args.run_dir / "source-after.json").is_file():
        print(json.dumps({"result": "NOT_READY_FINAL_RECEIPT_ABSENT", "recovery_version": VERSION,
                          "complete_node_log_read": False, "output_created": False}))
        return 2
    try:
        report = analyze(args)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as failure:
        report = {"schema": "pon-complete-node-top-level-counts-recovery-v3",
                  "recovery_version": VERSION, "recovery_provenance": RECOVERY_NOTE,
                  "result": "INCOMPLETE_OR_INVALID", "top_level_counting_complete": False,
                  "controlled_run_qualification_passed": False, "top_level_totals": None,
                  "errors": [{"code": "INPUT_OR_PARSER_ERROR", "type": type(failure).__name__,
                              "message": str(failure)}],
                  "original_result_rewritten": False, "production_activation": False}
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    try:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    except OSError as failure:
        print(json.dumps({"result": "OUTPUT_REFUSED", "message": str(failure)}), file=sys.stderr)
        return 2
    print(json.dumps({"result": report["result"], "output": str(args.output),
                      "bytes": len(encoded), "sha256": sha(encoded),
                      "top_level_totals": report.get("top_level_totals"),
                      "nested_summary_count": report.get("nested_summary_count"),
                      "error_count": len(report["errors"]), "original_result_rewritten": False},
                     sort_keys=True))
    return {"PASS": 0, "TEST_FAILURE": 1, "INCOMPLETE_OR_INVALID": 2}[report["result"]]


if __name__ == "__main__":
    raise SystemExit(main())
