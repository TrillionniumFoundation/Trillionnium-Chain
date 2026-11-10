#!/usr/bin/env python3
"""Replay retained cost-reader and workflow controls without executing native work.

Only Python's standard library is required. A matching repository checkout supplies
the current reader/tests; all historical inputs are included in this bundle.
Uncompressed journals and the before-fix overlay exist only in a temporary directory.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time

BUNDLE = Path(__file__).resolve().parent
WORKFLOW = ".github/workflows/pon-w1-work-security.yml"
SUITES = ("factorial-kernel-tests", "factorial-example-tests", "header-binding-tests",
          "history-w1-tests", "history-import-tests", "cpu-completion-tests")
NATIVE_PREFIX = "final-native/v4-observation/"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def relative_file(root, name):
    path = PurePosixPath(name)
    need(not path.is_absolute() and ".." not in path.parts, "UNSAFE_PATH:" + name)
    resolved = root / name
    need(resolved.is_file() and not resolved.is_symlink(), "MISSING_FILE:" + name)
    return resolved


def check_files(root, rows):
    for row in rows:
        data = relative_file(root, row["path"]).read_bytes()
        need(len(data) == row["bytes"] and sha(data) == row["sha256"],
             "FILE_BINDING:" + row["path"])
    return len(rows)


def command(out, name, argv, cwd, expected_exit, tests=None, failures=None):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    start = time.monotonic_ns()
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True)
    elapsed = time.monotonic_ns() - start
    (out / (name + ".stdout.log")).write_bytes(result.stdout)
    (out / (name + ".stderr.log")).write_bytes(result.stderr)
    row = {"name": name, "argv": argv, "cwd": str(cwd),
           "exit_code": result.returncode, "expected_exit_code": expected_exit,
           "reader_or_control_wall_ns": elapsed,
           "stdout_bytes": len(result.stdout), "stdout_sha256": sha(result.stdout),
           "stderr_bytes": len(result.stderr), "stderr_sha256": sha(result.stderr),
           "native_executed": False}
    diagnostic = result.stderr.decode("utf-8", errors="replace")
    if tests is not None:
        counts = re.findall(r"^Ran ([0-9]+) tests? in ", diagnostic, flags=re.M)
        row["expected_test_methods"] = tests
        row["observed_test_methods"] = [int(value) for value in counts]
    if failures is not None:
        row["expected_failure_subtests"] = failures
        row["observed_failure_summaries"] = re.findall(r"^FAILED \(([^\n]+)\)$", diagnostic, re.M)
    save(out / (name + ".result.json"), row)
    need(result.returncode == expected_exit, "COMMAND_EXIT:" + name)
    if tests is not None:
        need(row["observed_test_methods"] == [tests], "TEST_METHODS:" + name)
    if failures is not None:
        need(row["observed_failure_summaries"] == [f"failures={failures}"],
             "FAILURE_ROSTER:" + name)
    if tests is not None and expected_exit == 0:
        need(re.search(r"^OK$", diagnostic, re.M) is not None, "TEST_RESULT:" + name)
    print(name + ": expected exit " + str(expected_exit), flush=True)
    return row, result.stdout


def replay_controls(repo, temporary, out):
    pins = load(BUNDLE / "source-pins.json")
    overlay = temporary / "before-fix-overlay"
    for row in pins["files"]:
        target = overlay / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / row["path"], target)
    for row in pins["before_fix_files"]:
        source = relative_file(BUNDLE, row["bundle_path"])
        need(sha(source.read_bytes()) == row["sha256"], "BASELINE_SOURCE")
        shutil.copyfile(source, overlay / row["repository_path"])
    cases = [
        ("lifecycle-before", overlay, "test_w1_lifecycle_cost_v4.py", 1, 15, 76),
        ("lifecycle-after", repo, "test_w1_lifecycle_cost_v4.py", 0, 15, None),
        ("native-gate-before", overlay, "test_w1_factorial_native_gate.py", 1, 9, 3),
        ("native-gate-after", repo, "test_w1_factorial_native_gate.py", 0, 9, None),
        ("retained-material-reader", repo, "test_pon_w1_cost_matrix_reader.py", 0, 32, None),
    ]
    rows = []
    for name, root, test, expected, count, failures in cases:
        row, _ = command(out, name, [sys.executable, "-B", "scripts/ci/" + test, "-v"],
                         root, expected, tests=count, failures=failures)
        rows.append(row)
    return rows


def extract_hosted(out):
    target = out / "hosted-spans"
    target.mkdir()
    reports = []
    for job, names in ((129678540672, ("legal-native-controls",)), (129678540829, SUITES)):
        source = BUNDLE / "originals/hosted" / f"gh-job-{job}.log"
        raw = source.read_bytes()
        original_lines = raw.decode().splitlines()
        lines = [re.sub(r"^\d{4}-\d\d-\d\dT\S+Z ", "", line) for line in original_lines]
        spans = []
        for start, line in enumerate(lines):
            if re.fullmatch(r"running [0-9]+ tests?", line):
                end = next(i for i in range(start + 1, len(lines))
                           if lines[i].startswith("test result:"))
                spans.append((start, end))
        need(len(spans) == len(names), "HOSTED_SUITE_COUNT")
        rows = []
        for name, (start, end) in zip(names, spans):
            data = ("\n".join(lines[start:end + 1]) + "\n").encode()
            need(data == (BUNDLE / "originals/extracted-hosted" / (name + ".log")).read_bytes(),
                 "HOSTED_SPAN_BINDING:" + name)
            (target / (name + ".log")).write_bytes(data)
            rows.append({"suite": name, "original_first_line": start + 1,
                         "original_last_line": end + 1, "bytes": len(data), "sha256": sha(data)})
        reports.append({"job_id": job, "original_bytes": len(raw),
                        "original_sha256": sha(raw), "spans": rows})
    save(out / "hosted-extraction.json", reports)
    return target


def replay_hosted(repo, out):
    target = extract_hosted(out)
    rows = []
    for label, path, expected in (
        ("before", BUNDLE / "before-fix-source" / WORKFLOW, 1),
        ("after", repo / WORKFLOW, 0),
    ):
        workflow = path.read_text()
        marker = 'python3 - "$OUT/legal-native-controls.log" <<\'PY\'\n'
        need(workflow.count(marker) == 1 and workflow.count("<<'PYTEST'\n") == 1,
             "INLINE_GATE_MARKER")
        legal = textwrap.dedent(workflow.split(marker, 1)[1].split("          PY", 1)[0])
        factorial = textwrap.dedent(workflow.split("<<'PYTEST'\n", 1)[1].split("          PYTEST", 1)[0])
        for name, code, argument in (("legal", legal, target / "legal-native-controls.log"),
                                     ("factorial", factorial, target)):
            row, _ = command(out, "hosted-" + name + "-" + label,
                             [sys.executable, "-B", "-c", code, str(argument)], repo, expected)
            row["workflow_sha256"] = sha(path.read_bytes())
            row["inline_code_sha256"] = sha(code.encode())
            rows.append(row)
    return rows


def replay_historical(repo, temporary, out):
    root = BUNDLE / "historical-v4"
    published = root / "published-originals"
    metadata = load(published / "inventories/117-local-validation-archive.json")
    inventory = load(published / "inventories/117-local-validation-files.json")
    expected = {row["path"]: row for row in inventory["files"]}
    archive = published / "archives/117-local-validation.tar.xz"
    raw_archive = archive.read_bytes()
    need(len(raw_archive) == metadata["bytes"] and sha(raw_archive) == metadata["sha256"],
         "HISTORICAL_ARCHIVE_BINDING")
    selected, seen = {}, set()
    with tarfile.open(archive, "r:xz") as handle:
        for member in handle.getmembers():
            if member.isdir():
                continue
            need(member.isfile(), "HISTORICAL_NONFILE_MEMBER")
            name = member.name.removeprefix("./")
            path = PurePosixPath(name)
            need(not path.is_absolute() and ".." not in path.parts and name not in seen,
                 "HISTORICAL_MEMBER_PATH")
            data = handle.extractfile(member).read()
            need(name in expected and len(data) == expected[name]["bytes"]
                 and sha(data) == expected[name]["sha256"], "HISTORICAL_MEMBER_BINDING:" + name)
            seen.add(name)
            if name.startswith(NATIVE_PREFIX):
                selected[name[len(NATIVE_PREFIX):]] = data
    need(seen == set(expected) and len(seen) == metadata["file_count"], "HISTORICAL_ROSTER")
    need(selected["source-before.json"] == selected["source-after.json"], "HISTORICAL_SOURCE_CHANGED")
    source = json.loads(selected["source-before.json"])
    need(source["tested_commit"] == "11791e2da79b69322271be2cffe03725165151d1"
         and source["tested_tree"] == "162552848110fda532504b78865a16930bc6d9bb"
         and source["tracked_worktree_verified"] is True, "HISTORICAL_SOURCE_RECEIPT")
    binary = gzip.decompress(selected["pon_w1_lifecycle_cost_v4.bin.gz"])
    reports = []
    for name, expected_exit in (("complete", 0), ("terminated", 3)):
        receipt = json.loads(selected[name + "-receipt.json"])
        need(receipt["head"] == source["tested_commit"], "NATIVE_RECEIPT_SOURCE")
        for key in ("binary_before", "binary_after", "loaded_executable"):
            need(receipt[key]["sha256"] == sha(binary), "NATIVE_BINARY_BINDING")
            if "bytes" in receipt[key]:
                need(receipt[key]["bytes"] == len(binary), "NATIVE_BINARY_SIZE")
        for key in ("raw", "stderr"):
            data = selected[receipt[key]["file"]]
            need(len(data) == receipt[key]["bytes"] and sha(data) == receipt[key]["sha256"],
                 "NATIVE_PROCESS_BYTES:" + key)
        journal = temporary / (name + ".jsonl")
        journal.write_bytes(selected[name + ".jsonl"])
        row, output = command(out, "historical-" + name,
                              [sys.executable, "-B", str(repo / "scripts/pon_w1_lifecycle_cost_v4.py"),
                               str(journal), "--process-exit-code", str(receipt["exit_code"])],
                              repo, expected_exit)
        need(output == selected[name + "-readback.json"], "HISTORICAL_READBACK_CHANGED:" + name)
        row.update(original_native_exit_code=receipt["exit_code"],
                   original_reader_exit_code=receipt["reader_exit_code"],
                   historical_readback_byte_identical=True, readback=json.loads(output))
        save(out / ("historical-" + name + ".result.json"), row)
        reports.append(row)
    return {"archive_bytes": len(raw_archive), "archive_sha256": sha(raw_archive),
            "verified_member_count": len(seen), "historical_source": source,
            "retained_binary_bytes": len(binary), "retained_binary_sha256": sha(binary),
            "journal_replays": reports, "native_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=BUNDLE.parents[3],
                        help="matching repository checkout; defaults to this bundle's repository")
    parser.add_argument("--output", type=Path,
                        help="new or empty result directory; defaults to a new temporary directory")
    parser.add_argument("--include-ci-contract", action="store_true",
                        help="also rerun the complete 177-method repository CI contract")
    args = parser.parse_args()
    repo = args.repo.resolve()
    out = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="pon-cost-replay-results-"))
    out.mkdir(parents=True, exist_ok=True)
    need(not any(out.iterdir()), "OUTPUT_DIRECTORY_NOT_EMPTY")
    result = {"schema": "pon-open-consensus-cost-regression-replay-v1", "status": "FAIL",
              "native_executed": False, "full_w1_relation_replayed": False,
              "all_legal_work_cost_lower_bound_proved": False,
              "public_resource_qualified": False, "production_qualified": False,
              "consensus_credit_added": 0}
    try:
        result["verified_input_files"] = check_files(BUNDLE, load(BUNDLE / "INPUT_MANIFEST.json")["files"])
        pins = load(BUNDLE / "source-pins.json")
        result["verified_repository_source_files"] = check_files(repo, pins["files"])
        with tempfile.TemporaryDirectory(prefix="pon-cost-replay-work-") as work:
            temporary = Path(work)
            result["controls"] = replay_controls(repo, temporary, out)
            result["hosted_gate_replays"] = replay_hosted(repo, out)
            result["historical_v4"] = replay_historical(repo, temporary, out)
            if args.include_ci_contract:
                row, _ = command(out, "ci-contract", [sys.executable, "-B", "scripts/ci/test_ci_contract.py", "-v"],
                                 repo, 0, tests=177)
                result["ci_contract"] = row
        result["source_files_unchanged_after_replay"] = check_files(repo, pins["files"]) == len(pins["files"])
        result["status"] = "PASS"
    except (OSError, ValueError, StopIteration, tarfile.TarError) as error:
        result["error"] = str(error)
    save(out / "summary.json", result)
    print(json.dumps({"status": result["status"], "output": str(out), "native_executed": False}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
