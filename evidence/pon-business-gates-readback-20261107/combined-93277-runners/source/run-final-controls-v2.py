#!/usr/bin/env python3
"""Run frozen-source controls once; no source edits, native builds, or benchmarks."""
from __future__ import annotations
import argparse
import ast
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time
import traceback

BASE = Path("/home/qian-qi/chain-throughput-local-admin-20261107")
ROOT = BASE / "work-final-business-20261107"
PREP = BASE / "final-source-validation-20261107"
ROSTER = PREP / "prepared-test-roster.json"
EXPECTED_ROSTER_SHA256 = "d39c7938b75bfbe929248530494d23b6d2c307f7a91579f47e21e46da17d691a"
EXPECTED_TOTAL = 665
PYTHON = "/usr/bin/python3"
CARGO = "/home/qian-qi/.cargo/bin/cargo"
SOURCE_VERIFIER = "scripts/ci/verify_ci_source.py"
SOURCE_VERIFIER_SHA256 = "0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946"

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")

def prepare_environment():
    environment = os.environ.copy()
    environment.update(
        PATH="/home/qian-qi/.cargo/bin:" + environment.get("PATH", ""),
        PYTHONDONTWRITEBYTECODE="1",
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_TERMINAL_PROMPT="0",
        GIT_OPTIONAL_LOCKS="0",
        CARGO_HOME=str(BASE / "local-build/cargo"),
        CARGO_TARGET_DIR=str(PREP / "metadata-only-target"),
        CARGO_NET_OFFLINE="true",
    )
    return environment

def names_from_source(relative, selected_class=None):
    raw = (ROOT / relative).read_bytes()
    tree = ast.parse(raw, filename=relative)
    names = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and (
                selected_class is None or node.name == selected_class):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                    names.append(node.name + "." + item.name)
    return sorted(names)

def check_roster(roster):
    rows = []
    for suite in roster["suites"]:
        relative = suite["path"]
        actual_hash = sha(ROOT / relative)
        if actual_hash != suite["sha256"]:
            raise ValueError("prepared suite source changed: " + relative)
        names = names_from_source(relative)
        for imported in suite.get("imported_test_classes", []):
            if sha(ROOT / imported["path"]) != imported["sha256"]:
                raise ValueError("prepared imported test class changed: " + imported["path"])
            names += names_from_source(imported["path"], imported["class"])
        names.sort()
        if names != suite["expected_names"] or len(names) != suite["expected"]:
            raise ValueError("source test roster changed: " + relative)
        if len(set(names)) != len(names):
            raise ValueError("duplicate prepared test identity: " + relative)
        rows.append({"path": relative, "expected": suite["expected"], "sha256": actual_hash})
    if sum(row["expected"] for row in rows) != EXPECTED_TOTAL:
        raise ValueError("unexpected prepared aggregate denominator")
    return rows

def denominator(log, suite):
    text = log.read_text(encoding="utf-8", errors="replace")
    starts = re.findall(r"(?m)^(test\w*) \(([^)\r\n]+)\)", text)
    names = []
    full_ids = []
    for method, identity in starts:
        parts = identity.split(".")
        class_name = parts[-2] if parts[-1] == method and len(parts) >= 2 else parts[-1]
        names.append(class_name + "." + method)
        full_ids.append(identity)
    observed = collections.Counter(names)
    expected = collections.Counter(suite["expected_names"])
    summaries = re.findall(r"(?m)^Ran ([0-9]+) tests? in ([0-9.]+)s[ \t]*$", text)
    endings = re.findall(r"(?m)^(OK(?: \([^\n]*\))?|FAILED(?: \([^\n]*\))?)[ \t]*$", text)
    ran = int(summaries[0][0]) if len(summaries) == 1 else None
    missing = sorted((expected - observed).elements())
    unexpected = sorted((observed - expected).elements())
    duplicates = {name: count for name, count in observed.items() if count != 1}
    return {
        "expected_tests": suite["expected"],
        "observed_ran_tests": ran,
        "original_summary_rows": summaries,
        "original_final_status_rows": endings,
        "observed_verbose_test_starts": len(names),
        "observed_full_test_ids": full_ids,
        "missing_expected_test_names": missing,
        "unexpected_test_names": unexpected,
        "duplicate_test_names": duplicates,
        "strict_zero_failure_skip_expected_failure_success": (
            ran == suite["expected"] and len(names) == suite["expected"]
            and not missing and not unexpected and not duplicates
            and endings == ["OK"]),
        "raw_log_sha256": sha(log),
        "raw_log_bytes": log.stat().st_size,
        "scope": "Original unittest CLI output; counts are test methods, not subtests.",
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_head):
        parser.error("a complete immutable lowercase 40-hex final SHA is required")
    output = args.output.resolve()
    if output == ROOT or output.is_relative_to(ROOT):
        parser.error("all results must be outside the source worktree")
    if not output.is_relative_to(PREP):
        parser.error("output must be within the dedicated external validation directory")
    if sha(ROSTER) != EXPECTED_ROSTER_SHA256:
        raise ValueError("prepared roster identity changed")
    roster = json.loads(ROSTER.read_text())
    output.mkdir(parents=True, exist_ok=False)
    (output / "commands").mkdir()
    (output / "logs").mkdir()
    env = prepare_environment()
    summary = {
        "schema": "trnm-final-source-controls-local-v1",
        "source_root": str(ROOT),
        "expected_head": args.expected_head,
        "started_utc": utc(),
        "completed": False,
        "all_controls_passed": False,
        "expected_test_methods": EXPECTED_TOTAL,
        "source_before_verified": False,
        "source_after_verified": False,
        "source_before_after_equal": False,
        "commands": [],
        "test_suites": [],
        "failures": [],
        "scope": (
            "Source/reader/unit controls and Cell formal reference tests on the exact local committed source. "
            "Not the original 4-second service, 4105-block History, fixed-resource Actions, "
            "whole native workspace, useful-work, model-efficacy, or release qualification."),
        "original_business_gates_accepted": False,
        "production_qualified": False,
        "reruns_permitted_by_this_driver": False,
        "original_cell_child_timeout_seconds": 30,
        "original_cell_timeout_or_runtime_identity_modified": False,
    }
    write_json(output / "invocation.json", {
        "argv": sys.argv, "cwd": str(Path.cwd()), "utc": summary["started_utc"],
        "expected_head": args.expected_head, "runner": str(Path(__file__).resolve()),
        "runner_sha256": sha(__file__), "roster": str(ROSTER),
        "roster_sha256": sha(ROSTER), "source_verifier_sha256": SOURCE_VERIFIER_SHA256,
        "environment_overrides": {key: env[key] for key in (
            "PATH", "PYTHONDONTWRITEBYTECODE", "GIT_NO_LAZY_FETCH", "GIT_NO_REPLACE_OBJECTS",
            "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS", "CARGO_HOME", "CARGO_TARGET_DIR",
            "CARGO_NET_OFFLINE")},
        "cpu_limits_or_runtime_spoof_added": False,
        "native_build_commands": [],
        "benchmarks": [],
    })

    def run(name, command, timeout=600):
        start_utc = utc()
        begin = time.monotonic_ns()
        log = output / "logs" / (name + ".log")
        record = {
            "name": name, "argv": command, "cwd": str(ROOT),
            "start_utc": start_utc, "supervisor_timeout_seconds": timeout,
            "exit_code": None, "timed_out": False,
            "log": str(log.relative_to(output)),
        }
        process = None
        with log.open("xb") as stream:
            try:
                process = subprocess.Popen(
                    command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                    stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                record["pid"] = process.pid
                try:
                    record["exit_code"] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record["timed_out"] = True
                    os.killpg(process.pid, signal.SIGKILL)
                    record["exit_code"] = process.wait()
            except Exception:
                record["launch_or_wait_exception"] = traceback.format_exc()
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    record["exit_code"] = process.wait()
            finally:
                stream.flush()
                os.fsync(stream.fileno())
        record.update(
            end_utc=utc(), wall_ns=time.monotonic_ns() - begin,
            log_sha256=sha(log), log_bytes=log.stat().st_size)
        write_json(output / "commands" / (name + ".json"), record)
        summary["commands"].append(record)
        print(json.dumps({"event": "command_complete", "name": name,
                          "exit_code": record["exit_code"], "timed_out": record["timed_out"],
                          "log_bytes": record["log_bytes"]}), flush=True)
        if record["exit_code"] != 0 or record["timed_out"]:
            summary["failures"].append(name)
        return record, log

    def source_check(label):
        target = output / ("source-" + label + ".json")
        rec, log = run("source-" + label, [
            PYTHON, SOURCE_VERIFIER, "--kind", "head",
            "--expected-head", args.expected_head, "--output", str(target)], timeout=600)
        ok = rec["exit_code"] == 0 and not rec["timed_out"] and target.is_file()
        if ok:
            value = json.loads(target.read_text())
            ok = (
                value.get("schema") == "trnm-ci-source-v1"
                and value.get("kind") == "head"
                and value.get("tested_commit") == args.expected_head
                and value.get("candidate") == args.expected_head
                and value.get("tracked_worktree_verified") is True
                and value.get("tests_executed_by_identity_check") is False
                and value.get("base") is None and value.get("prospective_merge") is None)
        summary["source_" + label + "_verified"] = ok
        if not ok and "source-" + label not in summary["failures"]:
            summary["failures"].append("source-" + label)
        return ok

    primary_ready = False
    try:
        if sha(ROOT / SOURCE_VERIFIER) != SOURCE_VERIFIER_SHA256:
            raise ValueError("original source verifier changed")
        if not source_check("before"):
            raise ValueError("original full-source before verifier failed; test execution prohibited")
        primary_ready = True
        write_json(output / "test-roster-confirmed.json", {
            "prepared_roster_sha256": sha(ROSTER),
            "expected_total": EXPECTED_TOTAL,
            "source_checked_suites": check_roster(roster),
        })
        runtime_code = (
            "import sys,platform,json,numpy,cryptography;"
            "print(json.dumps({'executable':sys.executable,'version':sys.version,"
            "'implementation':platform.python_implementation(),"
            "'python':platform.python_version(),'numpy':numpy.__version__,"
            "'numpy_file':numpy.__file__,'cryptography':cryptography.__version__,"
            "'cryptography_file':cryptography.__file__},sort_keys=True))")
        rec, log = run("python-runtime", [PYTHON, "-B", "-c", runtime_code], timeout=60)
        if rec["exit_code"] != 0:
            raise ValueError("actual Python dependency discovery failed")
        runtime = json.loads(log.read_text())
        write_json(output / "actual-python-runtime.json", runtime)
        if (runtime["python"], runtime["numpy"], runtime["cryptography"]) != (
                "3.12.3", "1.26.4", "41.0.7"):
            raise ValueError("actual runtime differs from prepared genuine runtime")
        static_commands = [
            ("preflight-audit", ["bash", "scripts/project-preflight.sh", "--audit"]),
            ("ci-contract", [PYTHON, "scripts/ci/check_ci_contract.py"]),
            ("pq-research-integration", [PYTHON, "scripts/ci/check_pq_research_integration.py"]),
            ("distributed-source-inventory", [PYTHON, "scripts/refresh_distributed_source_inventory.py", "--check"]),
            ("repository-links-and-contracts", [PYTHON, "scripts/ci/check_repository.py"]),
            ("git-diff-check", ["git", "--no-replace-objects", "diff", "--check"]),
            ("cargo-version", [CARGO, "+1.95.0", "--version"]),
            ("rustc-version", ["/home/qian-qi/.cargo/bin/rustc", "+1.95.0", "--version", "--verbose"]),
            ("fmt-all-check", [CARGO, "+1.95.0", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"]),
            ("cargo-locked-offline-metadata", [CARGO, "+1.95.0", "metadata", "--manifest-path", "trillionnium/Cargo.toml",
                                              "--format-version", "1", "--all-features", "--locked", "--offline"]),
        ]
        for name, command in static_commands:
            run(name, command)
        for index, suite in enumerate(roster["suites"], 1):
            name = f"{index:02d}-" + Path(suite["path"]).stem
            rec, log = run(name, [PYTHON, suite["path"], "-v"], timeout=1800)
            parsed = denominator(log, suite)
            parsed.update({
                "path": suite["path"], "command_record": "commands/" + name + ".json",
                "source_sha256": suite["sha256"],
                "process_exit_code": rec["exit_code"], "process_timed_out": rec["timed_out"]})
            parsed["passed"] = (
                parsed["strict_zero_failure_skip_expected_failure_success"]
                and rec["exit_code"] == 0 and not rec["timed_out"])
            write_json(output / "commands" / (name + "-denominator.json"), parsed)
            summary["test_suites"].append(parsed)
            if not parsed["passed"] and name not in summary["failures"]:
                summary["failures"].append(name)
            print(json.dumps({
                "event": "suite_denominator", "name": name,
                "expected": parsed["expected_tests"], "observed": parsed["observed_ran_tests"],
                "verbose_starts": parsed["observed_verbose_test_starts"], "passed": parsed["passed"]
            }), flush=True)
    except Exception:
        summary["exception"] = traceback.format_exc()
        summary["failures"].append("runner")
        print(summary["exception"], file=sys.stderr, flush=True)
    finally:
        try:
            source_check("after")
            before = output / "source-before.json"
            after = output / "source-after.json"
            summary["source_before_after_equal"] = (
                before.is_file() and after.is_file()
                and before.read_bytes() == after.read_bytes())
            if not summary["source_before_after_equal"]:
                summary["failures"].append("source-before-after-comparison")
        except Exception:
            summary["source_after_exception"] = traceback.format_exc()
            summary["failures"].append("source-after-exception")
        summary["observed_test_methods"] = sum(
            row["observed_ran_tests"] or 0 for row in summary["test_suites"])
        summary["passed_test_methods"] = sum(
            row["expected_tests"] for row in summary["test_suites"] if row["passed"])
        summary["completed_suites"] = len(summary["test_suites"])
        summary["expected_suites"] = len(roster["suites"])
        summary["all_controls_passed"] = (
            primary_ready and not summary["failures"]
            and summary["source_before_verified"] and summary["source_after_verified"]
            and summary["source_before_after_equal"]
            and summary["completed_suites"] == summary["expected_suites"]
            and summary["observed_test_methods"] == EXPECTED_TOTAL
            and summary["passed_test_methods"] == EXPECTED_TOTAL)
        summary["completed"] = True
        summary["ended_utc"] = utc()
        write_json(output / "summary.json", summary)
        manifests = []
        for file in sorted(output.rglob("*")):
            if file.is_file():
                manifests.append(sha(file) + "  " + str(file.relative_to(output)))
        (output / "SHA256SUMS").write_text("\n".join(manifests) + "\n")
        print(json.dumps({
            "event": "validation_complete", "output": str(output),
            "all_controls_passed": summary["all_controls_passed"],
            "observed": summary["observed_test_methods"],
            "passed": summary["passed_test_methods"],
            "failures": summary["failures"],
        }), flush=True)
    return 0 if summary["all_controls_passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
