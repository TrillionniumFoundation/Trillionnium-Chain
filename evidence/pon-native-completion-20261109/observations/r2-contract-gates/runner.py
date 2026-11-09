from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
import traceback

ROOT = Path("/data/chain-abg-70ae-20261108/source")
OUT = Path("/data/chain-abg-70ae-20261108/evidence/r2-contract-gates")
HEAD = "843d7c3c0b58b5b0491f686df6a7fd3c26991d6c"
TREE = "6a5fad57d4e7dc6007c830650da6a351b3e8448e"
CARGO = "/home/qian-qi/.cargo/bin/cargo"
OUT.mkdir(parents=True, exist_ok=False)
(OUT / "runner-derivation.json").write_text('{\n  "original_runner": "/data/chain-abg-70ae-20261108/evidence/candidate-contract-gates/runner.py",\n  "original_runner_sha256": "c4a0c9f4d723d1ae38498cb368ace7bd5a5f95aeb1d83e8937e3f81663f887b2",\n  "changes": [\n    "output_directory",\n    "expected_head",\n    "expected_tree",\n    "replace R1-only launch observation with this derivation"\n  ],\n  "gate_argv_count_and_timeout_policy_unchanged": true\n}\n')
(OUT / "tmp").mkdir()
(OUT / "cargo-metadata-target").mkdir()
(OUT / "runner.py").write_text(__gates_source__)
ENV = os.environ.copy()
ENV.update(PYTHONDONTWRITEBYTECODE="1", GIT_OPTIONAL_LOCKS="0",
           GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
           CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never",
           TMPDIR=str(OUT / "tmp"),
           CARGO_TARGET_DIR=str(OUT / "cargo-metadata-target"))
RECORDS = []

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def identity():
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", *args],
            cwd=ROOT, env=ENV, text=True, stderr=subprocess.PIPE, timeout=30).strip()
    actual_head = git("rev-parse", "HEAD")
    actual_tree = git("rev-parse", "HEAD^{tree}")
    status = git("status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none")
    return {"head": actual_head, "tree": actual_tree, "clean": not bool(status),
            "status": status,
            "matches_frozen_source": actual_head == HEAD and actual_tree == TREE and not status}

def summary():
    value = {"schema": "exact-candidate-contract-gates-v1",
             "source": str(ROOT), "expected_head": HEAD, "expected_tree": TREE,
             "scope": "read-only static/graph gates; no compilation, Clippy, native execution or product deadline qualification",
             "output_directory": str(OUT), "python": sys.version,
             "environment_changes": {key: ENV[key] for key in
                 ["PYTHONDONTWRITEBYTECODE", "GIT_OPTIONAL_LOCKS", "GIT_NO_LAZY_FETCH",
                  "GIT_TERMINAL_PROMPT", "CARGO_NET_OFFLINE", "CARGO_TERM_COLOR",
                  "TMPDIR", "CARGO_TARGET_DIR"]},
             "cargo_executable": CARGO,
             "gates": RECORDS,
             "all_recorded_gates_pass": bool(RECORDS) and all(x["passed"] for x in RECORDS)}
    (OUT / "summary.json").write_text(json.dumps(value, indent=2) + "\n")

def execute(label, argv, timeout, expected_tests=None, metadata=False, source_report=None):
    prefix = f"{len(RECORDS):02d}-{label}"
    stdout_path = OUT / (prefix + ".stdout")
    stderr_path = OUT / (prefix + ".stderr")
    before = identity()
    record = {"label": label, "argv": argv, "command": shlex.join(argv),
              "cwd": str(ROOT), "expected_head": HEAD, "expected_tree": TREE,
              "before": before, "started_utc": stamp(),
              "timeout_seconds": timeout,
              "timeout_scope": "source/graph command wall-time supervisor only; no product deadline changed",
              "stdout": str(stdout_path), "stderr": str(stderr_path),
              "expected_tests": expected_tests, "tests_run": None, "skipped": None,
              "failures": None, "errors": None, "timed_out": False,
              "exit_code": None, "passed": False}
    if not before["matches_frozen_source"]:
        record["not_started_reason"] = "exact candidate changed or dirty before gate"
        stdout_path.write_text("")
        stderr_path.write_text(record["not_started_reason"] + "\n")
        record["after"] = before
    else:
        print(json.dumps({"event": "gate-start", "label": label, "command": record["command"],
                          "head": before["head"], "tree": before["tree"]}), flush=True)
        started = time.monotonic()
        with stdout_path.open("wb", buffering=0) as stdout, stderr_path.open("wb", buffering=0) as stderr:
            try:
                process = subprocess.Popen(argv, cwd=ROOT, env=ENV,
                    stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    record["exit_code"] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record["timed_out"] = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        record["exit_code"] = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        record["exit_code"] = process.wait(timeout=10)
            except Exception:
                stderr.write(traceback.format_exc().encode())
                record["runner_error"] = "subprocess launch/wait failed; inspect stderr"
        record["elapsed_seconds"] = round(time.monotonic() - started, 6)
        record["after"] = identity()
        record["passed"] = (record["exit_code"] == 0 and not record["timed_out"]
                            and record["after"]["matches_frozen_source"])
        output = stdout_path.read_text(errors="replace")
        error = stderr_path.read_text(errors="replace")
        if expected_tests is not None:
            joined = error + "\n" + output
            ran = re.findall(r"^Ran ([0-9]+) tests? in ([0-9.]+)s$", joined, re.MULTILINE)
            outcomes = re.findall(r"^(OK|FAILED)(?: \(([^)]*)\))?$", joined, re.MULTILINE)
            if ran:
                record["tests_run"] = int(ran[-1][0])
                record["harness_seconds"] = float(ran[-1][1])
            if outcomes:
                status, details = outcomes[-1]
                record["unittest_status"] = status
                totals = dict(re.findall(r"(failures|errors|skipped|expected failures|unexpected successes)=([0-9]+)", details))
                for name in ("failures", "errors", "skipped"):
                    record[name] = int(totals.get(name, "0"))
                record["expected_failures"] = int(totals.get("expected failures", "0"))
                record["unexpected_successes"] = int(totals.get("unexpected successes", "0"))
            record["passed"] = bool(record["passed"] and record["tests_run"] == expected_tests
                and record.get("unittest_status") == "OK"
                and record["skipped"] == 0 and record["failures"] == 0 and record["errors"] == 0
                and record.get("unexpected_successes") == 0)
        if metadata and record["exit_code"] == 0:
            try:
                graph = json.loads(output)
                workspace = set(graph["workspace_members"])
                packages = [p for p in graph["packages"] if p["id"] in workspace]
                record["graph"] = {
                    "packages": len(graph["packages"]),
                    "workspace_members": len(workspace),
                    "resolve_nodes": len(graph["resolve"]["nodes"]),
                    "workspace_test_targets": sum("test" in t["kind"]
                        for p in packages for t in p["targets"]),
                    "workspace_targets_with_test_enabled": sum(bool(t.get("test"))
                        for p in packages for t in p["targets"]),
                    "workspace_dev_dependency_edges": sum(d.get("kind") == "dev"
                        for p in packages for d in p["dependencies"]),
                    "target_directory": graph["target_directory"],
                    "workspace_root": graph["workspace_root"],
                }
                expected_members = 1 if label == "cargo-metadata-fuzz" else 26
                record["passed"] = bool(record["passed"]
                    and len(workspace) == expected_members
                    and Path(graph["target_directory"]) == OUT / "cargo-metadata-target")
            except Exception:
                record["passed"] = False
                record["metadata_parse_error"] = traceback.format_exc()
        if source_report is not None and record["exit_code"] == 0:
            try:
                checked = json.loads((OUT / source_report).read_text())
                record["source_identity_report"] = checked
                record["passed"] = bool(record["passed"]
                    and checked["tested_commit"] == HEAD and checked["tested_tree"] == TREE
                    and checked["tracked_worktree_verified"] is True
                    and checked["tracked_entries"] == 26128)
            except Exception:
                record["passed"] = False
                record["source_report_error"] = traceback.format_exc()
    record["finished_utc"] = stamp()
    record["stdout_bytes"] = stdout_path.stat().st_size
    record["stderr_bytes"] = stderr_path.stat().st_size
    record["stdout_sha256"] = digest(stdout_path)
    record["stderr_sha256"] = digest(stderr_path)
    RECORDS.append(record)
    (OUT / (prefix + ".json")).write_text(json.dumps(record, indent=2) + "\n")
    summary()
    print(json.dumps({"event": "gate-end", "label": label,
                      "exit_code": record["exit_code"], "passed": record["passed"],
                      "tests_run": record["tests_run"], "skipped": record["skipped"],
                      "elapsed_seconds": record.get("elapsed_seconds"),
                      "after_matches": record["after"]["matches_frozen_source"]}), flush=True)
    return record

try:
    first = execute("source-before", ["python3", "scripts/ci/verify_ci_source.py",
        "--kind", "head", "--expected-head", HEAD, "--output", str(OUT / "source-before.json")],
        300, source_report="source-before.json")
    if first["passed"]:
        gates = [
            ("preflight", ["bash", "scripts/project-preflight.sh"], 120, None, False),
            ("source-integrity-negative-43", ["python3", "scripts/ci/test_ci_source_integrity.py", "-v"], 600, 43, False),
            ("pq-research-negative-57", ["python3", "scripts/ci/test_pq_research_integration.py", "-v"], 600, 57, False),
            ("repository", ["python3", "scripts/ci/check_repository.py"], 600, None, False),
            ("distributed-inventory", ["python3", "scripts/refresh_distributed_source_inventory.py", "--check"], 180, None, False),
            ("pq-pinned-source", ["python3", "scripts/ci/check_pq_research_integration.py"], 300, None, False),
            ("cargo-version", [CARGO, "+1.95.0", "--version", "--verbose"], 60, None, False),
            ("cargo-metadata-default", [CARGO, "+1.95.0", "metadata", "--offline", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "--format-version", "1"], 180, None, True),
            ("cargo-metadata-all-features", [CARGO, "+1.95.0", "metadata", "--offline", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "--all-features", "--format-version", "1"], 180, None, True),
            ("cargo-test-dependency-graph", [CARGO, "+1.95.0", "tree", "--offline", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "--workspace", "--all-features", "--edges", "normal,build,dev"], 180, None, False),
            ("cargo-metadata-fuzz", [CARGO, "+1.95.0", "metadata", "--offline", "--locked", "--manifest-path", "tests/fuzz/Cargo.toml", "--format-version", "1"], 180, None, True),
        ]
        for label, argv, timeout, expected, is_metadata in gates:
            record = execute(label, argv, timeout, expected, is_metadata)
            if not record["after"]["matches_frozen_source"]:
                break
    execute("source-after", ["python3", "scripts/ci/verify_ci_source.py",
        "--kind", "head", "--expected-head", HEAD, "--output", str(OUT / "source-after.json")],
        300, source_report="source-after.json")
except BaseException:
    (OUT / "runner-fatal.txt").write_text(traceback.format_exc())
    print(traceback.format_exc(), file=sys.stderr, flush=True)
    summary()
    raise
summary()
passed = len(RECORDS) == 13 and all(record["passed"] for record in RECORDS)
print(json.dumps({"event": "complete", "head": HEAD, "tree": TREE,
                  "gates_recorded": len(RECORDS), "all_expected_gates_pass": passed,
                  "scope": "static and graph only; no native or product acceptance",
                  "summary": str(OUT / "summary.json")}), flush=True)
raise SystemExit(0 if passed else 1)
