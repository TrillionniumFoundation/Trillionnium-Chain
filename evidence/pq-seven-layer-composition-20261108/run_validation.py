#!/usr/bin/env python3
"""Record exact-source scoped checks without turning HOLD into qualification.

Write outputs outside the checkout. This runner never edits source, changes an
acceptance threshold, retries a failed command, or starts production services.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--cargo", help="Explicit trusted Cargo executable for native checks")
    parser.add_argument("--target", type=Path, help="Isolated Cargo target directory")
    args = parser.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    if out.is_relative_to(root) or out.exists():
        parser.error("use a new output directory outside the source checkout")
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_head) is None:
        parser.error("expected head must be a complete lowercase commit ID")
    if bool(args.cargo) != bool(args.target):
        parser.error("native checks require both --cargo and --target")
    out.mkdir(parents=True)
    env = dict(os.environ)
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1", RUST_TEST_THREADS="1")
    if args.target:
        env["CARGO_TARGET_DIR"] = str(args.target.resolve())
        env["CARGO_BUILD_JOBS"] = "2"
    py = [sys.executable, "-B"]
    guard = py + ["scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", args.expected_head]
    commands = [
        ("preflight", ["bash", "scripts/project-preflight.sh"]),
        ("source-before", guard + ["--output", str(out / "source-before.json")]),
        ("lifetime-tests", py + ["scripts/ci/test_pq_lifetime_budget.py", "-v"]),
        ("claim-tests", py + ["scripts/ci/test_pq_chain_claim_guard.py", "-v"]),
        ("effect-register-tests", py + ["scripts/ci/test_pq_authority_effect_register.py", "-v"]),
        ("root-policy-tests", py + ["-m", "unittest", "discover", "-s", "formal/pon-nakamoto-v1", "-p", "test_pq_root_recovery_policy_v1.py", "-v"]),
        ("lifetime-report", py + ["scripts/ci/pq_lifetime_budget.py"]),
        ("claim-report", py + ["scripts/ci/pq_chain_claim_guard.py"]),
        ("effect-register-report", py + ["scripts/ci/pq_authority_effect_register.py"]),
        ("root-policy-example", py + ["formal/pon-nakamoto-v1/pq_root_recovery_policy_v1.py", "--example"]),
        ("pq-source-integration", py + ["scripts/ci/check_pq_research_integration.py"]),
        ("pq-source-negatives", py + ["scripts/ci/test_pq_research_integration.py", "-v"]),
        ("authority-scanner-negatives", py + ["scripts/ci/test_pq_authority_surface_scan.py", "-v"]),
        ("ci-contract", py + ["scripts/ci/check_ci_contract.py"]),
        ("ci-contract-negatives", py + ["scripts/ci/test_ci_contract.py", "-v"]),
        ("source-integrity-negatives", py + ["scripts/ci/test_ci_source_integrity.py", "-v"]),
        ("repository", py + ["scripts/ci/check_repository.py"]),
        ("repository-negatives", py + ["scripts/ci/test_repository.py", "-v"]),
        ("distributed-inventory", py + ["scripts/refresh_distributed_source_inventory.py", "--check"]),
        ("diff-check", ["git", "diff", "--check"]),
    ]
    if args.cargo:
        cargo = [args.cargo]
        manifest = ["--manifest-path", "trillionnium/Cargo.toml"]
        common = ["--locked", "--offline", *manifest]
        commands += [
            ("cargo-version", cargo + ["--version"]),
            ("metadata-default", cargo + ["metadata", *common, "--format-version", "1"]),
            ("metadata-all-features", cargo + ["metadata", *common, "--all-features", "--format-version", "1"]),
            ("metadata-fuzz", cargo + ["metadata", "--locked", "--offline", "--manifest-path", "tests/fuzz/Cargo.toml", "--format-version", "1"]),
            ("formatting", cargo + ["fmt", *manifest, "--all", "--", "--check"]),
            ("strict-workspace-clippy", cargo + ["clippy", *common, "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]),
            ("native-crypto-default", cargo + ["test", *common, "-p", "trnm-crypto-primitives", "--lib", "--", "--test-threads=1"]),
            ("native-hepta-pq-comparator", cargo + ["test", *common, "-p", "trnm-research-protocol", "--test", "hepta_handoff_pq", "--", "--test-threads=1"]),
        ]
    commands.append(("source-after", guard + ["--output", str(out / "source-after.json")]))
    summary = {"schema": "trnm-pq-composition-validation-v1", "expected_head": args.expected_head,
               "root": str(root), "native_checks_requested": bool(args.cargo), "commands": [],
               "runner": digest(Path(__file__)), "started_unix_seconds": time.time(),
               "whole_chain_pq_qualified": False, "production_activation": False,
               "complete_node_suite_executed": False, "hosted_ci_accepted": False}
    save(out / "commands.json", [{"label": name, "argv": argv} for name, argv in commands])
    for label, argv in commands:
        stdout, stderr = out / (label + ".stdout.txt"), out / (label + ".stderr.txt")
        row = {"label": label, "argv": argv, "started_unix_seconds": time.time()}
        with stdout.open("wb") as output, stderr.open("wb") as error:
            try:
                result = subprocess.run(argv, cwd=root, env=env, stdout=output, stderr=error,
                                        timeout=1200, check=False)
                row["exit_code"] = result.returncode
            except subprocess.TimeoutExpired:
                row["exit_code"] = 124
                row["timeout"] = True
            except OSError as failure:
                row["exit_code"] = 127
                error.write((type(failure).__name__ + ": " + str(failure) + "\n").encode())
        row.update(finished_unix_seconds=time.time(), passed=row["exit_code"] == 0,
                   stdout=digest(stdout), stderr=digest(stderr))
        summaries = re.findall(r"Ran (\d+) tests? in [^\n]+\n\n(OK|FAILED[^\n]*)",
                               stderr.read_text(errors="replace"))
        if summaries:
            row["unittest_summaries"] = [{"tests": int(n), "result": status} for n, status in summaries]
        native = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
                            stdout.read_text(errors="replace"))
        if native:
            row["native_summaries"] = [dict(zip(("result", "passed", "failed", "ignored", "measured", "filtered"),
                                                               (state, *map(int, numbers)))) for state, *numbers in native]
        required_counts = {"lifetime-tests": 58, "claim-tests": 49,
                           "effect-register-tests": 18, "root-policy-tests": 26}
        if label in required_counts and row.get("unittest_summaries") != [
                {"tests": required_counts[label], "result": "OK"}]:
            row["passed"] = False
            row["summary_validation_error"] = "required test count/outcome not observed"
        if label.startswith("native-") and not (
                row.get("native_summaries")
                and sum(item["passed"] for item in row["native_summaries"]) > 0
                and all(item["result"] == "ok" and item["failed"] == 0
                        for item in row["native_summaries"])):
            row["passed"] = False
            row["summary_validation_error"] = "native test completion not observed"
        summary["commands"].append(row)
        save(out / "summary.json", summary)
        print(json.dumps({"label": label, "exit_code": row["exit_code"],
                          "elapsed_seconds": row["finished_unix_seconds"] - row["started_unix_seconds"]}), flush=True)
        if label in ("preflight", "source-before") and not row["passed"]:
            break
    summary["finished_unix_seconds"] = time.time()
    summary["commands_expected"] = len(commands)
    summary["commands_completed"] = len(summary["commands"])
    summary["failed_commands"] = [row["label"] for row in summary["commands"] if not row["passed"]]
    summary["result"] = "PASS" if not summary["failed_commands"] and len(summary["commands"]) == len(commands) else "FAIL"
    save(out / "summary.json", summary)
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
