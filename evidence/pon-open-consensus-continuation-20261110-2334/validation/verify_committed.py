#!/usr/bin/env python3
"""Run bounded retained controls with the repository's exact-source fence.

The output directory must be new and outside the source tree. A successful
command is only a scoped observation; all production qualification stays false.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--group", required=True, choices=("static", "native"))
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    output = args.output.resolve()
    if output.is_relative_to(repo):
        parser.error("output must be outside the source checkout")
    sys.path.insert(0, str(repo / "scripts/ci"))
    import ci_observation as observation

    if observation.ROOT != repo:
        parser.error("imported observer does not belong to the requested source")
    if observation.pin_source() != args.expected_head:
        parser.error("requested source is not the exact clean committed HEAD")
    output.mkdir(parents=True, exist_ok=False)
    py = sys.executable
    manifest = "trillionnium/Cargo.toml"
    if args.group == "static":
        commands = [
            ("preflight", ["bash", "scripts/project-preflight.sh", "--audit"], 120),
            ("cargo-metadata", ["cargo", "metadata", "--locked", "--offline",
                                "--manifest-path", manifest, "--format-version", "1"], 120),
            ("format", ["cargo", "fmt", "--manifest-path", manifest,
                        "--all", "--", "--check"], 300),
            ("repository", [py, "scripts/ci/check_repository.py"], 300),
            ("inventory", [py, "scripts/refresh_distributed_source_inventory.py", "--check"], 120),
            ("ci-contract", [py, "scripts/ci/test_ci_contract.py"], 600),
            ("source-integrity", [py, "scripts/ci/test_ci_source_integrity.py"], 300),
            ("corpus-negatives", [py, "scripts/ci/test_pq_research_integration.py"], 900),
            ("corpus", [py, "scripts/ci/check_pq_research_integration.py"], 300),
            ("v4-reader", [py, "scripts/ci/test_w1_lifecycle_cost_v4.py"], 300),
            ("material-reader", [py, "scripts/ci/test_pon_w1_cost_matrix_reader.py"], 300),
            ("native-gate", [py, "scripts/ci/test_w1_factorial_native_gate.py"], 300),
        ]
    else:
        common = ["--locked", "--offline", "--manifest-path", manifest]
        commands = [
            ("preflight", ["bash", "scripts/project-preflight.sh"], 120),
            ("public-v3", ["cargo", "test", *common, "-p", "trnm-pon-node", "--lib",
                           "ingress::public_v3::tests::", "--", "--test-threads=1"], 2400),
            ("mvcc-tests", ["cargo", "test", *common, "-p", "trnm-mvcc-fee", "--tests",
                            "--", "--test-threads=1"], 1800),
            ("strict-clippy", ["cargo", "clippy", *common, "--workspace", "--all-targets",
                               "--all-features", "--", "-D", "warnings"], 1800),
        ]
    report = {
        "schema": "pon-continuation-committed-validation-v1",
        "source_expected": args.expected_head,
        "group": args.group,
        "result": "RUNNING",
        "qualification": "HOLD_NO_GO",
        "production_activation": False,
        "open_consensus_qualified": False,
        "business_service_qualified": False,
        "observations": [],
    }
    for name, command, timeout in commands:
        row = observation.run(command, output / f"{name}.log", cwd=repo,
                              timeout=timeout, expected_source=args.expected_head)
        report["observations"].append(dict(name=name, **row))
        if row["exit_code"]:
            report["result"] = "FAIL"
        (output / "progress.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"name": name, "exit_code": row["exit_code"],
                          "executed": row["executed"],
                          "source_verified": row.get("source_verified", False)}), flush=True)
        if not row.get("source_verified", False):
            break
    if len(report["observations"]) != len(commands):
        report["result"] = "FAIL"
    elif report["result"] == "RUNNING":
        report["result"] = "PASS"
    observation.finish(output, report, [
        "trillionnium/Cargo.lock", "trillionnium/Cargo.toml", "rust-toolchain.toml",
        "scripts/pon_w1_lifecycle_cost_v4.py",
        ".github/workflows/pon-w1-work-security.yml",
        "trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs",
        "trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs",
        "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs",
    ])
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
