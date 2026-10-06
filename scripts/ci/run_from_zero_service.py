#!/usr/bin/env python3
"""Run finite native controls inside the existing head/merge protocol job.

Retain nonzero exits and named libtest observations. Never grant deployment,
network availability, economic work qualification or a speed threshold.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TESTS = (
    "resource_cost::cpu_span_cannot_cross_threads_or_turn_unknown_into_zero",
    "from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection",
    "from_zero_service_shares_cpu_with_honest_work_and_reopened_owner",
)


def main() -> int:
    parent = Path(os.environ.get("TRNM_CI_RECEIPT_DIR", "/tmp/trnm-ci-" + str(os.getpid())))
    parent.mkdir(parents=True, exist_ok=True)
    output = parent / "from-zero-service"
    output.mkdir()  # Never replace a prior campaign or its failure observations.
    env = os.environ.copy()
    env["TRNM_PUBLIC_V3_FROM_ZERO_DIR"] = str((output / "native").resolve())
    results = []
    for index, name in enumerate(TESTS):
        command = [
            "cargo", "test", "--offline", "--locked", "--release",
            "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"),
            "-p", "trnm-pon-node", "--test", "public_v3_from_zero", name,
            "--", "--exact", "--nocapture", "--test-threads=1",
        ]
        log = output / f"{index:02d}.log"
        error = None
        exit_code = None
        with log.open("xb") as stream:
            try:
                exit_code = subprocess.run(
                    command, cwd=ROOT, env=env, stdout=stream,
                    stderr=subprocess.STDOUT, timeout=600, check=False,
                ).returncode
            except (OSError, subprocess.TimeoutExpired) as exc:
                error = str(exc)
        checker = subprocess.run(
            [sys.executable, str(ROOT / "scripts/ci/check_required_native_test.py"),
             str(log), "--test", name],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False,
        )
        row = {"test": name, "command": command, "exit_code": exit_code,
               "error": error, "named_execution_check_exit": checker.returncode,
               "named_execution_check": checker.stdout,
               "passed": exit_code == 0 and checker.returncode == 0 and error is None}
        results.append(row)
        print(json.dumps(row), flush=True)
        (output / "results.json").write_text(json.dumps({
            "schema": "native-from-zero-execution-v1", "results": results,
            "complete": len(results) == len(TESTS),
            "result": "PASS" if len(results) == len(TESTS)
            and all(item["passed"] for item in results) else "INCOMPLETE_OR_FAILED",
            "public_network_qualification": False,
            "compute_qualification": False,
        }, indent=2) + "\n")
    return 0 if all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
