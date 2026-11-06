#!/usr/bin/env python3
"""Observe a complete reference witness in fresh bounded processes; no proving."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from bounded_process import ProcessFailure, run_bounded

SOURCE_PATHS = (
    "scripts/w1_specialized_relation_observation.py",
    "formal/pon-nakamoto-v1/w1_specialized_relation.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "formal/pon-nakamoto-v1/bounded_process.py",
    "config/pon/ledger-v1.json", "config/pon/work-profile-v1.json",
    "config/pon/model-family-v1.json", "config/pon/devnet-v1.json",
)


def source():
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    evidence = ROOT / "evidence/pon-w1-full-v2-20261105"
    raw = (evidence / "input.bin").read_bytes()
    header = (evidence / "header.bin").read_bytes()
    if len(raw) != 49506 or raw[:318] != header:
        raise ValueError("saved complete input/header mismatch")
    (out / "native-proof.bin").write_bytes(raw[318:])
    report = {
        "schema": "trnm-w1-exact-reference-observation-v1",
        "head_at_execution": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_files_sha256": source(), "stages": [], "success": False,
        "scope": "One existing full-W1 input; integer/SHA reference, no cryptographic proof generation. Child wait4 includes interpreter, JSON and file I/O; inner execute timings are a subset.",
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "expected_artifacts_sha256": hashlib.sha256((evidence / "expected-artifacts.bin").read_bytes()).hexdigest(),
        "quantum_security_bits": None, "production_activation": False,
    }
    wall, cpu = time.monotonic_ns(), time.process_time_ns()
    try:
        for mode in ("build", "check"):
            argv = [sys.executable, str(ROOT / "formal/pon-nakamoto-v1/w1_specialized_relation.py"), mode,
                    "--header", str(evidence / "header.bin"), "--proof", str(out / "native-proof.bin"),
                    "--expected-artifacts", str(evidence / "expected-artifacts.bin"),
                    "--witness", str(out / "full-w1-constraints.json")]
            stage_wall = time.monotonic_ns()
            failure = None
            try:
                result = run_bounded(argv, b"", timeout=30, stdout_limit=8192, stderr_limit=8192,
                    cwd=ROOT, env={"PATH": os.environ.get("PATH", ""), "PYTHONHASHSEED": "0",
                    "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}, collect_usage=True)
            except ProcessFailure as error:
                result, failure = error, str(error)
            for stream in ("stdout", "stderr"):
                (out / (mode + "." + stream + ".log")).write_bytes(getattr(result, stream))
            row = {"mode": mode, "argv": argv, "wall_ns": time.monotonic_ns() - stage_wall,
                   "returncode": result.returncode, "failure": failure,
                   "wait4": asdict(result.usage) if result.usage is not None else None}
            report["stages"].append(row)
            if failure is not None or result.returncode != 0 or result.usage is None:
                raise ValueError("reference stage failed: " + mode)
            row["inner_report"] = json.loads(result.stdout)
            if mode == "check" and row["inner_report"].get("complete_mathematical_witness_checked") is not True:
                raise ValueError("full reference checker did not complete")
        report["source_files_after_sha256"] = source()
        if report["source_files_after_sha256"] != report["source_files_sha256"]:
            raise ValueError("source changed during observation")
        report["success"] = True
    except (OSError, ValueError) as error:
        report["error"] = str(error)
    finally:
        report["outer_wall_ns"] = time.monotonic_ns() - wall
        report["supervisor_exclusive_cpu_ns"] = time.process_time_ns() - cpu
        report["memory_scope"] = "wait4 maximum single process RSS; not summed physical memory"
        (out / "observation.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"success": report["success"], "out": str(out)}))
    return 0 if report["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
