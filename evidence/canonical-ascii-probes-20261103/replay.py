#!/usr/bin/env python3
"""Verify retained rejected probes or reproduce their frozen standalone sources."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess


ROOT = Path(__file__).resolve().parent
VARIANTS = ("single-u128", "two-u64", "long-two-u64")


def read_json(path: Path):
    def reject_constant(value):
        raise ValueError(f"non-finite JSON value: {value}")
    return json.loads(path.read_text(), parse_constant=reject_constant)


def samples(path: Path, variant: str):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    controls = [row for row in rows if row.get("type") == "correctness"]
    if len(controls) != 1 or controls[0] != {"type": "correctness", "cases": 545361, "passed": True}:
        raise ValueError(f"missing complete scalar controls: {path}")
    observed = [row for row in rows if row.get("type") == "sample"]
    workloads = ("large",) if variant == "single-u128" else (("large", "short") if variant == "two-u64" else ("large", "threshold", "short"))
    if len(rows) != 1 + 64 * len(workloads) or len(observed) != 64 * len(workloads):
        raise ValueError(f"incomplete sample denominator: {path}")
    reports = []
    for workload in workloads:
        group = [row for row in observed if row.get("workload", "large") == workload]
        ratios = []
        for round_id in range(16):
            pair = [row for row in group if row["round"] == round_id]
            if [(row["sample"], row["arm"]) for row in pair] != list(enumerate(("A", "B", "B", "A"))):
                raise ValueError(f"ABBA identity drift: {path}")
            expected_calls = 2100 * {"large": 1, "short": 64, "threshold": 16}[workload]
            for row in pair:
                if row["complete_calls"] != expected_calls or type(row["thread_cpu_ns"]) is not int or row["thread_cpu_ns"] <= 0:
                    raise ValueError(f"incomplete call or clock observation: {path}")
            a = sum(row["thread_cpu_ns"] for row in pair if row["arm"] == "A")
            b = sum(row["thread_cpu_ns"] for row in pair if row["arm"] == "B")
            ratios.append(b / a)
        reports.append({"workload": workload, "samples": len(group), "median": statistics.median(ratios), "empirical_p95": sorted(ratios)[math.ceil(len(ratios) * .95) - 1], "round_cpu_ratios": ratios})
    return reports


def verify():
    manifest = read_json(ROOT / "manifest.json")
    for row in manifest["files"]:
        path = (ROOT / row["path"]).resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError("escaping retained input")
        data = path.read_bytes()
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError(f"retained input changed: {row['path']}")
    observed = {variant: {profile: samples(ROOT / variant / f"{profile}.jsonl", variant) for profile in ("debug-component", "release-component")} for variant in VARIANTS}
    return {"retained_file_identities_valid": True, "retained_input_files": len(manifest["files"]), "complete_timed_samples": 768, "disposition": manifest["disposition"], "native_tests_executed_by_this_check": False, "observed": observed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    retained = verify()
    if args.verify_only:
        print(json.dumps(retained, indent=2))
        return 0
    if args.work_dir is None:
        parser.error("--work-dir is required unless --verify-only is selected")
    version = subprocess.check_output([args.rustc, "--version"], text=True).strip()
    if not version.startswith("rustc 1.95.0 ") or platform.system() != "Linux" or platform.architecture()[0] != "64bit":
        raise ValueError("use a Linux 64-bit Rust 1.95.0 host compiler")
    work = args.work_dir.resolve()
    if work.is_relative_to(ROOT):
        raise ValueError("use a new output directory outside the retained evidence")
    work.mkdir(parents=True, exist_ok=False)
    reports = []
    all_rules_passed = True
    for variant in VARIANTS:
        target = work / variant
        target.mkdir()
        for name in ("baseline.rs", "candidate.rs", "main.rs"):
            (target / name).write_bytes((ROOT / variant / name).read_bytes())
        for profile, level in (("debug-component", "0"), ("release-component", "3")):
            binary = target / profile
            command = [args.rustc, "--edition=2024", "-C", f"opt-level={level}", "-C", "debuginfo=0", "-C", "strip=symbols", "main.rs", "-o", str(binary)]
            build = subprocess.run(command, cwd=target, text=True, capture_output=True, timeout=120)
            (target / f"{profile}-build.log").write_text(build.stdout + build.stderr)
            if build.returncode:
                return build.returncode
            with (target / f"{profile}.jsonl").open("w") as output, (target / f"{profile}.stderr").open("w") as errors:
                run = subprocess.run([str(binary)], cwd=target, stdout=output, stderr=errors, timeout=120)
            if run.returncode:
                return run.returncode
            measured = samples(target / f"{profile}.jsonl", variant)
            for row in measured:
                limits = (.95, 1.05) if profile == "debug-component" and row["workload"] == "large" else (1.05, 1.10)
                row["rule_passed"] = row["median"] <= limits[0] and row["empirical_p95"] <= limits[1]
                all_rules_passed &= row["rule_passed"]
            reports.append({"variant": variant, "profile": profile, "compiler": version, "host": platform.machine(), "command": command, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "measurements": measured})
            (work / "new-observations.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(json.dumps({"new_observations": str(work / "new-observations.json"), "all_new_rules_passed": all_rules_passed, "original_disposition_unchanged": retained["disposition"], "whole_node_qualified": False}, indent=2))
    return 0 if all_rules_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
