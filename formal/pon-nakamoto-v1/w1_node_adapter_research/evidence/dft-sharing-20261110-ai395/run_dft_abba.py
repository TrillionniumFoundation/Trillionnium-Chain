#!/usr/bin/env python3
"""Run unchanged receiver comparator in A/B/B/A order; retain all failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


KERNEL_EXPECTATIONS = (
    ("expected_cpu_max", "cpu.max"),
    ("expected_memory_max", "memory.max"),
    ("expected_memory_swap_max", "memory.swap.max"),
    ("expected_pids_max", "pids.max"),
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arm in ("a", "b"):
        parser.add_argument("--" + arm + "-repo", type=Path, required=True)
        parser.add_argument("--" + arm + "-binary", type=Path, required=True)
        parser.add_argument("--" + arm + "-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    for name, _kernel_file in KERNEL_EXPECTATIONS:
        parser.add_argument("--" + name.replace("_", "-"))
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    plan = {"schema": "trnm-w1-dft-abba-batches-v1", "order": list("ABBA"),
            "receiver_order_in_each_batch": "NPPNNPPN", "cpu_affinity_count": 2,
            "rayon_num_threads": 2, "per_child_timeout_seconds": 120,
            "independent_input_tasks": 1, "new_complete_proofs": 0,
            "planned_proof_replays": 16, "planned_native_receivers": 16,
            "host_exclusive": False, "os_caches_flushed": False,
            "production_activation": False, "qualification": "HOLD_NO_GO",
            "orchestrator_sha256": digest(__file__),
            "expected_kernel_limits": {
                kernel_file: getattr(args, name)
                for name, kernel_file in KERNEL_EXPECTATIONS
                if getattr(args, name) is not None},
            "arms": {}}
    for arm in ("a", "b"):
        repo = getattr(args, arm + "_repo").resolve(strict=True)
        binary = getattr(args, arm + "_binary").resolve(strict=True)
        expected = getattr(args, arm + "_head")
        actual = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        if actual != expected:
            raise ValueError("source head mismatch for arm " + arm)
        plan["arms"][arm.upper()] = {"repo": str(repo), "binary": str(binary),
            "head": actual, "binary_sha256": digest(binary)}
    save(args.output / "plan.json", plan)
    observations = []
    for index, arm in enumerate(plan["order"]):
        selected = plan["arms"][arm]
        repo = Path(selected["repo"])
        adapter = repo / "formal/pon-nakamoto-v1/w1_node_adapter_research"
        output = args.output / (str(index) + "-" + arm)
        command = ["python3", "-B", str(adapter / "run_receiver_comparison.py"),
            "--repo", str(repo), "--binary", selected["binary"],
            "--expected-binary-sha256", selected["binary_sha256"],
            "--fixture", str(adapter / "fixtures/node-input-v1"),
            "--proof", str(adapter / "fixtures/node-input-v1"),
            "--output", str(output), "--cpu-count", "2", "--rayon-threads", "2",
            "--timeout-seconds", "120"]
        for name, _kernel_file in KERNEL_EXPECTATIONS:
            value = getattr(args, name)
            if value is not None:
                command.extend(["--" + name.replace("_", "-"), value])
        start = time.monotonic_ns()
        with (args.output / (str(index) + "-" + arm + ".stdout")).open("xb") as stdout, \
                (args.output / (str(index) + "-" + arm + ".stderr")).open("xb") as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        row = {"index": index, "arm": arm, "argv": command,
            "exit_code": result.returncode,
            "batch_wall_seconds": (time.monotonic_ns() - start) / 1e9,
            "summary_sha256": digest(output / "summary.json")
            if (output / "summary.json").exists() else None}
        observations.append(row)
        save(args.output / "batch-observations.json", observations)
        print(json.dumps(row), flush=True)
    for arm, selected in plan["arms"].items():
        if digest(selected["binary"]) != selected["binary_sha256"]:
            raise ValueError("binary changed during experiment: " + arm)
    if digest(__file__) != plan["orchestrator_sha256"]:
        raise ValueError("orchestrator changed during experiment")
    save(args.output / "result.json", {"plan": plan, "observations": observations,
        "all_original_comparators_passed": all(row["exit_code"] == 0 for row in observations),
        "end_to_end_benefit": "NOT_ESTABLISHED", "production_activation": False,
        "qualification": "HOLD_NO_GO"})
    return 0 if all(row["exit_code"] == 0 for row in observations) else 1


if __name__ == "__main__":
    raise SystemExit(main())
