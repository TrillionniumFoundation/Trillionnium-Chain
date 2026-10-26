"""Same-host, same-implementation W1 transcript and false-ticket wall-cost census.

Research only; no CPU-cycle/energy model or fastest adversary/legitimate miner
bound. Every run has original 64x64 computation and honest full verification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import statistics
import subprocess
import tempfile
from pathlib import Path

SHAPES = ("dense", "zero", "rank1", "sparse")
HOME = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def campaign(samples=32):
    if not 2 <= samples <= 128:
        raise ValueError("sample count must be 2..128")
    with tempfile.TemporaryDirectory(prefix="trnm-w1-cost-") as tmp:
        binary = Path(tmp) / "w1-probe"
        subprocess.run(["go", "build", "-o", str(binary),
                        str(HOME / "work_go_probe.go")], check=True,
                       capture_output=True, timeout=90)
        rows = []
        binary_sha256 = digest(binary)
        for shape in SHAPES:
            for seed in range(samples):
                raw = subprocess.run([str(binary), "--shape", shape,
                                      "--seed", str(seed)], text=True,
                                     capture_output=True, timeout=25)
                if raw.returncode:
                    raise RuntimeError(f"Go probe failed: {shape}/{seed}: {raw.stderr}")
                row = json.loads(raw.stdout)
                if (row["shape"] != shape or row["seed"] != seed
                        or not row["valid_proof_full_target_verified"]
                        or not row["false_ticket_passed"]
                        or row["false_proof_full_rejection"] != "Transcript"
                        or row["proof_bytes"] != 49188
                        or row["negative_controls"] != 4
                        or row["production_eligible"] is not False):
                    raise RuntimeError(f"incomplete positive/negative controls {shape}/{seed}")
                rows.append(row)
    results = {}
    for shape in SHAPES:
        selected = [row for row in rows if row["shape"] == shape]
        summary = {}
        for field in ("producer_wall_ns", "verifier_wall_ns",
                      "false_producer_wall_ns", "false_rejection_wall_ns",
                      "false_ticket_hash_attempts", "honest_winner_attempts",
                      "honest_winner_full_search_wall_ns"):
            values = sorted(row[field] for row in selected)
            summary[field] = {"median": statistics.median(values),
                              "min": values[0], "max": values[-1]}
        ratios = sorted(row["false_rejection_wall_ns"] /
                        row["false_producer_wall_ns"] for row in selected
                        if row["false_producer_wall_ns"] > 0)
        honest_ratios = sorted(row["honest_winner_full_search_wall_ns"] /
                               row["false_producer_wall_ns"] for row in selected
                               if row["false_producer_wall_ns"] > 0)
        summary["honest_win_over_false_generation_wall_ratio"] = {
            "median": statistics.median(honest_ratios), "min": honest_ratios[0],
            "max": honest_ratios[-1], "n": len(honest_ratios)}
        summary["reject_over_false_generation_wall_ratio"] = {
            "median": statistics.median(ratios), "min": ratios[0],
            "max": ratios[-1], "n": len(ratios)}
        results[shape] = summary
    static_rows = [{key: item[key] for key in (
        "seed", "shape", "challenge", "task", "proof_sha256", "transcript_sha256",
        "decoded_product_sha256", "false_ticket_hash_attempts", "honest_winner_attempts",
                      "honest_winner_full_search_wall_ns")}
        for item in rows]
    return {"schema": "pon-w1-go-same-host-cost-v1",
            "samples_per_shape": samples, "rows": rows, "summaries": results,
            "w1_go_source_sha256": digest(HOME / "work_go_probe.go"),
            "w1_go_test_sha256": digest(HOME / "test_w1_go_research.py"),
            "go_binary_sha256": binary_sha256,
            "fixed_inputs_sha256": hashlib.sha256(json.dumps(static_rows,sort_keys=True,separators=(",", ":")).encode()).hexdigest(),
            "scope": "one local host; within-invocation monotonic wall spans only; no independent CPU/gpu/energy measurements",
            "qualification": {"native_rust_w1_tested": False,
                              "independent_hardware": False,
                              "fastest_valid_miner_cost": False,
                              "sybil_attacks_measured": False,
                              "production_security_accepted": False}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--samples", type=int, default=32)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = campaign(args.samples)
    with args.output.open("x", encoding="utf8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps({"schema": result["schema"], "samples": result["samples_per_shape"],
                      "fixed_inputs_sha256": result["fixed_inputs_sha256"]},sort_keys=True))


if __name__ == "__main__":
    main()
