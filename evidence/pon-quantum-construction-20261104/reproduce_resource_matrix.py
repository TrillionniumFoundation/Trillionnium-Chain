#!/usr/bin/env python3
"""Reproduce explicit illustrative construction-cost/event points, including refusals.

The actual W1 marked set and a physical QPU are not simulated. This wrapper uses
the source-bound campaign's compiler mode and keeps its scope/assumption flags.
"""
from dataclasses import asdict, replace
import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from quantum_oracle_resources import ClassicalCosts, Workload, example
from experiments.quantum_resource_clock_campaign import canonical, observe, verify, write_atomic
from experiments.w1_quantum_oracle_campaign import retained_template


def run(output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("FRESH_OUTPUT_REQUIRED")
    output.mkdir(parents=True)
    base = example(True)
    models = tuple(replace(model, magic_state_error="1e-60") for model in base.physical_models)
    classical = ClassicalCosts(10_000_000, 1_000_000, 1_000_000, 100_000_000,
                               1_000_000_000, 500_000_000)
    rows = []
    for profile, processors in (("PNH1", 1), ("PNH1", 3), ("PGH2", 1)):
        spec = retained_template(profile).spec()
        for model in models if profile == "PNH1" else (models[1],):
            name = f"{profile}-p{processors}-{model.physical_error}"
            request = replace(base, workload=Workload(1, 1, processors, 1, 32, (), 0),
                              classical=classical, physical_models=models)
            try:
                record = observe(request, model.name, 10**15, 17, 1200, spec)
            except ValueError as error:
                if str(error) != "NO_DISTANCE_FOR_CAMPAIGN_ENVELOPE":
                    raise
                row = {"name": name, "status": "CONDITIONAL_CAPACITY_REFUSED",
                       "reason": str(error), "maximum_distance": model.maximum_distance,
                       "event_runs": 0}
                write_atomic(output / (name + ".refusal.json"), canonical(row) + b"\n")
            else:
                raw = canonical(record) + b"\n"
                write_atomic(output / (name + ".json"), raw)
                replay = verify(record)
                write_atomic(output / (name + ".replay.json"), canonical(replay) + b"\n")
                row = {"name": name, "status": "REPLAY_PASS", "sha256": hashlib.sha256(raw).hexdigest(),
                       "source": record["source"], "event_runs": replay["replayed_cases"]}
            rows.append(row)
    summary = {"schema": "trnm-w1-resource-matrix-reproduction-v1",
               "recipe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "classical_costs": asdict(classical), "models": [asdict(m) for m in models],
               "physical_qubit_budget": 10**15, "seed": 17, "duration_seconds": 1200,
               "points": rows, "actual_W1_marked_set_simulated": False,
               "physical_calibration": False, "security_theorem": False, "production_activation": False}
    write_atomic(output / "summary.json", canonical(summary) + b"\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    summary = run(args.out)
    print(canonical({"points": len(summary["points"]),
                     "event_runs": sum(point["event_runs"] for point in summary["points"]),
                     "refusals": sum(point["status"] == "CONDITIONAL_CAPACITY_REFUSED"
                                      for point in summary["points"])}).decode())
