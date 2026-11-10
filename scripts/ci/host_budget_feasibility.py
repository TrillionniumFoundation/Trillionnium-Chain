#!/usr/bin/env python3
"""Descriptive quarter-core resource arithmetic for the pinned failed campaign.

Measured CPU is NOT a lower bound for future optimized code; a quota period
boundary also means a nominal 30-second CPU budget is not an exact wall bound.
This program grants no qualification, verification, or production authority.
"""
import argparse
from fractions import Fraction
import json
from pathlib import Path

RUNS = 3
PHASES = ("baseline", "from-zero", "late-product")
SOURCE_SCHEMA = "pon-original-native-host-checkpoint-cost-v1"
SOURCE_COMMIT = "81f00ca62d9ce53483d56d2f2ec12fb871a0b3ae"
SOURCE_RUN = 42773664165
SOURCE_ZIP_SHA256 = "f004b1cf52aca7f84b2eb24c75d6a43fd5dd95a7c0ff86cbb97a31afd0c575d5"
QUOTA_US = 25_000
PERIOD_US = 100_000
WINDOW_SECONDS = 30


def strict_int(value, label, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(label + ": expected nonnegative integer")
    return value


def analyze(data):
    if not isinstance(data, dict) or data.get("schema") != SOURCE_SCHEMA:
        raise ValueError("wrong source schema")
    if (data.get("source_commit") != SOURCE_COMMIT or data.get("source_ci_run") != SOURCE_RUN
            or data.get("zip_sha256") != SOURCE_ZIP_SHA256):
        raise ValueError("not pinned source, run or artifact")
    if (data.get("planned_runs") != RUNS or data.get("original_stages_per_run") != 3
            or data.get("all_phase_criteria_met") is not False):
        raise ValueError("original failure denominator/status changed")
    rows = data.get("observations")
    if not isinstance(rows, list) or len(rows) != 9:
        raise ValueError("expected exactly 3 runs x 3 phases")
    budget = Fraction(WINDOW_SECONDS * 1_000_000_000 * QUOTA_US, PERIOD_US)
    output = []
    for index, row in enumerate(rows):
        run, mode = divmod(index, 3)
        if (not isinstance(row, dict) or row.get("run") != run+1 or row.get("phase") != PHASES[mode]
                or row.get("original_input_shape_valid") is not True
                or row.get("finite_phase_criteria_met") is not False):
            raise ValueError("changed or missing original phase")
        calls = strict_int(row.get("host_checkpoint_calls"), "calls", 1)
        cpu = strict_int(row.get("host_checkpoint_thread_cpu_ns"), "Host CPU", 1)
        imported = strict_int(row.get("history_import_thread_cpu_ns"), "import CPU", 1)
        if cpu > imported:
            raise ValueError("nested Host CPU exceeds import")
        share = Fraction(cpu, budget)
        output.append({
            "run": run+1, "phase": PHASES[mode],
            "host_checks": calls, "observed_host_cpu_ns": cpu,
            "observed_history_import_cpu_ns": imported,
            "nominal_30s_quarter_core_cpu_ns": int(budget),
            "host_share_of_nominal_window_ppm": int(share * 1_000_000),
            "nominal_cpu_left_ns": int(budget - cpu),
            "measured_cpu_equivalent_at_quarter_core_wall_ns": cpu * PERIOD_US // QUOTA_US,
            "is_a_future_optimization_lower_bound": False,
            "is_exact_quota_window_bound": False,
            "original_phase_accepted": False,
        })
    return {"schema": "pon-original-quarter-core-feasibility-v1",
            "source_commit": SOURCE_COMMIT, "source_ci_run": SOURCE_RUN,
            "source_zip_sha256": SOURCE_ZIP_SHA256,
            "original_runs": 3, "original_phases": 9,
            "all_original_phase_gates_met": False, "production_qualified": False,
            "notes": "Nested CPU, nominal cgroup allocation and historical observations only; quota-period edges and concurrent work exclude exact wall-bound claims",
            "rows": output}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.source.read_bytes()
    if len(raw) > 2_000_000:
        raise ValueError("source too large")
    report = analyze(json.loads(raw))
    with args.output.open("x", encoding="utf-8") as file:
        json.dump(report, file, sort_keys=True, indent=2)
        file.write("\n")
    print("Nine original phases accounted; HOLD, no new acceptance")


if __name__ == "__main__":
    main()
