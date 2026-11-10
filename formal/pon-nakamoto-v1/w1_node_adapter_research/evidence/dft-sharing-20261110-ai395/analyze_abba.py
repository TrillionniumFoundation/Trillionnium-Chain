#!/usr/bin/env python3
"""Describe retained raw observations without overriding resource qualification."""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, required=True)
    p.add_argument("--reader", type=Path, required=True)
    args = p.parse_args()
    spec = importlib.util.spec_from_file_location("receiver_reader", args.reader)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    plan = json.loads((args.run / "plan.json").read_text())
    require(plan["order"] == list("ABBA"), "outer order changed")
    require(plan["receiver_order_in_each_batch"] == "NPPNNPPN", "inner order changed")
    batches, all_rows, errors = [], [], []
    for index, arm in enumerate(plan["order"]):
        directory = args.run / (str(index) + "-" + arm)
        manifest = reader.strict_json((directory / "manifest.json").read_text())
        original = reader.strict_json((directory / "summary.json").read_text())
        expected = reader.summarize(manifest)
        require({k: v for k, v in original.items() if k != "manifest_sha256"} == expected,
                "stored summary differs from original reader")
        require(original["manifest_sha256"] == reader.sha(directory / "manifest.json"),
                "manifest digest changed")
        for row in manifest["receivers"]:
            failures = reader.validate_receiver(row, manifest["plan"])
            errors.extend({"batch": index, "index": row["index"], "error": error}
                          for error in failures)
            m = row["measurement"]
            require(m["cpu_seconds"] == m["user_seconds"] + m["system_seconds"],
                    "CPU usage does not equal user plus system")
            for stream in ("stdout", "stderr"):
                source = Path(m[stream]["path"])
                require(source.stat().st_size == m[stream]["bytes"], "raw stream size changed")
                require(reader.sha(source) == m[stream]["sha256"], "raw stream digest changed")
            require(reader.final_receipt(Path(m["stdout"]["path"])) == m["receipt"],
                    "embedded receipt differs from raw stdout")
            all_rows.append({"batch": index, "arm": arm, "variant": row["variant"],
                             "measurement": m, "validation_errors": failures})
        raw = {}
        for variant in ("N", "P"):
            selected = [r["measurement"] for r in manifest["receivers"]
                        if r["variant"] == variant]
            require(len(selected) == 4, "all four planned samples per arm are required")
            raw[variant] = {key: statistics.median(r[key] for r in selected)
                           for key in ("wall_seconds", "cpu_seconds", "peak_rss_kib")}
        batches.append({"index": index, "arm": arm, "raw_descriptive_medians": raw,
                        "original_comparison": original["local_receiver_comparison"],
                        "original_qualified_medians": original["medians"],
                        "original_errors": original["errors"]})
    require(len(all_rows) == 32, "all 32 planned receiver attempts are required")
    descriptive = {}
    if not errors:
        for arm in ("A", "B"):
            descriptive[arm] = {}
            for variant in ("N", "P"):
                selected = [r["measurement"] for r in all_rows
                            if r["arm"] == arm and r["variant"] == variant]
                require(len(selected) == 8, "all eight planned samples per source/variant required")
                descriptive[arm][variant] = {key: statistics.median(r[key] for r in selected)
                    for key in ("wall_seconds", "cpu_seconds", "peak_rss_kib")}
    result = {"schema": "trnm-w1-dft-raw-analysis-v1", "batches": batches,
        "receiver_attempts": len(all_rows), "receiver_validation_errors": errors,
        "raw_descriptive_arm_medians": descriptive,
        "raw_medians_scope": "descriptive observations; original per-batch resource qualification is retained; no causal speedup or production qualification claim",
        "qualified_improvement": None, "original_service_acceptance": "NOT_ESTABLISHED",
        "new_complete_w1_proofs": 0, "distinct_input_tasks": 1,
        "network_transport_measured": False, "end_to_end_benefit": "NOT_ESTABLISHED",
        "production_activation": False, "qualification": "HOLD_NO_GO"}
    (args.run / "independent-analysis.json").write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
