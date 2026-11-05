#!/usr/bin/env python3
"""Reduce every fixed cohort; ratios are observations, never selected winners."""
import argparse
import collections
import csv
import gzip
import hashlib
import json
from pathlib import Path

from check_pure_pon_cost_campaign import check, require


def known_sum(values):
    values = list(values)
    return None if any(value is None for value in values) else sum(values)


def summarize(rows):
    checked = check(rows)
    grouped = collections.defaultdict(list)
    keys = ("material", "strategy", "reuse", "horizon", "target")
    for row in rows:
        if row["kind"] == "cohort":
            grouped[tuple(row[key] for key in keys)].append(row)
    results = []
    for key, members in sorted(grouped.items()):
        require(len({row["status"] for row in members}) == 1, "round-dependent support")
        result = dict(zip(keys, key))
        result.update(status=members[0]["status"], rounds=len(members),
                      setup_count=sum(row["setup_count"] for row in members),
                      setup_cpu_ns=known_sum(row["setup_cpu_ns"] for row in members),
                      setup_wall_ns=sum(row["setup_wall_ns"] for row in members))
        if result["status"] == "complete":
            for name in ("attempts", "winners", "exhausted", "native_accepted_calls",
                         "total_producer_wall_ns", "total_producer_cpu_ns"):
                result[name] = known_sum(row[name] for row in members)
            cpu = result["total_producer_cpu_ns"]
            wall = result["total_producer_wall_ns"]
            result["cpu_ns_per_attempt"] = None if cpu is None else cpu / result["attempts"]
            result["wall_ns_per_attempt"] = wall / result["attempts"]
            result["cpu_ns_per_win_including_failed_searches"] = (
                None if cpu is None or result["winners"] == 0 else cpu / result["winners"])
            result["round_cpu_ns_per_attempt"] = [
                None if row["total_producer_cpu_ns"] is None else
                row["total_producer_cpu_ns"] / row["attempts"] for row in members]
        results.append(result)
    references = {(row["material"], row["reuse"], row["horizon"], row["target"]): row
                  for row in results if row["strategy"] == "prepared-general"}
    for row in results:
        if row["status"] == "complete":
            reference = references[row["material"], row["reuse"], row["horizon"], row["target"]]
            require(row["attempts"] == reference["attempts"] and row["winners"] == reference["winners"],
                    "unpaired aggregate outcomes")
            reference_cpu = reference["total_producer_cpu_ns"]
            cpu = row["total_producer_cpu_ns"]
            row["reference_cpu_over_strategy_cpu"] = (
                None if reference_cpu is None or cpu in (None, 0) else reference_cpu / cpu)
    return {"schema": "pon-pure-w1-fixed-cohort-reduction-v1", "groups": results,
            "input_cohorts": checked["cohorts"], "offered_fixed_groups": len(results),
            "supported_groups": sum(row["status"] == "complete" for row in results),
            "attempts": checked["attempts"], "winning_calls": checked["winning_calls"],
            "exhausted_searches": checked["exhausted_searches"],
            "denominator": "sum of setup and every real attempt across all rounds, including failed searches; no warmup exclusion",
            "ratio_reference": "prepared-general within exactly the same material, target, horizon and preparation policy",
            "scope": "paired finite observations on a contended host; nested horizons and kernels reuse challenge streams; ratios are neither confidence intervals nor stable speedups",
            "hardness_proved": False, "production_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    args = parser.parse_args()
    with (gzip.open if args.input.suffix == ".gz" else open)(args.input, "rb") as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    require(len(raw) <= 32 * 1024 * 1024 and raw.endswith(b"\n"), "bounded complete input")
    result = summarize([json.loads(line) for line in raw.splitlines()])
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    with args.output.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    columns = sorted({name for row in result["groups"] for name in row})
    with args.csv.open("x", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(result["groups"])


if __name__ == "__main__":
    main()
