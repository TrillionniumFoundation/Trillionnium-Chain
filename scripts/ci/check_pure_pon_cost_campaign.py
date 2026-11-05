#!/usr/bin/env python3
"""Check complete paired native observations, not hardware authenticity/hardness."""
import argparse
import gzip
import hashlib
import itertools
import json
from pathlib import Path

SCHEMA = "pon-pure-w1-amortization-campaign-v1"
ARMS = {"prepared-general", "structured", "tiled-classical", "blocked-zero",
        "tiled-strassen-one-level", "paired-field-products", "blocked-one-zero-rank-one",
        "blocked-zero-integer-paired", "maintenance-split-limb", "maintenance-periodic",
        "maintenance-prefix", "maintenance-integer-paired"}
MATERIALS = {"periodic-dense-fixture", "full-rank-field", "zero", "identity",
             "rank-one", "sparse-diagonal", "genesis-maintenance", "zero-left-rank-one-right",
             "rank-one-left-zero-right"}
GENERAL_ARMS = {"prepared-general", "tiled-classical", "tiled-strassen-one-level", "paired-field-products"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def natural(value):
    return type(value) is int and value >= 0


def exact_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def check(rows):
    require(bool(rows), "empty campaign")
    require(all(r.get("schema") == SCHEMA for r in rows), "schema")
    begin, terminal = rows[0], rows[-1]
    require(begin.get("kind") == "begin", "missing begin")
    require(terminal.get("kind") == "terminal" and terminal.get("status") == "complete", "incomplete terminal")
    require(sum(r.get("kind") == "begin" for r in rows) == 1, "multiple begin")
    require(sum(r.get("kind") == "terminal" for r in rows) == 1, "multiple terminal")
    require(begin.get("hardness_proved") is False and terminal.get("hardness_proved") is False
            and terminal.get("production_qualified") is False, "unearned qualification")
    require(natural(begin["rounds"]) and 1 <= begin["rounds"] <= 64, "rounds")
    require(natural(begin["max_horizon"]) and 1 <= begin["max_horizon"] <= 1024, "horizon")
    require(natural(begin["attempt_budget"]) and 1 <= begin["attempt_budget"] <= 4096, "attempt budget")
    horizons = {n for n in (1, 8, 64, begin["max_horizon"]) if n <= begin["max_horizon"]}
    materials = [r for r in rows if r.get("kind") == "material"]
    require(len(materials) == len(MATERIALS) and {r["name"] for r in materials} == MATERIALS, "material cohort")
    cohorts = [r for r in rows if r.get("kind") == "cohort"]
    require(len(cohorts) == terminal["cohorts"], "terminal cohort count")
    targets = {r["target"] for r in cohorts}
    require(exact_hash(begin["native_target"]) and targets == {begin["native_target"], "07" + "ff" * 31}
            and len(targets) == 2, "targets")
    expected = set(itertools.product(MATERIALS, ARMS, (False, True), horizons,
                                     range(begin["rounds"]), targets))
    actual, streams = set(), {}
    total_attempts = total_winners = total_exhausted = 0
    summaries = []
    for row in cohorts:
        key = (row["material"], row["strategy"], row["reuse"], row["horizon"], row["round"], row["target"])
        require(type(row["reuse"]) is bool and key in expected and key not in actual, "cohort identity")
        actual.add(key)
        require(natural(row["setup_wall_ns"]) and (row["setup_cpu_ns"] is None or natural(row["setup_cpu_ns"])), "setup cost")
        if row["status"] == "unsupported":
            require(row["attempts"] == row["winners"] == 0 and row["setup_count"] == 1, "unsupported accounting")
            require(row["strategy"] not in GENERAL_ARMS, "missing general producer")
            continue
        require(row["status"] == "complete", "cohort incomplete")
        require(row["setup_count"] == (1 if row["reuse"] else row["horizon"]), "setup reuse accounting")
        searches = row["searches"]
        require(len(searches) == row["horizon"], "missing search")
        require([s["search"] for s in searches] == list(range(row["horizon"])), "search ordering")
        for search in searches:
            require(type(search["winner"]) is bool and natural(search["attempts"])
                    and 1 <= search["attempts"] <= begin["attempt_budget"], "search attempts")
            require(exact_hash(search["last_ticket"]), "ticket bytes")
            require((int(search["last_ticket"], 16) <= int(row["target"], 16)) == search["winner"], "ticket outcome")
            require(search["winner"] or search["attempts"] == begin["attempt_budget"], "dropped failed attempts")
            require(natural(search["search_wall_ns"]) and (search["search_cpu_ns"] is None
                    or natural(search["search_cpu_ns"])), "search cost")
        attempts = sum(s["attempts"] for s in searches)
        winners = sum(s["winner"] for s in searches)
        wall = sum(s["search_wall_ns"] for s in searches)
        cpu = None if any(s["search_cpu_ns"] is None for s in searches) else sum(s["search_cpu_ns"] for s in searches)
        require(row["attempts"] == attempts and row["winners"] == winners
                and row["exhausted"] == row["horizon"] - winners, "outcome sums")
        require(row["search_wall_ns"] == wall and row["total_producer_wall_ns"] == wall + row["setup_wall_ns"], "complete wall cost")
        require(row["search_cpu_ns"] == cpu, "search CPU sum")
        full_cpu = None if cpu is None or row["setup_cpu_ns"] is None else cpu + row["setup_cpu_ns"]
        require(row["total_producer_cpu_ns"] == full_cpu, "unknown CPU or full denominator")
        expected_native = winners if row["material"] == "genesis-maintenance" and row["target"] == begin["native_target"] else 0
        require(natural(row["native_accepted_calls"]) and row["native_accepted_calls"] == expected_native, "native admission scope")
        stream_key = (row["material"], row["horizon"], row["round"], row["target"])
        require(exact_hash(row["stream_sha256"]), "stream digest")
        require(streams.setdefault(stream_key, row["stream_sha256"]) == row["stream_sha256"], "unpaired proof streams")
        total_attempts += attempts
        total_winners += winners
        total_exhausted += row["exhausted"]
        summaries.append({k: row[k] for k in ("material", "strategy", "reuse", "horizon", "round", "target", "attempts", "winners", "exhausted", "total_producer_wall_ns", "total_producer_cpu_ns")})
    require(actual == expected, "missing offered cohort")
    rejections = [r for r in rows if r.get("kind") == "late_product_rejection"]
    require(len(rejections) == 1 and rejections[0]["cases"] == 64, "missing rejection comparison")
    return {"schema": "pon-pure-w1-cost-consistency-v1", "cohorts": len(cohorts),
            "attempts": total_attempts, "winning_calls": total_winners, "exhausted_searches": total_exhausted,
            "late_product_rejection": rejections[0], "complete_costs": summaries,
            "scope": "internally consistent finite observations; shared streams are not independent samples; no hardware authentication, timing confidence, hardness or public fairness proof",
            "hardness_proved": False, "production_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    opener = gzip.open if args.input.suffix == ".gz" else open
    with opener(args.input, "rb") as f:
        raw = f.read(32 * 1024 * 1024 + 1)
    require(len(raw) <= 32 * 1024 * 1024 and raw.endswith(b"\n"), "bounded complete input")
    rows = [json.loads(line) for line in raw.splitlines()]
    result = check(rows)
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    if args.output:
        with args.output.open("x") as f:
            json.dump(result, f, indent=2)
            f.write("\n")
    else:
        print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise SystemExit(f"campaign consistency rejected: {error}") from error
