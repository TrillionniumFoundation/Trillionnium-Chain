#!/usr/bin/env python3
"""Validate the actual single-test cache observation, not a performance claim."""
import argparse
import hashlib
import json
from pathlib import Path
import re

SELECTOR = (
    "store::native_authenticated::stored_delta_stream_tests::"
    "cached_delta_complete_call_observation_keeps_checks_and_results"
)
PREFIX = "native_statement_cache_observation_v1 "
SHA = re.compile(r"[0-9a-f]{40}\Z")
ROOT = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = {
    "delta_root", "elapsed_ns", "full_checks_preserved", "independent_operator",
    "progress_calls", "repetitions", "round", "rows", "statement_cache_capacity",
    "whole_node_throughput_measured", "width",
}


class Rejected(ValueError):
    """A missing, ambiguous, malformed or incorrectly bound native receipt."""


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise Rejected("nonfinite JSON number")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError, RecursionError) as error:
        raise Rejected(f"invalid JSON: {error}") from error


def read_bounded(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    require(0 < len(data) <= limit, "empty or oversized input")
    return data


def validate(log, source, after, *, head, kind, base=None, merge=None):
    """Validate supplied receipts; the CI source verifier owns checkout checks."""
    require(isinstance(head, str) and SHA.fullmatch(head), "invalid expected head")
    require(kind in ("head", "prospective-merge"), "invalid source kind")
    require(source == after and isinstance(source, dict), "source changed")
    expected = head
    if kind == "prospective-merge":
        require(isinstance(base, str) and SHA.fullmatch(base), "invalid expected base")
        require(isinstance(merge, str) and SHA.fullmatch(merge), "invalid expected merge")
        expected = merge
    else:
        require(base is None and merge is None, "head has unexpected merge arguments")
    require(
        source.get("schema") == "trnm-ci-source-v1"
        and source.get("candidate") == head
        and source.get("kind") == kind
        and source.get("tested_commit") == expected
        and source.get("base") == base
        and source.get("prospective_merge") == merge
        and source.get("tracked_worktree_verified") is True
        and source.get("tests_executed_by_identity_check") is False,
        "incorrect source binding",
    )
    tree = source.get("tested_tree")
    require(isinstance(tree, str) and SHA.fullmatch(tree), "invalid tested tree")
    lines = log.splitlines()
    successes = [line for line in lines if line.startswith("test ") and " ... " in line]
    require(successes == [f"test {SELECTOR} ... ok"], "not one successful exact native test")
    summaries = [line for line in lines if line.startswith("test result:")]
    require(
        len(summaries) == 1 and re.fullmatch(
            r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
            r"[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s", summaries[0]
        ),
        "missing or ambiguous successful singleton summary",
    )
    require(not any(line.startswith(("error:", "failures:")) for line in lines), "native failure")
    tagged = [line for line in lines if line.startswith("native_statement_cache_observation")]
    require(len(tagged) == 12, "expected twelve observations")
    records = []
    roots = {}
    order = [(rows, round_) for rows in (1, 257, 4096) for round_ in range(4)]
    for line, (rows, round_) in zip(tagged, order):
        require(line.startswith(PREFIX), "unknown observation version")
        row = strict_json(line[len(PREFIX):])
        require(isinstance(row, dict) and set(row) == FIELDS, "invalid observation fields")
        for key in ("elapsed_ns", "progress_calls", "repetitions", "round", "rows", "statement_cache_capacity", "width"):
            require(type(row[key]) is int, f"noninteger {key}")
        require(row["rows"] == rows and row["round"] == round_, "missing, duplicate or reordered observation")
        require(row["statement_cache_capacity"] == (0, 16, 16, 0)[round_], "wrong crossover order")
        require(row["width"] == 12 and row["repetitions"] == 50, "changed fixture or repetitions")
        require(row["progress_calls"] == 50 * (3 + rows // 256), "incomplete progress accounting")
        require(0 < row["elapsed_ns"] < 2**128, "invalid elapsed nanoseconds")
        require(
            row["full_checks_preserved"] is True
            and row["independent_operator"] is False
            and row["whole_node_throughput_measured"] is False,
            "unsupported scope promotion",
        )
        root = row["delta_root"]
        require(isinstance(root, str) and ROOT.fullmatch(root), "invalid root")
        require(roots.setdefault(rows, root) == root, "cache arms disagree")
        records.append(row)
    summaries = []
    for rows in (1, 257, 4096):
        group = [row for row in records if row["rows"] == rows]
        off = sum(row["elapsed_ns"] for row in group if row["statement_cache_capacity"] == 0)
        on = sum(row["elapsed_ns"] for row in group if row["statement_cache_capacity"] == 16)
        summaries.append({"rows": rows, "off_batch_mean_ns": off / 2,
                          "on_batch_mean_ns": on / 2, "on_over_off": on / off,
                          "batches_per_arm": 2, "complete_calls_per_batch": 50})
    return {"schema": "pon-native-cache-readback-v1", "source": source,
            "observations": records, "summaries": summaries,
            "complete_calls": 600, "whole_node_throughput_measured": False,
            "independent_operator": False, "speed_qualification": False,
            "scope": "Finite in-memory SQLite full delta checks; no whole Node, storage I/O, TPS, WAN or cheapest-adversary inference."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-after", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--kind", choices=("head", "prospective-merge"), required=True)
    parser.add_argument("--expected-base")
    parser.add_argument("--expected-merge")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        log = read_bounded(args.log, 2 * 1024 * 1024)
        source = read_bounded(args.source, 64 * 1024)
        after = read_bounded(args.source_after, 64 * 1024)
        result = validate(log.decode("utf-8"), strict_json(source), strict_json(after),
                          head=args.expected_head, kind=args.kind,
                          base=args.expected_base, merge=args.expected_merge)
        result.update(log_sha256=hashlib.sha256(log).hexdigest(),
                      source_sha256=hashlib.sha256(source).hexdigest(),
                      source_after_sha256=hashlib.sha256(after).hexdigest())
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    except (OSError, UnicodeError, Rejected) as error:
        parser.exit(1, f"NATIVE_CACHE_RECEIPT_REJECTED: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
