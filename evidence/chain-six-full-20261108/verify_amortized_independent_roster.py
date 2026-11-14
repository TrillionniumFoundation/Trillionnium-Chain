#!/usr/bin/env python3
"""Exact six-test supplement retaining the original F3 single-line-parser FAIL."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

HEAD = "1a446a79700cc093a2b1a7f10367ef4a5ddbd680"
TREE = "928b180bf769a813e5643827329667cb11f2a3a5"
SOURCE = "formal/pon-nakamoto-v1/test_amortized_cost_potential_independent.py"
SOURCE_SHA = "bec5e19103cfe8f8fc9995f01d665a10dd26e9341b92ab9e8934eae87b72e111"
# These exact two descriptions are printed on continuation lines by unittest.
# No arbitrary continuation, skipped test, or extra outcome is accepted.
ROSTER = (
    ("AdversarialInputRegressions", "test_delimiter_collision_cannot_alias_distinct_constraint_rows",
     "Old action:a:b:c labels merged two distinct state/action identities."),
    ("AdversarialInputRegressions", "test_iterators_cannot_erase_actions_outcomes_or_credit",
     "Reject before iteration, so validation cannot consume the declaration."),
    ("AdversarialInputRegressions", "test_model_name_boolean_and_integer_are_rejected", None),
    ("AdversarialInputRegressions", "test_typed_positive_credit_loop_has_an_exact_contradiction", None),
    ("IndependentFiniteOracles", "test_1600_deterministic_models_against_complete_integer_grid", None),
    ("IndependentFiniteOracles", "test_2025_stochastic_models_against_exact_difference_interval", None),
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_frame(stdout: bytes, stderr: bytes, exit_code: int, source: bytes):
    require(type(exit_code) is int and exit_code == 0 and stdout == b"", "original process outcome differs")
    require(sha(source) == SOURCE_SHA, "original test source drift")
    ids, entries = [], []
    for owner, method, description in ROSTER:
        identity = f"test_amortized_cost_potential_independent.{owner}.{method}"
        ids.append(identity)
        prefix = f"{method} ({identity})"
        entries.append(prefix + ("\n" + description if description is not None else "") + " ... ok\n")
    expected = "".join(entries)
    text = stderr.decode("utf-8", errors="strict")
    require(text.startswith(expected), "full named successes and original docstrings required")
    tail = text[len(expected):]
    require(re.fullmatch(r"\n-{70}\nRan 6 tests in [0-9]+\.[0-9]+s\n\nOK\n", tail) is not None,
            "exact six-test terminal frame required")
    return {"test_ids": ids, "executed_ok": 6, "skipped": 0,
            "source_sha256": sha(source), "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}


def identity(root):
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=root, text=True).strip()
    return {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "status": git("status", "--porcelain", "--untracked-files=all")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--original-campaign-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root, old, out = args.source_root.resolve(), args.original_campaign_dir.resolve(), args.output_dir.resolve()
    expected = {"head": HEAD, "tree": TREE, "status": ""}
    require(identity(root) == expected and not out.is_relative_to(root)
            and not out.is_relative_to(old), "exact source/separate output")
    original_files = [old / "campaign.json", old / "amortized-independent.stdout", old / "amortized-independent.stderr",
                      old / "current-pq-composition/source-before.json", old / "source-after-all.json"]
    pins = {str(p): sha(p.read_bytes()) for p in original_files}
    campaign = json.loads(original_files[0].read_bytes())
    require(campaign["expected_head"] == HEAD and campaign["result"] == "FAIL"
            and campaign["source_unchanged_for_complete_campaign"] is True
            and campaign["completed_stage_count"] == 29, "completed original F3 FAIL required")
    rows = [r for r in campaign["stages"] if r["stage"] == "amortized-independent"]
    require(len(rows) == 1, "one original stage required")
    row = rows[0]
    command = ["/usr/bin/python3", "-B", "-m", "unittest", "discover", "-s", "formal/pon-nakamoto-v1",
               "-p", "test_amortized_cost_potential_independent.py", "-v"]
    require(row["argv"] == command and row["exit_code"] == 0 and row["unittest_count"] == 6
            and row["named_success_count"] == 4 and row["passed"] is False, "original parser mismatch changed")
    require(len(row["artifacts"]) == 2
            and {item["path"] for item in row["artifacts"]}
                == {"amortized-independent.stdout", "amortized-independent.stderr"},
            "the two original stream artifacts are required exactly once")
    for item in row["artifacts"]:
        path = old / item["path"]
        require(path in original_files and sha(path.read_bytes()) == item["sha256"]
                and len(path.read_bytes()) == item["bytes"], "original actual log binding")
    original = verify_frame(original_files[1].read_bytes(), original_files[2].read_bytes(), row["exit_code"], (root / SOURCE).read_bytes())
    out.mkdir(parents=True, exist_ok=False)
    result = {"schema": "chain-six-amortized-independent-roster-supplement-v1", "source": expected,
              "original_failure_reinterpreted": False, "original_stage_passed": False,
              "original_input_sha256": pins, "original_frame": original, "commands": [],
              "qualification": "HOLD_NO_GO", "all_algorithm_cost_lower_bound": False, "complete": False}

    def execute(name, argv, timeout):
        before = identity(root); require(before == expected, "source before command changed")
        started = time.monotonic()
        so, se = out / (name+".stdout"), out / (name+".stderr")
        with so.open("xb") as stdout, se.open("xb") as stderr:
            process = subprocess.run(argv, cwd=root, stdout=stdout, stderr=stderr, timeout=timeout)
        after = identity(root)
        result["commands"].append({"name": name, "argv": argv, "timeout_seconds": timeout,
            "exit_code": process.returncode, "elapsed_seconds": time.monotonic()-started,
            "source_before": before, "source_after": after,
            "stdout_sha256": sha(so.read_bytes()), "stderr_sha256": sha(se.read_bytes())})
        require(process.returncode == 0 and before == after == expected, "original process/source failed")
        return so.read_bytes(), se.read_bytes(), process.returncode

    try:
        execute("source-before", ["/usr/bin/python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
            "--expected-head", HEAD, "--output", str(out / "source-before.json")], 1200)
        stdout, stderr, code = execute("original-six-tests", command, 1800)
        result["fresh_frame"] = verify_frame(stdout, stderr, code, (root / SOURCE).read_bytes())
        execute("source-after", ["/usr/bin/python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
            "--expected-head", HEAD, "--output", str(out / "source-after.json")], 1200)
        require(pins == {str(p): sha(p.read_bytes()) for p in original_files}, "original evidence mutated")
        require(sha((root / SOURCE).read_bytes()) == SOURCE_SHA, "original source drift after run")
        result["complete"] = True
        result["exact_six_test_validation_passed"] = True
        print(json.dumps({"complete": True, "fresh_original_six_passed": 6,
                          "original_stage_passed": False, "original_failure_reinterpreted": False}))
    finally:
        (out / "validation.json").write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
