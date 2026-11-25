#!/usr/bin/env python3
"""Observe every fixed current and retained V1 metadata control exactly once."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import traceback
import unittest

import pq_corpus_current_v2 as current

ROSTER = "scripts/ci/pq_corpus_current_required_controls_v2.json"
ROSTER_SHA256 = "f9ff508f211fd8e6e14c80428ec8d06eb1ccf56c4715f9d3b9c88cb9ce62f899"
MODULES = ("test_pq_corpus_current_v2", "test_pq_research_integration")
COUNTS = (18, 113)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.success_ids = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.success_ids.append(test.id())
        super().addSuccess(test)


def run(root, output):
    require = current.require
    require(output.is_absolute() and not output.resolve().is_relative_to(root.resolve()),
            "control receipt must be outside source")
    raw = current.read_regular(root, ROSTER, current.MAX_MAP_BYTES)
    require(hashlib.sha256(raw).hexdigest() == ROSTER_SHA256,
            "control roster differs from reviewed source")
    roster = current.strict_json(raw)
    current.fields(roster, "schema expected_tests suites qualification", "control roster")
    require(roster["schema"] == "trnm-pq-corpus-current-required-controls-v2"
            and type(roster["expected_tests"]) is int
            and roster["expected_tests"] == sum(COUNTS)
            and current.canonical(roster["qualification"]) == current.canonical(current.QUALIFICATION),
            "control roster scope changed")
    require(type(roster["suites"]) is list and len(roster["suites"]) == len(MODULES),
            "control suite count changed")
    for row, module, count in zip(roster["suites"], MODULES, COUNTS):
        current.fields(row, "module expected_tests tests", "control suite")
        names = row["tests"]
        require(row["module"] == module and type(row["expected_tests"]) is int
                and row["expected_tests"] == count and type(names) is list
                and all(type(name) is str and name.startswith(module + ".") for name in names)
                and len(names) == count and names == sorted(set(names)),
                "control suite registry changed")
    report = {
        "schema": "trnm-pq-corpus-current-named-observation-v2",
        "status": "RUNNING", "roster_sha256": ROSTER_SHA256,
        "required_tests": sum(COUNTS), "suites": [],
        "all_named_controls_passed": False, "qualification": dict(current.QUALIFICATION),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    for required in roster["suites"]:
        module, expected = required["module"], required["tests"]
        row = {"module": module, "expected_ids": expected, "passed": False}
        try:
            loader = unittest.TestLoader()
            suite = loader.discover(str(root / "scripts/ci"), pattern=module + ".py")
            registered = [test.id() for test in flatten(suite)]
            row.update(registered_ids=registered, loader_errors=list(loader.errors))
            require(not loader.errors and Counter(registered) == Counter(expected),
                    "registered complete module differs from fixed named roster")
            result = unittest.TextTestRunner(
                stream=sys.stderr, verbosity=2, descriptions=False,
                resultclass=ObservedResult).run(suite)
            row.update({
                "tests_run": result.testsRun,
                "started_ids": result.started_ids, "success_ids": result.success_ids,
                "skipped": [(test.id(), why) for test, why in result.skipped],
                "failures": [(test.id(), why) for test, why in result.failures],
                "errors": [(test.id(), why) for test, why in result.errors],
                "expected_failures": [(test.id(), why) for test, why in result.expectedFailures],
                "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
            })
            row["passed"] = (
                result.testsRun == required["expected_tests"]
                and Counter(result.started_ids) == Counter(expected)
                and Counter(result.success_ids) == Counter(expected)
                and result.wasSuccessful() and not result.skipped
                and not result.expectedFailures and not result.unexpectedSuccesses
                and not result.failures and not result.errors)
        except (Exception, SystemExit) as error:
            row["exception"] = str(error)
            traceback.print_exc(file=sys.stderr)
        report["suites"].append(row)
        output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    report["all_named_controls_passed"] = (
        len(report["suites"]) == len(MODULES)
        and all(row["passed"] is True for row in report["suites"]))
    report["status"] = "PASS_METADATA_ONLY" if report["all_named_controls_passed"] else "FAIL"
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "required_tests": sum(COUNTS),
                      "roster_sha256": ROSTER_SHA256}, sort_keys=True))
    return 0 if report["all_named_controls_passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(Path(__file__).resolve().parents[2], args.output)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print("REFUSE: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
