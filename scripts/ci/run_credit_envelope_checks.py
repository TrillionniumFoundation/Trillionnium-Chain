#!/usr/bin/env python3
"""Run the pinned finite-math roster and retain actual outcomes and reports.

The outer CI workflow separately verifies the complete committed source. This
runner identifies its exact selected bytes; neither check certifies W1 cost.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
FORMAL = ROOT / "formal/pon-nakamoto-v1"
ROSTER = FORMAL / "credit_envelope_test_roster_v1.json"
MODULES = ("test_credit_envelope_contract", "test_normalized_search_cost")
SOURCE_PATHS = (
    "formal/pon-nakamoto-v1/credit_envelope_contract.py",
    "formal/pon-nakamoto-v1/test_credit_envelope_contract.py",
    "formal/pon-nakamoto-v1/normalized_search_cost.py",
    "formal/pon-nakamoto-v1/test_normalized_search_cost.py",
    "formal/pon-nakamoto-v1/CREDIT_ENVELOPE_CONTRACT_V1.md",
    "formal/pon-nakamoto-v1/credit_envelope_test_roster_v1.json",
    "scripts/ci/run_credit_envelope_checks.py",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources() -> dict[str, str]:
    return {name: digest(ROOT / name) for name in SOURCE_PATHS}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_names = []
        self.successful_names = []

    def startTest(self, test):
        self.started_names.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.successful_names.append(test.id())
        super().addSuccess(test)


def write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    if out == ROOT or ROOT in out.parents:
        raise SystemExit("observation output must be outside the tracked source tree")
    out.mkdir(parents=True, exist_ok=False)
    before = sources()
    write_json(out / "sources-before.json", before)
    sys.path.insert(0, str(FORMAL))
    roster = json.loads(ROSTER.read_text())
    if set(roster) != {"schema", "test_names"} or roster["schema"] != "pon-credit-envelope-test-roster-v1":
        raise SystemExit("invalid test roster")
    expected = roster["test_names"]
    if not expected or expected != sorted(set(expected)) or any(type(name) is not str for name in expected):
        raise SystemExit("test roster must be nonempty, sorted and unique")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromName(module) for module in MODULES)
    discovered = sorted(test.id() for test in flatten(suite))
    if loader.errors or discovered != expected:
        write_json(out / "roster-failure.json", {"expected": expected, "discovered": discovered,
                                                 "loader_errors": loader.errors})
        raise SystemExit("registered test identities differ from the pinned roster")
    with (out / "named-tests.log").open("x", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2,
                                        resultclass=RecordedResult).run(suite)
    ok = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
          and not result.unexpectedSuccesses and sorted(result.started_names) == expected
          and sorted(result.successful_names) == expected and result.testsRun == len(expected))
    write_json(out / "test-outcomes.json", {
        "schema": "pon-credit-envelope-test-outcomes-v1", "passed": ok,
        "registered_names": expected, "started_names": result.started_names,
        "successful_names": result.successful_names,
        "failures": [(test.id(), text) for test, text in result.failures],
        "errors": [(test.id(), text) for test, text in result.errors],
        "skipped": [(test.id(), reason) for test, reason in result.skipped],
        "expected_failures": [(test.id(), text) for test, text in result.expectedFailures],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "tests_run": result.testsRun, "distinct_tests": len(set(result.started_names)),
        "subtest_cases_are_not_additional_test_methods": True,
        "whole_chain_or_cost_qualification": False,
    })
    if not ok:
        raise SystemExit("named test execution failed; outcomes retained")
    import credit_envelope_contract as credit
    import normalized_search_cost as search
    credit_report = credit.build_report()
    search_report = search.build_report()
    write_json(out / "credit-envelope.json", credit_report)
    write_json(out / "normalized-search.json", search_report)
    # Re-read actual retained JSON, then independently validate its contents.
    credit_verified = credit.verify_report(credit.load_json(out / "credit-envelope.json"))
    search_verified = search.verify_report(search.load_json(out / "normalized-search.json"))
    write_json(out / "credit-envelope-verified.json", credit_verified)
    write_json(out / "normalized-search-verified.json", search_verified)
    if (credit_verified.get("verification") != "PASS"
            or search_verified.get("verification") != "PASS"):
        raise SystemExit("report verification did not return PASS")
    after = sources()
    write_json(out / "sources-after.json", after)
    if before != after:
        raise SystemExit("selected source bytes changed during execution")
    write_json(out / "completion.json", {
        "schema": "pon-credit-envelope-completion-v1",
        "finite_math_checks": "PASS", "distinct_named_tests_passed": len(expected),
        "source_bytes_unchanged": True, "complete_worktree_verified_here": False,
        "actual_w1_minimum_cost": "UNPROVED", "stateful_portfolio_bound": "UNPROVED",
        "mixed_consensus_bound": "UNPROVED", "overall": "HOLD",
        "production_activation": False,
    })
    print(json.dumps({"output": str(out), "distinct_named_tests_passed": len(expected),
                      "finite_math_checks": "PASS", "overall": "HOLD"}, sort_keys=True))


if __name__ == "__main__":
    main()
