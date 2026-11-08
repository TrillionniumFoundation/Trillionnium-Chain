#!/usr/bin/env python3
"""Execute the frozen named research controls and retain failures without promotion."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
FORMAL = ROOT / "formal/pon-nakamoto-v1"
sys.path.insert(0, str(FORMAL))
import work_profile_contract_v1 as contract
import cost_envelope_contract_v1 as envelope

MODULES = ("test_work_profile_contract_v1", "test_branch_time_daa_v1",
           "test_cost_envelope_contract_v1", "test_legal_optimization_catalog_v1")
ROSTER = ROOT / "formal/pon-nakamoto-v1/contracts/work-time-required-tests-v1.json"
INPUTS = (
    "formal/pon-nakamoto-v1/work_profile_contract_v1.py",
    "formal/pon-nakamoto-v1/test_work_profile_contract_v1.py",
    "formal/pon-nakamoto-v1/branch_time_daa_v1.py",
    "formal/pon-nakamoto-v1/test_branch_time_daa_v1.py",
    "formal/pon-nakamoto-v1/cost_envelope_contract_v1.py",
    "formal/pon-nakamoto-v1/test_cost_envelope_contract_v1.py",
    "formal/pon-nakamoto-v1/legal_optimization_catalog_v1.py",
    "formal/pon-nakamoto-v1/test_legal_optimization_catalog_v1.py",
    "formal/pon-nakamoto-v1/contracts/work-cost-contract-v1.json",
    "formal/pon-nakamoto-v1/contracts/legal-optimization-catalog-v1.json",
    "formal/pon-nakamoto-v1/contracts/work-time-required-tests-v1.json",
    "formal/pon-nakamoto-v1/contracts/cost-envelope-current-hold-v1.json",
    "formal/pon-nakamoto-v1/contracts/cost-envelope-counterexample-v1.json",
    "docs/protocol/pon-nakamoto-v1/details/LEGAL_OPTIMIZATION_CATALOG_V1.md",
    ".github/workflows/pon-work-time-contract-v1.yml",
    "scripts/ci/run_work_time_contract_v1.py",
)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class NamedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started = []
        self.successful = []

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.successful.append(test.id())
        super().addSuccess(test)


def input_identity():
    result = []
    for relative in INPUTS:
        data = (ROOT / relative).read_bytes()
        result.append({"path": relative, "bytes": len(data),
                       "sha256": hashlib.sha256(data).hexdigest()})
    return result


def run_controls(out):
    before = input_identity()
    roster = contract.loads(ROSTER.read_bytes())
    contract.require(type(roster) is dict and set(roster) == {"schema", "tests"}
                     and roster["schema"] == "pon-work-time-required-tests-v1", "TEST_ROSTER_SCHEMA")
    required = roster["tests"]
    contract.require(type(required) is list and required and all(type(x) is str for x in required)
                     and sorted(set(required)) == required, "TEST_ROSTER")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in MODULES)
    observed = sorted(test.id() for test in flatten(suite))
    contract.require(observed == required and not loader.errors, "TEST_ROSTER_MISMATCH")
    start = time.monotonic_ns()
    with (out / "tests.log").open("x") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=NamedResult).run(suite)
    after = input_identity()
    success = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
               and not result.unexpectedSuccesses and result.testsRun == len(required)
               and sorted(result.started) == required and sorted(result.successful) == required
               and before == after)
    return {"schema": "pon-work-time-named-controls-v1", "python": platform.python_version(),
            "declared_inputs_before": before, "declared_inputs_after": after,
            "source_scope": "declared-research-inputs; separate full tracked-source CI guard required",
            "required": required, "started": sorted(result.started),
            "successful": sorted(result.successful), "tests_run": result.testsRun,
            "failed": len(result.failures), "errors": len(result.errors),
            "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
            "elapsed_wall_ns": time.monotonic_ns() - start, "controls_passed": success,
            "native_execution": False, "production_activation": False}


def execute(out, campaign):
    out = out.resolve()
    contract.require(not out.is_relative_to(ROOT), "OUTPUT_MUST_BE_OUTSIDE_SOURCE")
    out.mkdir(parents=True, exist_ok=False)
    summary = {"schema": "pon-work-time-execution-v1", "status": "HOLD_NO_GO",
               "stage_results": [], "passed_research_controls": False,
               "qualification": dict(contract.QUALIFICATION)}
    try:
        summary["head_at_execution"] = contract.git(ROOT, "rev-parse", "HEAD").strip().decode()
        summary["head_tree_at_execution"] = contract.git(ROOT, "rev-parse", "HEAD^{tree}").strip().decode()
        frozen = contract.check_contract(contract.loads((ROOT / contract.CONTRACT_PATH).read_bytes()))
        (out / "contract-before.json").write_text(json.dumps(frozen, indent=2) + "\n")
        summary["stage_results"].append({"stage": "frozen-contract-before", "passed": True})
        result = run_controls(out)
        (out / "named-controls.json").write_text(json.dumps(result, indent=2) + "\n")
        summary["stage_results"].append({"stage": "named-controls", "passed": result["controls_passed"]})
        contract.require(result["controls_passed"], "NAMED_CONTROLS_FAILED")
        profile_path = "config/pon/work-profile-v1.json"
        profile_sha256 = hashlib.sha256((ROOT / profile_path).read_bytes()).hexdigest()
        for name, expected in (("current-hold", "HOLD_MISSING_BOUNDS"),
                               ("counterexample", "INFEASIBLE")):
            model_path = FORMAL / "contracts" / ("cost-envelope-" + name + "-v1.json")
            model = contract.loads(model_path.read_bytes())
            contract.require(model["profile_sha256"] == profile_sha256, "COST_PROFILE_IDENTITY")
            checked = envelope.check_contract(model)
            joined = {"schema": "pon-cost-envelope-observation-v1",
                      "baseline_profile_path": profile_path, "baseline_profile_sha256": profile_sha256,
                      "baseline_profile_bytes_verified": True,
                      "scope": "identity join and declared finite-model arithmetic; variable-u native relation absent",
                      "result": checked}
            (out / ("cost-envelope-" + name + ".json")).write_text(json.dumps(joined, indent=2) + "\n")
            contract.require(checked["arithmetic_status"] == expected, "COST_MODEL_STATUS")
            summary["stage_results"].append({"stage": "cost-envelope-" + name,
                                             "arithmetic_status": expected, "passed": True})
        if campaign:
            for label, args in (
                ("catalog-generate", ["--output", str(out / "catalog.json")]),
                ("catalog-replay", ["--replay", str(out / "catalog.json")]),
            ):
                with (out / (label + ".stdout")).open("xb") as stdout, \
                     (out / (label + ".stderr")).open("xb") as stderr:
                    process = subprocess.run([sys.executable, str(FORMAL / "legal_optimization_catalog_v1.py"),
                                              *args], cwd=ROOT, stdout=stdout, stderr=stderr, check=False,
                                             timeout=300)
                summary["stage_results"].append({"stage": label, "exit_code": process.returncode,
                                                 "passed": process.returncode == 0})
                contract.require(process.returncode == 0, label.upper() + "_FAILED")
        after = contract.check_contract(contract.loads((ROOT / contract.CONTRACT_PATH).read_bytes()))
        (out / "contract-after.json").write_text(json.dumps(after, indent=2) + "\n")
        contract.require(frozen == after, "FROZEN_SOURCE_CHANGED")
        contract.require(result["declared_inputs_before"] == input_identity(), "RESEARCH_SOURCE_CHANGED")
        summary["stage_results"].append({"stage": "frozen-contract-after", "passed": True})
        summary["passed_research_controls"] = True
        return_code = 0
    except Exception as error:
        summary["error"] = {"type": type(error).__name__, "message": str(error)}
        return_code = 1
    finally:
        summary["artifacts"] = []
        for path in sorted(out.iterdir()):
            if path.is_file() and path.name != "execution.json":
                data = path.read_bytes()
                summary["artifacts"].append({"path": path.name, "bytes": len(data),
                                             "sha256": hashlib.sha256(data).hexdigest()})
        (out / "execution.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed_research_controls": summary["passed_research_controls"],
                      "status": summary["status"], "execution": str(out / "execution.json")}))
    return return_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--campaign", action="store_true")
    args = parser.parse_args()
    raise SystemExit(execute(args.output_dir, args.campaign))
