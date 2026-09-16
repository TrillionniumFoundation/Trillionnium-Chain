#!/usr/bin/env python3
"""Fail-closed entrypoint for the Plan v2 technical-convergence contract."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys
from types import ModuleType
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER_PATHS = (
    pathlib.Path("scripts/ci/technical_convergence_contract_v1.py"),
    pathlib.Path("scripts/ci/technical_convergence_workflows_v1.py"),
    pathlib.Path("scripts/ci/technical_convergence_coverage_v1.py"),
)


class ConvergenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConvergenceError(message)


def git_blob_sha(path: pathlib.Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ConvergenceError(f"{path}: unreadable helper: {error}") from error
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def load_helper(root: pathlib.Path, relative: pathlib.Path) -> ModuleType:
    path = root / relative
    require(path.is_file(), f"helper missing: {relative}")
    require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()),
            f"helper must be a repository file: {relative}")
    name = "trnm_" + relative.stem
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load helper: {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _helpers(root: pathlib.Path) -> tuple[ModuleType, ModuleType, ModuleType]:
    modules = [load_helper(root, path) for path in HELPER_PATHS]
    return modules[0], modules[1], modules[2]


def validate(root: pathlib.Path = ROOT) -> dict[str, Any]:
    try:
        contract_helper, workflow_helper, coverage_helper = _helpers(root)
        contract, contract_report = contract_helper.validate(root)
        workflow_report = workflow_helper.validate(root, contract, require)
        coverage_report = coverage_helper.validate(
            root, contract_helper.DETAILED_SPECS, require
        )
    except ConvergenceError:
        raise
    except (RuntimeError, OSError, UnicodeError) as error:
        raise ConvergenceError(str(error)) from error
    return {
        "schema": "trnm-technical-convergence-check-v1",
        **contract_report,
        "workflow_security": workflow_report,
        "module_coverage_binding": coverage_report,
        "helper_input_blobs": {str(p): git_blob_sha(root / p) for p in HELPER_PATHS},
        "production_candidate": False,
        "production_consensus_activation": False,
        "release_ready": False,
        "result": "PASS",
    }


# Stable aliases consumed by retained mutants. Helpers are reviewed source in
# the same checkout, not an independent trust root. Source/merge binding remains.
_contract, _workflows, _coverage = _helpers(ROOT)
CONTRACT = _contract.CONTRACT
PARAMETERS = _contract.PARAMETERS
MACHINE_TRUTH = _contract.MACHINE_TRUTH
MODULE_COVERAGE = _coverage.COVERAGE
BASELINE_WORKFLOW = _workflows.BASELINE
WORKFLOW_ROOT = _workflows.WORKFLOWS
EXPECTED_DETAILED_SPECS = _contract.DETAILED_SPECS
EXPECTED_RUNTIME_GAPS = _contract.RUNTIME_GAPS
EXPECTED_PROHIBITED_WORKFLOWS = _workflows.PROHIBITED
OPTIONAL_MACHINE_FALSE = ("public_testnet_ready", "release_ready", "all_gaps_closed")
load_toml = _contract.load_toml


def main() -> int:
    print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConvergenceError as error:
        print(f"technical convergence validation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
