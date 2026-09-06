#!/usr/bin/env python3
"""Bind module coverage to the exact convergence supplements."""
from __future__ import annotations

import pathlib
import tomllib
from typing import Callable

COVERAGE = pathlib.Path("config/module-coverage-v1.toml")
INDEX = "docs/modules/README.md"


def validate(root: pathlib.Path, specs: dict[str, str], require: Callable[[bool, str], None]) -> dict[str, object]:
    try:
        with (root / COVERAGE).open("rb") as handle:
            coverage = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"{COVERAGE}: {error}") from error
    require(coverage.get("technical_convergence") == "config/technical-convergence-v1.toml", "module coverage convergence binding drift")
    require(coverage.get("detailed_spec_index") == INDEX, "module coverage detailed index drift")
    require((root / INDEX).is_file(), "detailed specification index missing")
    policy = coverage.get("policy")
    require(isinstance(policy, dict) and policy.get("technical_convergence_must_remain_fail_closed") is True, "module coverage convergence policy disabled")
    rows = coverage.get("module_coverage")
    require(isinstance(rows, list), "module coverage rows missing")
    by_id = {row.get("id"): row for row in rows if isinstance(row, dict)}
    for module_id, relative in specs.items():
        row = by_id.get(module_id)
        require(isinstance(row, dict), f"{module_id}: module coverage row missing")
        contracts = row.get("contract_paths")
        require(isinstance(contracts, list) and relative in contracts, f"{module_id}: detailed specification not a contract path")
    return {
        "technical_convergence_bound": True,
        "detailed_spec_index_bound": True,
        "detailed_spec_contract_count": len(specs),
    }
