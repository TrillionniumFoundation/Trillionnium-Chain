#!/usr/bin/env python3
"""Check the per-module implementation/transition/acceptance documentation.

This is a source-bound documentation gate.  It proves that every registered
module has an implementation symbol, a regression symbol, an explicit ordered
transition, and requirement IDs that agree with the main registry.  It never
executes the referenced tests and never promotes semantic or production
acceptance.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs/modules/TRNM_MODULE_IMPLEMENTATION_ACCEPTANCE_MATRIX_V1.md"
REGISTRY = ROOT / "config/documentation-contracts-v1.json"
MODULES = [f"M{i:02d}" for i in range(18)]
STATUS = "source-regression-open"


class MatrixError(ValueError):
    """A malformed or source-inconsistent matrix entry."""


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise MatrixError(detail)


def _blocks(text: str) -> list[tuple[str, str]]:
    matches = list(re.finditer(r"^### (M\d{2}) — [^\n]+$", text, re.MULTILINE))
    require(bool(matches), "matrix has no module headings")
    return [
        (match.group(1), text[match.start(): matches[index + 1].start() if index + 1 < len(matches) else len(text)])
        for index, match in enumerate(matches)
    ]


def _field(block: str, name: str) -> str:
    match = re.search(r"^- \*\*" + re.escape(name) + r":\*\* (.+)$", block, re.MULTILINE)
    require(match is not None, f"missing {name}")
    return match.group(1).strip()


def _source_ref(value: str, label: str) -> tuple[str, str]:
    match = re.fullmatch(r"`([^`]+)::([A-Za-z_][A-Za-z0-9_]*)`", value)
    require(match is not None, f"{label} must be path::symbol")
    path, symbol = match.groups()
    local = ROOT / path
    require(local.is_file(), f"{label} path does not exist: {path}")
    text = local.read_text(encoding="utf-8")
    # The registry intentionally uses function/test symbols.  This lexical
    # check is navigation evidence only, not a behavioral equivalence proof.
    pattern = r"(?m)^\s*(?:(?:pub(?:\([^)]*\))?|async|const|unsafe)\s+)*(?:fn|def)\s+" + re.escape(symbol) + r"\s*(?:[<(])"
    require(re.search(pattern, text) is not None, f"{label} symbol is not a function/definition: {path}::{symbol}")
    return path, symbol


def _requirements(value: str, module: str) -> list[str]:
    found = re.findall(r"`(" + re.escape(module) + r"-[A-Z][A-Z0-9-]*)`", value)
    require(found and len(found) == len(set(found)), f"{module} has no unique acceptance requirements")
    return found


def load_registry() -> dict[str, Any]:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    require(isinstance(data, dict) and isinstance(data.get("modules"), list), "registry modules missing")
    require([row.get("id") for row in data["modules"]] == MODULES, "registry module order drift")
    return data


def validate_matrix(text: str, registry: dict[str, Any]) -> dict[str, int | str]:
    blocks = _blocks(text)
    require([module for module, _ in blocks] == MODULES, "matrix must contain ordered M00-M17 headings exactly once")
    registry_rows = {row["id"]: row for row in registry["modules"]}
    requirement_count = 0
    for module, block in blocks:
        row = registry_rows[module]
        _source_ref(_field(block, "Implementation source"), module + " implementation")
        _source_ref(_field(block, "Regression source"), module + " regression")
        transition = _field(block, "State transition")
        states = transition.strip("`").split(" -> ")
        require(len(states) >= 2 and all(state.strip() for state in states),
                f"{module} state transition must name a source and target")
        requirements = _requirements(_field(block, "Acceptance requirements"), module)
        expected = row["requirement_ids"]
        require(requirements == expected, f"{module} acceptance requirements do not match registry")
        require(_field(block, "Acceptance status") == f"`{STATUS}`",
                f"{module} cannot claim an assessed/accepted status")
        # Presence is structural evidence only. Fixed prose cannot establish
        # completeness; acceptance remains explicitly open above.
        require(bool(_field(block, "Open evidence")), f"{module} must state residual evidence")
        requirement_count += len(requirements)
    return {"module_count": len(blocks), "requirement_count": requirement_count,
            "status": STATUS, "semantic_acceptance": "not-assessed",
            "implementation_acceptance": "not-assessed", "result": "PASS"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = validate_matrix(MATRIX.read_text(encoding="utf-8"), load_registry())
        if args.output:
            args.output.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, sort_keys=True))
        return 0
    except (MatrixError, OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"result": "FAIL", "error": str(error),
                          "semantic_acceptance": "not-assessed",
                          "implementation_acceptance": "not-assessed"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
