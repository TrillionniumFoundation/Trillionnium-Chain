#!/usr/bin/env python3
"""Validate the E1/T1/S1 supplemental operation design records.

This gate checks source and test identity only.  It deliberately cannot promote
semantic acceptance or production authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config/documentation-operations-supplement-v1.json"
CONTRACTS = ROOT / "config/documentation-contracts-v1.json"
COVERAGE = ROOT / "config/module-coverage-v1.toml"


class SupplementError(ValueError):
    pass


def fail(message: str) -> None:
    raise SupplementError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label}: expected keys {sorted(expected)!r}")
    return value


def nonempty_strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        fail(f"{label}: expected nonempty string list")
    return value


def read_relative(path: str, label: str) -> tuple[Path, str]:
    if not isinstance(path, str) or not path or Path(path).is_absolute():
        fail(f"{label}: absolute or empty path")
    resolved = (ROOT / path).resolve()
    if not resolved.is_relative_to(ROOT):
        fail(f"{label}: path escapes repository")
    if not resolved.is_file():
        fail(f"{label}: missing file {path}")
    return resolved, path


def has_definition(text: str, symbol: str) -> bool:
    if not isinstance(symbol, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
        return False
    return re.search(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+" + re.escape(symbol) + r"\s*\(", text) is not None


def function_region(text: str, symbol: str) -> str:
    match = re.search(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+" + re.escape(symbol) + r"\s*\(", text)
    if not match:
        fail(f"test function missing: {symbol}")
    tail = text[match.end():]
    next_fn = re.search(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", tail)
    return text[match.start():match.end() + (next_fn.start() if next_fn else len(tail))]


def validate(root_data: dict[str, Any] | None = None) -> dict[str, Any]:
    data = root_data if root_data is not None else json.loads(CONFIG.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    exact_keys(
        data,
        {"schema", "plan_id", "scope", "production_authority", "semantic_acceptance", "implementation_acceptance", "operations"},
        "supplement",
    )
    if data["schema"] != "trnm-documentation-operations-supplement-v1":
        fail("schema")
    if data["plan_id"] != "trnm-chain-development-plan-v2":
        fail("plan_id")
    if data["scope"] != "E1-cross-epoch-T1-public-transaction-state-sync-S1-incremental-storage":
        fail("scope")
    if data["production_authority"] is not False:
        fail("production_authority cannot promote")
    if data["semantic_acceptance"] != "not-assessed" or data["implementation_acceptance"] != "not-assessed":
        fail("acceptance fields cannot promote")
    operations = data["operations"]
    if not isinstance(operations, list) or not operations:
        fail("operations")

    contracts = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    modules = {row["id"]: row for row in contracts["modules"]}
    coverage = tomllib.loads(COVERAGE.read_text(encoding="utf-8"))
    owners = {crate: row["id"] for row in coverage["module_coverage"] for crate in row["primary_crates"]}
    identities: set[str] = set()
    cases_seen: set[str] = set()
    refs: set[str] = {"config/documentation-operations-supplement-v1.json", "docs/modules/TRNM_OPERATION_CLOSURE_SUPPLEMENT_V1.md"}
    recovery_count = 0
    workstreams: set[str] = set()
    for row in operations:
        exact_keys(
            row,
            {"id", "workstream", "module_id", "requirement_ids", "profile", "implementation", "normative_clauses", "schema_refs", "domain_refs", "limit_refs", "state", "errors", "producer_modules", "consumer_modules", "cases", "independent_vectors", "open_requirements"},
            "operation",
        )
        oid = row["id"]
        if not isinstance(oid, str) or oid in identities:
            fail(f"duplicate/invalid operation id: {oid}")
        identities.add(oid)
        mid = row["module_id"]
        if mid not in modules:
            fail(f"unknown module: {mid}")
        workstream = row["workstream"]
        if workstream not in {"E1", "T1", "S1"}:
            fail(f"unknown workstream: {workstream}")
        workstreams.add(workstream)
        requirements = nonempty_strings(row["requirement_ids"], oid + " requirement_ids")
        if not set(requirements) <= set(modules[mid]["requirement_ids"]):
            fail(f"foreign requirement in {oid}")
        if row["profile"] not in modules[mid]["profiles"]:
            fail(f"profile not owned by module in {oid}")
        impl = exact_keys(row["implementation"], {"package", "path", "symbol"}, oid + " implementation")
        if owners.get(impl["package"]) != mid:
            fail(f"implementation package owner mismatch in {oid}")
        if not impl["path"].startswith(f"trillionnium/crates/{impl['package']}/src/"):
            fail(f"implementation path outside package in {oid}")
        path, relative = read_relative(impl["path"], oid + " implementation")
        text = path.read_text(encoding="utf-8")
        if not has_definition(text, impl["symbol"]):
            fail(f"implementation symbol missing in {oid}: {impl['symbol']}")
        refs.add(relative)
        for clause in row["normative_clauses"]:
            clause = exact_keys(clause, {"path", "heading", "rule"}, oid + " clause")
            clause_path, clause_rel = read_relative(clause["path"], oid + " clause")
            if clause["heading"] not in clause_path.read_text(encoding="utf-8").splitlines():
                fail(f"normative heading missing in {oid}: {clause['heading']}")
            if not isinstance(clause["rule"], str) or not clause["rule"]:
                fail(f"empty normative rule in {oid}")
            refs.add(clause_rel)
        for field in ("schema_refs", "domain_refs", "limit_refs"):
            if not isinstance(row[field], list) or not row[field]:
                fail(f"empty {field} in {oid}")
            for reference in row[field]:
                reference = exact_keys(reference, {"path", "selector"}, oid + " reference")
                reference_path, reference_rel = read_relative(reference["path"], oid + " reference")
                if reference["selector"] not in reference_path.read_text(encoding="utf-8"):
                    fail(f"selector missing in {oid}: {reference['selector']}")
                refs.add(reference_rel)
        state = exact_keys(row["state"], {"authenticated_inputs", "preconditions", "accepted_effects", "rejected_effects", "uncertain_recovery", "publication"}, oid + " state")
        for field in state:
            nonempty_strings(state[field], oid + " state." + field)
        for error in row["errors"]:
            error = exact_keys(error, {"class", "reference", "meaning"}, oid + " error")
            if error["class"] not in {"reject", "unavailable", "uncertain", "halt"}:
                fail(f"unknown error class in {oid}")
            reference = exact_keys(error["reference"], {"path", "selector"}, oid + " error reference")
            error_path, error_rel = read_relative(reference["path"], oid + " error reference")
            if reference["selector"] not in error_path.read_text(encoding="utf-8"):
                fail(f"error selector missing in {oid}: {reference['selector']}")
            if not isinstance(error["meaning"], str) or not error["meaning"]:
                fail(f"empty error meaning in {oid}")
            refs.add(error_rel)
        for field in ("producer_modules", "consumer_modules"):
            if not set(nonempty_strings(row[field], oid + " " + field)) <= set(modules):
                fail(f"unknown module in {oid} {field}")
        vectors = exact_keys(row["independent_vectors"], {"status", "reason"}, oid + " vectors")
        if vectors["status"] != "open" or not isinstance(vectors["reason"], str) or not vectors["reason"]:
            fail(f"independent vector status in {oid}")
        nonempty_strings(row["open_requirements"], oid + " open_requirements")
        kinds: set[str] = set()
        for case in row["cases"]:
            case = exact_keys(case, {"id", "kind", "package", "source_path", "symbol", "target", "test_filter", "features", "expected_outcome", "assertion_fragments"}, oid + " case")
            cid = case["id"]
            if not isinstance(cid, str) or cid in cases_seen or not cid.startswith(oid + "-"):
                fail(f"case identity in {oid}")
            cases_seen.add(cid)
            if case["kind"] not in {"positive", "negative", "recovery"}:
                fail(f"case kind in {cid}")
            kinds.add(case["kind"])
            if owners.get(case["package"]) != mid:
                fail(f"case package owner mismatch in {cid}")
            case_path, case_rel = read_relative(case["source_path"], cid + " source")
            case_text = case_path.read_text(encoding="utf-8")
            if not has_definition(case_text, case["symbol"]):
                fail(f"case test symbol missing in {cid}: {case['symbol']}")
            region = function_region(case_text, case["symbol"])
            symbol_line = next(
                index for index, line in enumerate(case_text.splitlines()) if re.search(
                    r"\bfn\s+" + re.escape(case["symbol"]) + r"\s*\(", line
                )
            )
            if "#[test]" not in "\n".join(case_text.splitlines()[max(0, symbol_line - 4):symbol_line]):
                fail(f"case is not an attributed test in {cid}")
            if not isinstance(case["test_filter"], str) or case["symbol"] not in case["test_filter"]:
                fail(f"test filter does not bind symbol in {cid}")
            if not isinstance(case["features"], list) or not all(isinstance(feature, str) and feature for feature in case["features"]):
                fail(f"features in {cid}")
            if not isinstance(case["expected_outcome"], str) or not case["expected_outcome"]:
                fail(f"expected outcome in {cid}")
            for fragment in nonempty_strings(case["assertion_fragments"], cid + " assertions"):
                if fragment not in region:
                    fail(f"assertion fragment missing in {cid}: {fragment}")
            refs.add(case_rel)
            if case["kind"] == "recovery":
                recovery_count += 1
        if "positive" not in kinds or "negative" not in kinds:
            fail(f"positive/negative coverage missing in {oid}")
    if workstreams != {"E1", "T1", "S1"}:
        fail(f"workstream coverage is {sorted(workstreams)!r}")
    canonical = json.dumps(sorted(refs), separators=(",", ":")).encode()
    return {
        "schema": "trnm-documentation-integrity-supplement-report-v1",
        "result": "PASS",
        "operation_count": len(operations),
        "source_regression_case_count": len(cases_seen),
        "recovery_case_count": recovery_count,
        "workstreams": sorted(workstreams),
        "catalog_complete_for_declared_scope": True,
        "independent_golden_vector_count": 0,
        "semantic_acceptance": "not-assessed",
        "implementation_acceptance": "not-assessed",
        "production_authority": False,
        "reference_count": len(refs),
        "reference_set_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate()
    if args.output:
        if args.output.resolve().is_relative_to(ROOT):
            fail("report must be outside repository")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SupplementError, OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(json.dumps({"result": "FAIL", "detail": str(error)}))
        raise SystemExit(2)
