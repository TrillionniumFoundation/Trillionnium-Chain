#!/usr/bin/env python3
"""Fail-closed M00-M17 source, documentation, ownership, and SLO coverage gate."""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib
from collections import Counter
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
COVERAGE = ROOT / "config/module-coverage-v1.toml"
REGISTRY = ROOT / "docs/development/module-registry-v1.toml"
REFERENCE = ROOT / "docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md"
CODEOWNERS = ROOT / ".github/CODEOWNERS"


class CoverageError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CoverageError(message)


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CoverageError(f"{path.relative_to(ROOT)}: invalid TOML: {error}") from error
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: table required")
    return value


def rows(value: dict[str, Any], singular: str, plural: str) -> list[dict[str, Any]]:
    candidate = value.get(singular, value.get(plural))
    require(isinstance(candidate, list), f"missing {plural}")
    require(all(isinstance(row, dict) for row in candidate), f"{plural}: object rows required")
    return candidate


def ensure_path(relative: str, label: str) -> pathlib.Path:
    require(isinstance(relative, str) and relative and not relative.startswith("/"), f"{label}: relative path required")
    path = ROOT / relative
    require(path.exists(), f"{label}: missing path {relative}")
    return path


def workspace_crates(manifest_relative: str) -> dict[str, str]:
    manifest = load_toml(ensure_path(manifest_relative, "workspace manifest"))
    members = manifest.get("workspace", {}).get("members")
    require(isinstance(members, list) and members, "workspace members missing")
    packages: dict[str, str] = {}
    for member in members:
        require(isinstance(member, str), "workspace member must be a path")
        member_path = (ROOT / "trillionnium" / member).resolve()
        require(member_path.is_relative_to(ROOT / "trillionnium"), f"workspace member escapes root: {member}")
        cargo = member_path / "Cargo.toml"
        data = load_toml(cargo)
        name = data.get("package", {}).get("name")
        require(isinstance(name, str) and name, f"{cargo.relative_to(ROOT)}: package name missing")
        require(name not in packages, f"duplicate workspace package name: {name}")
        packages[name] = str(member_path.relative_to(ROOT))
    return packages


def contract_crates(manifest_relative: str) -> dict[str, str]:
    manifest_path = ensure_path(manifest_relative, "contracts manifest")
    manifest = load_toml(manifest_path)
    members = manifest.get("workspace", {}).get("members")
    require(isinstance(members, list) and members, "contracts workspace members missing")
    packages: dict[str, str] = {}
    for member in members:
        require(isinstance(member, str), "contract member must be a path")
        cargo = manifest_path.parent / member / "Cargo.toml"
        data = load_toml(cargo)
        name = data.get("package", {}).get("name")
        require(isinstance(name, str) and name, f"{cargo.relative_to(ROOT)}: package name missing")
        packages[name] = str(cargo.parent.relative_to(ROOT))
    return packages


def assert_acyclic(graph: dict[str, list[str]]) -> None:
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in graph[node]:
            require(target in graph, f"{node}: unknown allowed dependency {target}")
            if state.get(target) == 1:
                start = stack.index(target)
                raise CoverageError("module dependency cycle: " + " -> ".join(stack[start:] + [target]))
            if state.get(target, 0) == 0:
                visit(target)
        stack.pop()
        state[node] = 2

    for node in graph:
        if state.get(node, 0) == 0:
            visit(node)


def main() -> int:
    coverage = load_toml(COVERAGE)
    registry = load_toml(REGISTRY)
    require(coverage.get("schema_version") == 1, "coverage schema drift")
    require(coverage.get("coverage_id") == "trnm-module-coverage-v1", "coverage id drift")
    require(coverage.get("plan_id") == "trnm-chain-development-plan-v2", "coverage plan id drift")
    require(coverage.get("production_authority") is False, "coverage cannot promote production")

    reference_path = ensure_path(coverage.get("technical_reference"), "technical reference")
    require(reference_path == REFERENCE, "technical reference path drift")
    reference_text = reference_path.read_text(encoding="utf-8")

    registry_rows = rows(registry, "module", "modules")
    coverage_rows = rows(coverage, "module_coverage", "module_coverage")
    expected_ids = [f"M{index:02d}" for index in range(18)]
    registry_ids = [row.get("id") for row in registry_rows]
    coverage_ids = [row.get("id") for row in coverage_rows]
    require(registry_ids == expected_ids, f"registry IDs drift: {registry_ids}")
    require(coverage_ids == expected_ids, f"coverage IDs drift: {coverage_ids}")

    registry_by_id = {row["id"]: row for row in registry_rows}
    coverage_by_id = {row["id"]: row for row in coverage_rows}
    allowed_slos = {
        "contract-library-v1",
        "authority-hot-path-v1",
        "bounded-io-runtime-v1",
        "candidate-application-v1",
        "non-authoritative-service-v1",
        "evidence-tooling-v1",
    }

    maintainers = coverage.get("maintainers")
    minimum = coverage.get("minimum_maintainers")
    require(isinstance(maintainers, list) and all(isinstance(item, str) and item for item in maintainers), "maintainers missing")
    require(isinstance(minimum, int) and minimum >= 2 and len(set(maintainers)) >= minimum, "two distinct maintainers required")
    codeowners = CODEOWNERS.read_text(encoding="utf-8")
    for maintainer in maintainers:
        require(f"@{maintainer}" in codeowners, f"maintainer absent from CODEOWNERS: {maintainer}")

    workspace = workspace_crates(coverage.get("workspace_manifest"))
    mapped: list[str] = []
    graph: dict[str, list[str]] = {}
    report_modules: list[dict[str, Any]] = []

    for module_id in expected_ids:
        registry_row = registry_by_id[module_id]
        row = coverage_by_id[module_id]
        require(re.fullmatch(r"m\d{2}", str(row.get("anchor"))) is not None, f"{module_id}: invalid anchor")
        require(row["anchor"] == module_id.lower(), f"{module_id}: anchor drift")
        require(re.search(rf"^## {module_id}\s+—", reference_text, re.MULTILINE) is not None, f"{module_id}: technical section missing")
        require(isinstance(row.get("slo_profile"), str) and row["slo_profile"] in allowed_slos, f"{module_id}: invalid SLO profile")
        require(isinstance(row.get("testkit_profile"), str) and row["testkit_profile"].endswith("-v1"), f"{module_id}: testkit profile missing")
        contracts = row.get("contract_paths")
        require(isinstance(contracts, list) and contracts, f"{module_id}: contract paths missing")
        for contract in contracts:
            ensure_path(contract, f"{module_id} contract")
        crates = row.get("primary_crates")
        require(isinstance(crates, list), f"{module_id}: primary_crates must be a list")
        for crate in crates:
            require(isinstance(crate, str) and crate in workspace, f"{module_id}: unknown workspace crate {crate!r}")
            mapped.append(crate)
            crate_root = ensure_path(workspace[crate], f"{module_id} crate")
            require((crate_root / "Cargo.toml").is_file(), f"{module_id}: Cargo.toml missing for {crate}")
        if not crates:
            source_paths = row.get("source_paths")
            require(isinstance(source_paths, list) and source_paths, f"{module_id}: crate-less module needs source_paths")
            for source in source_paths:
                ensure_path(source, f"{module_id} source")
        dependencies = registry_row.get("allowed_module_dependencies")
        require(isinstance(dependencies, list), f"{module_id}: allowed dependencies missing")
        graph[module_id] = dependencies
        require(isinstance(registry_row.get("owner_group"), str) and registry_row["owner_group"], f"{module_id}: owner group missing")
        forbidden = registry_row.get("forbidden_capabilities")
        require(isinstance(forbidden, list) and forbidden, f"{module_id}: forbidden capabilities missing")
        report_modules.append(
            {
                "id": module_id,
                "primary_crate_count": len(crates),
                "contract_count": len(contracts),
                "slo_profile": row["slo_profile"],
                "testkit_profile": row["testkit_profile"],
            }
        )

    duplicates = sorted(name for name, count in Counter(mapped).items() if count != 1)
    require(not duplicates, f"workspace crates do not have exactly one primary module: {duplicates}")
    require(set(mapped) == set(workspace), f"workspace mapping drift: missing={sorted(set(workspace)-set(mapped))} extra={sorted(set(mapped)-set(workspace))}")
    assert_acyclic(graph)

    auxiliary = rows(coverage, "auxiliary_unit", "auxiliary_units")
    auxiliary_ids: set[str] = set()
    auxiliary_paths: dict[str, str] = {}
    for row in auxiliary:
        unit_id = row.get("id")
        module_id = row.get("primary_module")
        path = row.get("path")
        require(isinstance(unit_id, str) and unit_id not in auxiliary_ids, f"duplicate auxiliary unit: {unit_id!r}")
        auxiliary_ids.add(unit_id)
        require(module_id in expected_ids, f"{unit_id}: unknown primary module {module_id}")
        ensure_path(path, f"{unit_id} path")
        require(path not in auxiliary_paths, f"auxiliary path mapped twice: {path}")
        auxiliary_paths[path] = module_id

    contracts = contract_crates(coverage.get("contracts_manifest"))
    missing_contracts = sorted(set(contracts.values()) - set(auxiliary_paths))
    require(not missing_contracts, f"contract crates missing auxiliary mapping: {missing_contracts}")
    web_manifest = ensure_path(coverage.get("web_package_manifest"), "web package manifest")
    require(str(web_manifest.parent.relative_to(ROOT)) in auxiliary_paths, "Web4 package missing auxiliary mapping")

    policy = coverage.get("policy")
    require(isinstance(policy, dict), "coverage policy missing")
    for key in (
        "one_primary_module_per_workspace_crate",
        "one_primary_module_per_auxiliary_unit",
        "all_modules_require_technical_reference",
        "all_modules_require_slo_profile",
        "all_modules_require_testkit_profile",
        "all_modules_require_contract_paths",
        "all_modules_require_evidence_roots",
        "module_dependency_graph_must_be_acyclic",
    ):
        require(policy.get(key) is True, f"coverage policy disabled: {key}")
    require(policy.get("production_may_depend_on_candidate_or_lab") is False, "production contamination policy drift")
    require(policy.get("control_plane_may_hold_consensus_authority") is False, "control-plane authority policy drift")

    report = {
        "schema": "trnm-module-coverage-report-v1",
        "coverage_id": coverage["coverage_id"],
        "module_count": len(expected_ids),
        "workspace_crate_count": len(workspace),
        "mapped_workspace_crate_count": len(mapped),
        "auxiliary_unit_count": len(auxiliary),
        "maintainer_count": len(set(maintainers)),
        "module_dependency_graph_acyclic": True,
        "modules": report_modules,
        "production_authority": False,
        "result": "PASS",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CoverageError as error:
        print(f"module coverage failed: {error}", file=sys.stderr)
        raise SystemExit(2)
