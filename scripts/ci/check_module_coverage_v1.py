#!/usr/bin/env python3
"""Fail-closed M00-M17 source, documentation, ownership, SLO, and snapshot gate."""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib
from collections import Counter
from typing import Any

from module_coverage_guard_v1 import (
    ContractError, active_codeowners, dependency_graph, module_sections, repository_path,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
COVERAGE = ROOT / "config/module-coverage-v1.toml"
REGISTRY = ROOT / "docs/development/module-registry-v1.toml"
REFERENCE = ROOT / "docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md"
SNAPSHOT = ROOT / "docs/development/CURRENT_SNAPSHOT_V1.json"
CODEOWNERS = ROOT / ".github/CODEOWNERS"

TECHNICAL_REQUIRED_MARKERS = (
    "**Authority.**",
    "**Primary code.**",
    "**Verification.**",
    "SLO profile:",
)
TECHNICAL_CONTRACT_MARKERS = (
    "**Contract.**",
    "**State machine.**",
    "**Durability contract.**",
    "**Execution contract.**",
    "**Storage contract.**",
    "**Ledger contract.**",
    "**Plan contract.**",
    "**Composition contract.**",
    "**Evidence contract.**",
)


class CoverageError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CoverageError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoverageError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CoverageError(f"{path.relative_to(ROOT)}: invalid JSON: {error}") from error
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: object required")
    return value


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
    try:
        return repository_path(ROOT, relative, label)
    except ContractError as error:
        raise CoverageError(str(error)) from error


def workspace_crates(manifest_relative: str) -> dict[str, str]:
    manifest_path = ensure_path(manifest_relative, "workspace manifest")
    manifest = load_toml(manifest_path)
    members = manifest.get("workspace", {}).get("members")
    require(isinstance(members, list) and members, "workspace members missing")
    packages: dict[str, str] = {}
    for member in members:
        require(isinstance(member, str), "workspace member must be a path")
        try:
            member_path = repository_path(manifest_path.parent, member, "workspace member")
        except ContractError as error:
            raise CoverageError(str(error)) from error
        require(
            member_path.is_relative_to(manifest_path.parent),
            f"workspace member escapes root: {member}",
        )
        cargo = ensure_path(str((member_path / "Cargo.toml").relative_to(ROOT)), "workspace Cargo.toml")
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
        try:
            member_path = repository_path(manifest_path.parent, member, "contract member")
        except ContractError as error:
            raise CoverageError(str(error)) from error
        cargo = ensure_path(str((member_path / "Cargo.toml").relative_to(ROOT)), "contract Cargo.toml")
        data = load_toml(cargo)
        name = data.get("package", {}).get("name")
        require(isinstance(name, str) and name, f"{cargo.relative_to(ROOT)}: package name missing")
        require(name not in packages, f"duplicate contract package name: {name}")
        packages[name] = str(cargo.parent.relative_to(ROOT))
    return packages


def assert_acyclic(graph: dict[str, list[str]]) -> None:
    try:
        dependency_graph(graph)
    except ContractError as error:
        raise CoverageError(str(error)) from error


def technical_sections(reference_text: str) -> dict[str, str]:
    try:
        return module_sections(reference_text)
    except ContractError as error:
        raise CoverageError(str(error)) from error


def resolve_module_roots(
    coverage: dict[str, Any],
    row: dict[str, Any],
    key: str,
    default_key: str,
    module_id: str,
) -> list[str]:
    value = row.get(key)
    if value is None:
        value = coverage.get(default_key)
        if isinstance(value, str):
            value = [value]
    require(
        isinstance(value, list) and value and all(isinstance(item, str) and item for item in value),
        f"{module_id}: {key} missing and no valid {default_key}",
    )
    resolved = [ensure_path(relative, f"{module_id} {key}") for relative in value]
    require(len(set(resolved)) == len(resolved), f"{module_id}: duplicate or aliased {key}")
    return value


def main() -> int:
    coverage = load_toml(COVERAGE)
    registry = load_toml(REGISTRY)
    snapshot = load_json(SNAPSHOT)
    require(coverage.get("schema_version") == 1, "coverage schema drift")
    require(coverage.get("coverage_id") == "trnm-module-coverage-v1", "coverage id drift")
    require(coverage.get("plan_id") == "trnm-chain-development-plan-v2", "coverage plan id drift")
    require(coverage.get("production_authority") is False, "coverage cannot promote production")
    require(snapshot.get("schema") == "trnm-current-snapshot-v1", "snapshot schema drift")

    reference_path = ensure_path(coverage.get("technical_reference"), "technical reference")
    require(reference_path == REFERENCE, "technical reference path drift")
    reference_text = reference_path.read_text(encoding="utf-8")
    sections = technical_sections(reference_text)

    registry_rows = rows(registry, "module", "modules")
    coverage_rows = rows(coverage, "module_coverage", "module_coverage")
    expected_ids = [f"M{index:02d}" for index in range(18)]
    registry_ids = [row.get("id") for row in registry_rows]
    coverage_ids = [row.get("id") for row in coverage_rows]
    require(registry_ids == expected_ids, f"registry IDs drift: {registry_ids}")
    require(coverage_ids == expected_ids, f"coverage IDs drift: {coverage_ids}")
    require(sorted(sections) == expected_ids, f"technical section IDs drift: {sorted(sections)}")

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
    require(
        isinstance(maintainers, list)
        and all(isinstance(item, str) and item for item in maintainers),
        "maintainers missing",
    )
    require(
        isinstance(minimum, int) and minimum >= 2 and len(set(maintainers)) >= minimum,
        "two distinct maintainers required",
    )
    codeowners = active_codeowners(CODEOWNERS.read_text(encoding="utf-8"))
    for maintainer in maintainers:
        require(maintainer in codeowners, f"maintainer absent from CODEOWNERS: {maintainer}")

    workspace = workspace_crates(coverage.get("workspace_manifest"))
    mapped: list[str] = []
    documented_primary_crates: list[str] = []
    graph: dict[str, list[str]] = {}
    report_modules: list[dict[str, Any]] = []

    for module_id in expected_ids:
        registry_row = registry_by_id[module_id]
        row = coverage_by_id[module_id]
        section = sections[module_id]
        require(
            re.fullmatch(r"m\d{2}", str(row.get("anchor"))) is not None,
            f"{module_id}: invalid anchor",
        )
        require(row["anchor"] == module_id.lower(), f"{module_id}: anchor drift")
        require(len(section.encode("utf-8")) >= 700, f"{module_id}: technical section is too shallow")
        for marker in TECHNICAL_REQUIRED_MARKERS:
            require(marker in section, f"{module_id}: technical section missing marker {marker}")
        require(
            any(marker in section for marker in TECHNICAL_CONTRACT_MARKERS),
            f"{module_id}: technical section lacks an explicit contract/state-machine paragraph",
        )

        slo_profile = row.get("slo_profile")
        require(
            isinstance(slo_profile, str) and slo_profile in allowed_slos,
            f"{module_id}: invalid SLO profile",
        )
        require(
            f"`{slo_profile}`" in section,
            f"{module_id}: technical section does not bind declared SLO profile {slo_profile}",
        )
        require(
            isinstance(row.get("testkit_profile"), str)
            and row["testkit_profile"].endswith("-v1"),
            f"{module_id}: testkit profile missing",
        )

        contracts = row.get("contract_paths")
        require(isinstance(contracts, list) and contracts, f"{module_id}: contract paths missing")
        for contract in contracts:
            ensure_path(contract, f"{module_id} contract")

        test_roots = resolve_module_roots(
            coverage, row, "test_roots", "default_test_gate_root", module_id
        )
        evidence_roots = resolve_module_roots(
            coverage, row, "evidence_roots", "default_evidence_roots", module_id
        )

        crates = row.get("primary_crates")
        require(isinstance(crates, list), f"{module_id}: primary_crates must be a list")
        for crate in crates:
            require(
                isinstance(crate, str) and crate in workspace,
                f"{module_id}: unknown workspace crate {crate!r}",
            )
            require(
                f"`{crate}`" in section,
                f"{module_id}: primary crate is absent from its technical section: {crate}",
            )
            documented_primary_crates.append(crate)
            mapped.append(crate)
            crate_root = ensure_path(workspace[crate], f"{module_id} crate")
            require((crate_root / "Cargo.toml").is_file(), f"{module_id}: Cargo.toml missing for {crate}")
        if not crates:
            source_paths = row.get("source_paths")
            require(
                isinstance(source_paths, list) and source_paths,
                f"{module_id}: crate-less module needs source_paths",
            )
            for source in source_paths:
                ensure_path(source, f"{module_id} source")

        dependencies = registry_row.get("allowed_module_dependencies")
        require(isinstance(dependencies, list), f"{module_id}: allowed dependencies missing")
        graph[module_id] = dependencies
        require(
            isinstance(registry_row.get("owner_group"), str) and registry_row["owner_group"],
            f"{module_id}: owner group missing",
        )
        forbidden = registry_row.get("forbidden_capabilities")
        require(isinstance(forbidden, list) and forbidden, f"{module_id}: forbidden capabilities missing")

        report_modules.append(
            {
                "id": module_id,
                "primary_crate_count": len(crates),
                "contract_count": len(contracts),
                "test_root_count": len(test_roots),
                "evidence_root_count": len(evidence_roots),
                "technical_section_bytes": len(section.encode("utf-8")),
                "slo_profile": slo_profile,
                "testkit_profile": row["testkit_profile"],
                "test_roots_explicit": "test_roots" in row,
                "evidence_roots_explicit": "evidence_roots" in row,
            }
        )

    duplicates = sorted(name for name, count in Counter(mapped).items() if count != 1)
    require(not duplicates, f"workspace crates do not have exactly one primary module: {duplicates}")
    require(
        set(mapped) == set(workspace),
        f"workspace mapping drift: missing={sorted(set(workspace)-set(mapped))} "
        f"extra={sorted(set(mapped)-set(workspace))}",
    )
    require(
        set(documented_primary_crates) == set(workspace),
        "technical-reference primary crate inventory does not match workspace",
    )
    assert_acyclic(graph)

    auxiliary = rows(coverage, "auxiliary_unit", "auxiliary_units")
    auxiliary_ids: set[str] = set()
    auxiliary_paths: dict[str, str] = {}
    for row in auxiliary:
        unit_id = row.get("id")
        module_id = row.get("primary_module")
        path = row.get("path")
        require(
            isinstance(unit_id, str) and unit_id not in auxiliary_ids,
            f"duplicate auxiliary unit: {unit_id!r}",
        )
        auxiliary_ids.add(unit_id)
        require(module_id in expected_ids, f"{unit_id}: unknown primary module {module_id}")
        ensure_path(path, f"{unit_id} path")
        require(path not in auxiliary_paths, f"auxiliary path mapped twice: {path}")
        auxiliary_paths[path] = module_id

    contracts = contract_crates(coverage.get("contracts_manifest"))
    missing_contracts = sorted(set(contracts.values()) - set(auxiliary_paths))
    require(not missing_contracts, f"contract crates missing auxiliary mapping: {missing_contracts}")
    web_manifest = ensure_path(coverage.get("web_package_manifest"), "web package manifest")
    require(
        str(web_manifest.parent.relative_to(ROOT)) in auxiliary_paths,
        "Web4 package missing auxiliary mapping",
    )

    implementation = snapshot.get("repository_implementation")
    require(isinstance(implementation, dict), "snapshot repository_implementation missing")
    snapshot_coverage = implementation.get("module_coverage")
    require(isinstance(snapshot_coverage, dict), "snapshot module_coverage missing")
    require(
        snapshot_coverage.get("module_count") == len(expected_ids),
        "snapshot module_count does not match registry",
    )
    require(
        snapshot_coverage.get("workspace_crates_uniquely_mapped") == len(workspace),
        "snapshot workspace crate count does not match Cargo workspace",
    )
    require(
        snapshot_coverage.get("auxiliary_unit_count") == len(auxiliary),
        "snapshot auxiliary unit count does not match coverage manifest",
    )
    snapshot_auxiliary = snapshot_coverage.get("auxiliary_units_mapped")
    require(
        isinstance(snapshot_auxiliary, list)
        and sorted(snapshot_auxiliary) == sorted(auxiliary_ids),
        "snapshot auxiliary unit inventory does not match coverage manifest",
    )

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
    require(
        policy.get("production_may_depend_on_candidate_or_lab") is False,
        "production contamination policy drift",
    )
    require(
        policy.get("control_plane_may_hold_consensus_authority") is False,
        "control-plane authority policy drift",
    )

    report = {
        "schema": "trnm-module-coverage-report-v1",
        "coverage_id": coverage["coverage_id"],
        "module_count": len(expected_ids),
        "workspace_crate_count": len(workspace),
        "mapped_workspace_crate_count": len(mapped),
        "documented_primary_crate_count": len(documented_primary_crates),
        "auxiliary_unit_count": len(auxiliary),
        "snapshot_counts_match": True,
        "technical_sections_semantically_checked": False,
        "technical_sections_structurally_checked": True,
        "coverage_scope": "structural-source-ownership-only",
        "detailed_design_acceptance": "not-assessed",
        "implementation_acceptance": "not-assessed",
        "maintainer_scope": "repository-fallback-not-independent-review",
        "dependency_scope": "declared-graph-not-cargo-resolved",
        "primary_crate_names_bound_to_technical_sections": True,
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
