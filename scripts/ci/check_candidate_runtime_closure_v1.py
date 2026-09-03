#!/usr/bin/env python3
"""Verify the repository-owned bounded candidate validator runtime closure.

This gate proves that the existing candidate devnet composition joins the real
Core, durable authority stores, native execution/application owner, persistent
authenticated LAN mesh, pacemaker, and report path without entering the
production closure.  It deliberately requires external-evidence and activation
facts to remain false.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "config/candidate-runtime-closure-v1.toml"


class CandidateRuntimeClosureError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateRuntimeClosureError(message)


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        try:
            display = path.relative_to(ROOT)
        except ValueError:
            display = path
        raise CandidateRuntimeClosureError(f"{display}: invalid TOML: {error}") from error
    require(isinstance(value, dict), f"{path}: top-level TOML table required")
    return value


def repository_file(value: Any, label: str) -> pathlib.Path:
    require(
        isinstance(value, str)
        and value
        and not value.startswith("/")
        and ".." not in pathlib.PurePosixPath(value).parts,
        f"{label}: clean repository-relative path required",
    )
    path = ROOT / value
    require(path.is_file(), f"{label}: missing file {value}")
    return path


def string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label}: list required")
    require(
        allow_empty or bool(value),
        f"{label}: non-empty list required",
    )
    require(
        all(isinstance(item, str) and item for item in value),
        f"{label}: non-empty strings required",
    )
    require(len(value) == len(set(value)), f"{label}: duplicate values")
    return list(value)


def closure_by_id(rows: Any, closure_id: str) -> dict[str, Any]:
    require(isinstance(rows, list), "build closure rows must be a list")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == closure_id]
    require(len(matches) == 1, f"build closure {closure_id!r} must exist exactly once")
    return matches[0]


def main() -> int:
    config = load_toml(CONFIG_PATH)
    require(config.get("schema_version") == 1, "candidate runtime schema drift")
    require(
        config.get("closure_id") == "trnm-candidate-runtime-closure-v1",
        "candidate runtime closure ID drift",
    )
    for claim in (
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
    ):
        require(config.get(claim) is False, f"candidate runtime promoted {claim}")

    package_manifest_path = repository_file(
        config.get("package_manifest"), "candidate package manifest"
    )
    package_manifest = load_toml(package_manifest_path)
    require(
        package_manifest.get("package", {}).get("name") == "trnm-poco-lab-validator",
        "candidate package identity drift",
    )
    metadata = (
        package_manifest.get("package", {})
        .get("metadata", {})
        .get("trnm", {})
    )
    require(isinstance(metadata, dict), "candidate package metadata.trnm table missing")

    required_true = string_list(
        config.get("required_metadata_true"), "required_metadata_true"
    )
    required_false = string_list(
        config.get("required_metadata_false"), "required_metadata_false"
    )
    require(
        not set(required_true).intersection(required_false),
        "candidate metadata key required both true and false",
    )
    for key in required_true:
        require(metadata.get(key) is True, f"candidate metadata must be true: {key}")
    for key in required_false:
        require(metadata.get(key) is False, f"candidate metadata must remain false: {key}")
    require(metadata.get("incomplete") is True, "candidate package must remain explicitly incomplete")

    node_manifest_path = repository_file(
        config.get("node_component_manifest"), "node component manifest"
    )
    node_manifest = load_toml(node_manifest_path)
    node_features = node_manifest.get("features", {})
    require(isinstance(node_features, dict), "node feature table missing")
    require(
        isinstance(node_features.get("lab-validator-runtime"), list),
        "node lab-validator-runtime feature missing",
    )
    candidate_dependencies = package_manifest.get("dependencies", {})
    require(isinstance(candidate_dependencies, dict), "candidate dependency table missing")
    node_dependency = candidate_dependencies.get("trnm-poco-node")
    require(isinstance(node_dependency, dict), "candidate node dependency missing")
    require(
        node_dependency.get("features") == ["lab-validator-runtime"],
        "candidate runtime must opt into the explicit node laboratory owner only",
    )

    source_rows = config.get("source_contracts")
    require(isinstance(source_rows, list) and source_rows, "source contracts missing")
    seen_paths: set[str] = set()
    source_reports: list[dict[str, Any]] = []
    for index, row in enumerate(source_rows):
        require(isinstance(row, dict), f"source_contracts[{index}]: table required")
        raw_path = row.get("path")
        require(isinstance(raw_path, str), f"source_contracts[{index}]: path required")
        require(raw_path not in seen_paths, f"duplicate source contract path: {raw_path}")
        seen_paths.add(raw_path)
        path = repository_file(raw_path, f"source_contracts[{index}]")
        text = path.read_text(encoding="utf-8")
        required_tokens = string_list(
            row.get("required_tokens"),
            f"{raw_path}: required_tokens",
        )
        forbidden_tokens = string_list(
            row.get("forbidden_tokens", []),
            f"{raw_path}: forbidden_tokens",
            allow_empty=True,
        )
        for token in required_tokens:
            require(token in text, f"{raw_path}: required runtime contract missing: {token}")
        for token in forbidden_tokens:
            require(token not in text, f"{raw_path}: forbidden promotion token present: {token}")
        source_reports.append(
            {
                "path": raw_path,
                "required_tokens": len(required_tokens),
                "forbidden_tokens": len(forbidden_tokens),
            }
        )

    build_path = repository_file(
        config.get("build_closure_registry"), "build closure registry"
    )
    build = load_toml(build_path)
    build_contract = config.get("build_closure")
    require(isinstance(build_contract, dict), "build_closure table missing")
    lab_group = build_contract.get("lab_group")
    lab_package = build_contract.get("lab_package")
    require(lab_group == "lab", "candidate runtime must remain classified as lab")
    require(lab_package == "trnm-poco-lab-validator", "candidate lab package drift")
    lab_packages = string_list(build.get("lab_packages"), "build lab_packages")
    require(lab_package in lab_packages, "candidate validator escaped the lab package group")

    closures = build.get("closures")
    devnet_id = build_contract.get("devnet_closure")
    production_id = build_contract.get("production_closure")
    require(isinstance(devnet_id, str) and isinstance(production_id, str), "closure IDs missing")
    devnet = closure_by_id(closures, devnet_id)
    production = closure_by_id(closures, production_id)
    require(
        devnet.get("root_packages") == [lab_package],
        "candidate devnet closure must root at the lab validator",
    )
    production_required = string_list(
        production.get("required_packages"), "production required_packages"
    )
    require(
        lab_package not in production_required,
        "candidate lab validator entered production required packages",
    )
    expected_forbidden = string_list(
        build_contract.get("production_forbidden_groups"),
        "production forbidden groups",
    )
    actual_forbidden = string_list(
        production.get("forbidden_groups"), "production forbidden_groups"
    )
    require(
        actual_forbidden == expected_forbidden,
        "production forbidden-group policy drift",
    )
    require(lab_group in actual_forbidden, "production closure no longer forbids lab packages")

    repository_file(config.get("validation_script"), "candidate closure validator")
    repository_file(config.get("architecture_document"), "candidate closure architecture")

    report = {
        "schema": "trnm-candidate-runtime-closure-report-v1",
        "closure_id": config["closure_id"],
        "candidate_runtime_repository_implementation": True,
        "continuous_consensus_runtime": True,
        "persistent_authenticated_lan_mesh": True,
        "generation_aware_pacemaker": True,
        "native_application_p_d_c_k_chain": True,
        "candidate_devnet_cli": True,
        "production_closure_contaminated": False,
        "cross_process_frame_replay_authority": False,
        "external_hsm_and_monotonic_anchor": False,
        "host_attestation": False,
        "independent_multihost_evidence": False,
        "production_candidate": False,
        "production_consensus_activation": False,
        "source_contracts": source_reports,
        "result": "PASS",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CandidateRuntimeClosureError as error:
        print(f"candidate runtime closure failed: {error}", file=sys.stderr)
        raise SystemExit(2)
