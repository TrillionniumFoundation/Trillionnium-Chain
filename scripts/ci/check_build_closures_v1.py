#!/usr/bin/env python3
"""Resolve local Cargo feature closures and reject production contamination."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "config/build-closures-v1.toml"


class ClosureError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ClosureError(message)


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ClosureError(f"{path.relative_to(ROOT)}: invalid TOML: {error}") from error
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: table required")
    return value


def relative_path(value: Any, label: str) -> pathlib.Path:
    require(isinstance(value, str) and value and not value.startswith("/"), f"{label}: relative path required")
    path = ROOT / value
    require(path.is_file(), f"{label}: missing file {value}")
    return path


@dataclass(frozen=True)
class Dependency:
    alias: str
    package: str
    optional: bool
    default_features: bool
    features: tuple[str, ...]


@dataclass
class Package:
    name: str
    manifest: pathlib.Path
    features: dict[str, list[str]]
    dependencies: dict[str, Dependency]
    all_dependencies: dict[str, bool]


def workspace_packages(manifest_path: pathlib.Path) -> dict[str, Package]:
    workspace = load_toml(manifest_path)
    members = workspace.get("workspace", {}).get("members")
    require(isinstance(members, list) and members, "workspace members missing")
    packages: dict[str, Package] = {}
    workspace_root = manifest_path.parent
    for member in members:
        require(isinstance(member, str), "workspace member path must be a string")
        member_root = (workspace_root / member).resolve()
        require(member_root.is_relative_to(workspace_root.resolve()), f"workspace member escapes root: {member}")
        manifest = member_root / "Cargo.toml"
        data = load_toml(manifest)
        name = data.get("package", {}).get("name")
        require(isinstance(name, str) and name, f"{manifest.relative_to(ROOT)}: package.name missing")
        require(name not in packages, f"duplicate package: {name}")
        feature_table = data.get("features", {})
        require(isinstance(feature_table, dict), f"{name}: features must be a table")
        features: dict[str, list[str]] = {}
        for feature, values in feature_table.items():
            require(isinstance(feature, str) and isinstance(values, list), f"{name}: invalid feature {feature!r}")
            require(all(isinstance(item, str) for item in values), f"{name}/{feature}: string feature items required")
            features[feature] = list(values)
        dependencies: dict[str, Dependency] = {}
        all_dependencies: dict[str, bool] = {}
        for section in ("dependencies", "build-dependencies"):
            table = data.get(section, {})
            require(isinstance(table, dict), f"{name}: {section} must be a table")
            for alias, raw in table.items():
                optional = isinstance(raw, dict) and bool(raw.get("optional", False))
                all_dependencies[alias] = optional
                if not isinstance(raw, dict) or "path" not in raw:
                    continue
                package = raw.get("package", alias)
                require(isinstance(package, str), f"{name}: invalid local dependency {alias}")
                raw_features = raw.get("features", [])
                require(isinstance(raw_features, list) and all(isinstance(item, str) for item in raw_features), f"{name}->{alias}: invalid feature list")
                dependencies[alias] = Dependency(
                    alias=alias,
                    package=package,
                    optional=bool(raw.get("optional", False)),
                    default_features=bool(raw.get("default-features", True)),
                    features=tuple(raw_features),
                )
        packages[name] = Package(name, manifest, features, dependencies, all_dependencies)
    for package in packages.values():
        for dependency in package.dependencies.values():
            require(dependency.package in packages, f"{package.name}: local dependency missing from workspace: {dependency.package}")
    return packages


def expand_features(package: Package, requested: set[str], include_default: bool) -> tuple[set[str], set[str], dict[str, set[str]]]:
    active = set(requested)
    if include_default and "default" in package.features:
        active.add("default")
    queue = deque(active)
    activated_dependencies: set[str] = set()
    dependency_features: dict[str, set[str]] = defaultdict(set)
    while queue:
        feature = queue.popleft()
        values = package.features.get(feature, [])
        for value in values:
            if value.startswith("dep:"):
                alias = value[4:]
                require(alias in package.all_dependencies, f"{package.name}/{feature}: unknown dependency {alias}")
                if alias in package.dependencies:
                    activated_dependencies.add(alias)
                continue
            if "/" in value:
                alias, child_feature = value.split("/", 1)
                optional_forward = alias.endswith("?")
                alias = alias.removesuffix("?")
                require(alias in package.all_dependencies, f"{package.name}/{feature}: unknown dependency feature target {alias}")
                if alias in package.dependencies:
                    if not optional_forward:
                        activated_dependencies.add(alias)
                    dependency_features[alias].add(child_feature)
                continue
            if value in package.features:
                if value not in active:
                    active.add(value)
                    queue.append(value)
                continue
            if value in package.all_dependencies and package.all_dependencies[value]:
                if value in package.dependencies:
                    activated_dependencies.add(value)
                continue
            raise ClosureError(f"{package.name}/{feature}: unknown feature token {value}")
    return active, activated_dependencies, dependency_features


def resolve_closure(packages: dict[str, Package], roots: list[str], root_features: set[str], root_default: bool) -> tuple[set[str], dict[str, set[str]]]:
    for root in roots:
        require(root in packages, f"unknown root package: {root}")
    requested: dict[str, set[str]] = defaultdict(set)
    default_enabled: dict[str, bool] = defaultdict(bool)
    for root in roots:
        requested[root].update(root_features)
        default_enabled[root] = root_default
    queue = deque(roots)
    queued = set(roots)
    resolved_feature_state: dict[str, tuple[frozenset[str], bool]] = {}
    reached: set[str] = set()
    active_features: dict[str, set[str]] = defaultdict(set)
    while queue:
        name = queue.popleft()
        queued.discard(name)
        package = packages[name]
        features, activated_optional, forwarded = expand_features(
            package, requested[name], default_enabled[name]
        )
        state = (frozenset(features), default_enabled[name])
        if resolved_feature_state.get(name) == state and name in reached:
            continue
        resolved_feature_state[name] = state
        reached.add(name)
        active_features[name] = features
        for alias, dependency in package.dependencies.items():
            if dependency.optional and alias not in activated_optional:
                continue
            child = dependency.package
            before = (frozenset(requested[child]), default_enabled[child])
            requested[child].update(dependency.features)
            requested[child].update(forwarded.get(alias, set()))
            default_enabled[child] = default_enabled[child] or dependency.default_features
            after = (frozenset(requested[child]), default_enabled[child])
            if child not in reached or after != before:
                if child not in queued:
                    queue.append(child)
                    queued.add(child)
    return reached, active_features


def validate_persistent_authority_boundary(
    packages: dict[str, Package], production_reached: set[str]
) -> set[str]:
    candidate_adapter = "trnm-durable-file-adapters-v0"
    require(candidate_adapter not in production_reached,
            "production closure contains the candidate durable file adapter")
    candidate_reached, _ = resolve_closure(
        packages, ["trnm-poco-node-host"], {"persistent-authority-candidate"}, False
    )
    require(candidate_adapter in candidate_reached,
            "explicit persistent candidate feature lost its real domain owner")

    return candidate_reached


def group_sets(config: dict[str, Any]) -> dict[str, set[str]]:
    mapping = {
        "ai-v1-candidate": "ai_v1_candidate_packages",
        "lab": "lab_packages",
        "evidence": "evidence_packages",
        "poc": "poc_packages",
        "legacy": "legacy_excluded_packages",
    }
    groups: dict[str, set[str]] = {}
    for group, key in mapping.items():
        values = config.get(key)
        require(isinstance(values, list) and all(isinstance(item, str) for item in values), f"{key}: string list required")
        groups[group] = set(values)
    return groups


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve and verify fail-closed Trillionnium build closures."
    )
    parser.add_argument(
        "--verify-cargo-tree",
        action="store_true",
        help="compare the static resolver with Cargo's locked offline dependency tree",
    )
    return parser.parse_args()


def cargo_tree_workspace_packages(
    workspace_manifest: pathlib.Path,
    roots: list[str],
    features: list[str],
    default_features: bool,
    workspace_names: set[str],
) -> set[str]:
    reached: set[str] = set()
    for root in roots:
        command = [
            "cargo",
            "tree",
            "--manifest-path",
            str(workspace_manifest),
            "--package",
            root,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--no-dedupe",
            "--locked",
            "--offline",
        ]
        if not default_features:
            command.append("--no-default-features")
        if features:
            command.extend(["--features", ",".join(features)])
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as error:
            raise ClosureError("cargo is unavailable for --verify-cargo-tree") from error
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or error.stdout or "cargo tree failed").strip()
            raise ClosureError(f"cargo tree failed for {root}: {detail}") from error
        for line in completed.stdout.splitlines():
            match = re.match(r"^([A-Za-z0-9_-]+)\s+v[0-9]", line.strip())
            if match and match.group(1) in workspace_names:
                reached.add(match.group(1))
    return reached


def main() -> int:
    args = parse_args()
    config = load_toml(CONFIG_PATH)
    require(config.get("schema_version") == 1, "build closure schema drift")
    require(config.get("closure_registry_id") == "trnm-build-closures-v1", "build closure ID drift")
    for key in ("production_candidate", "production_consensus_activation", "release_ready"):
        require(config.get(key) is False, f"build closure config promoted {key}")
    workspace_manifest = relative_path(config.get("workspace_manifest"), "workspace manifest")
    packages = workspace_packages(workspace_manifest)
    node_manifest_path = relative_path(config.get("node_manifest"), "node manifest")
    node_manifest = load_toml(node_manifest_path)
    require(node_manifest.get("package", {}).get("name") == "trnm-poco-node", "node manifest package drift")
    groups = group_sets(config)
    for group, names in groups.items():
        if group == "legacy":
            for name in names:
                require(name not in packages, f"legacy package entered active workspace: {name}")
        else:
            missing = sorted(names - set(packages))
            require(not missing, f"{group}: missing classified packages: {missing}")

    candidate_feature = node_manifest.get("features", {}).get("ai-v1-candidate")
    expected_candidate_feature = [f"dep:{name}" for name in config["ai_v1_candidate_packages"]]
    require(candidate_feature == expected_candidate_feature, "node ai-v1-candidate feature drift")
    node_dependencies = node_manifest.get("dependencies", {})
    for name in config["ai_v1_candidate_packages"]:
        row = node_dependencies.get(name)
        require(isinstance(row, dict), f"node candidate dependency missing: {name}")
        require(row.get("optional") is True, f"node candidate dependency is not optional: {name}")
    require(node_manifest.get("features", {}).get("default", []) == [], "node default feature set must be empty")
    metadata = node_manifest.get("package", {}).get("metadata", {}).get("trnm", {})
    require(metadata.get("poco_ai_v1_default_dependency_closure") is False, "node default candidate-closure claim drift")
    require(metadata.get("poco_ai_v1_candidate_dependency_feature") == "ai-v1-candidate", "node candidate feature metadata drift")

    node_lib = (node_manifest_path.parent / "src/lib.rs").read_text(encoding="utf-8")
    node_main = (node_manifest_path.parent / "src/main.rs").read_text(encoding="utf-8")
    for module in (
        "cross_plane_checkpoint_v1",
        "g2_manifest_bound_process_v2",
        "g2_manifest_bound_v2",
        "g2_order_commit_v1",
    ):
        marker = f'#[cfg(feature = "ai-v1-candidate")]'
        position = node_lib.find(f"mod {module};")
        require(position >= 0, f"node candidate module missing: {module}")
        prefix = node_lib[max(0, position - 120):position]
        require(marker in prefix, f"node candidate module not feature-gated: {module}")
    require('cfg(not(feature = "ai-v1-candidate"))' in node_main, "default candidate-command refusal missing")
    require("rebuild explicitly with --features ai-v1-candidate" in node_main, "candidate command feature guidance missing")
    tests = node_manifest.get("test", [])
    target = [row for row in tests if row.get("name") == "g2_manifest_bound_process_v2"]
    require(target == [{
        "name": "g2_manifest_bound_process_v2",
        "path": "tests/g2_manifest_bound_process_v2.rs",
        "required-features": ["ai-v1-candidate"],
    }], "G2 process test feature boundary drift")

    closures = config.get("closures")
    require(isinstance(closures, list) and closures, "closure rows missing")
    ids: set[str] = set()
    report_rows: list[dict[str, Any]] = []
    reached_by_id: dict[str, set[str]] = {}
    for row in closures:
        require(isinstance(row, dict), "closure row must be a table")
        closure_id = row.get("id")
        require(isinstance(closure_id, str) and closure_id not in ids, f"duplicate/invalid closure id: {closure_id!r}")
        ids.add(closure_id)
        roots = row.get("root_packages")
        features = row.get("features")
        require(isinstance(roots, list) and roots and all(isinstance(item, str) for item in roots), f"{closure_id}: roots missing")
        require(isinstance(features, list) and all(isinstance(item, str) for item in features), f"{closure_id}: features invalid")
        reached, active = resolve_closure(
            packages,
            roots,
            set(features),
            bool(row.get("default_features", True)),
        )
        required_packages = row.get("required_packages", [])
        require(isinstance(required_packages, list), f"{closure_id}: required_packages invalid")
        missing_packages = sorted(set(required_packages) - reached)
        require(not missing_packages, f"{closure_id}: required packages absent: {missing_packages}")
        required_groups = row.get("required_groups", [])
        require(isinstance(required_groups, list), f"{closure_id}: required_groups invalid")
        for group in required_groups:
            require(group in groups, f"{closure_id}: unknown required group {group}")
            missing = sorted(groups[group] - reached)
            require(not missing, f"{closure_id}: required group {group} absent: {missing}")
        forbidden_groups = row.get("forbidden_groups", [])
        require(isinstance(forbidden_groups, list), f"{closure_id}: forbidden_groups invalid")
        violations: dict[str, list[str]] = {}
        for group in forbidden_groups:
            require(group in groups, f"{closure_id}: unknown forbidden group {group}")
            overlap = sorted(groups[group] & reached)
            if overlap:
                violations[group] = overlap
        require(not violations, f"{closure_id}: forbidden packages reached: {violations}")
        for package_name in reached:
            package_meta = load_toml(packages[package_name].manifest).get("package", {}).get("metadata", {}).get("trnm", {})
            for key in ("production_candidate", "production_consensus_activation", "activation"):
                if key in package_meta:
                    require(package_meta[key] is False, f"{closure_id}/{package_name}: {key} promoted")
        reached_by_id[closure_id] = reached
        report_rows.append({
            "id": closure_id,
            "root_packages": roots,
            "root_features": sorted(features),
            "resolved_package_count": len(reached),
            "resolved_packages": sorted(reached),
            "authority": row.get("authority"),
        })

    require(ids == {"node-prod-v0", "node-devnet-v0", "ai-v1-candidate", "lab-and-evidence"}, f"closure IDs drift: {sorted(ids)}")
    production = next(row for row in report_rows if row["id"] == "node-prod-v0")
    require(not (set(production["resolved_packages"]) & groups["ai-v1-candidate"]), "production closure contains AI-v1 candidate")

    candidate_reached = validate_persistent_authority_boundary(packages, reached_by_id["node-prod-v0"])

    if args.verify_cargo_tree:
        workspace_names = set(packages)
        candidate_cargo = cargo_tree_workspace_packages(
            workspace_manifest, ["trnm-poco-node-host"],
            ["persistent-authority-candidate"], False, workspace_names,
        )
        require(candidate_cargo == candidate_reached,
                "persistent authority candidate Cargo/static closure mismatch")
        for row in closures:
            closure_id = row["id"]
            cargo_reached = cargo_tree_workspace_packages(
                workspace_manifest,
                row["root_packages"],
                row["features"],
                bool(row.get("default_features", True)),
                workspace_names,
            )
            static_reached = reached_by_id[closure_id]
            require(
                cargo_reached == static_reached,
                f"{closure_id}: Cargo/static closure mismatch "
                f"missing_from_cargo={sorted(static_reached - cargo_reached)} "
                f"extra_from_cargo={sorted(cargo_reached - static_reached)}",
            )

    policy = config.get("policy")
    require(isinstance(policy, dict), "build closure policy missing")
    for key, expected in {
        "default_node_has_no_ai_v1_dependencies": True,
        "candidate_commands_require_explicit_feature": True,
        "candidate_modules_require_explicit_feature": True,
        "production_has_no_lab_fixture_research_poc_or_legacy": True,
        "feature_resolution_is_recursive": True,
        "dev_dependencies_are_not_runtime_authority": True,
        "no_feature_silently_promotes_machine_truth": True,
    }.items():
        require(policy.get(key) is expected, f"build closure policy drift: {key}")

    report = {
        "schema": "trnm-build-closure-report-v1",
        "closure_registry_id": config["closure_registry_id"],
        "workspace_package_count": len(packages),
        "closure_count": len(report_rows),
        "closures": report_rows,
        "node_default_ai_v1_dependency_count": 0,
        "node_default_candidate_adapter_count": 0,
        "persistent_candidate_owner_reachable": True,
        "cargo_tree_verified": args.verify_cargo_tree,
        "production_candidate": False,
        "production_consensus_activation": False,
        "release_ready": False,
        "result": "PASS",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ClosureError as error:
        print(f"build closure failed: {error}", file=sys.stderr)
        raise SystemExit(2)
