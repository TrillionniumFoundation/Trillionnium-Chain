#!/usr/bin/env python3
"""Fail-closed validation for the PoCO node composition decomposition."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib
from collections import defaultdict, deque
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config/node-decomposition-v1.toml"


class DecompositionError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DecompositionError(message)


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise DecompositionError(f"{path.relative_to(ROOT)}: invalid TOML: {error}") from error
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: table required")
    return value


def relative_file(value: Any, label: str) -> pathlib.Path:
    require(
        isinstance(value, str) and value and not value.startswith("/"),
        f"{label}: relative path required",
    )
    path = ROOT / value
    require(path.is_file(), f"{label}: missing file {value}")
    return path


def workspace_packages(manifest_path: pathlib.Path) -> dict[str, pathlib.Path]:
    workspace = load_toml(manifest_path)
    members = workspace.get("workspace", {}).get("members")
    require(isinstance(members, list) and members, "workspace members missing")
    root = manifest_path.parent.resolve()
    packages: dict[str, pathlib.Path] = {}
    for member in members:
        require(isinstance(member, str), "workspace member path must be a string")
        package_root = (root / member).resolve()
        require(package_root.is_relative_to(root), f"workspace member escapes root: {member}")
        manifest = package_root / "Cargo.toml"
        data = load_toml(manifest)
        name = data.get("package", {}).get("name")
        require(isinstance(name, str) and name, f"{manifest.relative_to(ROOT)}: package.name missing")
        require(name not in packages, f"duplicate package: {name}")
        packages[name] = manifest
    return packages


def local_runtime_dependencies(manifest: pathlib.Path) -> set[str]:
    data = load_toml(manifest)
    dependencies: set[str] = set()
    for section in ("dependencies", "build-dependencies"):
        table = data.get(section, {})
        require(isinstance(table, dict), f"{manifest.relative_to(ROOT)}: {section} table required")
        for alias, raw in table.items():
            if isinstance(raw, dict) and "path" in raw:
                package = raw.get("package", alias)
                require(isinstance(package, str), f"{manifest.relative_to(ROOT)}: invalid package alias")
                dependencies.add(package)
    return dependencies


def package_metadata(manifest: pathlib.Path) -> dict[str, Any]:
    value = load_toml(manifest).get("package", {}).get("metadata", {}).get("trnm", {})
    require(isinstance(value, dict), f"{manifest.relative_to(ROOT)}: package.metadata.trnm required")
    return value


def assert_acyclic(edges: set[tuple[str, str]], nodes: set[str]) -> None:
    graph: dict[str, list[str]] = defaultdict(list)
    for source, target in edges:
        graph[source].append(target)
    indegree = {node: 0 for node in nodes}
    for source in nodes:
        for target in graph[source]:
            require(target in nodes, f"unknown decomposition target: {target}")
            indegree[target] += 1
    queue = deque(sorted(node for node, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for target in graph[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    require(visited == len(nodes), "node decomposition runtime edges contain a cycle")


def require_source_contract(package_root: pathlib.Path, required: list[str], forbidden: list[str]) -> None:
    source_root = package_root / "src"
    require(source_root.is_dir(), f"{package_root.relative_to(ROOT)}: src directory missing")
    sources = sorted(source_root.glob("*.rs"))
    require(sources, f"{package_root.relative_to(ROOT)}: Rust source missing")
    text = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    for token in required:
        require(token in text, f"{package_root.relative_to(ROOT)}: required source contract missing: {token}")
    for token in forbidden:
        require(token not in text, f"{package_root.relative_to(ROOT)}: forbidden source token: {token}")


def main() -> int:
    config = load_toml(CONFIG)
    require(config.get("schema_version") == 1, "node decomposition schema drift")
    require(
        config.get("decomposition_id") == "trnm-poco-node-decomposition-v1",
        "node decomposition ID drift",
    )
    for key in ("production_candidate", "production_consensus_activation", "release_ready"):
        require(config.get(key) is False, f"node decomposition promoted {key}")

    workspace_manifest = relative_file(config.get("workspace_manifest"), "workspace manifest")
    packages = workspace_packages(workspace_manifest)
    declared = config.get("packages")
    require(isinstance(declared, dict), "decomposition packages table missing")
    roles = {
        "component_library",
        "authority_boundary",
        "io_boundary",
        "host_composition",
        "cli_entrypoint",
        "lab_runtime",
    }
    require(set(declared) == roles, f"decomposition package roles drift: {sorted(declared)}")
    require(all(isinstance(value, str) and value in packages for value in declared.values()), "unknown decomposition package")
    require(len(set(declared.values())) == len(declared), "decomposition roles must use distinct packages")

    edge_rows = config.get("runtime_edges")
    require(isinstance(edge_rows, list), "runtime edge rows missing")
    expected_edges = {
        (declared["authority_boundary"], declared["component_library"]),
        (declared["host_composition"], declared["authority_boundary"]),
        (declared["host_composition"], declared["io_boundary"]),
        (declared["cli_entrypoint"], declared["host_composition"]),
    }
    configured_edges: set[tuple[str, str]] = set()
    for row in edge_rows:
        require(isinstance(row, dict), "runtime edge must be a table")
        source, target = row.get("from"), row.get("to")
        require(isinstance(source, str) and isinstance(target, str), "runtime edge endpoints required")
        require((source, target) not in configured_edges, f"duplicate runtime edge: {source}->{target}")
        configured_edges.add((source, target))
    require(configured_edges == expected_edges, f"runtime edge registry drift: {sorted(configured_edges)}")

    boundary_packages = {
        declared["component_library"],
        declared["authority_boundary"],
        declared["io_boundary"],
        declared["host_composition"],
        declared["cli_entrypoint"],
    }
    actual_edges: set[tuple[str, str]] = set()
    for package in boundary_packages:
        for dependency in local_runtime_dependencies(packages[package]):
            if dependency in boundary_packages:
                actual_edges.add((package, dependency))
    require(actual_edges == expected_edges, f"actual decomposition edge drift: {sorted(actual_edges)}")
    assert_acyclic(actual_edges, boundary_packages)

    expected_metadata = {
        declared["authority_boundary"]: {
            "composition_only": True,
            "domain_state_machine": False,
            "signing_authority": False,
            "voting_authority": False,
            "finality_authority": False,
        },
        declared["io_boundary"]: {
            "composition_only": True,
            "domain_state_machine": False,
            "network_listener": False,
            "state_sync_downloader": False,
            "rpc_listener": False,
        },
        declared["host_composition"]: {
            "composition_only": True,
            "domain_state_machine": False,
            "storage_owner": False,
            "network_owner": False,
            "signing_authority": False,
            "voting_authority": False,
            "finality_authority": False,
        },
        declared["cli_entrypoint"]: {
            "composition_only": True,
            "domain_state_machine": False,
            "production_entrypoint": True,
        },
    }
    for package, expected in expected_metadata.items():
        metadata = package_metadata(packages[package])
        for key, value in expected.items():
            require(metadata.get(key) is value, f"{package}: metadata drift for {key}")
        for key in ("production_candidate", "production_consensus_activation"):
            require(metadata.get(key) is False, f"{package}: promoted {key}")

    roots = {name: manifest.parent for name, manifest in packages.items()}
    require_source_contract(
        roots[declared["authority_boundary"]],
        ["NodeAuthorityCoordinatorV0", "production_activation_gate_v0"],
        ["SigningKey", "fn sign", "fn vote", "fn finalize"],
    )
    require_source_contract(
        roots[declared["io_boundary"]],
        ["NodeIoRuntimeV0", "REQUIRED_NODE_IO_SURFACES_V0"],
        ["std::net", "std::fs", "std::thread", "TcpListener", "UdpSocket"],
    )
    require_source_contract(
        roots[declared["host_composition"]],
        ["PocoNodeHostV0", "NodeHostStartBlockedV0"],
        ["trnm_consensus_", "rusqlite", "SigningKey", "TcpListener"],
    )
    require_source_contract(
        roots[declared["cli_entrypoint"]],
        ["NodeCliCommandV0", "run_v0"],
        ["trnm_poco_node::", "trnm_consensus_", "rusqlite", "SigningKey"],
    )

    build_closures_path = relative_file(config.get("build_closure_registry"), "build closure registry")
    build_closures = load_toml(build_closures_path)
    rows = build_closures.get("closures")
    require(isinstance(rows, list), "build closure rows missing")
    production = next((row for row in rows if row.get("id") == "node-prod-v0"), None)
    require(isinstance(production, dict), "node-prod-v0 closure missing")
    require(
        production.get("root_packages") == [declared["cli_entrypoint"]],
        "production closure must root at the dedicated CLI package",
    )
    required = production.get("required_packages")
    require(isinstance(required, list), "production required packages missing")
    for role in ("component_library", "authority_boundary", "io_boundary", "host_composition", "cli_entrypoint"):
        require(declared[role] in required, f"production closure omits {role}")
    require(declared["lab_runtime"] not in required, "lab runtime entered production required packages")

    policy = config.get("policy")
    require(isinstance(policy, dict), "decomposition policy missing")
    for key in (
        "composition_performs_wiring_only",
        "authority_boundary_has_no_sign_vote_finalize_api",
        "io_boundary_has_no_live_backend",
        "cli_has_no_direct_kernel_dependency",
        "lab_is_outside_production_closure",
        "candidate_features_are_outside_production_closure",
        "no_boundary_promotes_machine_truth",
    ):
        require(policy.get(key) is True, f"decomposition policy disabled: {key}")

    report = {
        "schema": "trnm-poco-node-decomposition-report-v1",
        "decomposition_id": config["decomposition_id"],
        "component_library": declared["component_library"],
        "authority_boundary": declared["authority_boundary"],
        "io_boundary": declared["io_boundary"],
        "host_composition": declared["host_composition"],
        "cli_entrypoint": declared["cli_entrypoint"],
        "lab_runtime": declared["lab_runtime"],
        "runtime_edges": sorted(f"{source}->{target}" for source, target in actual_edges),
        "composition_only": True,
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
    except DecompositionError as error:
        print(f"node decomposition failed: {error}", file=sys.stderr)
        raise SystemExit(2)
