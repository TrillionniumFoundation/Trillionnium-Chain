#!/usr/bin/env python3
"""Fail-closed registry and dependency-closure checks for Plan-v2 blocker cores."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tomllib
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "config" / "repository-blocker-cores-v0.toml"
WORKSPACE_MANIFEST = ROOT / "trillionnium" / "Cargo.toml"
VALID_MODULES = {f"M{index:02d}" for index in range(18)}
AI_V1_CANDIDATE_DENYLIST = {
    "trnm-poco-cross-plane-readback-v1",
    "trnm-poco-agent-market-v1",
    "trnm-poco-consumption-settlement-v1",
    "trnm-poco-da-v1",
    "trnm-poco-global-execution-v1",
    "trnm-poco-mvcc-fee-v1",
    "trnm-poco-order-application-v1",
    "trnm-poco-order-finality-verifier-v1",
    "trnm-poco-order-state-v1",
    "trnm-poco-order-types-v1",
    "trnm-poco-verify-challenge-v1",
}


class RegistryFailure(RuntimeError):
    """Raised for a closed-world registry or dependency violation."""


@dataclass(frozen=True)
class RegistryEntry:
    name: str
    path: Path
    primary_module: str
    secondary_modules: tuple[str, ...]
    authority: str
    production_allowed: bool
    lab_fixture: bool
    owner: str
    technical_design: Path
    slo_class: str
    testkit: str
    failure_model: tuple[str, ...]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryFailure(message)


def nonempty_text(value: Any, field: str, name: str) -> str:
    require(isinstance(value, str) and value.strip() == value and bool(value), f"{name}: invalid {field}")
    return value


def load_registry(path: Path) -> tuple[dict[str, Any], list[RegistryEntry]]:
    require(path.is_file(), f"registry not found: {path}")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    require(data.get("schema_version") == 1, "unsupported registry schema_version")
    require(data.get("registry_id") == "trnm.repository-blocker-cores.v0", "unexpected registry_id")
    require(data.get("plan_id") == "trnm-chain-development-plan-v2", "unexpected plan_id")
    require(data.get("protocol") == "poco-bft-v0", "unexpected protocol")
    raw_entries = data.get("crate")
    require(isinstance(raw_entries, list) and raw_entries, "registry must contain [[crate]] entries")

    entries: list[RegistryEntry] = []
    seen_names: set[str] = set()
    seen_paths: set[Path] = set()
    for raw in raw_entries:
        require(isinstance(raw, dict), "each [[crate]] entry must be a table")
        name = nonempty_text(raw.get("name"), "name", "registry")
        rel_path = Path(nonempty_text(raw.get("path"), "path", name))
        primary = nonempty_text(raw.get("primary_module"), "primary_module", name)
        secondary_raw = raw.get("secondary_modules", [])
        require(
            isinstance(secondary_raw, list) and all(isinstance(item, str) for item in secondary_raw),
            f"{name}: secondary_modules must be an array of strings",
        )
        secondary = tuple(secondary_raw)
        authority = nonempty_text(raw.get("authority"), "authority", name)
        production_allowed = raw.get("production_allowed")
        lab_fixture = raw.get("lab_fixture")
        require(isinstance(production_allowed, bool), f"{name}: production_allowed must be boolean")
        require(isinstance(lab_fixture, bool), f"{name}: lab_fixture must be boolean")
        owner = nonempty_text(raw.get("owner"), "owner", name)
        technical_design = Path(nonempty_text(raw.get("technical_design"), "technical_design", name))
        slo_class = nonempty_text(raw.get("slo_class"), "slo_class", name)
        testkit = nonempty_text(raw.get("testkit"), "testkit", name)
        failure_raw = raw.get("failure_model")
        require(
            isinstance(failure_raw, list)
            and failure_raw
            and all(isinstance(item, str) and item for item in failure_raw),
            f"{name}: failure_model must be a non-empty string array",
        )
        failure_model = tuple(failure_raw)

        require(primary in VALID_MODULES, f"{name}: unknown primary module {primary}")
        require(len(set(secondary)) == len(secondary), f"{name}: duplicate secondary module")
        require(all(module in VALID_MODULES for module in secondary), f"{name}: unknown secondary module")
        require(primary not in secondary, f"{name}: primary module repeated as secondary")
        require(name not in seen_names, f"duplicate registry crate name: {name}")
        require(rel_path not in seen_paths, f"duplicate registry crate path: {rel_path}")
        require(not rel_path.is_absolute() and ".." not in rel_path.parts, f"{name}: path must stay within repository")
        require(
            not technical_design.is_absolute() and ".." not in technical_design.parts,
            f"{name}: technical_design must stay within repository",
        )
        if lab_fixture:
            require(not production_allowed, f"{name}: lab_fixture cannot be production_allowed")
        seen_names.add(name)
        seen_paths.add(rel_path)
        entries.append(
            RegistryEntry(
                name=name,
                path=rel_path,
                primary_module=primary,
                secondary_modules=secondary,
                authority=authority,
                production_allowed=production_allowed,
                lab_fixture=lab_fixture,
                owner=owner,
                technical_design=technical_design,
                slo_class=slo_class,
                testkit=testkit,
                failure_model=failure_model,
            )
        )
    return data, entries


def package_manifest(entry: RegistryEntry) -> dict[str, Any]:
    directory = ROOT / entry.path
    manifest_path = directory / "Cargo.toml"
    lib_path = directory / "src" / "lib.rs"
    require(directory.is_dir(), f"{entry.name}: crate directory missing")
    require(manifest_path.is_file(), f"{entry.name}: Cargo.toml missing")
    require(lib_path.is_file(), f"{entry.name}: src/lib.rs missing")
    lib_text = lib_path.read_text(encoding="utf-8")
    require("#![forbid(unsafe_code)]" in lib_text, f"{entry.name}: unsafe code is not forbidden")
    require("#[cfg(test)]" in lib_text, f"{entry.name}: crate has no in-crate conformance tests")

    design_path = ROOT / entry.technical_design
    require(design_path.is_file(), f"{entry.name}: technical design missing")
    design_text = design_path.read_text(encoding="utf-8")
    require(entry.name in design_text, f"{entry.name}: technical design does not name the crate")
    require("non-claim" in design_text.lower(), f"{entry.name}: technical design lacks explicit non-claims")

    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    package = manifest.get("package")
    require(isinstance(package, dict), f"{entry.name}: [package] table missing")
    require(package.get("name") == entry.name, f"{entry.name}: package name mismatch")
    metadata = package.get("metadata", {}).get("trnm", {})
    require(isinstance(metadata, dict), f"{entry.name}: [package.metadata.trnm] missing")
    require(metadata.get("module") == entry.primary_module, f"{entry.name}: primary module metadata mismatch")
    require(metadata.get("protocol") == "poco-bft-v0", f"{entry.name}: protocol metadata mismatch")
    require(metadata.get("production_allowed") is entry.production_allowed, f"{entry.name}: production classification mismatch")
    require(metadata.get("lab_fixture") is entry.lab_fixture, f"{entry.name}: lab classification mismatch")
    require(metadata.get("candidate_authority") is False, f"{entry.name}: candidate_authority must be false")
    nonempty_text(metadata.get("role"), "package.metadata.trnm.role", entry.name)

    declared_secondary: set[str] = set()
    one_secondary = metadata.get("secondary_module")
    if one_secondary is not None:
        require(isinstance(one_secondary, str), f"{entry.name}: secondary_module must be a string")
        declared_secondary.add(one_secondary)
    many_secondary = metadata.get("secondary_modules", [])
    require(
        isinstance(many_secondary, list) and all(isinstance(item, str) for item in many_secondary),
        f"{entry.name}: secondary_modules metadata must be an array of strings",
    )
    declared_secondary.update(many_secondary)
    require(
        declared_secondary.issubset(set(entry.secondary_modules)),
        f"{entry.name}: Cargo metadata declares secondary modules absent from registry",
    )
    return manifest


def cargo_metadata() -> dict[str, Any]:
    command = [
        "cargo",
        "metadata",
        "--manifest-path",
        str(WORKSPACE_MANIFEST),
        "--format-version",
        "1",
        "--locked",
    ]
    environment = os.environ.copy()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise RegistryFailure(
            "cargo metadata failed without mutating the lockfile:\n" + completed.stderr.strip()
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RegistryFailure(f"cargo metadata returned invalid JSON: {exc}") from exc


def dependency_closure(metadata: dict[str, Any], root_name: str) -> set[str]:
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    require(isinstance(packages, list), "cargo metadata packages missing")
    require(isinstance(resolve, dict), "cargo metadata resolve graph missing")
    id_to_name = {package["id"]: package["name"] for package in packages}
    name_to_id = {package["name"]: package["id"] for package in packages}
    require(root_name in name_to_id, f"production root absent from workspace: {root_name}")
    graph: dict[str, list[str]] = {}
    for node in resolve.get("nodes", []):
        graph[node["id"]] = [dependency["pkg"] for dependency in node.get("deps", [])]

    closure: set[str] = set()
    pending: deque[str] = deque([name_to_id[root_name]])
    while pending:
        package_id = pending.popleft()
        if package_id in closure:
            continue
        closure.add(package_id)
        pending.extend(graph.get(package_id, []))
    return {id_to_name[package_id] for package_id in closure if package_id in id_to_name}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    try:
        registry, entries = load_registry(args.registry)
        manifests = {entry.name: package_manifest(entry) for entry in entries}
        metadata = cargo_metadata()
        workspace_member_ids = set(metadata.get("workspace_members", []))
        packages_by_name = {package["name"]: package for package in metadata.get("packages", [])}
        for entry in entries:
            package = packages_by_name.get(entry.name)
            require(package is not None, f"{entry.name}: absent from cargo metadata")
            require(package["id"] in workspace_member_ids, f"{entry.name}: not a workspace member")
            manifest_path = Path(package["manifest_path"]).resolve()
            expected_manifest = (ROOT / entry.path / "Cargo.toml").resolve()
            require(manifest_path == expected_manifest, f"{entry.name}: cargo manifest path mismatch")

        production_root = nonempty_text(registry.get("production_root"), "production_root", "registry")
        entry_by_name = {entry.name: entry for entry in entries}
        require(production_root in entry_by_name, "production root not registered")
        require(entry_by_name[production_root].production_allowed, "production root is not production-allowed")
        closure = dependency_closure(metadata, production_root)
        require(not (closure & AI_V1_CANDIDATE_DENYLIST), "AI-v1 candidate dependency entered production root")
        require("trnm-production-adapter-conformance-v0" not in closure, "adapter testkit entered production root")
        for name in closure:
            entry = entry_by_name.get(name)
            if entry is not None:
                require(entry.production_allowed, f"non-production registered crate entered production root: {name}")
                require(not entry.lab_fixture, f"lab fixture entered production root: {name}")
            package = packages_by_name.get(name)
            if package is not None:
                metadata_trnm = package.get("metadata", {}).get("trnm", {})
                require(metadata_trnm.get("candidate_authority") is not True, f"candidate authority entered production root: {name}")
                require(metadata_trnm.get("lab_fixture") is not True, f"Cargo lab fixture entered production root: {name}")
                if metadata_trnm.get("production_allowed") is False:
                    raise RegistryFailure(f"Cargo metadata forbids production dependency: {name}")

        # Stronger isolation: no registered production crate may transitively
        # depend on a registered non-production or lab crate.
        for entry in entries:
            if not entry.production_allowed:
                continue
            entry_closure = dependency_closure(metadata, entry.name)
            for dependency_name in entry_closure:
                dependency_entry = entry_by_name.get(dependency_name)
                if dependency_entry is not None:
                    require(
                        dependency_entry.production_allowed and not dependency_entry.lab_fixture,
                        f"{entry.name}: transitive dependency on non-production crate {dependency_name}",
                    )

        summary = {
            "schema": "trnm.repository-blocker-registry-check.v0",
            "result": "pass",
            "registry_id": registry["registry_id"],
            "registered_crates": sorted(entry_by_name),
            "production_root": production_root,
            "production_closure": sorted(closure),
            "production_registered_crates": sorted(
                entry.name for entry in entries if entry.production_allowed
            ),
            "lab_crates": sorted(entry.name for entry in entries if entry.lab_fixture),
            "modules": sorted(
                {entry.primary_module for entry in entries}
                | {module for entry in entries for module in entry.secondary_modules}
            ),
        }
        rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0
    except RegistryFailure as exc:
        print(f"repository blocker registry check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
