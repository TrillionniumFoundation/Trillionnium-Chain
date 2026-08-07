#!/usr/bin/env python3
"""Deterministic CycloneDX/provenance kernel for the Paper Raid Chain candidate."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import tomllib
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable


TARGETS = (
    {
        "artifact_id": "consensus_app",
        "package": "trnm-consensus-app",
        "binary": "trnm-cometbft-app",
        "cargo_profile": "debug",
        "features": (),
    },
    {
        "artifact_id": "chain_cli",
        "package": "trnm-node",
        "binary": "trnm-chain-cli",
        "cargo_profile": "debug",
        "features": ("legacy-harness",),
    },
    {
        "artifact_id": "receipt_v2",
        "package": "trnm-finality-verifier",
        "binary": "trnm-research-receipt-v2",
        "cargo_profile": "debug",
        "features": (),
    },
)

SBOM_NAME = "trillionnium-chain-paper-raid-debug-candidate"
SBOM_REF = "urn:trnm:paper-raid:chain-debug-candidate"
PROVENANCE_SCHEMA = "trnm.paper-raid.chain-debug-candidate-provenance.v1"
TOOL_VERSION = "1"


class EvidenceError(ValueError):
    """Fail-closed input or evidence error."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular(path: pathlib.Path) -> bytes:
    """Read one regular file once without following a final-component symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open regular non-symlink file {path}: {error}")
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            fail(f"input is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(read_regular(path))


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(
            read_regular(path).decode("utf-8"), object_pairs_hook=_unique_object
        )
    except UnicodeDecodeError as error:
        fail(f"JSON is not UTF-8: {path}: {error}")
    except json.JSONDecodeError as error:
        fail(f"invalid JSON: {path}: {error}")


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def require_canonical_json(path: pathlib.Path) -> Any:
    raw = read_regular(path)
    value = load_json(path)
    if raw != canonical_json(value):
        fail(f"JSON is not in canonical byte form: {path}")
    return value


def require_hex(value: str, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or any(
        char not in "0123456789abcdef" for char in value
    ):
        fail(f"{label} must be exactly {length} lowercase hexadecimal characters")
    return value


def require_source_root(path: pathlib.Path) -> pathlib.Path:
    if path.is_symlink():
        fail("source root symlink is forbidden")
    try:
        root = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve source root: {error}")
    if not root.is_dir():
        fail("source root is not a directory")
    for directory, names, files in os.walk(root, followlinks=False):
        base = pathlib.Path(directory)
        for name in [*names, *files]:
            candidate = base / name
            if candidate.is_symlink():
                fail(f"source symlink is forbidden: {candidate.relative_to(root)}")
    return root


def within(root: pathlib.Path, candidate: pathlib.Path, label: str) -> pathlib.Path:
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label}: {error}")
    try:
        resolved.relative_to(root)
    except ValueError:
        fail(f"{label} escapes source root: {resolved}")
    if candidate.is_symlink() or resolved.is_symlink():
        fail(f"{label} symlink is forbidden: {candidate}")
    return resolved


def property_list(values: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    pairs = sorted(values)
    if len(pairs) != len(set(pairs)):
        fail("duplicate property name/value pair")
    return [{"name": name, "value": value} for name, value in pairs]


def parse_component_lock(path: pathlib.Path) -> tuple[str, dict[str, Any]]:
    value = load_json(path)
    if not isinstance(value, dict):
        fail("Integration component lock root is not an object")
    components = value.get("components")
    if not isinstance(components, list):
        fail("Integration component lock has no components array")
    chain = [item for item in components if isinstance(item, dict) and item.get("component_id") == "canonical-chain"]
    if len(chain) != 1:
        fail("Integration component lock must contain exactly one canonical-chain component")
    live = chain[0].get("live_binaries")
    if not isinstance(live, list):
        fail("canonical-chain component has no live_binaries array")
    seen_artifacts: set[str] = set()
    seen_packages: set[str] = set()
    seen_binaries: set[str] = set()
    normalized: list[dict[str, str]] = []
    for item in live:
        if not isinstance(item, dict) or set(item) != {
            "artifact_id",
            "binary",
            "cargo_profile",
            "package",
        }:
            fail("Integration live binary field set differs")
        artifact = item.get("artifact_id")
        package = item.get("package")
        binary = item.get("binary")
        profile = item.get("cargo_profile")
        if not all(isinstance(entry, str) and entry for entry in (artifact, package, binary, profile)):
            fail("Integration live binary contains a blank or non-string field")
        if artifact in seen_artifacts or package in seen_packages or binary in seen_binaries:
            fail("Integration live binary identifiers, packages, and binary names must be unique")
        seen_artifacts.add(artifact)
        seen_packages.add(package)
        seen_binaries.add(binary)
        normalized.append(dict(item))
    expected = [
        {key: target[key] for key in ("artifact_id", "binary", "cargo_profile", "package")}
        for target in TARGETS
    ]
    if normalized != expected:
        fail("Integration canonical-chain live_binaries set/order differs from the Paper Raid contract")
    return sha256_file(path), chain[0]


@dataclass(frozen=True)
class CargoModel:
    packages: dict[str, dict[str, Any]]
    nodes: dict[str, dict[str, Any]]
    roots: dict[str, str]
    closure: frozenset[str]
    edges: dict[str, tuple[str, ...]]
    lock_entries: dict[tuple[str, str, str], dict[str, Any]]


def _load_lock(path: pathlib.Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    try:
        lock = tomllib.loads(read_regular(path).decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"invalid Cargo.lock: {error}")
    packages = lock.get("package")
    if not isinstance(packages, list):
        fail("Cargo.lock has no package array")
    entries: dict[tuple[str, str, str], dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            fail("Cargo.lock package is not an object")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source", "")
        if not all(isinstance(item, str) and item for item in (name, version)) or not isinstance(source, str):
            fail("Cargo.lock package identity is invalid")
        key = (name, version, source)
        if key in entries:
            fail(f"duplicate Cargo.lock package: {name} {version} {source}")
        entries[key] = package
    return entries


def _runtime_dependencies(node: dict[str, Any]) -> tuple[str, ...]:
    dependencies = node.get("deps")
    if not isinstance(dependencies, list):
        fail(f"cargo metadata node has no deps array: {node.get('id')!r}")
    result: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not isinstance(dependency.get("pkg"), str):
            fail("cargo metadata dependency is malformed")
        kinds = dependency.get("dep_kinds", [])
        if not isinstance(kinds, list):
            fail("cargo metadata dependency dep_kinds is malformed")
        include = not kinds
        for kind in kinds:
            if not isinstance(kind, dict):
                fail("cargo metadata dependency kind is malformed")
            if kind.get("kind") != "dev":
                include = True
        if include:
            result.add(dependency["pkg"])
    return tuple(sorted(result))


def cargo_model(metadata_path: pathlib.Path, lock_path: pathlib.Path) -> CargoModel:
    metadata = load_json(metadata_path)
    if not isinstance(metadata, dict) or metadata.get("version") != 1:
        fail("cargo metadata format version must be 1")
    package_values = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(package_values, list) or not isinstance(resolve, dict):
        fail("cargo metadata packages/resolve are missing")
    packages: dict[str, dict[str, Any]] = {}
    for package in package_values:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            fail("cargo metadata package is malformed")
        package_id = package["id"]
        if package_id in packages:
            fail(f"duplicate cargo metadata package id: {package_id}")
        packages[package_id] = package
    nodes: dict[str, dict[str, Any]] = {}
    node_values = resolve.get("nodes")
    if not isinstance(node_values, list):
        fail("cargo metadata resolve.nodes is missing")
    for node in node_values:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            fail("cargo metadata resolve node is malformed")
        node_id = node["id"]
        if node_id in nodes:
            fail(f"duplicate cargo metadata resolve node id: {node_id}")
        nodes[node_id] = node
    roots: dict[str, str] = {}
    for target in TARGETS:
        matches = [
            package_id
            for package_id, package in packages.items()
            if package.get("name") == target["package"]
        ]
        if len(matches) != 1:
            fail(f"cargo metadata must contain exactly one package named {target['package']}")
        package_id = matches[0]
        package_targets = packages[package_id].get("targets")
        if not isinstance(package_targets, list):
            fail(f"package {target['package']} has no targets array")
        binary_targets = [
            item
            for item in package_targets
            if isinstance(item, dict)
            and item.get("name") == target["binary"]
            and "bin" in item.get("kind", [])
        ]
        if len(binary_targets) != 1:
            fail(
                f"package {target['package']} must contain exactly one binary target {target['binary']}"
            )
        required = binary_targets[0].get("required-features", [])
        if sorted(required) != sorted(target["features"]):
            fail(f"binary {target['binary']} required-features differ")
        roots[target["package"]] = package_id

    closure: set[str] = set(roots.values())
    pending = list(closure)
    edges: dict[str, tuple[str, ...]] = {}
    while pending:
        package_id = pending.pop()
        if package_id not in packages:
            fail(f"dependency closure references missing package: {package_id}")
        if package_id not in nodes:
            fail(f"dependency closure references missing resolve node: {package_id}")
        dependencies = _runtime_dependencies(nodes[package_id])
        edges[package_id] = dependencies
        for dependency in dependencies:
            if dependency not in packages:
                fail(f"dependency closure references missing package: {dependency}")
            if dependency not in closure:
                closure.add(dependency)
                pending.append(dependency)

    lock_entries = _load_lock(lock_path)
    for package_id in closure:
        package = packages[package_id]
        name = package.get("name")
        version = package.get("version")
        source = package.get("source") or ""
        if not isinstance(name, str) or not isinstance(version, str) or not isinstance(source, str):
            fail(f"cargo metadata package identity is malformed: {package_id}")
        key = (name, version, source)
        if key not in lock_entries:
            fail(f"dependency closure package is missing from Cargo.lock: {name} {version} {source}")
        metadata_checksum = package.get("checksum")
        lock_checksum = lock_entries[key].get("checksum")
        if metadata_checksum != lock_checksum:
            fail(f"Cargo.lock checksum differs from cargo metadata for {name} {version}")
        if source and (
            not isinstance(lock_checksum, str)
            or len(lock_checksum) != 64
            or any(char not in "0123456789abcdef" for char in lock_checksum)
        ):
            fail(f"external package has no canonical Cargo.lock checksum: {name} {version}")
    return CargoModel(packages, nodes, roots, frozenset(closure), edges, lock_entries)


def _stable_package_identity(
    package_id: str, package: dict[str, Any], source_root: pathlib.Path
) -> str:
    """Remove extraction-root entropy from Cargo path package IDs."""
    if package.get("source"):
        return package_id
    name = package.get("name")
    version = package.get("version")
    manifest_value = package.get("manifest_path")
    if not all(isinstance(value, str) and value for value in (name, version, manifest_value)):
        fail(f"path package identity is malformed: {package_id}")
    manifest = within(
        source_root, pathlib.Path(manifest_value), f"manifest for path package {name}"
    )
    relative = manifest.relative_to(source_root).as_posix()
    return "path+trnm-source:///{manifest}#{name}@{version}".format(
        manifest=urllib.parse.quote(relative, safe="/"),
        name=urllib.parse.quote(name, safe=""),
        version=urllib.parse.quote(version, safe=""),
    )


def _package_ref(stable_identity: str) -> str:
    return "urn:trnm:cargo-package:" + hashlib.sha256(
        stable_identity.encode("utf-8")
    ).hexdigest()


def _package_component(
    package_id: str,
    stable_identity: str,
    package: dict[str, Any],
    source_root: pathlib.Path,
    model: CargoModel,
) -> dict[str, Any]:
    name = package["name"]
    version = package["version"]
    source = package.get("source") or "path"
    purl = "pkg:cargo/{name}@{version}".format(
        name=urllib.parse.quote(name, safe=""), version=urllib.parse.quote(version, safe="")
    )
    properties: list[tuple[str, str]] = [
        ("trnm:cargo-package-id", stable_identity),
        ("trnm:cargo-source", source),
    ]
    component: dict[str, Any] = {
        "bom-ref": _package_ref(stable_identity),
        "name": name,
        "purl": purl,
        "type": "application" if name in model.roots else "library",
        "version": version,
    }
    lock = model.lock_entries[(name, version, package.get("source") or "")]
    checksum = lock.get("checksum")
    if checksum:
        component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        properties.append(("trnm:cargo-lock-checksum", f"sha256:{checksum}"))

    manifest_value = package.get("manifest_path")
    if not isinstance(manifest_value, str):
        fail(f"package manifest_path is missing: {package_id}")
    manifest_candidate = pathlib.Path(manifest_value)
    if not package.get("source"):
        manifest = within(source_root, manifest_candidate, f"manifest for {name}")
        if not manifest.is_file():
            fail(f"package manifest is not a regular file: {manifest}")
        relative = manifest.relative_to(source_root).as_posix()
        properties.extend(
            [
                ("trnm:manifest:path", relative),
                ("trnm:manifest:sha256", f"sha256:{sha256_file(manifest)}"),
            ]
        )
        targets = package.get("targets")
        if not isinstance(targets, list):
            fail(f"package targets are missing: {name}")
        build_scripts = [
            item
            for item in targets
            if isinstance(item, dict) and "custom-build" in item.get("kind", [])
        ]
        seen_build_paths: set[str] = set()
        for target in build_scripts:
            source_path = target.get("src_path")
            if not isinstance(source_path, str):
                fail(f"custom build target source path is missing: {name}")
            script = within(source_root, pathlib.Path(source_path), f"build script for {name}")
            if not script.is_file():
                fail(f"custom build target is not a regular file: {script}")
            relative_script = script.relative_to(source_root).as_posix()
            if relative_script in seen_build_paths:
                fail(f"duplicate custom build target: {relative_script}")
            seen_build_paths.add(relative_script)
            properties.append(
                (
                    f"trnm:build-script:{relative_script}:sha256",
                    f"sha256:{sha256_file(script)}",
                )
            )
    component["properties"] = property_list(properties)
    return component


def _tool_version_evidence(
    path: pathlib.Path, tool: str, expected_release: str
) -> tuple[dict[str, Any], str]:
    raw = read_regular(path)
    if b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        fail(f"{tool} verbose version evidence is not canonical LF-terminated UTF-8")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"{tool} verbose version evidence is not UTF-8: {error}")
    if not lines or not lines[0].startswith(f"{tool} "):
        fail(f"{tool} verbose version banner differs")
    details: dict[str, str] = {}
    for line in lines[1:]:
        key, separator, value = line.partition(": ")
        if not separator or not key or not value or key in details:
            fail(f"{tool} verbose version detail is malformed or duplicated: {line!r}")
        details[key] = value
    for required in ("commit-hash", "host", "release"):
        if not details.get(required):
            fail(f"{tool} verbose version evidence has no {required}")
    if details["release"] != expected_release:
        fail(
            f"{tool} release {details['release']} differs from rust-toolchain {expected_release}"
        )
    return {"banner": lines[0], "details": dict(sorted(details.items()))}, sha256_bytes(raw)


def _binary_maps(values: dict[str, pathlib.Path], label: str) -> dict[str, pathlib.Path]:
    expected = {target["binary"] for target in TARGETS}
    if set(values) != expected:
        fail(f"{label} binary set differs; expected {sorted(expected)}")
    result: dict[str, pathlib.Path] = {}
    for name, path in values.items():
        if path.is_symlink():
            fail(f"{label} binary symlink is forbidden: {name}")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            fail(f"cannot resolve {label} binary {name}: {error}")
        if not resolved.is_file():
            fail(f"{label} binary is not a regular file: {name}")
        result[name] = resolved
    return result


def build_artifacts(
    *,
    metadata_path: pathlib.Path,
    source_root: pathlib.Path,
    revision: str,
    source_tree: str,
    component_lock_path: pathlib.Path,
    cargo_version_path: pathlib.Path,
    rustc_version_path: pathlib.Path,
    binaries_a: dict[str, pathlib.Path],
    binaries_b: dict[str, pathlib.Path],
    tool_paths: dict[str, pathlib.Path],
) -> tuple[dict[str, Any], dict[str, Any]]:
    root = require_source_root(source_root)
    revision = require_hex(revision, 40, "source revision")
    source_tree = require_hex(source_tree, 40, "source tree")
    workspace = root / "trillionnium"
    lock_path = workspace / "Cargo.lock"
    toolchain_path = root / "rust-toolchain.toml"
    for path, label in ((lock_path, "Cargo.lock"), (toolchain_path, "rust-toolchain.toml")):
        within(root, path, label)
        read_regular(path)
    component_lock_sha256, chain = parse_component_lock(component_lock_path)
    expected_chain_lock = {
        "project_id": "trillionnium-chain",
        "revision": revision,
        "source_tree": source_tree,
        "cargo_lock_sha256": sha256_file(lock_path),
        "rust_toolchain_sha256": sha256_file(toolchain_path),
        "working_tree_dirty": False,
    }
    for field, expected in expected_chain_lock.items():
        if chain.get(field) != expected:
            fail(
                f"Integration canonical-chain {field} does not bind the immutable source candidate"
            )
    required_tools = {"gate", "generator", "library", "verifier"}
    if set(tool_paths) != required_tools:
        fail(f"tool path set differs; expected {sorted(required_tools)}")
    tool_hashes: dict[str, str] = {}
    for name, path in tool_paths.items():
        if path.is_symlink():
            fail(f"{name} tool symlink is forbidden")
        tool_hashes[name] = sha256_file(path)

    model = cargo_model(metadata_path, lock_path)
    stable_identities = {
        package_id: _stable_package_identity(package_id, model.packages[package_id], root)
        for package_id in model.closure
    }
    if len(stable_identities) != len(set(stable_identities.values())):
        fail("cargo dependency closure contains duplicate stable package identities")
    first = _binary_maps(binaries_a, "build A")
    second = _binary_maps(binaries_b, "build B")
    binary_hashes: dict[str, str] = {}
    for target in TARGETS:
        name = target["binary"]
        first_bytes = read_regular(first[name])
        second_bytes = read_regular(second[name])
        if first_bytes != second_bytes:
            fail(f"isolated build outputs differ byte-for-byte: {name}")
        binary_hashes[name] = sha256_bytes(first_bytes)

    package_components = [
        _package_component(
            package_id,
            stable_identities[package_id],
            model.packages[package_id],
            root,
            model,
        )
        for package_id in sorted(model.closure)
    ]
    binary_components: list[dict[str, Any]] = []
    for target in TARGETS:
        name = target["binary"]
        binary_components.append(
            {
                "bom-ref": f"file:target/debug/{name}",
                "hashes": [{"alg": "SHA-256", "content": binary_hashes[name]}],
                "name": name,
                "properties": property_list(
                    [
                        ("trnm:artifact-id", target["artifact_id"]),
                        ("trnm:cargo-features", ",".join(target["features"])),
                        ("trnm:cargo-package", target["package"]),
                        ("trnm:cargo-profile", target["cargo_profile"]),
                    ]
                ),
                "type": "file",
            }
        )

    toolchain = tomllib.loads(read_regular(toolchain_path).decode("utf-8"))
    channel = toolchain.get("toolchain", {}).get("channel")
    if not isinstance(channel, str) or not channel:
        fail("rust-toolchain.toml has no pinned channel")
    cargo_evidence, cargo_evidence_sha256 = _tool_version_evidence(
        cargo_version_path, "cargo", channel
    )
    rustc_evidence, rustc_evidence_sha256 = _tool_version_evidence(
        rustc_version_path, "rustc", channel
    )
    metadata_properties: list[tuple[str, str]] = [
        ("trnm:binary-byte-identical", "true"),
        ("trnm:build-profile", "debug"),
        ("trnm:cargo-lock:sha256", f"sha256:{sha256_file(lock_path)}"),
        ("trnm:cargo-version-evidence:sha256", f"sha256:{cargo_evidence_sha256}"),
        ("trnm:integration-component-lock:sha256", f"sha256:{component_lock_sha256}"),
        ("trnm:isolated-target-build-count", "2"),
        ("trnm:rust-toolchain:sha256", f"sha256:{sha256_file(toolchain_path)}"),
        ("trnm:rustc-version-evidence:sha256", f"sha256:{rustc_evidence_sha256}"),
        ("trnm:source-revision:git-sha1", revision),
        ("trnm:source-tree:git-sha1", source_tree),
        ("trnm:volatile-metadata", "omitted"),
    ]
    metadata_properties.extend(
        (f"trnm:{name}-script:sha256", f"sha256:{digest}")
        for name, digest in tool_hashes.items()
    )
    candidate_component = {
        "bom-ref": SBOM_REF,
        "name": SBOM_NAME,
        "properties": property_list(
            [
                ("trnm:candidate-boundary", "debug-integration-only"),
                ("trnm:economic-eligibility", "false"),
            ]
        ),
        "type": "application",
        "version": f"0.0.0+git.{revision[:12]}",
    }
    dependencies: list[dict[str, Any]] = [
        {
            "dependsOn": sorted(f"file:target/debug/{target['binary']}" for target in TARGETS),
            "ref": SBOM_REF,
        }
    ]
    for target in TARGETS:
        dependencies.append(
            {
                "dependsOn": [
                    _package_ref(stable_identities[model.roots[target["package"]]])
                ],
                "ref": f"file:target/debug/{target['binary']}",
            }
        )
    for package_id in sorted(model.closure):
        dependencies.append(
            {
                "dependsOn": sorted(
                    _package_ref(stable_identities[dependency])
                    for dependency in model.edges[package_id]
                    if dependency in model.closure
                ),
                "ref": _package_ref(stable_identities[package_id]),
            }
        )
    sbom = {
        "bomFormat": "CycloneDX",
        "components": sorted(
            [*package_components, *binary_components], key=lambda item: item["bom-ref"]
        ),
        "dependencies": sorted(dependencies, key=lambda item: item["ref"]),
        "metadata": {
            "component": candidate_component,
            "properties": property_list(metadata_properties),
            "tools": {
                "components": [
                    {
                        "name": "cargo",
                        "type": "application",
                        "version": cargo_evidence["details"]["release"],
                    },
                    {
                        "name": "trnm-paper-raid-chain-sbom-generator",
                        "type": "application",
                        "version": TOOL_VERSION,
                    },
                    {
                        "name": "rustc",
                        "type": "application",
                        "version": rustc_evidence["details"]["release"],
                    },
                ]
            },
        },
        "specVersion": "1.5",
        "version": 1,
    }
    sbom_sha256 = sha256_bytes(canonical_json(sbom))
    provenance = {
        "build": {
            "binary_byte_identical": True,
            "isolated_target_builds": 2,
            "profile": "debug",
            "targets": [
                {
                    "artifact_id": target["artifact_id"],
                    "binary": target["binary"],
                    "features": list(target["features"]),
                    "package": target["package"],
                    "sha256": binary_hashes[target["binary"]],
                }
                for target in TARGETS
            ],
        },
        "candidate_boundary": "debug-integration-only",
        "integration_component_lock_sha256": component_lock_sha256,
        "schema": PROVENANCE_SCHEMA,
        "scripts": {name: f"sha256:{digest}" for name, digest in sorted(tool_hashes.items())},
        "sbom": {
            "bom_format": "CycloneDX",
            "sha256": sbom_sha256,
            "spec_version": "1.5",
        },
        "source": {
            "cargo_lock_sha256": sha256_file(lock_path),
            "revision": revision,
            "rust_toolchain_sha256": sha256_file(toolchain_path),
            "tree": source_tree,
        },
        "toolchain_evidence": {
            "cargo": {**cargo_evidence, "sha256": cargo_evidence_sha256},
            "rustc": {**rustc_evidence, "sha256": rustc_evidence_sha256},
        },
    }
    forbidden = {"serialNumber", "timestamp"}

    def reject_volatile(value: Any) -> None:
        if isinstance(value, dict):
            if forbidden.intersection(value):
                fail("volatile timestamp/serialNumber fields are forbidden")
            for child in value.values():
                reject_volatile(child)
        elif isinstance(value, list):
            for child in value:
                reject_volatile(child)

    reject_volatile(sbom)
    reject_volatile(provenance)
    return sbom, provenance


def verify_artifacts(
    *,
    sbom_path: pathlib.Path,
    provenance_path: pathlib.Path,
    **build_arguments: Any,
) -> dict[str, str]:
    actual_sbom = require_canonical_json(sbom_path)
    actual_provenance = require_canonical_json(provenance_path)
    expected_sbom, expected_provenance = build_artifacts(**build_arguments)
    if actual_sbom != expected_sbom:
        fail("CycloneDX SBOM differs from canonical cargo/source/binary evidence")
    if actual_provenance != expected_provenance:
        fail("provenance differs from canonical dual-build evidence")
    if actual_provenance["sbom"]["sha256"] != sha256_file(sbom_path):
        fail("provenance SBOM digest does not bind the canonical SBOM bytes")
    return {
        target["binary"]: actual_provenance["build"]["targets"][index]["sha256"]
        for index, target in enumerate(TARGETS)
    }
