#!/usr/bin/env python3
"""Fail-closed checks for the Rust dependency and CI supply-chain boundary.

The Cargo.lock file is the reviewable dependency bill of materials for this
portable workspace.  These checks deliberately reject any dependency source
that is not the pinned crates.io registry and reject unpinned/wildcard
manifest requirements.  RustSec and license/advisory policy checks are run by
the CI job with cargo-audit and cargo-deny; this module verifies the inputs
those tools consume and the immutable GitHub Actions references around them.
"""
from __future__ import annotations

import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "trillionnium"
LOCK = WORKSPACE / "Cargo.lock"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = re.compile(r"[0-9a-f]{64}\Z")
ACTION_SHA = re.compile(r"[0-9a-f]{40}\Z", re.IGNORECASE)
EXPECTED_TOOLCHAIN = "1.95.0"
ALLOWED_ACTIONS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
}
PERMISSION_KEYS = (
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "security-events",
    "statuses",
)


class Invalid(ValueError):
    """Raised when a supply-chain input violates the repository policy."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def dependency_tables(manifest: dict):
    """Yield every dependency table, including target-specific tables."""
    yield "workspace-dependencies", manifest.get("workspace", {}).get("dependencies", {})
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield key, manifest.get(key, {})
    for target in manifest.get("target", {}).values():
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield key, target.get(key, {})


def check_manifest(manifest_path: pathlib.Path) -> None:
    data = tomllib.loads(manifest_path.read_text())
    package = data.get("package", {})
    if package:
        require(package.get("publish") is False, f"publishable workspace crate {manifest_path.relative_to(ROOT)}")
    # Build scripts are a particularly easy way for a transitive dependency
    # to turn a compile into arbitrary code execution.  The portable workspace
    # has no first-party build script or build dependency; keep that boundary
    # explicit and let upstream build scripts remain covered by cargo-deny.
    require("build" not in package, f"first-party build script declared in {manifest_path.relative_to(ROOT)}")
    # Patch/replace tables can redirect an apparently normal crates.io
    # dependency to an unreviewed fork.  The workspace has no such override;
    # require any future one to go through an explicit policy review first.
    require(not data.get("patch"), f"dependency patch override in {manifest_path.relative_to(ROOT)}")
    require(not data.get("replace"), f"dependency replace override in {manifest_path.relative_to(ROOT)}")
    for category, table in dependency_tables(data):
        if category == "build-dependencies":
            require(not table, f"first-party build dependency declared in {manifest_path.relative_to(ROOT)}")
        for alias, declaration in table.items():
            if isinstance(declaration, str):
                require(declaration != "*", f"wildcard dependency {alias} in {manifest_path.relative_to(ROOT)}")
                continue
            require(isinstance(declaration, dict), f"invalid dependency declaration {alias}")
            require("git" not in declaration, f"git dependency {alias} in {manifest_path.relative_to(ROOT)}")
            version = declaration.get("version")
            require(version != "*", f"wildcard dependency {alias} in {manifest_path.relative_to(ROOT)}")
            if "path" in declaration:
                path = (manifest_path.parent / declaration["path"]).resolve()
                require(path.is_relative_to(ROOT / "trillionnium" / "crates") and path.is_dir(), f"external path dependency {alias} in {manifest_path.relative_to(ROOT)}")
            # A registry URL in a manifest is not needed for crates.io and can
            # silently bypass the allow-registry policy in deny.toml.
            registry = declaration.get("registry")
            require(registry in (None, "crates-io"), f"unknown registry for {alias} in {manifest_path.relative_to(ROOT)}")


def check_toolchain() -> None:
    path = ROOT / "rust-toolchain.toml"
    require(path.is_file(), "rust-toolchain.toml is missing")
    data = tomllib.loads(path.read_text())
    toolchain = data.get("toolchain")
    require(isinstance(toolchain, dict), "rust-toolchain.toml has no toolchain table")
    require(toolchain.get("channel") == EXPECTED_TOOLCHAIN, "Rust toolchain channel is not pinned")
    require(toolchain.get("profile") == "minimal", "Rust toolchain profile is not minimal")
    require(set(toolchain.get("components", [])) >= {"clippy", "rustfmt"}, "Rust toolchain components are incomplete")


def check_local_cargo_overrides() -> None:
    # Cargo reads repository-local configuration before the isolated CARGO_HOME.
    # An unreviewed config can replace the registry or install a compiler wrapper,
    # and cargo-audit also supports a repository-local audit.toml.
    for directory in (ROOT / ".cargo", WORKSPACE / ".cargo"):
        require(not directory.exists(), f"unreviewed Cargo configuration directory {directory.relative_to(ROOT)}")
    for path in ROOT.rglob("audit.toml"):
        require(False, f"unreviewed cargo-audit configuration {path.relative_to(ROOT)}")


def check_deny_policy() -> None:
    path = ROOT / "deny.toml"
    require(path.is_file(), "deny.toml is missing")
    data = tomllib.loads(path.read_text())
    graph = data.get("graph", {})
    require("x86_64-unknown-linux-gnu" in graph.get("targets", []), "deny.toml omits the CI target")
    advisories = data.get("advisories", {})
    require(advisories.get("version") == 2, "deny.toml advisory schema is not pinned")
    require(advisories.get("yanked") == "deny", "deny.toml does not deny yanked crates")
    require(not advisories.get("ignore", []), "deny.toml advisory ignore list is not empty")
    bans = data.get("bans", {})
    require(bans.get("wildcards") == "deny", "deny.toml does not deny wildcard dependencies")
    sources = data.get("sources", {})
    require(sources.get("unknown-registry") == "deny", "deny.toml allows unknown registries")
    require(sources.get("unknown-git") == "deny", "deny.toml allows unknown git sources")
    require(sources.get("allow-registry") == ["https://github.com/rust-lang/crates.io-index"], "deny.toml registry allowlist drift")


def check_lock() -> dict:
    require(LOCK.is_file(), "trillionnium/Cargo.lock is missing")
    lock = tomllib.loads(LOCK.read_text())
    require(lock.get("version") == 4, "Cargo.lock must use lockfile format v4")
    packages = lock.get("package")
    require(isinstance(packages, list) and packages, "Cargo.lock has no packages")
    members = tomllib.loads((WORKSPACE / "Cargo.toml").read_text())["workspace"]["members"]
    check_manifest(WORKSPACE / "Cargo.toml")
    workspace_names = set()
    for member in members:
        manifest_path = WORKSPACE / member / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text())
        workspace_names.add(manifest["package"]["name"])
        check_manifest(manifest_path)

    seen = set()
    local_names = set()
    for package in packages:
        name = package.get("name")
        version = package.get("version")
        require(isinstance(name, str) and isinstance(version, str), "lock package missing name/version")
        key = (name, version, package.get("source"))
        require(key not in seen, f"duplicate lock package {name} {version}")
        seen.add(key)
        source = package.get("source")
        if source is None:
            require(name in workspace_names, f"unresolved path package {name}")
            require("checksum" not in package, f"path package {name} has a registry checksum")
            local_names.add(name)
        else:
            require(source == REGISTRY, f"non-crates.io dependency source for {name}: {source}")
            checksum = package.get("checksum")
            require(isinstance(checksum, str) and CHECKSUM.fullmatch(checksum) is not None, f"missing/invalid checksum for {name} {version}")
    require(local_names == workspace_names, "workspace members and path packages differ")
    return {"packages": len(packages), "registry_packages": len(packages) - len(local_names), "workspace_packages": len(local_names)}


def check_workflow_policy() -> None:
    """Keep CI read-only and prevent accidental release/deployment surfaces.

    This repository intentionally has no deployment or artifact-publishing
    workflow.  A future release pipeline must be reviewed as a separate,
    explicitly attested change instead of silently inheriting the PR runner.
    """
    workflows = ROOT / ".github" / "workflows"
    require(workflows.is_dir(), ".github/workflows directory is missing")
    for path in [*workflows.rglob("*.yml"), *workflows.rglob("*.yaml")]:
        text = path.read_text()
        rel = path.relative_to(ROOT)
        require(re.search(r"(?mi)^\s*permissions\s*:", text), f"workflow has no explicit permissions policy in {rel}")
        require("pull_request_target" not in text, f"privileged pull-request event in {rel}")
        require("workflow_run" not in text, f"privileged workflow event in {rel}")
        require("self-hosted" not in text, f"persistent runner in {rel}")
        write_keys = "|".join(re.escape(key) for key in PERMISSION_KEYS)
        require(not re.search(rf"(?mi)^\s*(?:{write_keys})\s*:\s*write\b", text), f"write token permission in {rel}")
        require(not re.search(r"(?mi)^\s*permissions\s*:\s*(?:write|write-all)\b", text), f"broad write token permission in {rel}")
        require(not re.search(r"\bsecrets(?:\.|\[)", text), f"secret interpolation in untrusted workflow {rel}")
        require("upload-artifact" not in text, f"unattested artifact publishing in {rel}")
        require("attest-build-provenance" not in text, f"artifact attestation without reviewed release gate in {rel}")
        require(not re.search(r"(?mi)^\s*environment:\s*", text), f"deployment environment in {rel}")
        require(not re.search(r"(?mi)^\s*(?:deploy|deployment|release):\s*", text), f"deployment step in {rel}")


def check_actions() -> int:
    count = 0
    workflows = ROOT / ".github" / "workflows"
    require(workflows.is_dir(), ".github/workflows directory is missing")
    for path in [*workflows.rglob("*.yml"), *workflows.rglob("*.yaml")]:
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"\buses\s*:\s*$", line):
                raise Invalid(f"multiline GitHub Action reference at {path.relative_to(ROOT)}:{line_number}")
            match = re.search(r"\buses\s*:\s*([^\s#]+)", line)
            if not match:
                continue
            reference = match.group(1).rsplit("@", 1)
            require(len(reference) == 2 and ACTION_SHA.fullmatch(reference[1]) is not None, f"unpinned GitHub Action at {path.relative_to(ROOT)}:{line_number}")
            require(reference[0] in ALLOWED_ACTIONS and reference[1].lower() == ALLOWED_ACTIONS[reference[0]].lower(), f"unreviewed GitHub Action at {path.relative_to(ROOT)}:{line_number}")
            count += 1
    require(count > 0, "no GitHub Actions references found to audit")
    return count


def check(root: pathlib.Path = ROOT) -> dict:
    # Keep the optional root argument for mutation tests; all paths are
    # resolved relative to that root when tests supply a copied repository.
    global ROOT, WORKSPACE, LOCK
    original = (ROOT, WORKSPACE, LOCK)
    ROOT = root
    WORKSPACE = root / "trillionnium"
    LOCK = WORKSPACE / "Cargo.lock"
    try:
        report = check_lock()
        check_toolchain()
        check_local_cargo_overrides()
        check_deny_policy()
        check_workflow_policy()
        report["pinned_actions"] = check_actions()
        return report
    finally:
        ROOT, WORKSPACE, LOCK = original


if __name__ == "__main__":
    try:
        print(check())
    except (Invalid, KeyError, OSError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"Supply-chain check failed: {exc}")
