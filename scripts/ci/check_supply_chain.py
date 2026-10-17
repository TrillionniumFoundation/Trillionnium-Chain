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
ALLOWED_LICENSES = [
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "ISC",
    "MIT",
    "MPL-2.0",
    "NCSA",
    "Unicode-3.0",
    "Zlib",
]
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
    "repository-projects",
    "security-events",
    "statuses",
    "workflows",
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
    # Cargo implicitly executes a crate-root build.rs even when the manifest
    # omits the `build` key.  Check the file itself so a newly added script
    # cannot bypass the manifest-only guard and execute during every build.
    require(not (manifest_path.parent / "build.rs").is_file(), f"first-party build script declared in {manifest_path.relative_to(ROOT)}")
    # First-party procedural macros execute during dependent compilation just
    # like build scripts.  Keep this portable workspace free of that hidden
    # compile-time execution surface.
    lib = data.get("lib", {})
    require(not (isinstance(lib, dict) and lib.get("proc-macro") is True), f"first-party procedural macro declared in {manifest_path.relative_to(ROOT)}")
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
    licenses = data.get("licenses", {})
    require(licenses.get("version") == 2, "deny.toml license schema is not pinned")
    require(licenses.get("unlicensed") == "deny", "deny.toml allows unlicensed crates")
    require(licenses.get("copyleft") == "deny", "deny.toml allows copyleft crates")
    require(licenses.get("confidence-threshold") == 0.93, "deny.toml license confidence threshold drift")
    require(licenses.get("allow") == ALLOWED_LICENSES, "deny.toml license allowlist drift")
    require(not licenses.get("exceptions", []), "deny.toml license exceptions are not empty")
    require(not licenses.get("clarify", []), "deny.toml license clarifications are not empty")
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
        # A job-level read mapping does not constrain jobs added later: GitHub
        # otherwise inherits the repository's default token permissions.  Keep
        # the workflow-level default explicitly empty and grant only the
        # per-job read scope used by the checked-out source.
        require(re.search(r"(?mi)^\s*[\"']?permissions[\"']?\s*:\s*\{\s*\}(?:\s*#.*)?$", text), f"workflow root permissions are not empty in {rel}")
        require(re.search(r"(?mi)^\s*[\"']?permissions[\"']?\s*:", text), f"workflow has no explicit permissions policy in {rel}")
        require("pull_request_target" not in text, f"privileged pull-request event in {rel}")
        require("workflow_run" not in text, f"privileged workflow event in {rel}")
        require("self-hosted" not in text, f"persistent runner in {rel}")
        # Required checks must always execute on the pinned hosted image.  A
        # conditional or continue-on-error step could make a failing check
        # appear successful, while a container/service introduces an
        # unreviewed executable image into the trust boundary.
        require(not re.search(r"(?mi)^\s*(?:-\s*)?[\"']?if[\"']?\s*:", text), f"conditional workflow step in {rel}")
        require(not re.search(r"(?mi)(?:\{|,)\s*[\"']?if[\"']?\s*:", text), f"conditional workflow step in {rel}")
        require(not re.search(r"(?mi)^\s*(?:-\s*)?[\"']?continue-on-error[\"']?\s*:", text), f"non-failing workflow step in {rel}")
        require(not re.search(r"(?mi)(?:\{|,)\s*[\"']?continue-on-error[\"']?\s*:", text), f"non-failing workflow step in {rel}")
        # ``||`` is valid in GitHub expressions (the source SHA selector uses
        # it), but shell fallbacks can turn a failed required check green.
        shell_text = re.sub(r"\$\{\{.*?\}\}", "", text, flags=re.S)
        require("||" not in shell_text, f"workflow suppresses command failure in {rel}")
        require(not re.search(r"(?mi)\bset\s+\+e\b", shell_text), f"workflow disables fail-fast mode in {rel}")
        require(not re.search(r"(?mi)^\s*[\"']?(?:container|services)[\"']?\s*:", text), f"unreviewed workflow image/service in {rel}")
        require(not re.search(r"(?mi)(?:\{|,)\s*[\"']?(?:container|services)[\"']?\s*:", text), f"unreviewed workflow image/service in {rel}")
        # Keep the hosted runner image deterministic; dynamic labels can
        # select a persistent or otherwise unreviewed runner at dispatch time.
        runners = re.findall(r"(?mi)^\s*[\"']?runs-on[\"']?\s*:\s*[\"']?([^\s#\"']+)", text)
        runners.extend(re.findall(r"(?mi)(?:\{|,)\s*[\"']?runs-on[\"']?\s*:\s*[\"']?([^,}\s#\"']+)", text))
        require(runners and all(runner == "ubuntu-24.04" for runner in runners), f"workflow runner is not pinned in {rel}")
        write_keys = "|".join(re.escape(key) for key in PERMISSION_KEYS)
        quoted_write_key = rf"[\"']?(?:{write_keys})[\"']?"
        require(not re.search(rf"(?mi)^\s*{quoted_write_key}\s*:\s*[\"']?write(?:-all)?\b", text), f"write token permission in {rel}")
        # GitHub accepts flow-style permission maps (for example,
        # ``permissions: { contents: write }``).  A line-oriented check that
        # only recognizes block mappings would silently allow a write token.
        # Reject both broad scalar permissions and any inline ``write`` value;
        # the block-mapping check above still gives a precise error for the
        # common multiline form.
        require(not re.search(r"(?mi)^\s*(?:-\s*)?[\"']?permissions[\"']?\s*:[^\n]*\bwrite(?:-all)?\b", text), f"write token permission in {rel}")
        # A flow-style job map may use the broad scalar form
        # ``permissions: write-all`` rather than an individual key.
        require(not re.search(r"(?mi)(?:\{|,)\s*[\"']?permissions[\"']?\s*:\s*[\"']?write(?:-all)?\b", text), f"write token permission in {rel}")
        # Flow-style job maps can put the permission key after another key
        # (``job: { permissions: { contents: write } }``), so also inspect
        # mapping entries that begin after ``{`` or ``,``.
        require(not re.search(rf"(?mi)(?:\{{|,)\s*{quoted_write_key}\s*:\s*[\"']?write(?:-all)?\b", text), f"write token permission in {rel}")
        # Secret contexts are forbidden for these untrusted PR jobs.  Match
        # the whole identifier so whitespace or alternate expression forms
        # (``secrets ["TOKEN"]``, ``toJSON(secrets)``) cannot evade this gate.
        require(not re.search(r"\bsecrets\b", text), f"secret interpolation in untrusted workflow {rel}")
        require("upload-artifact" not in text, f"unattested artifact publishing in {rel}")
        require("attest-build-provenance" not in text, f"artifact attestation without reviewed release gate in {rel}")
        require(not re.search(r"(?mi)^\s*[\"']?environment[\"']?\s*:", text), f"deployment environment in {rel}")
        require(not re.search(r"(?mi)^\s*[\"']?(?:deploy|deployment|release)[\"']?\s*:", text), f"deployment step in {rel}")
        require(not re.search(r"(?mi)(?:\{|,)\s*[\"']?(?:environment|deploy|deployment|release)[\"']?\s*:", text), f"deployment surface in {rel}")
        # Checkout persists its token by default.  Every checkout in these
        # untrusted jobs must opt out; otherwise source code can read the
        # credential file even though the workflow declares read-only scopes.
        checkout_count = len(re.findall(r"(?mi)^\s*[\"']?uses[\"']?\s*:\s*actions/checkout@", text))
        no_credential_count = len(re.findall(r"(?mi)^\s*[\"']?persist-credentials[\"']?\s*:\s*false\b", text))
        require(checkout_count > 0 and no_credential_count == checkout_count, f"checkout credentials are not disabled in {rel}")
        require(not re.search(r"(?mi)^\s*[\"']?persist-credentials[\"']?\s*:\s*true\b", text), f"checkout credentials retained in {rel}")


def check_actions() -> int:
    count = 0
    workflows = ROOT / ".github" / "workflows"
    require(workflows.is_dir(), ".github/workflows directory is missing")
    for path in [*workflows.rglob("*.yml"), *workflows.rglob("*.yaml")]:
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"[\"']?\buses[\"']?\s*:\s*$", line):
                raise Invalid(f"multiline GitHub Action reference at {path.relative_to(ROOT)}:{line_number}")
            match = re.search(r"[\"']?\buses[\"']?\s*:\s*([^\s#]+)", line)
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
