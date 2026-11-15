#!/usr/bin/env python3
"""Read immutable Chain/Hepta dependency identities; never grant native acceptance.

No checkout, build, network request, service dispatch, or receipt promotion occurs.
The caller must still bind actual binaries, effective build configuration, model
bytes, and original native evidence before claiming a complete system candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

CHAIN_REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
HEPTA_REPOSITORY = "TrillionniumFoundation/hepta-private-ci"
CHAIN_URL = "https://github.com/" + CHAIN_REPOSITORY + ".git"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
LOCK_SOURCE = re.compile(re.escape("git+" + CHAIN_URL) + r"\?rev=([0-9a-f]{40})#([0-9a-f]{40})\Z")
BAZEL_SOURCE = re.compile(re.escape("git+" + CHAIN_URL) + r"\?rev=([0-9a-f]{40})#([0-9a-f]{40})_(trnm-[a-z0-9-]+)\Z")
REQUIRED_PACKAGES = {"trnm-crypto-primitives", "trnm-protocol", "trnm-release-bundle"}
CHAIN_FILES = (
    "trillionnium/Cargo.toml", "trillionnium/Cargo.lock", "rust-toolchain.toml",
    "config/consensus-mainline.json", "config/pon-nakamoto-v1.json",
    "config/pon/devnet-v1.json", "config/pon/post-quantum-transition-v1.json",
    "config/pon/work-profile-v1.json", "config/pon/pq-cross-branch-corpus-v1.json",
    "config/pon/model-family-smollm2-135m-v1.json", "config/pon/model-composition-v4.json",
)
HEPTA_FILES = (
    "codex-rs/Cargo.toml", "codex-rs/Cargo.lock", "codex-rs/rust-toolchain.toml",
    "codex-rs/hepta-fleet/Cargo.toml", "MODULE.bazel", "MODULE.bazel.lock",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def load_json(raw):
    def invalid_constant(value):
        raise ValueError("non-finite JSON value: " + value)
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


class GitSource:
    """An immutable object reader, deliberately separate from a live worktree."""

    def __init__(self, root, commit, repository):
        require(isinstance(commit, str) and HEX40.fullmatch(commit), "full lowercase commit required")
        self.root, self.commit = Path(root).resolve(strict=True), commit
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.environment.update(GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
        require(self.command("cat-file", "-t", commit).strip() == b"commit", "not a commit object")
        raw = self.object("commit", commit)
        tree = raw.split(b"\n", 1)[0].decode()
        require(tree.startswith("tree ") and HEX40.fullmatch(tree[5:]), "invalid commit tree")
        self.identity = {"repository": repository, "commit": commit, "tree": tree[5:],
                         "commit_object_sha256": hashlib.sha256(raw).hexdigest()}
        self.entries = {}
        for row in self.command("ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
            if not row:
                continue
            metadata, path = row.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            name = path.decode("utf-8")
            require(name not in self.entries, "duplicate Git tree path")
            self.entries[name] = (mode, kind, oid)
        self.cache, self.pins = {}, {}

    def command(self, *args):
        result = subprocess.run(
            ["git", "--no-replace-objects", "-c", "protocol.allow=never", "-C", str(self.root), *args],
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
        require(result.returncode == 0, "Git object unavailable: " + " ".join(args[:3]))
        require(len(result.stdout) <= 16 * 1024 * 1024, "Git output exceeds bound")
        return result.stdout

    def object(self, kind, oid):
        size = int(self.command("cat-file", "-s", oid))
        require(0 <= size <= 4 * 1024 * 1024, "Git object exceeds inspection bound")
        raw = self.command("cat-file", kind, oid)
        digest = hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False)
        require(size == len(raw) and digest.hexdigest() == oid, "Git object identity mismatch")
        return raw

    def read(self, path):
        require(isinstance(path, str) and path and not path.startswith("/")
                and all(p not in {"", ".", ".."} for p in path.split("/")), "noncanonical source path")
        require(path in self.entries, "missing required source: " + path)
        mode, kind, oid = self.entries[path]
        require(mode in {"100644", "100755"} and kind == "blob", "non-regular source: " + path)
        if path not in self.cache:
            raw = self.object("blob", oid)
            self.cache[path] = raw
            self.pins[path] = {"path": path, "mode": mode, "git_blob": oid,
                               "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        return self.cache[path]


def dictionaries(value, location=()):
    if isinstance(value, dict):
        yield location, value
        for key, child in value.items():
            yield from dictionaries(child, location + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from dictionaries(child, location + (str(index),))


def inspect(chain_root, chain_commit, hepta_root, hepta_commit):
    chain = GitSource(chain_root, chain_commit, CHAIN_REPOSITORY)
    hepta = GitSource(hepta_root, hepta_commit, HEPTA_REPOSITORY)
    issues, declarations, lock_rows, bazel_rows = [], [], [], []
    for source, files in ((chain, CHAIN_FILES), (hepta, HEPTA_FILES)):
        for path in files:
            source.read(path)
        # Pin every checked-in Cargo configuration, including overrides outside
        # codex-rs. The caller's external Cargo home/environment is not inspected.
        for path in sorted(source.entries):
            if path.endswith(("/Cargo.lock", "/rust-toolchain.toml")) or path in {"Cargo.lock", "rust-toolchain.toml"} \
                    or path.endswith((".cargo/config", ".cargo/config.toml")):
                source.read(path)
            if path.endswith((".cargo/config", ".cargo/config.toml")):
                config = tomllib.loads(source.read(path).decode())
                if any(config.get(key) for key in ("source", "paths", "patch", "replace")):
                    issues.append({"code": "CARGO_CONFIG_SOURCE_OVERRIDE_REQUIRES_RESOLUTION",
                                   "repository": source.identity["repository"], "path": path})

    for path in sorted(hepta.entries):
        if path != "Cargo.toml" and not path.endswith("/Cargo.toml"):
            continue
        data = tomllib.loads(hepta.read(path).decode())
        for location, dependencies in dictionaries(data):
            if not location or not (location[-1] in {"dependencies", "dev-dependencies", "build-dependencies"}
                                    or (len(location) >= 2 and location[-2] == "patch")
                                    or location == ("replace",)):
                continue
            for alias, specification in dependencies.items():
                table = specification if isinstance(specification, dict) else {}
                package = table.get("package", alias.split(":", 1)[0])
                relevant = str(package).startswith("trnm-") or "trillionnium-chain" in str(table.get("git", "")).lower()
                if not relevant:
                    continue
                at = list(location + (alias,))
                row = {"path": path, "table": at, "package": package,
                       "git": table.get("git"), "rev": table.get("rev")}
                declarations.append(row)
                if table.get("workspace") is True:
                    issues.append({"code": "UNRESOLVED_WORKSPACE_CHAIN_DEPENDENCY", "path": path, "table": at})
                elif table.get("git") != CHAIN_URL or table.get("rev") != chain_commit \
                        or any(key in table for key in ("branch", "tag", "path")):
                    issues.append({"code": "CARGO_DECLARATION_CHAIN_MISMATCH", **row, "expected": chain_commit})
    if not declarations:
        issues.append({"code": "NO_CHAIN_DEPENDENCY_DECLARATION"})

    for path in sorted(hepta.entries):
        if path != "Cargo.lock" and not path.endswith("/Cargo.lock"):
            continue
        lock = tomllib.loads(hepta.read(path).decode())
        local_names = []
        for package in lock.get("package", []):
            name, source = package.get("name", ""), package.get("source", "")
            if not name.startswith("trnm-") and "trillionnium-chain" not in source.lower():
                continue
            row = {"path": path, "package": name, "version": package.get("version"), "source": source}
            lock_rows.append(row)
            local_names.append(name)
            matched = LOCK_SOURCE.fullmatch(source)
            if not matched or matched.groups() != (chain_commit, chain_commit):
                issues.append({"code": "CARGO_LOCK_CHAIN_MISMATCH", **row, "expected": chain_commit})
        if len(local_names) != len(set(local_names)):
            issues.append({"code": "DUPLICATE_CHAIN_LOCK_PACKAGE", "path": path})
    names = [row["package"] for row in lock_rows if row["path"] == "codex-rs/Cargo.lock"]
    if len(names) != len(set(names)) or not REQUIRED_PACKAGES <= set(names):
        issues.append({"code": "CARGO_CHAIN_PACKAGE_ROSTER", "packages": names})
    if not {row["package"] for row in declarations} <= {row["package"] for row in lock_rows}:
        issues.append({"code": "DECLARED_CHAIN_PACKAGE_ABSENT_FROM_LOCK"})

    bazel = load_json(hepta.read("MODULE.bazel.lock"))
    require(isinstance(bazel, dict) and type(bazel.get("lockFileVersion")) is int
            and bazel["lockFileVersion"] == 28, "unsupported Bazel lock consumer schema")
    for location, table in dictionaries(bazel):
        for key, value in table.items():
            if "trillionnium-chain" not in key.lower() and not re.search(r"_trnm-[a-z0-9-]+$", key):
                continue
            matched = BAZEL_SOURCE.fullmatch(key)
            row = {"location": list(location), "source": key}
            if location != ("facts", "@@rules_rs+//rs:extensions.bzl%crate"):
                issues.append({"code": "BAZEL_CHAIN_FACTS_LOCATION_MISMATCH", **row})
                continue
            bazel_rows.append(row)
            if not matched or matched.groups()[:2] != (chain_commit, chain_commit):
                issues.append({"code": "BAZEL_LOCK_CHAIN_MISMATCH", **row, "expected": chain_commit})
            if matched:
                row["package"] = matched.group(3)
                require(isinstance(value, str), "Bazel crate facts must be serialized JSON")
                metadata = load_json(value)
                if not isinstance(metadata, dict) or metadata.get("strip_prefix") != "crates/" + row["package"]:
                    issues.append({"code": "BAZEL_CHAIN_WORKSPACE_MISMATCH", **row})
    bazel_names = [row.get("package") for row in bazel_rows]
    if len(bazel_names) != len(set(bazel_names)) or set(bazel_names) != set(names):
        issues.append({"code": "BAZEL_CARGO_CHAIN_ROSTER_MISMATCH", "bazel": bazel_names, "cargo": names})

    for name in sorted({row["package"] for row in lock_rows}):
        path = "trillionnium/crates/" + name + "/Cargo.toml"
        data = tomllib.loads(chain.read(path).decode())
        if data.get("package", {}).get("name") != name:
            issues.append({"code": "CHAIN_PACKAGE_IDENTITY_MISMATCH", "path": path})
        version = data.get("package", {}).get("version")
        if version == {"workspace": True}:
            workspace = tomllib.loads(chain.read("trillionnium/Cargo.toml").decode())
            version = workspace.get("workspace", {}).get("package", {}).get("version")
        if not isinstance(version, str) or any(row["version"] != version for row in lock_rows if row["package"] == name):
            issues.append({"code": "CHAIN_PACKAGE_VERSION_MISMATCH", "package": name, "expected": version})
    inputs = {"chain": {**chain.identity, "files": [chain.pins[p] for p in sorted(chain.pins)]},
              "hepta": {**hepta.identity, "files": [hepta.pins[p] for p in sorted(hepta.pins)]}}
    return {
        "schema": "trnm-cross-repository-source-inspection-v1",
        "candidate_sha256": hashlib.sha256(canonical(inputs)).hexdigest(), "inputs": inputs,
        "dependency_declarations": declarations, "cargo_chain_packages": lock_rows, "bazel_chain_packages": bazel_rows,
        "issues": issues, "source_dependency_alignment": "PASS" if not issues else "FAIL",
        "scope": "Immutable Git objects and checked-in dependency pins only; not an effective build or native receipt",
        "remote_repository_membership_verified": False,
        "working_tree_verified": False, "effective_build_environment_verified": False,
        "model_material_bytes_verified": False, "release_binary_set_verified": False,
        "native_tests_executed": 0, "complete_candidate_qualified": False,
        "independent_accepted": False, "production_activation": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain-root", required=True, type=Path)
    parser.add_argument("--chain-commit", required=True)
    parser.add_argument("--hepta-root", required=True, type=Path)
    parser.add_argument("--hepta-commit", required=True)
    parser.add_argument("--expected-candidate-sha256")
    args = parser.parse_args()
    try:
        result = inspect(args.chain_root, args.chain_commit, args.hepta_root, args.hepta_commit)
        if args.expected_candidate_sha256 is not None:
            require(args.expected_candidate_sha256 == result["candidate_sha256"], "candidate identity changed")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["source_dependency_alignment"] == "PASS" else 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"schema": "trnm-cross-repository-source-error-v1", "error": str(error),
                          "complete_candidate_qualified": False, "production_activation": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
