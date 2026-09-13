#!/usr/bin/env python3
"""M17: select an exact, complete runner Node cache; never install or download.

The administrator-provisioned RUNNER_TOOL_CACHE is the authority, as it is for
setup-node's cache path. This is not an attestation against a compromised runner
or concurrent same-UID modification. No system-PATH or network fallback exists.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


class NodeProvisionError(RuntimeError):
    pass


def exact_version(value: str) -> str:
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value):
        raise NodeProvisionError("an exact numeric Node version is required")
    return value


def regular_inside(path: Path, root: Path, *, executable: bool = False) -> Path:
    target = path.resolve(strict=True)
    if not target.is_relative_to(root) or not target.is_file():
        raise NodeProvisionError("cache entry escapes its version tree or is not a file")
    if executable and not os.access(target, os.X_OK):
        raise NodeProvisionError("Node cache executable is not executable")
    return target


def select_node(cache: Path, version: str, *, architecture: str = "x64") -> dict[str, str]:
    exact_version(version)
    if architecture not in {"x64", "arm64"}:
        raise NodeProvisionError("unsupported Node architecture")
    if not cache.is_absolute() or any(c in str(cache) for c in "\r\n\0"):
        raise NodeProvisionError("RUNNER_TOOL_CACHE must be an absolute single-line path")
    root = cache.resolve(strict=True)
    tool = root / "node" / version / architecture
    # Match the completion sentinel required by @actions/tool-cache.find().
    marker = Path(str(tool) + ".complete")
    if not marker.is_file() or marker.is_symlink():
        raise NodeProvisionError("exact Node cache is missing its completion marker; provision it out of band")
    if tool.is_symlink():
        raise NodeProvisionError("Node cache architecture directory must not be a symlink")
    resolved_tool = tool.resolve(strict=True)
    if not resolved_tool.is_relative_to(root):
        raise NodeProvisionError("Node cache version escapes RUNNER_TOOL_CACHE")
    node = regular_inside(tool / "bin/node", resolved_tool, executable=True)
    npm = regular_inside(tool / "bin/npm", resolved_tool)
    npx = regular_inside(tool / "bin/npx", resolved_tool)
    # Check the runner's existing command authority; never change it. Operators
    # must provision the exact cache into the service environment before a job.
    for command, expected in (("node", node), ("npm", npm), ("npx", npx)):
        current = shutil.which(command)
        if current is None or Path(current).resolve(strict=True) != expected:
            raise NodeProvisionError(f"runner command {command} is not the exact provisioned cache executable")
    env = os.environ.copy()
    # Do not permit startup hooks to alter the identity/version probe.
    for key in ("NODE_OPTIONS", "NODE_PATH"):
        if env.get(key):
            raise NodeProvisionError(f"{key} must not override the pinned Node runtime")
    result = subprocess.run(
        [str(node), "-p", "JSON.stringify({version:process.versions.node,arch:process.arch,platform:process.platform})"],
        check=True, capture_output=True, text=True, timeout=15, env=env,
    )
    identity = json.loads(result.stdout)
    if identity != {"version": version, "arch": architecture, "platform": "linux"}:
        raise NodeProvisionError("cached Node runtime identity does not match the exact Linux version/architecture")
    npm_result = subprocess.run([str(node), str(npm), "--version"], check=True,
                                capture_output=True, text=True, timeout=15, env=env)
    npm_version = npm_result.stdout.strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", npm_version):
        raise NodeProvisionError("cached npm did not report a release version")
    return {"schema": "trnm-preprovisioned-node-v1", "version": version,
            "architecture": architecture, "platform": "linux", "npm_version": npm_version,
            "bin": str(tool / "bin"), "node": str(node), "npm": str(npm), "npx": str(npx)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    versions = parser.add_mutually_exclusive_group(required=True)
    versions.add_argument("--version")
    versions.add_argument("--version-file", type=Path)
    parser.add_argument("--architecture", choices=("x64", "arm64"), default="x64")
    args = parser.parse_args(argv)
    try:
        version = args.version
        if args.version_file is not None:
            version = args.version_file.read_text(encoding="utf-8").strip()
        cache_value = os.environ.get("RUNNER_TOOL_CACHE", "")
        if not cache_value:
            raise NodeProvisionError("RUNNER_TOOL_CACHE is required; no network or PATH fallback")
        report = select_node(Path(cache_value), exact_version(version), architecture=args.architecture)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (NodeProvisionError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"preprovisioned_node=FAIL: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
