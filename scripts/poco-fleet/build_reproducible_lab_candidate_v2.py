#!/usr/bin/env python3
"""Build the Stage0 lab candidate with a canonical rust-src source root.

The v1 builder is evidence-bound and therefore remains byte-for-byte frozen.
This v2 entry point reuses that audited boundary while replacing only its
native build step.  The replacement maps an installed physical rust-src tree
to rustc's virtual ``/rustc/<commit>`` root before Cargo may run.  Without the
mapping, installing rust-src can change release binary bytes even when the
source candidate, Cargo.lock, compiler, target, and two-build result agree.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile


HERE = pathlib.Path(__file__).resolve().parent
V1_PATH = HERE / "build_reproducible_lab_candidate.py"
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def load_v1():
    spec = importlib.util.spec_from_file_location(
        "poco_g3_reproducible_lab_candidate_v1", V1_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the evidence-bound v1 builder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


v1 = load_v1()


def bind_rustc_source_remap(
    source: pathlib.Path,
    environment: dict[str, str],
    rustc_vv: bytes,
) -> dict[str, str]:
    """Map an installed rust-src tree to rustc's canonical virtual root."""

    try:
        version_text = rustc_vv.decode("utf-8")
    except UnicodeDecodeError as error:
        v1.fail(f"candidate-selected rustc -vV is not UTF-8: {error}")
    commit_lines = [
        line.removeprefix("commit-hash: ")
        for line in version_text.splitlines()
        if line.startswith("commit-hash: ")
    ]
    if len(commit_lines) != 1 or HEX40.fullmatch(commit_lines[0]) is None:
        v1.fail("candidate-selected rustc -vV lacks one exact commit hash")
    commit_hash = commit_lines[0]

    result = subprocess.run(
        ["rustc", "--print", "sysroot"],
        check=True,
        cwd=source,
        env=environment,
        capture_output=True,
    )
    if not result.stdout or len(result.stdout) > 64 * 1024 or result.stderr:
        v1.fail("candidate-selected rustc sysroot output crosses its exact bound")
    try:
        sysroot_text = result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        v1.fail(f"candidate-selected rustc sysroot is not UTF-8: {error}")
    if sysroot_text.count("\n") != 1 or not sysroot_text.endswith("\n"):
        v1.fail("candidate-selected rustc sysroot is not one exact line")
    unresolved_sysroot = pathlib.Path(sysroot_text[:-1])
    if not unresolved_sysroot.is_absolute():
        v1.fail("candidate-selected rustc sysroot is not absolute")
    try:
        sysroot_metadata = unresolved_sysroot.lstat()
        sysroot = unresolved_sysroot.resolve(strict=True)
    except OSError as error:
        v1.fail(f"cannot resolve candidate-selected rustc sysroot: {error}")
    if (
        unresolved_sysroot != sysroot
        or unresolved_sysroot.is_symlink()
        or not stat.S_ISDIR(sysroot_metadata.st_mode)
    ):
        v1.fail("candidate-selected rustc sysroot must be one real directory")

    unresolved_rust_source = sysroot / "lib/rustlib/src/rust"
    if not unresolved_rust_source.exists() and not unresolved_rust_source.is_symlink():
        return dict(environment)
    try:
        source_metadata = unresolved_rust_source.lstat()
        rust_source = unresolved_rust_source.resolve(strict=True)
    except OSError as error:
        v1.fail(f"cannot resolve candidate-selected rust-src root: {error}")
    if (
        unresolved_rust_source != rust_source
        or unresolved_rust_source.is_symlink()
        or not stat.S_ISDIR(source_metadata.st_mode)
    ):
        v1.fail("candidate-selected rust-src root must be one real directory")

    rustflags = environment.get("RUSTFLAGS")
    if rustflags is None or "\n" in rustflags or "\r" in rustflags:
        v1.fail("isolated build environment lacks one bounded RUSTFLAGS value")
    bound = dict(environment)
    bound["RUSTFLAGS"] = (
        f"{rustflags} --remap-path-prefix={rust_source}=/rustc/{commit_hash}"
    )
    return bound


def build(
    source: pathlib.Path,
    target: pathlib.Path,
    cargo_home: pathlib.Path,
):
    """Run the v1 native build boundary with the additional canonical map."""

    manifest = source / "trillionnium/Cargo.toml"
    if not manifest.is_file() or manifest.is_symlink():
        v1.fail("candidate lacks the active Trillionnium Cargo workspace")
    v1.reject_cargo_home_configs(cargo_home)
    v1.reject_ambient_ancestor_configs(source)
    environment = v1.isolated_build_environment(source, target, cargo_home)
    rustc_before = v1.rustc_version(source, environment)
    environment = bind_rustc_source_remap(source, environment, rustc_before)
    if v1.rustc_version(source, environment) != rustc_before:
        v1.fail("candidate-selected rustc changed while binding its source root")
    subprocess.run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(manifest),
            "--locked",
            "--offline",
            "--release",
            "-p",
            v1.PACKAGE,
            "--bin",
            v1.VALIDATOR_BINARY,
            "--bin",
            v1.MATERIAL_BUILDER_BINARY,
        ],
        check=True,
        cwd=source,
        env=environment,
        stdout=sys.stderr,
    )
    v1.reject_cargo_home_configs(cargo_home)
    v1.reject_ambient_ancestor_configs(source)
    rustc_after = v1.rustc_version(source, environment)
    if rustc_before != rustc_after:
        v1.fail("candidate-selected rustc changed across the native build")
    binaries = {
        "validator": target / "release" / v1.VALIDATOR_BINARY,
        "material_builder": target / "release" / v1.MATERIAL_BUILDER_BINARY,
    }
    for role, binary in binaries.items():
        if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
            v1.fail(f"Cargo did not emit one executable regular {role} binary")
    return v1.BuildResultV1(binaries=binaries, rustc_vv=rustc_after)


# v1 main resolves this global from its own module. Replace only that seam;
# candidate pinning, extraction, independent-build comparison, output inode
# pinning, and schema-3 reporting stay on the frozen implementation.
v1.build = build


if __name__ == "__main__":
    try:
        v1.main()
    except (OSError, subprocess.SubprocessError, tarfile.TarError, ValueError) as error:
        v1.fail(str(error))
