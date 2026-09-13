#!/usr/bin/env python3
"""No-Cargo boundary tests for the rust-src canonical-remap v2 builder."""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
BUILDER = HERE / "build_reproducible_lab_candidate_v2.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("poco_g3_repro_builder_v2_test", BUILDER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load v2 builder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = load_builder()


def expect_failure(callback, expected: str) -> None:
    try:
        callback()
    except SystemExit as error:
        if expected not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError(f"expected failure containing: {expected}")


def sysroot_result(path: str, *, stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        ["rustc", "--print", "sysroot"], 0, stdout=f"{path}\n".encode(), stderr=stderr
    )


def main() -> None:
    rustc_commit = "59807616e1fa2540724bfbac14d7976d7e4a3860"
    rustc_vv = (
        "rustc 1.95.0 (59807616e 2026-04-14)\n"
        f"commit-hash: {rustc_commit}\n"
        "host: x86_64-unknown-linux-gnu\n"
    ).encode()
    environment = {"RUSTFLAGS": "--remap-path-prefix=/input=/src"}

    with tempfile.TemporaryDirectory(prefix="poco-g3-rust-src-remap-v2-") as raw:
        root = pathlib.Path(raw)
        source = root / "source"
        source.mkdir()
        sysroot = root / "rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu"
        rust_source = sysroot / "lib/rustlib/src/rust"
        (rust_source / "library").mkdir(parents=True)
        result = sysroot_result(str(sysroot))
        with mock.patch.object(builder.subprocess, "run", return_value=result) as run:
            bound = builder.bind_rustc_source_remap(source, environment, rustc_vv)
        run.assert_called_once_with(
            ["rustc", "--print", "sysroot"],
            check=True,
            cwd=source,
            env=environment,
            capture_output=True,
        )
        expected = f"--remap-path-prefix={rust_source}=/rustc/{rustc_commit}"
        if bound["RUSTFLAGS"].split()[-1] != expected:
            raise AssertionError("installed rust-src lacks the exact canonical mapping")
        if environment != {"RUSTFLAGS": "--remap-path-prefix=/input=/src"}:
            raise AssertionError("caller environment was mutated")
        if builder.v1.build is not builder.build:
            raise AssertionError("v1 main was not bound to the v2 native build seam")

        absent = root / "rustup/toolchains/no-rust-src"
        absent.mkdir(parents=True)
        with mock.patch.object(
            builder.subprocess, "run", return_value=sysroot_result(str(absent))
        ):
            if builder.bind_rustc_source_remap(source, environment, rustc_vv) != environment:
                raise AssertionError("absent rust-src unexpectedly changed the environment")

        malformed_vv = rustc_vv.replace(rustc_commit.encode(), b"0" * 39)
        expect_failure(
            lambda: builder.bind_rustc_source_remap(source, environment, malformed_vv),
            "lacks one exact commit hash",
        )
        duplicate_vv = rustc_vv + f"commit-hash: {rustc_commit}\n".encode()
        expect_failure(
            lambda: builder.bind_rustc_source_remap(source, environment, duplicate_vv),
            "lacks one exact commit hash",
        )

        with mock.patch.object(
            builder.subprocess,
            "run",
            return_value=sysroot_result("relative-sysroot"),
        ):
            expect_failure(
                lambda: builder.bind_rustc_source_remap(source, environment, rustc_vv),
                "sysroot is not absolute",
            )

        symlink_sysroot = root / "rustup/toolchains/symlink-rust-src"
        symlink_parent = symlink_sysroot / "lib/rustlib/src"
        symlink_parent.mkdir(parents=True)
        symlink_target = root / "rust-source-target"
        symlink_target.mkdir()
        (symlink_parent / "rust").symlink_to(symlink_target, target_is_directory=True)
        with mock.patch.object(
            builder.subprocess,
            "run",
            return_value=sysroot_result(str(symlink_sysroot)),
        ):
            expect_failure(
                lambda: builder.bind_rustc_source_remap(source, environment, rustc_vv),
                "rust-src root must be one real directory",
            )

        with mock.patch.object(
            builder.subprocess,
            "run",
            return_value=sysroot_result(str(sysroot), stderr=b"unexpected"),
        ):
            expect_failure(
                lambda: builder.bind_rustc_source_remap(source, environment, rustc_vv),
                "sysroot output crosses its exact bound",
            )

        with mock.patch.object(builder.subprocess, "run", return_value=result):
            expect_failure(
                lambda: builder.bind_rustc_source_remap(source, {}, rustc_vv),
                "lacks one bounded RUSTFLAGS value",
            )

    print(
        "poco_g3_reproducible_builder_v2_boundary_test=passed "
        "v1_evidence_bytes_unchanged=true rust_src_canonical_remap=true "
        "absent_rust_src_compatible=true malformed_and_duplicate_commit=fail-closed "
        "relative_sysroot=fail-closed symlink_rust_src=fail-closed "
        "unexpected_stderr=fail-closed actual_build_executed=false "
        "production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
