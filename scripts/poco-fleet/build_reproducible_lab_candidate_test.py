#!/usr/bin/env python3
"""No-Cargo boundary tests for the native reproducible candidate builder."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = load("build_reproducible_lab_candidate", "build_reproducible_lab_candidate.py")
source_builder = load("prepare_source_candidate", "prepare_source_candidate.py")


def expect_failure(action, contains: str) -> None:
    try:
        action()
    except SystemExit as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure {error}") from error
    else:
        raise AssertionError("negative control unexpectedly passed")


def main() -> None:
    ambient_controls = {
        "RUSTFLAGS": "-C opt-level=0",
        "RUSTC_BOOTSTRAP": "1",
        "CARGO_PROFILE_RELEASE_LTO": "false",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/tmp/linker",
        "CARGO_BUILD_TARGET": "foreign-target",
        "CARGO_REGISTRIES_CRATES_IO_INDEX": "file:///tmp/registry",
        "CC": "/tmp/cc",
        "LDFLAGS": "-L/tmp/lib",
        "SDKROOT": "/tmp/sdk",
        "PKG_CONFIG_PATH": "/tmp/pkgconfig",
        "BINDGEN_EXTRA_CLANG_ARGS": "-I/tmp/include",
        "OPENSSL_DIR": "/tmp/openssl",
    }
    observed = builder.ambient_override_names(ambient_controls)
    if observed != sorted(ambient_controls):
        raise AssertionError(f"ambient override inventory differs: {observed}")
    if builder.ambient_override_names(
        {
            "PATH": "/usr/bin:/bin",
            "HOME": "/private/build-home",
            "CARGO_HOME": "/private/cargo-home",
            "RUSTUP_HOME": "/private/rustup-home",
        }
    ):
        raise AssertionError("closed environment allowlist was treated as an override")
    git_overrides = source_builder.ambient_git_override_names(
        {
            "GIT_INDEX_FILE": "/tmp/index",
            "GIT_CONFIG_PARAMETERS": "'core.excludesfile=/tmp/ignore'",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.excludesfile",
            "GIT_CONFIG_VALUE_0": "/tmp/ignore",
            "GIT_PAGER": "cat",
        }
    )
    if git_overrides != [
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_VALUE_0",
        "GIT_INDEX_FILE",
    ]:
        raise AssertionError(f"Git authority override inventory differs: {git_overrides}")

    lock_payload = b"# exact Cargo.lock\n"
    strict_report = {
        "source_candidate_sha256": "1" * 64,
        "archive_bytes": 10240,
        "file_count": 2,
        "source_bytes": len(lock_payload) + 1,
        "source_profile": "clean-commit-v1",
        "base_commit": "2" * 40,
        "git_object_format": "sha1",
        "git_tree_oid": "3" * 40,
        "git_status_sha256": builder.EMPTY_STATUS_SHA256,
        "cargo_lock_path": builder.CARGO_LOCK_PATH,
        "cargo_lock_sha256": hashlib.sha256(lock_payload).hexdigest(),
        "cargo_lock_bytes": len(lock_payload),
        "production_activation": False,
        "geo_wan_evidence": False,
    }
    checked = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(strict_report, sort_keys=True),
        stderr="",
    )
    with mock.patch.object(builder.subprocess, "run", return_value=checked) as invoke:
        observed_report = builder.run_candidate_checker(pathlib.Path("candidate.tar"))
    if observed_report != strict_report:
        raise AssertionError("strict checker report changed during exact parsing")
    invocation = invoke.call_args.args[0]
    if invocation[-1] != "--require-clean" or str(builder.CHECK) not in invocation:
        raise AssertionError("formal builder did not require the strict checker profile")
    for name, mutation in (
        ("legacy-profile", {"source_profile": "exact-git-visible-worktree-v1"}),
        ("dirty-status", {"git_status_sha256": "4" * 64}),
        ("wrong-tree", {"git_tree_oid": "5" * 64}),
        ("bool-lock-bytes", {"cargo_lock_bytes": True}),
    ):
        candidate_report = dict(strict_report)
        candidate_report.update(mutation)
        expect_failure(
            lambda candidate_report=candidate_report: builder.validate_strict_candidate_report(
                candidate_report
            ),
            "non-canonical strict result",
        )
    missing = dict(strict_report)
    missing.pop("cargo_lock_sha256")
    expect_failure(
        lambda: builder.validate_strict_candidate_report(missing),
        "fields outside the strict contract",
    )

    with tempfile.TemporaryDirectory(prefix="poco-g3-builder-boundary-") as raw:
        root = pathlib.Path(raw)
        cargo_home = root / "cargo-home"
        cargo_home.mkdir()
        builder.reject_cargo_home_configs(cargo_home)
        source = root / "source"
        source.mkdir()
        builder.reject_ambient_ancestor_configs(source)

        left_source = root / "left-source"
        right_source = root / "right-source"
        for extracted in (left_source, right_source):
            (extracted / "trillionnium").mkdir(parents=True)
            (extracted / builder.CARGO_LOCK_PATH).write_bytes(lock_payload)
            builder.verify_cargo_lock(extracted, strict_report)
        fake_result = builder.BuildResultV1(
            binaries={}, rustc_vv=b"rustc 1.95.0\nhost: x86_64-unknown-linux-gnu\n"
        )
        with mock.patch.object(builder, "build", side_effect=[fake_result, fake_result]) as builds:
            pair = builder.build_verified_pair(
                left_source,
                right_source,
                root / "left-target",
                root / "right-target",
                cargo_home,
                strict_report,
            )
        if pair != (fake_result, fake_result) or builds.call_count != 2:
            raise AssertionError("verified pair did not execute exactly two mocked builds")

        (right_source / builder.CARGO_LOCK_PATH).write_bytes(b"wrong lock\n")
        with mock.patch.object(builder, "build") as builds:
            expect_failure(
                lambda: builder.build_verified_pair(
                    left_source,
                    right_source,
                    root / "bad-left-target",
                    root / "bad-right-target",
                    cargo_home,
                    strict_report,
                ),
                "differs from strict candidate report",
            )
            if builds.call_count != 0:
                raise AssertionError("Cargo/build was reached before both locks passed")
        (right_source / builder.CARGO_LOCK_PATH).unlink()
        with mock.patch.object(builder, "build") as builds:
            try:
                builder.build_verified_pair(
                    left_source,
                    right_source,
                    root / "missing-left-target",
                    root / "missing-right-target",
                    cargo_home,
                    strict_report,
                )
            except FileNotFoundError:
                pass
            else:
                raise AssertionError("missing right Cargo.lock unexpectedly passed")
            if builds.call_count != 0:
                raise AssertionError("build was reached with a missing right Cargo.lock")
        with mock.patch.dict(
            builder.os.environ,
            {
                "PATH": "/usr/bin:/bin",
                "HOME": str(root),
                "UNDECLARED_BUILD_INPUT": "must-not-cross",
            },
            clear=True,
        ):
            closed_environment = builder.isolated_build_environment(
                source, root / "target-control", cargo_home
            )
        if "UNDECLARED_BUILD_INPUT" in closed_environment or set(closed_environment) != {
            "PATH",
            "HOME",
            "TMPDIR",
            "CARGO_INCREMENTAL",
            "CARGO_NET_OFFLINE",
            "CARGO_TERM_COLOR",
            "CARGO_TARGET_DIR",
            "CARGO_HOME",
            "SOURCE_DATE_EPOCH",
            "TZ",
            "LC_ALL",
            "LANG",
            "RUSTFLAGS",
        }:
            raise AssertionError("isolated build environment is not closed")
        with mock.patch.dict(
            builder.os.environ,
            {"PATH": "relative-bin:/usr/bin", "HOME": str(root)},
            clear=True,
        ):
            expect_failure(
                lambda: builder.isolated_build_environment(
                    source, root / "target-relative-path", cargo_home
                ),
                "absolute non-empty entries",
            )

        cargo_config = cargo_home / "config.toml"
        cargo_config.write_text("[build]\ntarget = 'ambient'\n", encoding="utf-8")
        expect_failure(
            lambda: builder.reject_cargo_home_configs(cargo_home),
            "ambient Cargo config is forbidden",
        )
        cargo_config.unlink()

        source_cargo = source / ".cargo"
        source_cargo.mkdir()
        (source_cargo / "config").write_text(
            "[source.crates-io]\nreplace-with = 'ambient'\n", encoding="utf-8"
        )
        expect_failure(
            lambda: builder.reject_ambient_ancestor_configs(source),
            "ambient ancestor Cargo config is forbidden",
        )
        (source_cargo / "config").unlink()
        source_cargo.rmdir()

        candidate = root / "candidate.tar"
        candidate.write_bytes(b"frozen candidate bytes")
        frozen_candidate = root / "frozen-candidate.tar"
        builder.freeze_candidate(candidate, frozen_candidate)
        if frozen_candidate.read_bytes() != candidate.read_bytes():
            raise AssertionError("candidate pinned copy changed bytes")
        candidate_link = root / "candidate-link.tar"
        candidate_link.symlink_to(candidate)
        expect_failure(
            lambda: builder.freeze_candidate(candidate_link, root / "bad-copy.tar"),
            "regular non-symlink",
        )

        binary = root / "candidate-binary"
        binary.write_bytes(b"native executable bytes")
        binary.chmod(0o755)
        frozen_binary = builder.freeze_binary(binary, "candidate binary")
        if frozen_binary.payload != binary.read_bytes():
            raise AssertionError("binary pinned read changed bytes")
        binary_link = root / "candidate-binary-link"
        binary_link.symlink_to(binary)
        expect_failure(
            lambda: builder.freeze_binary(binary_link, "linked binary"),
            "regular non-symlink",
        )
        non_executable = root / "non-executable"
        non_executable.write_bytes(b"not executable")
        expect_failure(
            lambda: builder.freeze_binary(non_executable, "non-executable binary"),
            "bounded executable regular",
        )

        outputs = root / "outputs"
        outputs.mkdir()
        output = outputs / "validator"
        slot = builder.prepare_output_slot(output, "validator")
        try:
            builder.emit_binary(frozen_binary.payload, slot)
            emitted = builder.freeze_emitted_binary(slot, "emitted validator")
            if emitted != frozen_binary:
                raise AssertionError("emitted binary differs from pinned build bytes")
        finally:
            builder.unlink_owned_output(slot)
            builder.os.close(slot.parent_fd)

        substituted = outputs / "substituted"
        substituted_slot = builder.prepare_output_slot(substituted, "substituted")
        try:
            builder.emit_binary(frozen_binary.payload, substituted_slot)
            displaced = outputs / "owned-displaced"
            substituted.rename(displaced)
            substituted.write_bytes(b"unowned replacement")
            substituted.chmod(0o755)
            expect_failure(
                lambda: builder.freeze_emitted_binary(
                    substituted_slot, "substituted output"
                ),
                "changed identity",
            )
            builder.unlink_owned_output(substituted_slot)
            if substituted.read_bytes() != b"unowned replacement":
                raise AssertionError("cleanup deleted or changed an unowned replacement")
        finally:
            builder.os.close(substituted_slot.parent_fd)

        output_parent_link = root / "outputs-link"
        output_parent_link.symlink_to(outputs, target_is_directory=True)
        expect_failure(
            lambda: builder.prepare_output_slot(
                output_parent_link / "linked-parent-output", "linked-parent"
            ),
            "real non-symlink directory",
        )
        existing = outputs / "existing"
        existing.write_bytes(b"preexisting")
        expect_failure(
            lambda: builder.prepare_output_slot(existing, "existing"),
            "already exists",
        )

        report_slots = {
            "validator": builder.OutputSlotV1(
                root / "validator-output", -1, 0, 0, "validator-output"
            ),
            "material_builder": builder.OutputSlotV1(
                root / "material-output", -1, 0, 0, "material-output"
            ),
        }
        local_report = builder.make_build_report(
            strict_report,
            {"validator": "6" * 64, "material_builder": "7" * 64},
            {"validator": 11, "material_builder": 12},
            b"rustc 1.95.0\nhost: x86_64-unknown-linux-gnu\n",
            report_slots,
        )
        expected_provenance = {
            "schema_version": 3,
            "source_candidate_profile": strict_report["source_profile"],
            "source_base_commit": strict_report["base_commit"],
            "source_git_object_format": strict_report["git_object_format"],
            "source_git_tree_oid": strict_report["git_tree_oid"],
            "source_git_status_sha256": strict_report["git_status_sha256"],
            "cargo_lock_path": strict_report["cargo_lock_path"],
            "cargo_lock_sha256": strict_report["cargo_lock_sha256"],
            "cargo_lock_bytes": strict_report["cargo_lock_bytes"],
        }
        for key, expected in expected_provenance.items():
            if local_report.get(key) != expected:
                raise AssertionError(f"schema-3 report lost strict field {key}")

    print(
        "poco_g3_reproducible_builder_boundary_test=passed "
        f"ambient_overrides={len(ambient_controls)} git_authority_overrides=5 "
        "all_cargo_configs_rejected=true closed_build_environment=true "
        "candidate_inode_pinned=true strict_checker_required=true "
        "cargo_lock_verified_before_build=true schema3_provenance=true "
        "binary_inode_pinned=true output_inode_pinned=true "
        "unowned_replacement_preserved=true actual_build_executed=false "
        "production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
