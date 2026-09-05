#!/usr/bin/env python3
"""No-Cargo controls for the strict cross-architecture build-report join."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
PREPARE = HERE / "prepare_source_candidate.py"
SPEC = importlib.util.spec_from_file_location(
    "assemble_reproducible_build_report",
    HERE / "assemble_reproducible_build_report.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load build-report assembler")
assembler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assembler
SPEC.loader.exec_module(assembler)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name)
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {result.stdout}{result.stderr}"
        )
    return result


def init_candidate_repo(path: pathlib.Path) -> None:
    path.mkdir()
    run(["git", "-C", str(path), "init", "-q"])
    run(["git", "-C", str(path), "config", "user.email", "test@invalid"])
    run(["git", "-C", str(path), "config", "user.name", "PoCO test"])
    (path / "trillionnium").mkdir()
    (path / "trillionnium/Cargo.lock").write_text(
        "# aggregate fixture lock\nversion = 4\n", encoding="utf-8"
    )
    (path / "candidate.txt").write_text("candidate source bytes\n", encoding="utf-8")
    run(["git", "-C", str(path), "add", "."])
    run(["git", "-C", str(path), "commit", "-qm", "fixture"])


def prepare_candidate(repo: pathlib.Path, path: pathlib.Path, *, strict: bool) -> None:
    arguments = [sys.executable, str(PREPARE), str(repo), "--output", str(path)]
    if strict:
        arguments.append("--require-clean")
    run(arguments)


def write_report(path: pathlib.Path, value: dict[str, object]) -> None:
    path.write_bytes((json.dumps(value, sort_keys=True) + "\n").encode("utf-8"))


def write_executable(path: pathlib.Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o755)


def report(
    candidate: dict[str, Any],
    validator_binary: bytes,
    material_builder: bytes,
    triple: str,
) -> dict[str, object]:
    return {
        "schema_version": 3,
        "source_candidate_sha256": candidate["source_candidate_sha256"],
        "source_candidate_profile": candidate["source_profile"],
        "source_base_commit": candidate["base_commit"],
        "source_git_object_format": candidate["git_object_format"],
        "source_git_tree_oid": candidate["git_tree_oid"],
        "source_git_status_sha256": candidate["git_status_sha256"],
        "cargo_lock_path": candidate["cargo_lock_path"],
        "cargo_lock_sha256": candidate["cargo_lock_sha256"],
        "cargo_lock_bytes": candidate["cargo_lock_bytes"],
        "validator_binary_sha256": digest(validator_binary),
        "validator_binary_bytes": len(validator_binary),
        "material_builder_binary_sha256": digest(material_builder),
        "material_builder_binary_bytes": len(material_builder),
        "host_triple": triple,
        "rustc_vv_sha256": digest(triple.encode("ascii")),
        "reproducible_build": True,
        "independent_build_count": 2,
        "output_validator_binary": "/immutable/validator-candidate",
        "output_material_builder_binary": "/immutable/material-builder-candidate",
        "production_activation": False,
        "geo_wan_evidence": False,
    }


def expect_failure(action, contains: str) -> None:
    try:
        action()
    except SystemExit as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure {error}") from error
    else:
        raise AssertionError("negative control unexpectedly passed")


def assemble(
    candidate: pathlib.Path,
    linux_report: pathlib.Path,
    linux_binary: pathlib.Path,
    linux_material_builder: pathlib.Path,
    macos_report: pathlib.Path,
    macos_binary: pathlib.Path,
    macos_material_builder: pathlib.Path,
) -> dict[str, Any]:
    return assembler.assemble(
        candidate,
        linux_report,
        linux_binary,
        linux_material_builder,
        macos_report,
        macos_binary,
        macos_material_builder,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-build-report-test-") as raw:
        root = pathlib.Path(raw)
        repo = root / "repo"
        init_candidate_repo(repo)
        candidate = root / "source-v2.tar"
        legacy_candidate = root / "source-v1.tar"
        prepare_candidate(repo, candidate, strict=True)
        prepare_candidate(repo, legacy_candidate, strict=False)
        candidate_report = assembler.validated_candidate_sha256(candidate)

        linux_binary = root / "linux.bin"
        linux_material_builder = root / "linux-material-builder.bin"
        macos_binary = root / "macos.bin"
        macos_material_builder = root / "macos-material-builder.bin"
        linux_report = root / "linux.json"
        macos_report = root / "macos.json"
        write_executable(linux_binary, b"linux-binary")
        write_executable(linux_material_builder, b"linux-material-builder")
        write_executable(macos_binary, b"macos-binary")
        write_executable(macos_material_builder, b"macos-material-builder")
        linux = report(
            candidate_report,
            linux_binary.read_bytes(),
            linux_material_builder.read_bytes(),
            "x86_64-unknown-linux-gnu",
        )
        macos = report(
            candidate_report,
            macos_binary.read_bytes(),
            macos_material_builder.read_bytes(),
            "aarch64-apple-darwin",
        )
        write_report(linux_report, linux)
        write_report(macos_report, macos)

        result = assemble(
            candidate,
            linux_report,
            linux_binary,
            linux_material_builder,
            macos_report,
            macos_binary,
            macos_material_builder,
        )
        expected_aggregate = {
            "schema_version": 3,
            "source_tree_sha256": candidate_report["source_candidate_sha256"],
            "source_candidate_profile": candidate_report["source_profile"],
            "source_base_commit": candidate_report["base_commit"],
            "source_git_object_format": candidate_report["git_object_format"],
            "source_git_tree_oid": candidate_report["git_tree_oid"],
            "source_git_status_sha256": candidate_report["git_status_sha256"],
            "cargo_lock_path": candidate_report["cargo_lock_path"],
            "cargo_lock_sha256": candidate_report["cargo_lock_sha256"],
            "cargo_lock_bytes": candidate_report["cargo_lock_bytes"],
        }
        for key, value in expected_aggregate.items():
            if result.get(key) != value:
                raise AssertionError(f"aggregate lost strict field {key}")
        assert result["linux_first_sha256"] == result["linux_second_sha256"]
        assert result["macos_first_sha256"] == result["macos_second_sha256"]
        assert (
            result["linux_material_builder_first_sha256"]
            == result["linux_material_builder_second_sha256"]
        )
        assert (
            result["macos_material_builder_first_sha256"]
            == result["macos_material_builder_second_sha256"]
        )
        aggregate = root / "aggregate.json"
        assembler.write_new(aggregate, result)
        assert json.loads(aggregate.read_text(encoding="utf-8")) == result

        provenance_mutations: tuple[tuple[str, object], ...] = (
            ("source_candidate_profile", "exact-git-visible-worktree-v1"),
            ("source_base_commit", "0" * 40),
            ("source_git_object_format", "sha256"),
            ("source_git_tree_oid", "1" * 40),
            ("source_git_status_sha256", "2" * 64),
            ("cargo_lock_path", "Cargo.lock"),
            ("cargo_lock_sha256", "3" * 64),
            ("cargo_lock_bytes", candidate_report["cargo_lock_bytes"] + 1),
        )
        for architecture in ("linux", "macos"):
            for field, mutation in provenance_mutations:
                changed = dict(linux if architecture == "linux" else macos)
                changed[field] = mutation
                write_report(
                    linux_report if architecture == "linux" else macos_report,
                    changed,
                )
                expect_failure(
                    lambda: assemble(
                        candidate,
                        linux_report,
                        linux_binary,
                        linux_material_builder,
                        macos_report,
                        macos_binary,
                        macos_material_builder,
                    ),
                    f"{architecture}-{'x86_64' if architecture == 'linux' else 'arm64'} report",
                )
                write_report(linux_report, linux)
                write_report(macos_report, macos)

        expect_failure(
            lambda: assemble(
                legacy_candidate,
                linux_report,
                linux_binary,
                linux_material_builder,
                macos_report,
                macos_binary,
                macos_material_builder,
            ),
            "strict source candidate must use clean-commit-v1",
        )

        schema2 = dict(linux)
        schema2["schema_version"] = 2
        for field in (
            "source_candidate_profile",
            "source_base_commit",
            "source_git_object_format",
            "source_git_tree_oid",
            "source_git_status_sha256",
            "cargo_lock_path",
            "cargo_lock_sha256",
            "cargo_lock_bytes",
        ):
            schema2.pop(field)
        write_report(linux_report, schema2)
        expect_failure(
            lambda: assemble(
                candidate,
                linux_report,
                linux_binary,
                linux_material_builder,
                macos_report,
                macos_binary,
                macos_material_builder,
            ),
            "fields differ from the frozen schema",
        )
        write_report(linux_report, linux)

        write_executable(macos_binary, b"substituted")
        expect_failure(
            lambda: assemble(
                candidate,
                linux_report,
                linux_binary,
                linux_material_builder,
                macos_report,
                macos_binary,
                macos_material_builder,
            ),
            "macos-arm64 report",
        )
        write_executable(macos_binary, b"macos-binary")

        write_executable(linux_material_builder, b"substituted-material-builder")
        expect_failure(
            lambda: assemble(
                candidate,
                linux_report,
                linux_binary,
                linux_material_builder,
                macos_report,
                macos_binary,
                macos_material_builder,
            ),
            "linux-x86_64 report",
        )
        write_executable(linux_material_builder, b"linux-material-builder")

        write_executable(linux_material_builder, linux_binary.read_bytes())
        collision = dict(linux)
        collision["material_builder_binary_sha256"] = digest(linux_binary.read_bytes())
        collision["material_builder_binary_bytes"] = len(linux_binary.read_bytes())
        write_report(linux_report, collision)
        expect_failure(
            lambda: assemble(
                candidate,
                linux_report,
                linux_binary,
                linux_material_builder,
                macos_report,
                macos_binary,
                macos_material_builder,
            ),
            "linux-x86_64 report",
        )
        write_executable(linux_material_builder, b"linux-material-builder")
        write_report(linux_report, linux)

        duplicate = root / "duplicate.json"
        duplicate.write_text('{"schema_version":3,"schema_version":3}', encoding="utf-8")
        expect_failure(
            lambda: assembler.read_json(duplicate, "duplicate report"),
            "duplicate JSON object name",
        )
        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(linux, indent=2), encoding="utf-8")
        expect_failure(
            lambda: assembler.read_json(noncanonical, "noncanonical report"),
            "not canonical builder JSON",
        )
        report_link = root / "linux-report-link.json"
        report_link.symlink_to(linux_report)
        expect_failure(
            lambda: assembler.read_json(report_link, "linked report"),
            "regular non-symlink",
        )
        binary_link = root / "linux-binary-link"
        binary_link.symlink_to(linux_binary)
        expect_failure(
            lambda: assemble(
                candidate,
                linux_report,
                binary_link,
                linux_material_builder,
                macos_report,
                macos_binary,
                macos_material_builder,
            ),
            "regular non-symlink",
        )
        invalid_candidate = root / "invalid-source.tar"
        invalid_candidate.write_bytes(b"not a canonical candidate")
        expect_failure(
            lambda: assemble(
                invalid_candidate,
                linux_report,
                linux_binary,
                linux_material_builder,
                macos_report,
                macos_binary,
                macos_material_builder,
            ),
            "failed independent validation",
        )

        output_parent = root / "real-output-parent"
        output_parent.mkdir()
        output_parent_link = root / "linked-output-parent"
        output_parent_link.symlink_to(output_parent, target_is_directory=True)
        expect_failure(
            lambda: assembler.write_new(output_parent_link / "report.json", result),
            "real non-symlink directory",
        )
        expect_failure(
            lambda: assembler.write_new(aggregate, result),
            "already exists",
        )

    print(
        "poco_g3_reproducible_build_report_test=passed strict_candidate=true "
        "schema3_provenance=true both_architectures_bound=true "
        "legacy_candidate_rejected=true schema2_local_rejected=true "
        "validator_binary_bytes_rehashed=true material_builder_bytes_rehashed=true "
        "input_inode_pinned=true output_inode_pinned=true unique_json=true "
        "actual_build_executed=false production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
