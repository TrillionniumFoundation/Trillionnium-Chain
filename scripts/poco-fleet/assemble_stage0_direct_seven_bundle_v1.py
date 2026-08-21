#!/usr/bin/env python3
"""Assemble one immutable, public-only Stage0 direct-seven observation bundle.

The assembler copies exact already-produced evidence.  It never runs Cargo,
starts validators, creates signatures, changes runner truth bits, or copies the
coordinator's private keys.  The independent checker must derive the scoped
observation from the copied raw bytes before the new directory is retained.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import sys
import tarfile
from dataclasses import dataclass
from typing import Any, NoReturn


HERE = pathlib.Path(__file__).resolve().parent
SOURCE_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import check_stage0_direct_seven_bundle_v1 as checker  # noqa: E402
import run_consensus_fleet as consensus_runner  # noqa: E402


@dataclass(frozen=True)
class SourceSnapshot:
    root_device: int
    root_inode: int
    files: tuple[tuple[str, int, int, int, int, int, int], ...]


def fail(message: str) -> NoReturn:
    raise SystemExit(f"PoCO G3 Stage0 direct-seven assembler failed: {message}")


def existing_regular(
    raw: pathlib.Path,
    field: str,
    *,
    allow_empty: bool = False,
) -> pathlib.Path:
    path = pathlib.Path(raw).absolute()
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {field}: {error}")
    if (
        resolved != path
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (not allow_empty and metadata.st_size <= 0)
        or metadata.st_size > checker.MAXIMUM_FILE_BYTES
    ):
        fail(f"{field} must be one bounded regular non-symlink, non-hardlinked file")
    return path


def existing_root(raw: pathlib.Path, field: str) -> pathlib.Path:
    try:
        return checker.real_root(pathlib.Path(raw), field)
    except SystemExit as error:
        fail(str(error))


def disjoint_output(raw: pathlib.Path, inputs: tuple[pathlib.Path, ...]) -> pathlib.Path:
    output = pathlib.Path(os.path.abspath(raw))
    if output.exists() or output.is_symlink():
        fail("output already exists; observation bundles are immutable")
    try:
        parent_metadata = output.parent.lstat()
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve output parent: {error}")
    if (
        parent != output.parent
        or stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
    ):
        fail("output parent must be one real non-symlink directory")
    output = parent / output.name
    source_root = SOURCE_ROOT.resolve(strict=True)
    if output == source_root or source_root in output.parents or output in source_root.parents:
        fail("output must remain outside and disjoint from the source tree")
    for source in inputs:
        resolved = source.resolve(strict=True)
        if output == resolved or output in resolved.parents or resolved in output.parents:
            fail("output must remain disjoint from every input path")
    return output


def snapshot_tree(root: pathlib.Path, *, include: set[str] | None = None) -> SourceSnapshot:
    root = existing_root(root, "input root")
    root_metadata = root.stat()
    records: list[tuple[str, int, int, int, int, int, int]] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"input root contains symbolic link {relative!r}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"input root contains a non-regular or hardlinked entry {relative!r}")
        if include is None or relative in include:
            records.append(
                (
                    relative,
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )
            )
    if include is not None and {item[0] for item in records} != include:
        fail("input root omits one exact referenced file")
    return SourceSnapshot(root_metadata.st_dev, root_metadata.st_ino, tuple(sorted(records)))


def copy_pinned(
    source: pathlib.Path,
    target: pathlib.Path,
    field: str,
    *,
    executable: bool = False,
    allow_empty: bool = False,
) -> dict[str, Any]:
    source = existing_regular(source, field, allow_empty=allow_empty)
    before = source.stat()
    source_descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target_descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o500 if executable else 0o400,
    )
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(source_descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        expected = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if identity != expected:
            fail(f"{field} changed identity while opening")
        remaining = opened.st_size
        while remaining:
            chunk = os.read(source_descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} truncated during its pinned copy")
            pending = memoryview(chunk)
            while pending:
                written = os.write(target_descriptor, pending)
                if written <= 0:
                    fail(f"{field} could not make progress during its pinned copy")
                pending = pending[written:]
            digest.update(chunk)
            remaining -= len(chunk)
            size += len(chunk)
        if os.read(source_descriptor, 1):
            fail(f"{field} grew during its pinned copy")
        os.fsync(target_descriptor)
        after = os.fstat(source_descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != identity:
            fail(f"{field} changed during its pinned copy")
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_descriptor)
        os.close(target_descriptor)
    if size == 0 and not allow_empty:
        target.unlink(missing_ok=True)
        fail(f"{field} is empty")
    return {"sha256": digest.hexdigest(), "bytes": size}


def write_new(path: pathlib.Path, content: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o500 if executable else 0o400,
    )
    try:
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                fail(f"could not make progress while writing {path}")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def coordinator_public_paths(root: pathlib.Path) -> tuple[dict[str, Any], set[str]]:
    document = checker.strict_json(root / "manifest.json", "coordinator manifest")
    values = document.get("public_files")
    if not isinstance(values, list):
        fail("coordinator manifest public_files must be a list")
    paths = {"manifest.json"}
    for index, raw in enumerate(values):
        reference = checker.exact(
            raw, {"path", "sha256", "bytes"}, f"coordinator public_files[{index}]"
        )
        relative = checker.safe_relative(
            reference["path"], f"coordinator public_files[{index}].path"
        ).as_posix()
        if relative in paths:
            fail("coordinator public file paths must be unique")
        paths.add(relative)
    return document, paths


def runner_paths(
    root: pathlib.Path,
    *,
    run_id: str,
    coordinator_anchor: str,
) -> tuple[dict[str, Any], set[str]]:
    try:
        manifest = consensus_runner.validate_runner_output_manifest(
            root,
            expected_run_id=run_id,
            expected_validator_count=checker.VALIDATOR_COUNT,
            expected_coordinator_anchor=coordinator_anchor,
        )
    except SystemExit as error:
        fail(f"runner output failed its sealed-manifest validation: {error}")
    paths = {consensus_runner.RUNNER_OUTPUT_MANIFEST}
    paths.update(item["path"] for item in manifest["artifacts"])
    return manifest, paths


def artifact_records(root: pathlib.Path) -> list[dict[str, Any]]:
    expected = checker.expected_artifact_identities(root)
    records: list[dict[str, Any]] = []
    for relative, (role, subject) in expected.items():
        path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
        allow_empty = role in {"validator_process_stdout", "validator_process_stderr"}
        _payload, fact = checker.read_pinned(path, relative, allow_empty=allow_empty)
        records.append(
            {
                "role": role,
                "subject": subject,
                "path": relative,
                "sha256": fact.sha256,
                "bytes": fact.bytes,
            }
        )
    records.sort(key=lambda item: (item["role"], item["subject"], item["path"]))
    return records


def assemble(
    *,
    candidate_source: pathlib.Path,
    aggregate_build_report: pathlib.Path,
    linux_validator_binary: pathlib.Path,
    linux_material_builder_binary: pathlib.Path,
    macos_validator_binary: pathlib.Path,
    macos_material_builder_binary: pathlib.Path,
    fleet_inventory: pathlib.Path,
    probe_fleet: pathlib.Path,
    run_readiness: pathlib.Path,
    coordinator_root: pathlib.Path,
    runner_output: pathlib.Path,
    coordinator_manifest_sha256: str,
    output: pathlib.Path,
) -> pathlib.Path:
    if not isinstance(coordinator_manifest_sha256, str) or checker.HEX64.fullmatch(
        coordinator_manifest_sha256
    ) is None:
        fail("out-of-band coordinator manifest anchor must be canonical SHA-256")
    candidate_source = existing_regular(candidate_source, "source candidate")
    aggregate_build_report = existing_regular(
        aggregate_build_report, "aggregate build report"
    )
    linux_validator_binary = existing_regular(
        linux_validator_binary, "Linux validator binary"
    )
    linux_material_builder_binary = existing_regular(
        linux_material_builder_binary, "Linux material-builder binary"
    )
    macos_validator_binary = existing_regular(
        macos_validator_binary, "macOS validator binary"
    )
    macos_material_builder_binary = existing_regular(
        macos_material_builder_binary, "macOS material-builder binary"
    )
    fleet_inventory = existing_regular(fleet_inventory, "fleet inventory")
    probe_fleet = existing_regular(probe_fleet, "probe-fleet-v1")
    run_readiness = existing_regular(run_readiness, "run-readiness-v2")
    coordinator_root = existing_root(coordinator_root, "coordinator root")
    runner_output = existing_root(runner_output, "runner output")
    inputs = (
        candidate_source,
        aggregate_build_report,
        linux_validator_binary,
        linux_material_builder_binary,
        macos_validator_binary,
        macos_material_builder_binary,
        fleet_inventory,
        probe_fleet,
        run_readiness,
        coordinator_root,
        runner_output,
    )
    output = disjoint_output(output, inputs)

    coordinator_document, public_paths = coordinator_public_paths(coordinator_root)
    observed_anchor = checker.sha256(
        coordinator_root / "manifest.json", "coordinator manifest"
    )
    if observed_anchor != coordinator_manifest_sha256:
        fail("coordinator manifest differs from the out-of-band pre-run anchor")
    run_id = coordinator_document.get("run_id")
    if not isinstance(run_id, str):
        fail("coordinator run_id must be a string")
    _runner_manifest, sealed_runner_paths = runner_paths(
        runner_output, run_id=run_id, coordinator_anchor=observed_anchor
    )
    coordinator_before = snapshot_tree(coordinator_root, include=public_paths)
    runner_before = snapshot_tree(runner_output, include=sealed_runner_paths)

    output.mkdir(mode=0o700)
    try:
        fixed_copies = (
            (candidate_source, "candidate/source.tar", "source candidate", False),
            (
                aggregate_build_report,
                "candidate/aggregate-build-report.json",
                "aggregate build report",
                False,
            ),
            (
                linux_validator_binary,
                "candidate/linux-x86_64/trnm-poco-lab-validator",
                "Linux validator binary",
                True,
            ),
            (
                linux_material_builder_binary,
                "candidate/linux-x86_64/trnm-poco-lab-material-builder",
                "Linux material-builder binary",
                True,
            ),
            (
                macos_validator_binary,
                "candidate/macos-arm64/trnm-poco-lab-validator",
                "macOS validator binary",
                True,
            ),
            (
                macos_material_builder_binary,
                "candidate/macos-arm64/trnm-poco-lab-material-builder",
                "macOS material-builder binary",
                True,
            ),
            (fleet_inventory, "preflight/inventory.toml", "fleet inventory", False),
            (probe_fleet, "preflight/probe-fleet-v1.json", "probe-fleet-v1", False),
            (
                run_readiness,
                "preflight/run-readiness-v2.json",
                "run-readiness-v2",
                False,
            ),
        )
        for source, relative, field, executable in fixed_copies:
            copy_pinned(
                source,
                output.joinpath(*pathlib.PurePosixPath(relative).parts),
                field,
                executable=executable,
            )

        try:
            lock = checker.cargo_lock_bytes(output / "candidate/source.tar")
        except (SystemExit, OSError, tarfile.TarError) as error:
            fail(f"cannot materialize candidate Cargo.lock: {error}")
        write_new(output / "candidate/Cargo.lock", lock)

        for relative in sorted(public_paths):
            copy_pinned(
                coordinator_root.joinpath(*pathlib.PurePosixPath(relative).parts),
                output / "coordinator" / pathlib.PurePosixPath(relative),
                f"coordinator/{relative}",
            )
        for relative in sorted(sealed_runner_paths):
            role, _subject = (
                ("runner_output_manifest", "")
                if relative == consensus_runner.RUNNER_OUTPUT_MANIFEST
                else consensus_runner.runner_artifact_identity(relative)
            )
            allow_empty = role in {"validator_process_stdout", "validator_process_stderr"}
            copy_pinned(
                runner_output.joinpath(*pathlib.PurePosixPath(relative).parts),
                output / "runner" / pathlib.PurePosixPath(relative),
                f"runner/{relative}",
                allow_empty=allow_empty,
            )
        if snapshot_tree(coordinator_root, include=public_paths) != coordinator_before:
            fail("coordinator public material changed across assembly")
        if snapshot_tree(runner_output, include=sealed_runner_paths) != runner_before:
            fail("runner output changed across assembly")

        derived = checker.derive(output)
        artifacts = artifact_records(output)
        manifest = {
            "schema_version": checker.SCHEMA_VERSION,
            "evidence_profile": checker.PROFILE,
            "run_id": derived["run_id"],
            "validator_count": checker.VALIDATOR_COUNT,
            "network_scope": "single-lan",
            "candidate": derived["candidate"],
            "preflight": derived["preflight"],
            "coordinator_manifest_sha256": derived[
                "coordinator_manifest_sha256"
            ],
            "runner_ordered_artifact_root": derived[
                "runner_ordered_artifact_root"
            ],
            "artifacts": artifacts,
            "ordered_artifact_root": checker.ordered_artifact_root(artifacts),
            "derived_observation": derived["derived_observation"],
            "stage0_status_projection": checker.STAGE0_STATUS_PROJECTION,
            "claims": checker.CLAIMS,
        }
        write_new(output / "manifest.json", checker.canonical_json(manifest))
        checker.validate(output, emit=False)
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-source", required=True, type=pathlib.Path)
    parser.add_argument("--aggregate-build-report", required=True, type=pathlib.Path)
    parser.add_argument("--linux-validator-binary", required=True, type=pathlib.Path)
    parser.add_argument(
        "--linux-material-builder-binary", required=True, type=pathlib.Path
    )
    parser.add_argument("--macos-validator-binary", required=True, type=pathlib.Path)
    parser.add_argument(
        "--macos-material-builder-binary", required=True, type=pathlib.Path
    )
    parser.add_argument(
        "--fleet-inventory",
        type=pathlib.Path,
        default=HERE / "inventory.toml",
    )
    parser.add_argument("--probe-fleet", required=True, type=pathlib.Path)
    parser.add_argument("--run-readiness", required=True, type=pathlib.Path)
    parser.add_argument("--coordinator-root", required=True, type=pathlib.Path)
    parser.add_argument("--runner-output", required=True, type=pathlib.Path)
    parser.add_argument("--coordinator-manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    result = assemble(
        candidate_source=args.candidate_source,
        aggregate_build_report=args.aggregate_build_report,
        linux_validator_binary=args.linux_validator_binary,
        linux_material_builder_binary=args.linux_material_builder_binary,
        macos_validator_binary=args.macos_validator_binary,
        macos_material_builder_binary=args.macos_material_builder_binary,
        fleet_inventory=args.fleet_inventory,
        probe_fleet=args.probe_fleet,
        run_readiness=args.run_readiness,
        coordinator_root=args.coordinator_root,
        runner_output=args.runner_output,
        coordinator_manifest_sha256=args.coordinator_manifest_sha256,
        output=args.output,
    )
    print(
        "poco_g3_stage0_direct_seven_assembler=passed validators=7 "
        "private_keys_bundled=false runner_truth_bits_changed=false "
        "stage0_direct_seven_observed=true validator_run_7_completed_observed=true "
        "fault_matrix=false performance=false "
        "g3_lan=false geo_wan=false production=false "
        f"output={result}"
    )


if __name__ == "__main__":
    main()
