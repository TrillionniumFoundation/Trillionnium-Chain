#!/usr/bin/env python3
"""Assemble one immutable, public-only Stage0 direct-seven observation bundle.

The assembler copies exact already-produced evidence.  It never runs Cargo,
starts validators, creates signatures, changes runner truth bits, or copies the
coordinator's private keys.  The checker must recompute artifact/replay hashes
and signed terminal facts from the copied raw bytes before the new directory is
retained.  It does not independently decode Proposal/QC/finality semantics.
Its 128 MiB item limit is the stricter Stage0/X230 profile, not a generic
512 MiB runner-compatibility claim.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import stat
import sys
import tarfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn


HERE = pathlib.Path(__file__).resolve().parent
SOURCE_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import check_stage0_direct_seven_bundle_v1 as checker  # noqa: E402
import run_consensus_fleet as consensus_runner  # noqa: E402


_OUTPUT_STATVFS_V1 = os.fstatvfs
OUTPUT_FREE_SPACE_RESERVE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class SourceSnapshot:
    root_device: int
    root_inode: int
    files: tuple[tuple[str, int, int, int, int, int, int], ...]


@dataclass(frozen=True)
class DirectoryLink:
    name: str
    device: int
    inode: int


class RelativeDirectoryPin:
    """One output-relative ancestor chain rooted in a held output dirfd."""

    def __init__(
        self,
        output: OutputTree,
        descriptors: list[int],
        links: list[DirectoryLink],
    ) -> None:
        self.output = output
        self.descriptors = descriptors
        self.links = links
        self.closed = False

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]

    def validate(self) -> None:
        if self.closed:
            fail("output-relative directory pin is already closed")
        self.output.validate()
        root = os.fstat(self.descriptors[0])
        if (root.st_dev, root.st_ino) != (
            self.output.identity.st_dev,
            self.output.identity.st_ino,
        ):
            fail("output-relative root descriptor changed identity")
        for index, link in enumerate(self.links):
            child = os.fstat(self.descriptors[index + 1])
            linked = os.stat(
                link.name,
                dir_fd=self.descriptors[index],
                follow_symlinks=False,
            )
            expected = (link.device, link.inode, stat.S_IFDIR)
            if (
                child.st_dev,
                child.st_ino,
                stat.S_IFMT(child.st_mode),
            ) != expected or (
                linked.st_dev,
                linked.st_ino,
                stat.S_IFMT(linked.st_mode),
            ) != expected:
                fail("output-relative ancestor was replaced")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)


class OutputTree:
    """A newly created output tree addressed only through pinned dirfds."""

    def __init__(
        self,
        path: pathlib.Path,
        parent: checker.PinnedDirectory,
        descriptor: int,
        identity: os.stat_result,
    ) -> None:
        self.path = path
        self.parent = parent
        self.descriptor = descriptor
        self.identity = identity
        self.closed = False

    @classmethod
    def create(
        cls,
        path: pathlib.Path,
        *,
        _after_parent_ancestors_pinned: Callable[[], None] | None = None,
        _after_output_opened: Callable[[], None] | None = None,
    ) -> OutputTree:
        path = checker.absolute_path(path)
        parent = checker.pin_directory(
            path.parent,
            "output parent",
            _after_ancestors_pinned=_after_parent_ancestors_pinned,
        )
        created = False
        created_identity: tuple[int, int] | None = None
        descriptor: int | None = None
        try:
            try:
                os.stat(path.name, dir_fd=parent.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                fail("output already exists; observation bundles are immutable")
            os.mkdir(path.name, mode=0o700, dir_fd=parent.descriptor)
            created = True
            created_metadata = os.stat(
                path.name, dir_fd=parent.descriptor, follow_symlinks=False
            )
            created_identity = (created_metadata.st_dev, created_metadata.st_ino)
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                dir_fd=parent.descriptor,
            )
            identity = os.fstat(descriptor)
            linked = os.stat(
                path.name, dir_fd=parent.descriptor, follow_symlinks=False
            )
            if (
                linked.st_dev,
                linked.st_ino,
                stat.S_IFMT(linked.st_mode),
            ) != (identity.st_dev, identity.st_ino, stat.S_IFDIR):
                fail("output directory changed identity while opening")
            result = cls(path, parent, descriptor, identity)
            if _after_output_opened is not None:
                _after_output_opened()
            result.validate()
            return result
        except BaseException:
            if descriptor is not None:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            if created and created_identity is not None:
                with contextlib.suppress(OSError):
                    linked = os.stat(
                        path.name,
                        dir_fd=parent.descriptor,
                        follow_symlinks=False,
                    )
                    if (linked.st_dev, linked.st_ino) == created_identity:
                        os.rmdir(path.name, dir_fd=parent.descriptor)
            parent.close()
            raise

    def validate(self) -> None:
        if self.closed:
            fail("output directory pin is already closed")
        self.parent.validate()
        opened = os.fstat(self.descriptor)
        linked = os.stat(
            self.path.name,
            dir_fd=self.parent.descriptor,
            follow_symlinks=False,
        )
        expected = (self.identity.st_dev, self.identity.st_ino, stat.S_IFDIR)
        if (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode),
        ) != expected or (
            linked.st_dev,
            linked.st_ino,
            stat.S_IFMT(linked.st_mode),
        ) != expected:
            fail("output directory path was replaced")

    def pin_parent(self, relative: str) -> tuple[RelativeDirectoryPin, str]:
        path = checker.safe_relative(relative, "output relative path")
        descriptors = [os.dup(self.descriptor)]
        links: list[DirectoryLink] = []
        try:
            for component in path.parts[:-1]:
                try:
                    before = os.stat(
                        component,
                        dir_fd=descriptors[-1],
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    os.mkdir(component, mode=0o700, dir_fd=descriptors[-1])
                    before = os.stat(
                        component,
                        dir_fd=descriptors[-1],
                        follow_symlinks=False,
                    )
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                    dir_fd=descriptors[-1],
                )
                opened = os.fstat(child)
                if (
                    before.st_dev,
                    before.st_ino,
                    stat.S_IFMT(before.st_mode),
                ) != (opened.st_dev, opened.st_ino, stat.S_IFDIR):
                    os.close(child)
                    fail("output-relative ancestor changed while opening")
                links.append(DirectoryLink(component, opened.st_dev, opened.st_ino))
                descriptors.append(child)
            result = RelativeDirectoryPin(self, descriptors, links)
            result.validate()
            return result, path.name
        except BaseException:
            for descriptor in reversed(descriptors):
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise

    def cleanup(
        self,
        *,
        _before_final_remove: Callable[[], None] | None = None,
    ) -> None:
        """Delete only the exact inode created by this assembler."""

        self.validate()

        def clear(descriptor: int) -> None:
            with os.scandir(descriptor) as iterator:
                entries = list(iterator)
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    child = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                        dir_fd=descriptor,
                    )
                    try:
                        clear(child)
                    finally:
                        os.close(child)
                    os.rmdir(entry.name, dir_fd=descriptor)
                else:
                    os.unlink(entry.name, dir_fd=descriptor)

        clear(self.descriptor)
        if _before_final_remove is not None:
            _before_final_remove()
        linked = os.stat(
            self.path.name,
            dir_fd=self.parent.descriptor,
            follow_symlinks=False,
        )
        if (linked.st_dev, linked.st_ino) != (
            self.identity.st_dev,
            self.identity.st_ino,
        ):
            fail("refusing to remove a substituted output directory")
        os.rmdir(self.path.name, dir_fd=self.parent.descriptor)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        os.close(self.descriptor)
        self.parent.close()


def fail(message: str) -> NoReturn:
    raise SystemExit(f"PoCO G3 Stage0 direct-seven assembler failed: {message}")


def existing_regular(
    raw: pathlib.Path,
    field: str,
    *,
    allow_empty: bool = False,
) -> pathlib.Path:
    try:
        with checker.open_pinned_regular(
            raw,
            field,
            allow_empty=allow_empty,
            maximum=checker.MAXIMUM_FILE_BYTES,
        ) as pinned:
            pinned.validate()
            return pinned.path
    except SystemExit as error:
        fail(str(error))


def existing_root(raw: pathlib.Path, field: str) -> pathlib.Path:
    try:
        return checker.real_root(pathlib.Path(raw), field)
    except SystemExit as error:
        fail(str(error))


def disjoint_output(raw: pathlib.Path, inputs: tuple[pathlib.Path, ...]) -> pathlib.Path:
    output = checker.absolute_path(raw)
    with checker.pin_directory(output.parent, "output parent") as parent:
        try:
            os.stat(output.name, dir_fd=parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail("output already exists; observation bundles are immutable")
    source_root = checker.absolute_path(SOURCE_ROOT)
    if output == source_root or source_root in output.parents or output in source_root.parents:
        fail("output must remain outside and disjoint from the source tree")
    for source in inputs:
        source = checker.absolute_path(source)
        if output == source or output in source.parents or source in output.parents:
            fail("output must remain disjoint from every input path")
    return output


def snapshot_tree(root: pathlib.Path, *, include: set[str] | None = None) -> SourceSnapshot:
    root = existing_root(root, "input root")
    files = checker.tree_files(root)
    with checker.pin_directory(root, "input root") as pinned_root:
        root_metadata = os.fstat(pinned_root.descriptor)
    records: list[tuple[str, int, int, int, int, int, int]] = []
    for relative, path in files.items():
        if include is None or relative in include:
            with checker.open_pinned_regular(
                path,
                f"input root file {relative}",
                allow_empty=True,
            ) as pinned:
                metadata = pinned.metadata
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
    output: OutputTree,
    relative: str,
    field: str,
    *,
    executable: bool = False,
    allow_empty: bool = False,
    _after_source_ancestors_pinned: Callable[[], None] | None = None,
    _after_target_ancestors_pinned: Callable[[], None] | None = None,
) -> dict[str, Any]:
    pinned_source = checker.open_pinned_regular(
        source,
        field,
        allow_empty=allow_empty,
        maximum=checker.MAXIMUM_FILE_BYTES,
        _after_ancestors_pinned=_after_source_ancestors_pinned,
    )
    source_descriptor = pinned_source.descriptor
    target_parent: RelativeDirectoryPin | None = None
    try:
        target_parent, target_name = output.pin_parent(relative)
        if _after_target_ancestors_pinned is not None:
            _after_target_ancestors_pinned()
    except BaseException:
        if target_parent is not None:
            target_parent.close()
        pinned_source.close()
        raise
    target_descriptor: int | None = None
    target_identity: tuple[int, int] | None = None
    digest = hashlib.sha256()
    size = 0
    try:
        try:
            os.stat(target_name, dir_fd=target_parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail(f"output artifact {relative!r} already exists")
        target_descriptor = os.open(
            target_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o500 if executable else 0o400,
            dir_fd=target_parent.descriptor,
        )
        os.fchmod(target_descriptor, 0o500 if executable else 0o400)
        created = os.fstat(target_descriptor)
        target_identity = (created.st_dev, created.st_ino)
        remaining = pinned_source.metadata.st_size
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
        pinned_source.validate()
        target_after = os.fstat(target_descriptor)
        target_link = os.stat(
            target_name, dir_fd=target_parent.descriptor, follow_symlinks=False
        )
        if (
            target_after.st_dev,
            target_after.st_ino,
            target_after.st_size,
            stat.S_IFMT(target_after.st_mode),
        ) != (
            target_link.st_dev,
            target_link.st_ino,
            size,
            stat.S_IFREG,
        ):
            fail(f"output artifact {relative!r} changed during its pinned copy")
        target_parent.validate()
    except BaseException:
        if target_identity is not None:
            with contextlib.suppress(OSError):
                linked = os.stat(
                    target_name,
                    dir_fd=target_parent.descriptor,
                    follow_symlinks=False,
                )
                if (linked.st_dev, linked.st_ino) == target_identity:
                    os.unlink(target_name, dir_fd=target_parent.descriptor)
        raise
    finally:
        pinned_source.close()
        if target_descriptor is not None:
            os.close(target_descriptor)
        target_parent.close()
    if size == 0 and not allow_empty:
        fail(f"{field} is empty")
    return {"sha256": digest.hexdigest(), "bytes": size}


def write_new(
    output: OutputTree,
    relative: str,
    content: bytes,
    *,
    executable: bool = False,
) -> None:
    parent, name = output.pin_parent(relative)
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o500 if executable else 0o400,
            dir_fd=parent.descriptor,
        )
        os.fchmod(descriptor, 0o500 if executable else 0o400)
        created = os.fstat(descriptor)
        identity = (created.st_dev, created.st_ino)
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                fail(f"could not make progress while writing {relative}")
            remaining = remaining[written:]
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            stat.S_IFMT(after.st_mode),
        ) != (linked.st_dev, linked.st_ino, len(content), stat.S_IFREG):
            fail(f"output artifact {relative!r} changed during its pinned write")
        parent.validate()
    except BaseException:
        if identity is not None:
            with contextlib.suppress(OSError):
                linked = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
                if (linked.st_dev, linked.st_ino) == identity:
                    os.unlink(name, dir_fd=parent.descriptor)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        parent.close()


def coordinator_public_paths(root: pathlib.Path) -> tuple[dict[str, Any], set[str]]:
    document = checker.strict_json(root / "manifest.json", "coordinator manifest")
    try:
        public_paths, _secret_paths = checker.validate_source_coordinator_inventory(
            root, document
        )
    except SystemExit as error:
        fail(f"coordinator public/secret inventory is not closed: {error}")
    return document, {"manifest.json", *public_paths}


def runner_paths(
    root: pathlib.Path,
    *,
    run_id: str,
    coordinator_anchor: str,
) -> tuple[dict[str, Any], set[str]]:
    checker.tree_files(root)
    exact_manifest = checker.strict_json(
        root / consensus_runner.RUNNER_OUTPUT_MANIFEST,
        "source runner output manifest",
    )
    checker.validate_runner_manifest_exact_types(exact_manifest)
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


def copy_envelope(
    fixed: tuple[pathlib.Path, ...],
    coordinator_root: pathlib.Path,
    public_paths: set[str],
    runner_root: pathlib.Path,
    runner_paths_set: set[str],
    cargo_lock: bytes,
) -> tuple[int, int]:
    """Pre-sum every output item before the first output byte is created."""

    total = len(cargo_lock)
    count = len(fixed) + 1
    for field, root, paths in (
        ("coordinator", coordinator_root, public_paths),
        ("runner", runner_root, runner_paths_set),
    ):
        for relative in paths:
            with checker.open_pinned_regular(
                root.joinpath(*pathlib.PurePosixPath(relative).parts),
                f"{field}/{relative}",
                allow_empty=relative.endswith((".stdout", ".stderr")),
            ) as pinned:
                total += pinned.metadata.st_size
                count += 1
    for index, path in enumerate(fixed):
        with checker.open_pinned_regular(
            path,
            f"fixed copy source {index}",
            allow_empty=False,
        ) as pinned:
            total += pinned.metadata.st_size
    # Reserve one small outer manifest in addition to the exact copied inputs.
    total += checker.MAXIMUM_JSON_BYTES
    count += 1
    if count > checker.MAXIMUM_FILE_COUNT or total > checker.MAXIMUM_BUNDLE_BYTES:
        fail("planned bundle crosses its X230 file-count or aggregate-byte envelope")
    return count, total


def validate_output_capacity(output: pathlib.Path, planned_bytes: int) -> None:
    """Check the actual selected output filesystem before creating output."""

    with checker.pin_directory(output.parent, "output parent capacity") as parent:
        capacity = _OUTPUT_STATVFS_V1(parent.descriptor)
        available = capacity.f_bavail * capacity.f_frsize
        if available < planned_bytes + OUTPUT_FREE_SPACE_RESERVE_BYTES:
            fail("output filesystem lacks the bounded bundle plus safety reserve")


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

    # This authority split is the first mutating boundary.  A secret path
    # disguised as public material must therefore fail while ``output`` is
    # still absent and zero bytes have been materialized.
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
    try:
        runner_bridge_manifest = checker.runner_bridge.validate_coordinator(
            coordinator_root,
            checker.VALIDATOR_COUNT,
            candidate_source,
            linux_validator_binary,
            macos_validator_binary,
            linux_material_builder_binary,
        )
    except SystemExit as error:
        fail(f"coordinator failed its exact candidate binding: {error}")
    if not checker.typed_equal(runner_bridge_manifest, coordinator_document):
        fail("coordinator validators returned different exact manifest facts")
    checker.validate_source_candidate_resource_envelope(candidate_source)
    try:
        checker.validate_clean_source_candidate(candidate_source)
    except SystemExit as error:
        fail(f"source candidate failed pre-copy deep verification: {error}")
    try:
        checker.validate_preflight(fleet_inventory, probe_fleet, run_readiness)
    except SystemExit as error:
        fail(f"fleet preflight failed before copy: {error}")
    try:
        lock = checker.cargo_lock_bytes(candidate_source)
    except (SystemExit, OSError, tarfile.TarError) as error:
        fail(f"cannot prevalidate candidate Cargo.lock: {error}")

    coordinator_before = snapshot_tree(coordinator_root, include=public_paths)
    runner_before = snapshot_tree(runner_output, include=sealed_runner_paths)
    fixed_sources = (
        candidate_source,
        aggregate_build_report,
        linux_validator_binary,
        linux_material_builder_binary,
        macos_validator_binary,
        macos_material_builder_binary,
        fleet_inventory,
        probe_fleet,
        run_readiness,
    )
    _planned_count, planned_bytes = copy_envelope(
        fixed_sources,
        coordinator_root,
        public_paths,
        runner_output,
        sealed_runner_paths,
        lock,
    )
    validate_output_capacity(output, planned_bytes)

    output_tree = OutputTree.create(output)
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
                output_tree,
                relative,
                field,
                executable=executable,
            )

        write_new(output_tree, "candidate/Cargo.lock", lock)

        for relative in sorted(public_paths):
            copy_pinned(
                coordinator_root.joinpath(*pathlib.PurePosixPath(relative).parts),
                output_tree,
                f"coordinator/{relative}",
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
                output_tree,
                f"runner/{relative}",
                f"runner/{relative}",
                allow_empty=allow_empty,
            )
        output_tree.validate()
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
        write_new(output_tree, "manifest.json", checker.canonical_json(manifest))
        output_tree.validate()
        checker.validate(output, emit=False)
    except BaseException:
        with contextlib.suppress(BaseException):
            output_tree.cleanup()
        output_tree.close()
        raise
    output_tree.close()
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
        "raw_replay_hash_chain=recomputed terminal_seal_signature=verified "
        "proposal_qc_finality_semantics_independently_decoded=false "
        "stage0_profile_max_file_bytes=134217728 "
        "runner_generic_512m_compatibility_claim=false "
        "stage0_direct_seven_observed=true validator_run_7_completed_observed=true "
        "fault_matrix=false performance=false "
        "g3_lan=false geo_wan=false production=false "
        f"output={result}"
    )


if __name__ == "__main__":
    main()
