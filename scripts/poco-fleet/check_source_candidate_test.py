#!/usr/bin/env python3
"""Positive and mutation tests for legacy and clean-commit source candidates."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable


HERE = pathlib.Path(__file__).resolve().parent
PREPARE = HERE / "prepare_source_candidate.py"
CHECK = HERE / "check_source_candidate.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("candidate_checker_test", CHECK)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load source-candidate checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = load_checker()


def run(
    arguments: list[str],
    expected: str | None = None,
    *,
    environment: dict[str, str] | None = None,
    strip_git_authority: bool = True,
) -> subprocess.CompletedProcess[str]:
    effective_environment = dict(os.environ if environment is None else environment)
    if strip_git_authority:
        for name in tuple(effective_environment):
            if name.startswith("GIT_"):
                effective_environment.pop(name)
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        env=effective_environment,
        timeout=60,
    )
    observed = result.stdout + result.stderr
    if expected is None:
        if result.returncode != 0:
            raise AssertionError(f"command failed ({result.returncode}): {observed}")
    elif result.returncode == 0 or expected not in observed:
        raise AssertionError(
            f"negative returned {result.returncode}, expected {expected!r}: {observed}"
        )
    return result


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def init_repo(path: pathlib.Path) -> None:
    path.mkdir()
    run(["git", "-C", str(path), "init", "-q"])
    run(["git", "-C", str(path), "config", "user.email", "test@invalid"])
    run(["git", "-C", str(path), "config", "user.name", "PoCO test"])
    (path / ".gitignore").write_text("ignored\n", encoding="utf-8")
    (path / "trillionnium").mkdir()
    (path / "trillionnium/Cargo.lock").write_text(
        "# exact workspace lock\nversion = 4\n", encoding="utf-8"
    )
    (path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    (path / "empty.txt").write_bytes(b"")
    executable = path / "run.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    # Exercise Git's file-vs-directory ordering and GNU long-name encoding.
    for name in ("fo", "foo-", "foo.bar", "foo0"):
        (path / name).write_text(name + "\n", encoding="utf-8")
    (path / "foo").mkdir()
    (path / "foo/child").write_text("nested\n", encoding="utf-8")
    (path / ("long-" + "x" * 110 + ".txt")).write_text("long\n", encoding="utf-8")
    run(["git", "-C", str(path), "add", "."])
    run(["git", "-C", str(path), "commit", "-qm", "fixture"])


def clone(source: pathlib.Path, target: pathlib.Path) -> None:
    run(["git", "clone", "-q", str(source), str(target)])
    run(["git", "-C", str(target), "config", "user.email", "test@invalid"])
    run(["git", "-C", str(target), "config", "user.name", "PoCO test"])


def prepare(source: pathlib.Path, output: pathlib.Path, *, strict: bool) -> None:
    arguments = [sys.executable, str(PREPARE), str(source), "--output", str(output)]
    if strict:
        arguments.append("--require-clean")
    run(arguments)


def read_candidate(
    path: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, int]]:
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        inventory_stream = archive.extractfile(members[0])
        if inventory_stream is None:
            raise AssertionError("fixture inventory has no stream")
        inventory = json.loads(inventory_stream.read())
        contents: dict[str, bytes] = {}
        modes: dict[str, int] = {}
        for member in members[1:]:
            stream = archive.extractfile(member)
            if stream is None:
                raise AssertionError("fixture member has no stream")
            relative = member.name.removeprefix("source/")
            contents[relative] = stream.read()
            modes[relative] = member.mode
    return inventory, contents, modes


def write_candidate(
    path: pathlib.Path,
    inventory: dict[str, Any],
    contents: dict[str, bytes],
    modes: dict[str, int],
    *,
    tar_format: int = tarfile.GNU_FORMAT,
    extra: tuple[str, bytes, int] | None = None,
    bad_mtime_path: str | None = None,
) -> None:
    inventory_bytes = checker.canonical_json(inventory)
    with tarfile.open(path, "w", format=tar_format) as archive:
        archive.addfile(
            checker.canonical_tar_info(
                "source/SOURCE-CANDIDATE.json", inventory_bytes, 0o644
            ),
            io.BytesIO(inventory_bytes),
        )
        for record in inventory["files"]:
            relative = record["path"]
            data = contents[relative]
            member = checker.canonical_tar_info(
                f"source/{relative}", data, modes[relative]
            )
            if relative == bad_mtime_path:
                member.mtime = 1
            archive.addfile(member, io.BytesIO(data))
        if extra is not None:
            relative, data, mode = extra
            archive.addfile(
                checker.canonical_tar_info(f"source/{relative}", data, mode),
                io.BytesIO(data),
            )


def mutate(
    source: pathlib.Path,
    target: pathlib.Path,
    action: Callable[[dict[str, Any], dict[str, bytes], dict[str, int]], None],
    **write_options: Any,
) -> None:
    inventory, contents, modes = read_candidate(source)
    action(inventory, contents, modes)
    write_candidate(target, inventory, contents, modes, **write_options)


def strict_check(path: pathlib.Path, expected: str | None = None) -> None:
    run([sys.executable, str(CHECK), str(path), "--require-clean"], expected)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    inherited_index = os.environ.get("GIT_INDEX_FILE")
    inherited_index_bytes = (
        pathlib.Path(inherited_index).read_bytes()
        if inherited_index and pathlib.Path(inherited_index).is_file()
        else None
    )
    with tempfile.TemporaryDirectory(prefix="poco-g3-source-candidate-test-") as temporary:
        parent = pathlib.Path(temporary)
        source = parent / "repo"
        init_repo(source)
        if inherited_index_bytes is not None and pathlib.Path(inherited_index).read_bytes() != inherited_index_bytes:
            raise AssertionError("isolated fixture mutated the caller's candidate index")

        left = parent / "left-v2.tar"
        right = parent / "right-v2.tar"
        prepare(source, left, strict=True)
        prepare(source, right, strict=True)
        strict_check(left)
        strict_check(right)
        run([sys.executable, str(CHECK), str(left)])
        if left.read_bytes() != right.read_bytes():
            raise AssertionError("two strict source candidates are not byte-identical")
        inventory, contents, _ = read_candidate(left)
        tracked = run(
            ["git", "-C", str(source), "ls-tree", "-r", "--name-only", "-z", "HEAD"]
        ).stdout.encode("utf-8").split(b"\0")
        expected_paths = sorted(item.decode("utf-8") for item in tracked if item)
        if [record["path"] for record in inventory["files"]] != expected_paths:
            raise AssertionError("strict candidate membership differs from git ls-tree")
        observed_tree = run(
            ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"]
        ).stdout.strip()
        if checker.compute_git_tree_oid(inventory["files"], inventory["git_object_format"]) != observed_tree:
            raise AssertionError("strict records do not reconstruct the committed Git tree")

        clone_a = parent / "clone-a"
        clone_b = parent / "clone-b"
        clone(source, clone_a)
        clone(source, clone_b)
        clone_a_tar = parent / "clone-a.tar"
        clone_b_tar = parent / "clone-b.tar"
        prepare(clone_a, clone_a_tar, strict=True)
        prepare(clone_b, clone_b_tar, strict=True)
        if not (left.read_bytes() == clone_a_tar.read_bytes() == clone_b_tar.read_bytes()):
            raise AssertionError("fresh clones did not reproduce the exact candidate bytes")

        (source / ".git/info/exclude").write_text("hidden.txt\n", encoding="utf-8")
        (source / "hidden.txt").write_text("must never enter v2\n", encoding="utf-8")
        (source / "ignored").write_text("ignored by tracked .gitignore\n", encoding="utf-8")
        ignored_tar = parent / "ignored-v2.tar"
        prepare(source, ignored_tar, strict=True)
        if ignored_tar.read_bytes() != left.read_bytes():
            raise AssertionError("Git-local exclude changed strict candidate bytes")
        with tarfile.open(ignored_tar, "r:") as archive:
            if "source/hidden.txt" in archive.getnames():
                raise AssertionError("ignored untracked file entered strict membership")

        (source / "untracked.txt").write_text("legacy untracked\n", encoding="utf-8")
        legacy = parent / "legacy-v1.tar"
        prepare(source, legacy, strict=False)
        run([sys.executable, str(CHECK), str(legacy)])
        with tarfile.open(legacy, "r:") as archive:
            legacy_names = set(archive.getnames())
        if not {
            "source/untracked.txt",
            "source/hidden.txt",
        }.issubset(legacy_names) or "source/ignored" in legacy_names:
            raise AssertionError("legacy v1 worktree membership compatibility changed")
        strict_check(legacy, "strict source candidate must use clean-commit-v1")
        legacy_empty = parent / "legacy-empty-status.tar"
        mutate(
            legacy,
            legacy_empty,
            lambda value, _contents, _modes: value.update(
                {"git_status_sha256": checker.EMPTY_STATUS_SHA256}
            ),
        )
        strict_check(legacy_empty, "strict source candidate must use clean-commit-v1")

        dirty_cases = {
            "tracked-modification": lambda repo: (repo / "tracked.txt").write_text(
                "modified\n", encoding="utf-8"
            ),
            "staged-modification": lambda repo: (
                (repo / "tracked.txt").write_text("staged\n", encoding="utf-8"),
                run(["git", "-C", str(repo), "add", "tracked.txt"]),
            ),
            "tracked-deletion": lambda repo: (repo / "tracked.txt").unlink(),
            "ordinary-untracked": lambda repo: (repo / "ordinary.txt").write_text(
                "ordinary\n", encoding="utf-8"
            ),
        }
        for name, action in dirty_cases.items():
            repo = parent / f"dirty-{name}"
            clone(clone_a, repo)
            action(repo)
            run(
                [
                    sys.executable,
                    str(PREPARE),
                    str(repo),
                    "--output",
                    str(parent / f"dirty-{name}.tar"),
                    "--require-clean",
                ],
                "requires an empty Git status",
            )

        git_override_environment = os.environ.copy()
        git_override_environment["GIT_INDEX_FILE"] = str(parent / "foreign-index")
        run(
            [
                sys.executable,
                str(PREPARE),
                str(clone_a),
                "--output",
                str(parent / "git-override.tar"),
                "--require-clean",
            ],
            "ambient Git authority override is forbidden",
            environment=git_override_environment,
            strip_git_authority=False,
        )
        run(
            [
                sys.executable,
                str(PREPARE),
                str(clone_a),
                "--output",
                str(clone_a / "inside.tar"),
                "--require-clean",
            ],
            "outside the source tree",
        )
        real_parent = parent / "real-output-parent"
        real_parent.mkdir()
        linked_parent = parent / "linked-output-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        run(
            [
                sys.executable,
                str(PREPARE),
                str(clone_a),
                "--output",
                str(linked_parent / "candidate.tar"),
                "--require-clean",
            ],
            "real non-symlink directory",
        )

        symlink_repo = parent / "symlink-repo"
        clone(clone_a, symlink_repo)
        (symlink_repo / "visible-link").symlink_to("tracked.txt")
        run(["git", "-C", str(symlink_repo), "add", "visible-link"])
        run(["git", "-C", str(symlink_repo), "commit", "-qm", "symlink"])
        run(
            [
                sys.executable,
                str(PREPARE),
                str(symlink_repo),
                "--output",
                str(parent / "symlink-tree.tar"),
                "--require-clean",
            ],
            "unsupported mode/type 120000 blob",
        )

        submodule_source = parent / "submodule-source"
        init_repo(submodule_source)
        submodule_repo = parent / "submodule-repo"
        clone(clone_a, submodule_repo)
        run(
            [
                "git",
                "-C",
                str(submodule_repo),
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(submodule_source),
                "vendor",
            ]
        )
        run(["git", "-C", str(submodule_repo), "commit", "-qm", "submodule"])
        run(
            [
                sys.executable,
                str(PREPARE),
                str(submodule_repo),
                "--output",
                str(parent / "submodule-tree.tar"),
                "--require-clean",
            ],
            "unsupported mode/type 160000 commit",
        )

        missing_lock_repo = parent / "missing-lock-repo"
        clone(clone_a, missing_lock_repo)
        run(
            [
                "git",
                "-C",
                str(missing_lock_repo),
                "rm",
                "-q",
                checker.CARGO_LOCK_PATH,
            ]
        )
        run(["git", "-C", str(missing_lock_repo), "commit", "-qm", "remove lock"])
        run(
            [
                sys.executable,
                str(PREPARE),
                str(missing_lock_repo),
                "--output",
                str(parent / "missing-lock.tar"),
                "--require-clean",
            ],
            "requires exactly one active workspace Cargo.lock",
        )
        executable_lock_repo = parent / "executable-lock-repo"
        clone(clone_a, executable_lock_repo)
        executable_lock = executable_lock_repo / checker.CARGO_LOCK_PATH
        executable_lock.chmod(0o755)
        run(["git", "-C", str(executable_lock_repo), "add", checker.CARGO_LOCK_PATH])
        run(["git", "-C", str(executable_lock_repo), "commit", "-qm", "executable lock"])
        run(
            [
                sys.executable,
                str(PREPARE),
                str(executable_lock_repo),
                "--output",
                str(parent / "executable-lock.tar"),
                "--require-clean",
            ],
            "Cargo.lock must not be executable",
        )
        reserved_repo = parent / "reserved-name-repo"
        clone(clone_a, reserved_repo)
        (reserved_repo / "SOURCE-CANDIDATE.json").write_text("reserved\n", encoding="utf-8")
        run(["git", "-C", str(reserved_repo), "add", "SOURCE-CANDIDATE.json"])
        run(["git", "-C", str(reserved_repo), "commit", "-qm", "reserved name"])
        run(
            [
                sys.executable,
                str(PREPARE),
                str(reserved_repo),
                "--output",
                str(parent / "reserved-name.tar"),
                "--require-clean",
            ],
            "forbidden or non-canonical tree path",
        )

        mutants: list[tuple[str, Callable, str]] = []
        mutants.append(
            (
                "dirty-status-resigned",
                lambda value, _contents, _modes: value.update(
                    {"git_status_sha256": "1" * 64}
                ),
                "must bind the empty Git status",
            )
        )
        mutants.append(
            (
                "commit-base64",
                lambda value, _contents, _modes: value.update(
                    {"git_commit_payload_base64": "not!base64"}
                ),
                "commit payload is not canonical base64",
            )
        )
        mutants.append(
            (
                "base-commit",
                lambda value, _contents, _modes: value.update(
                    {"base_commit": "f" * len(value["base_commit"])}
                ),
                "commit payload does not match base_commit",
            )
        )
        mutants.append(
            (
                "schema-bool",
                lambda value, _contents, _modes: value.update({"schema_version": True}),
                "schema_version must be one exact integer",
            )
        )
        mutants.append(
            (
                "file-count-bool",
                lambda value, _contents, _modes: value.update({"file_count": True}),
                "inventory totals must be exact integers",
            )
        )
        mutants.append(
            (
                "source-bytes-bool",
                lambda value, _contents, _modes: value.update({"source_bytes": True}),
                "inventory totals must be exact integers",
            )
        )
        mutants.append(
            (
                "blob-oid",
                lambda value, _contents, _modes: value["files"][0].update(
                    {"git_blob_oid": "0" * len(value["files"][0]["git_blob_oid"])}
                ),
                "bytes differ from git_blob_oid",
            )
        )
        mutants.append(
            (
                "tree-oid",
                lambda value, _contents, _modes: value.update(
                    {"git_tree_oid": "0" * len(value["git_tree_oid"])}
                ),
                "base_commit does not bind git_tree_oid",
            )
        )
        mutants.append(
            (
                "cargo-binding",
                lambda value, _contents, _modes: value["cargo_lock"].update(
                    {"sha256": "0" * 64}
                ),
                "cargo_lock binding differs",
            )
        )
        mutants.append(
            (
                "cargo-executable",
                lambda value, _contents, modes: (
                    next(
                        record
                        for record in value["files"]
                        if record["path"] == checker.CARGO_LOCK_PATH
                    ).update({"mode": "0755"}),
                    modes.update({checker.CARGO_LOCK_PATH: 0o755}),
                ),
                "Cargo.lock must not be executable",
            )
        )
        for name, action, expected in mutants:
            target = parent / f"mutant-{name}.tar"
            mutate(left, target, action)
            strict_check(target, expected)

        def mutate_committed_bytes(
            value: dict[str, Any], candidate_contents: dict[str, bytes], _modes: dict[str, int]
        ) -> None:
            record = next(item for item in value["files"] if item["path"] == "tracked.txt")
            old_size = record["bytes"]
            data = b"mutated tracked bytes\n"
            candidate_contents["tracked.txt"] = data
            record["bytes"] = len(data)
            record["sha256"] = digest(data)
            record["git_blob_oid"] = checker.git_object_oid(
                value["git_object_format"], "blob", data
            )
            value["source_bytes"] += len(data) - old_size
            value["git_tree_oid"] = checker.compute_git_tree_oid(
                value["files"], value["git_object_format"]
            )

        substituted_tree = parent / "mutant-substituted-tree.tar"
        mutate(left, substituted_tree, mutate_committed_bytes)
        strict_check(substituted_tree, "base_commit does not bind git_tree_oid")

        def add_extra_record(
            value: dict[str, Any], candidate_contents: dict[str, bytes], modes: dict[str, int]
        ) -> None:
            data = b"extra tracked-like bytes\n"
            record = {
                "path": "zzz-extra.txt",
                "sha256": digest(data),
                "bytes": len(data),
                "mode": "0644",
                "git_blob_oid": checker.git_object_oid(
                    value["git_object_format"], "blob", data
                ),
            }
            value["files"].append(record)
            value["files"].sort(key=lambda item: item["path"].encode("utf-8"))
            value["file_count"] += 1
            value["source_bytes"] += len(data)
            candidate_contents[record["path"]] = data
            modes[record["path"]] = 0o644

        extra_record = parent / "mutant-extra-record.tar"
        mutate(left, extra_record, add_extra_record)
        strict_check(extra_record, "do not reconstruct git_tree_oid")

        def remove_record(
            value: dict[str, Any], candidate_contents: dict[str, bytes], modes: dict[str, int]
        ) -> None:
            index = next(
                i for i, record in enumerate(value["files"]) if record["path"] == "tracked.txt"
            )
            record = value["files"].pop(index)
            value["file_count"] -= 1
            value["source_bytes"] -= record["bytes"]
            candidate_contents.pop(record["path"])
            modes.pop(record["path"])

        missing_record = parent / "mutant-missing-record.tar"
        mutate(left, missing_record, remove_record)
        strict_check(missing_record, "do not reconstruct git_tree_oid")

        inventory_copy, candidate_contents, modes = read_candidate(left)
        byte_mutant = parent / "mutant-bytes.tar"
        candidate_contents["tracked.txt"] = b"unresigned\n"
        write_candidate(byte_mutant, inventory_copy, candidate_contents, modes)
        strict_check(byte_mutant, "bytes differ from inventory")
        extra_tar = parent / "mutant-extra-tar.tar"
        inventory_copy, candidate_contents, modes = read_candidate(left)
        write_candidate(
            extra_tar,
            inventory_copy,
            candidate_contents,
            modes,
            extra=("undeclared-extra", b"extra", 0o644),
        )
        strict_check(extra_tar, "extra, missing, or reordered")
        mtime = parent / "mutant-mtime.tar"
        inventory_copy, candidate_contents, modes = read_candidate(left)
        write_candidate(
            mtime,
            inventory_copy,
            candidate_contents,
            modes,
            bad_mtime_path="tracked.txt",
        )
        strict_check(mtime, "metadata is non-canonical")
        pax = parent / "mutant-pax.tar"
        inventory_copy, candidate_contents, modes = read_candidate(left)
        write_candidate(
            pax,
            inventory_copy,
            candidate_contents,
            modes,
            tar_format=tarfile.PAX_FORMAT,
        )
        strict_check(pax, "unique canonical GNU encoding")
        trailing = parent / "mutant-trailing.tar"
        shutil.copyfile(left, trailing)
        with trailing.open("ab") as output:
            output.write(b"\0" * tarfile.RECORDSIZE)
        strict_check(trailing, "unique canonical GNU encoding")
        linked = parent / "candidate-link.tar"
        linked.symlink_to(left)
        strict_check(linked, "regular non-symlink")

        duplicate_json = parent / "mutant-duplicate-json.tar"
        duplicate_inventory, duplicate_contents, duplicate_modes = read_candidate(left)
        canonical_inventory = checker.canonical_json(duplicate_inventory)
        duplicate_inventory_bytes = canonical_inventory.replace(
            b'  "schema_version": 2,\n',
            b'  "schema_version": 2,\n  "schema_version": 2,\n',
            1,
        )
        with tarfile.open(duplicate_json, "w", format=tarfile.GNU_FORMAT) as archive:
            archive.addfile(
                checker.canonical_tar_info(
                    "source/SOURCE-CANDIDATE.json", duplicate_inventory_bytes, 0o644
                ),
                io.BytesIO(duplicate_inventory_bytes),
            )
            for record in duplicate_inventory["files"]:
                relative = record["path"]
                data = duplicate_contents[relative]
                archive.addfile(
                    checker.canonical_tar_info(
                        f"source/{relative}", data, duplicate_modes[relative]
                    ),
                    io.BytesIO(data),
                )
        strict_check(duplicate_json, "duplicate JSON object name")

    print(
        "poco_g3_source_candidate_test=passed strict_profile=clean-commit-v1 "
        "fresh_clone_byte_identity=true git_tree_blob_binding=true "
        "commit_tree_binding=true cargo_lock_bound=true dirty_worktrees_rejected=true "
        "legacy_v1_audit_only=true actual_build_executed=false "
        "production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
