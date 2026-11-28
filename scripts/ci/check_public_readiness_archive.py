#!/usr/bin/env python3
"""Replay the fixed public-readiness observation through a complete original view.

This is an exact storage migration, not a new runtime qualification. All 1,334
original manifest entries remain mandatory. The retained current files and the
new archive index must be tracked, and the removed files must match the complete
original Git tree scopes. A private, disposable view restores the original byte
roster before the unchanged measured checker is actually executed.

Only local objects are read. Missing measured source, payload or checker objects
are errors; this command never fetches or substitutes a different implementation.
The measured checker runs in a private repository containing its exact source
tree, so neither its worktree bookkeeping nor its imports use the current tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import check_historical_archive as history


PACKAGE = "evidence/pon-public-readiness-v1"
INDEX_NAME = "PRE_CORRECTION_ARCHIVE.json"
ARCHIVE_COMMIT = "893210a45b44742edfe2510fea1d92e9974b5f95"
ARCHIVE_TREE = "a2d04b29621bb78504244471aacac3be3bc78d1d"
MEASURED_COMMIT = "c2b1ca2503aeca35873d20d1b188689369edc752"
MEASURED_TREE = "5df72527b22520b27f5ad858bbca98456c7ad9cf"
CHECKER_PATH = "scripts/ci/check_public_readiness_evidence.py"
CHECKER_BLOB = "4aba7362ad3b1125ba3c1b98f1517bb12de55d06"
CHECKER_BYTES = 40860
CHECKER_SHA256 = "5a959a30e89afc02d23db726d381aba7c0114f1b590a59914cde0aaa0f0636b2"
SOURCE_FILES = 793
ORIGINAL_FILES = 1335
ORIGINAL_BYTES = 553888741
ARCHIVED_FILES = 885
ARCHIVED_BYTES = 413594755
FLAGS = ("public_network_ready", "production_activation", "independent_accepted",
         "future_window_accepted", "work_profile_qualified", "physical_power_loss")
SUBDIRECTORIES = ("attribution", "baseline", "logs", "pipeline-disjoint4-protected",
                  "pipeline-growth-protected", "pipeline-hot-legacy", "pipeline-hot-protected")
SCOPES = tuple(sorted(PACKAGE + "/observations/pre-correction-" + version + "/" + child
                      for version in "bcd" for child in SUBDIRECTORIES))
HISTORICAL_MANIFESTS = frozenset({"README.md", "manifest.json", "qualification.json"})


def local_environment():
    """The original child also inherits a Git protocol refusal, never auto-fetch."""
    env = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "GIT_CONFIG_PARAMETERS", "GIT_DIR",
                "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        env.pop(key, None)
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
               GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
               GIT_TERMINAL_PROMPT="0", GIT_CONFIG_COUNT="2",
               GIT_CONFIG_KEY_0="protocol.allow", GIT_CONFIG_VALUE_0="never",
               GIT_CONFIG_KEY_1="core.hooksPath", GIT_CONFIG_VALUE_1=os.devnull)
    return env


def local_git(root, *args, input=None):
    result = subprocess.run(["git", "--no-replace-objects", *args], cwd=root,
                            env=local_environment(), input=input, capture_output=True)
    history.require(result.returncode == 0,
                    "required local Git object or operation unavailable: " + " ".join(args[:3]))
    return result.stdout


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    def invalid_constant(value):
        raise history.Invalid("noncanonical JSON constant: " + value)
    return json.loads(raw, object_pairs_hook=history.unique, parse_constant=invalid_constant)


def original_tree(root, commit, tree, paths=()):
    history.require(local_git(root, "cat-file", "-t", commit).strip() == b"commit",
                    "required source is not a local commit")
    history.require(local_git(root, "rev-parse", commit + "^{tree}").decode().strip() == tree,
                    "fixed original tree differs")
    rows = {}
    for raw in local_git(root, "ls-tree", "-rz", commit, "--", *paths).split(b"\0"):
        if not raw:
            continue
        metadata, path = raw.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        name = history.canonical(path.decode("utf-8"))
        history.require(kind == "blob" and mode in {"100644", "100755"},
                        "unsupported original entry: " + name)
        history.require(name not in rows, "duplicate original tree path")
        rows[name] = {"path": name, "mode": mode, "blob": oid}
    identifiers = sorted({row["blob"] for row in rows.values()})
    request = "".join(oid + "\n" for oid in identifiers).encode("ascii")
    responses = local_git(root, "cat-file", "--batch-check", input=request).splitlines()
    history.require(len(responses) == len(identifiers), "incomplete local object response")
    sizes = {}
    for oid, response in zip(identifiers, responses):
        parts = response.decode("ascii").split()
        history.require(len(parts) == 3 and parts[0] == oid and parts[1] == "blob",
                        "required local blob missing: " + oid)
        sizes[oid] = int(parts[2])
    for row in rows.values():
        row["bytes"] = sizes[row["blob"]]
    return rows


def original_bytes(root, row):
    raw = local_git(root, "cat-file", "blob", row["blob"])
    actual_oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    history.require(len(raw) == row["bytes"] and actual_oid == row["blob"],
                    "original object bytes differ: " + row["path"])
    return raw


def relevant_source(path):
    # The exact predicate in the pinned measured checker, independently bound
    # to its blob and to the retained qualification's complete 793-entry map.
    return ((path.startswith(("trillionnium/", "formal/pon-nakamoto-v1/", "scripts/"))
             and not path.endswith(".md"))
            or path.startswith(("config/pon/", ".github/workflows/")))


def current_roster(root, folder):
    result = set()
    for path in folder.rglob("*"):
        history.require(not path.is_symlink(), "symlink in current public-readiness package")
        if path.is_file():
            result.add(path.relative_to(root).as_posix())
    return result


def fixed_inputs(root, index):
    """Reject incomplete local sources before the shared generic reader runs."""
    root = root.resolve()
    expected_index = root / PACKAGE / INDEX_NAME
    history.require(index.absolute() == expected_index, "archive index outside fixed evidence package")
    captured = history.local_file(root, PACKAGE + "/" + INDEX_NAME).read_bytes()
    data = document(captured)
    history.require(data["source_commit"] == ARCHIVE_COMMIT
                    and data["source_tree"] == ARCHIVE_TREE,
                    "archive source is not the fixed original package snapshot")
    history.require(data["scopes"] == list(SCOPES), "archive must cover the 21 complete original scopes")
    original = original_tree(root, ARCHIVE_COMMIT, ARCHIVE_TREE, [PACKAGE])
    measured = original_tree(root, MEASURED_COMMIT, MEASURED_TREE)
    history.require(len(original) == ORIGINAL_FILES
                    and sum(row["bytes"] for row in original.values()) == ORIGINAL_BYTES,
                    "original package denominator differs")
    archived = {name for name in original if any(name.startswith(scope + "/") for scope in SCOPES)}
    history.require(len(archived) == ARCHIVED_FILES
                    and sum(original[name]["bytes"] for name in archived) == ARCHIVED_BYTES,
                    "original archived denominator differs")
    history.require({row["path"] for row in data["files"]} == archived,
                    "archive roster does not match every fixed original path")
    history.require({row["path"] for row in data["historical_manifests"]}
                    == {PACKAGE + "/" + name for name in HISTORICAL_MANIFESTS},
                    "original README, manifest and qualification must be bound")
    preserved = set(original) - archived - {PACKAGE + "/README.md"}
    history.require({row["path"] for row in data["preserved_files"]} == preserved,
                    "every retained original file must remain byte-identical")
    history.require(data["retained_copies"] == [], "unexpected replacement copies")
    expected_current = (set(original) - archived) | {PACKAGE + "/" + INDEX_NAME}
    history.require(current_roster(root, root / PACKAGE) == expected_current,
                    "current public-readiness package has missing or extra files")
    tracked = set(local_git(root, "ls-files", "-z").decode().rstrip("\0").split("\0"))
    history.require(expected_current <= tracked, "untracked retained evidence or archive index")
    # The current index proves publication of the retained paths/new index.
    # The fixed original Git tree proves tracking of every removed path. Neither
    # proof is replaced by setting the original validator's tracked=False.
    manifest_raw = history.local_file(root, PACKAGE + "/manifest.json").read_bytes()
    qualification_raw = history.local_file(root, PACKAGE + "/qualification.json").read_bytes()
    history.require(manifest_raw == original_bytes(root, original[PACKAGE + "/manifest.json"]),
                    "original root manifest changed")
    history.require(qualification_raw == original_bytes(root, original[PACKAGE + "/qualification.json"]),
                    "original qualification changed")
    original_readme = original_bytes(root, original[PACKAGE + "/README.md"])
    history.require(history.local_file(root, PACKAGE + "/README.md").read_bytes().startswith(original_readme),
                    "original README claims must remain unchanged before the storage appendix")
    manifest, qualification = document(manifest_raw), document(qualification_raw)
    history.require(manifest["schema"] == "trnm-public-readiness-evidence-v1"
                    and manifest["implementation_commit"] == MEASURED_COMMIT
                    and manifest["implementation_tree"] == MEASURED_TREE,
                    "root measured identity differs")
    expected_payloads = {name[len(PACKAGE) + 1:] for name in original} - {"manifest.json"}
    history.require(set(manifest["files"]) == expected_payloads
                    and len(manifest["files"]) == ORIGINAL_FILES - 1,
                    "root manifest must bind the entire original package")
    sources = {name for name in measured if relevant_source(name)}
    history.require(set(qualification["source_files_sha256"]) == sources
                    and len(sources) == SOURCE_FILES,
                    "measured source inventory differs")
    for name in sorted(sources):
        history.require(digest(original_bytes(root, measured[name]))
                        == qualification["source_files_sha256"][name],
                        "measured source SHA-256 differs: " + name)
    checker = measured.get(CHECKER_PATH)
    history.require(checker is not None and checker["blob"] == CHECKER_BLOB
                    and checker["bytes"] == CHECKER_BYTES
                    and digest(original_bytes(root, checker)) == CHECKER_SHA256,
                    "original semantic checker differs")
    return root, captured, data, original, measured, archived, manifest


def original_view(root, folder, original, archived, manifest):
    for name, row in original.items():
        relative = name[len(PACKAGE) + 1:]
        if name in archived or relative == "README.md":
            raw = original_bytes(root, row)
        else:
            raw = history.local_file(root, name).read_bytes()
            actual_oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            history.require(actual_oid == row["blob"] and len(raw) == row["bytes"],
                            "retained file changed while reconstructing view: " + relative)
        if relative != "manifest.json":
            history.require(digest(raw) == manifest["files"][relative],
                            "original root manifest checksum differs: " + relative)
        destination = folder / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(int(row["mode"], 8) & 0o777)
    # Preserve all current artifact checks as well as the unchanged old gate.
    # Its default tracking check applies in-place; the dual current/history
    # tracking proof above covers this owned reconstruction outside the root.
    from check_public_readiness_evidence import validate_artifacts
    validate_artifacts(root, folder, manifest)


def measured_repository(root, folder, measured):
    """Build an owned detached repository without checkout filters or hooks."""
    folder.mkdir()
    local_git(folder, "init", "--quiet", "--template=")
    objects = Path(local_git(root, "rev-parse", "--git-path", "objects").decode().strip())
    if not objects.is_absolute():
        objects = root / objects
    objects = objects.resolve()
    history.require(objects.is_dir() and "\n" not in str(objects), "unsafe local Git object directory")
    (folder / ".git/objects/info/alternates").write_text(str(objects) + "\n")
    (folder / ".git/HEAD").write_text(MEASURED_COMMIT + "\n")
    local_git(folder, "read-tree", MEASURED_COMMIT)
    for name, row in measured.items():
        destination = folder / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(original_bytes(root, row))
        destination.chmod(int(row["mode"], 8) & 0o777)


def run_original_gate(source, folder):
    """The measured historical CLI runs its unchanged full semantic validator."""
    result = subprocess.run([sys.executable, "-B", "-s", str(source / CHECKER_PATH),
                             "--root", str(source), "--historical", "--evidence", str(folder)],
                            cwd=source, env=local_environment(), capture_output=True,
                            text=True, timeout=300)
    history.require(result.returncode == 0,
                    "original historical semantic gate failed: " + result.stderr[-6000:].strip())
    lines = result.stdout.splitlines()
    history.require(bool(lines), "original historical semantic gate returned no result")
    original = document(lines[-1])
    expected = {"measured_commit": MEASURED_COMMIT, "current_source_qualified_by_this_check": False,
                "runtime_matches": False, "engineering_observations_verified": True,
                "historical_semantics_verified": True, "pipeline_cases": 4,
                "actual_confirmed_transfers": 20480, **{flag: False for flag in FLAGS}}
    # JSON spelling distinguishes integer zero/one from authority booleans.
    history.require(json.dumps(original, sort_keys=True) == json.dumps(expected, sort_keys=True),
                    "original historical outcome or qualification scope differs")
    return original


def run_archive_reader(root, index):
    # Keep the existing generic implementation unchanged, and propagate the
    # same protocol prohibition to all of its Git subprocesses as well.
    result = subprocess.run([sys.executable, "-B", "-s", str(Path(history.__file__).resolve()),
                             "--root", str(root), "--manifest", str(index)],
                            cwd=root, env=local_environment(), capture_output=True,
                            text=True, timeout=300)
    history.require(result.returncode == 0,
                    "original archive binding failed: " + result.stderr[-6000:].strip())
    report = document(result.stdout)
    history.require(report["result"] == "PASS" and report["archive_files"] == ARCHIVED_FILES
                    and report["archive_bytes"] == ARCHIVED_BYTES
                    and report["production_activation"] is False,
                    "generic archive binding result differs")
    return report


def validate(root: Path, index: Path):
    root, captured, data, original, measured, archived, manifest = fixed_inputs(root, index)
    archive_report = run_archive_reader(root, index)
    with tempfile.TemporaryDirectory(prefix="pon-public-archive-") as owned:
        owned = Path(owned)
        view = owned / "original-evidence"
        view.mkdir()
        original_view(root, view, original, archived, manifest)
        source = owned / "measured-source"
        measured_repository(root, source, measured)
        semantic = run_original_gate(source, view)
        from check_public_readiness_evidence import validate_artifacts
        validate_artifacts(root, view, manifest)
    history.require(history.local_file(root, PACKAGE + "/" + INDEX_NAME).read_bytes() == captured,
                    "archive index changed while validating")
    return dict(archive_report, **semantic, original_manifest_entries=ORIGINAL_FILES - 1,
                original_package_files=ORIGINAL_FILES, original_package_bytes=ORIGINAL_BYTES,
                original_source_files_sha256=SOURCE_FILES,
                original_source_tree_paths=len(measured),
                original_source_blobs=len({row["blob"] for row in measured.values()}),
                original_checker_blob=CHECKER_BLOB,
                original_checker_sha256=CHECKER_SHA256,
                original_semantic_gate_executed=True,
                current_and_original_tracking_verified=True,
                network_fetches=0, current_runtime_tests_executed=0,
                native_execution_authenticated=False, qualification_changed=False)


def dispatch_historical_archive(root: Path, folder: Path):
    """Only the exact historical V1 package can select this storage reader."""
    expected = root.resolve() / PACKAGE
    if folder.absolute() != expected:
        return None
    index = expected / INDEX_NAME
    if not index.exists() and not index.is_symlink():
        return None
    return validate(root, index)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root, args.manifest), sort_keys=True))
        return 0
    except (history.Invalid, KeyError, TypeError, OSError, UnicodeError, ValueError,
            subprocess.SubprocessError) as error:
        print("Public-readiness archive check failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
