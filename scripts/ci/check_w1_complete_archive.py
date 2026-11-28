#!/usr/bin/env python3
"""Run the unchanged W1 byte verifier against its complete original Git view.

The current package retains all small records and the root validation archive.
All 172 original files, the 170-row FILE_INDEX, SHA256SUMS, all 60 archives and
their 4,960 members remain mandatory. No native W1 experiment is reexecuted.
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


PACKAGE = "evidence/pon-w1-complete-work-20261101"
INDEX_NAME = "W1_COMPLETE_ARCHIVE.json"
COMMIT = "893210a45b44742edfe2510fea1d92e9974b5f95"
TREE = "a2d04b29621bb78504244471aacac3be3bc78d1d"
CHECKER = "verify_archives.py"
CHECKER_BLOB = "0cfb6b0d24438d92c6ad2992d57c18074237ec37"
CHECKER_SHA256 = "0c996bbb2b5b8ea11c29036cc163460a936149344dbe2e6b0d34834230cd39ef"
RUNS = [41297071118, 41297714882, 41298626837, 41299973417]
SCOPES = ["codeql-export", "other-ci-8327719", "recent-ci-repair",
          *["run-" + str(run) for run in RUNS]]
ORIGINAL_FILES = 172
ORIGINAL_BYTES = 145800078
ARCHIVED_FILES = 150
ARCHIVED_BYTES = 144798166
PAYLOAD_FILES = 59
PAYLOAD_BYTES = 138750512
SMALL_FILES = 91
ARCHIVES = 60
MEMBERS = 4960
MEMBER_BYTES = 4463919709
MANIFESTS = frozenset({"README.md", CHECKER, "FILE_INDEX.json", "SHA256SUMS"})
CONTROL_PINS = {
    "README.md": ("2d34ece4079fadb46872786b5e77e43c024d54bf", 28206,
                  "f5a1ebd23e3065f9814aa9c0b63bd54d037151559ed4c99d9df59bc381964b89"),
    CHECKER: (CHECKER_BLOB, 5952, CHECKER_SHA256),
    "FILE_INDEX.json": ("45098a349d5613e9685a727ffea061b1e501f71a", 42703,
                        "536f9a527624db0b41b5237d3095596dd07e8849e40a87600890991937d0b805"),
    "SHA256SUMS": ("7ccc62f47e79eb55d715f33057781e692afb64c7", 19181,
                   "e840182c453d71cdd604802764765acfee70c04fadcdec4b6dcc20a1eb4f34ad"),
}
MAIN_MARKER = b"\nif __name__ == '__main__':\n"
DISPATCH = b'''\nif __name__ == '__main__':
    # The current package always uses the read-only historical-byte view.
    # The private view restores the exact original verifier from its Git blob.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts' / 'ci'))
    from check_w1_complete_archive import current_cli
    raise SystemExit(current_cli(Path(__file__).resolve().parent))
'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob_id(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def document(raw):
    def bad_constant(value):
        raise history.Invalid("invalid JSON constant: " + value)
    return json.loads(raw, object_pairs_hook=history.unique, parse_constant=bad_constant)


def original_bytes(root, row):
    raw = history.git(root, "cat-file", "blob", row["blob"])
    history.require(len(raw) == row["bytes"] and blob_id(raw) == row["blob"],
                    "original blob identity differs: " + row["path"])
    return raw


def current_source(original):
    history.require(original.count(MAIN_MARKER) == 1, "original main marker differs")
    return original.partition(MAIN_MARKER)[0] + DISPATCH


def current_files(root):
    package = root / PACKAGE
    history.require(package.is_dir() and not package.is_symlink(), "missing or symlink package")
    found = set()
    for path in package.rglob("*"):
        history.require(not path.is_symlink(), "symlink in current W1 evidence")
        if path.is_file():
            found.add(path.relative_to(root).as_posix())
        else:
            history.require(path.is_dir(), "special file in current W1 evidence")
    return found


def tracked_state(root, expected, original, copies):
    staged = {}
    for line in history.git(root, "ls-files", "--stage", "-z", "--", PACKAGE).split(b"\0"):
        if not line:
            continue
        metadata, name = line.split(b"\t", 1)
        mode, oid, stage = metadata.decode("ascii").split()
        path = history.canonical(name.decode("utf-8"))
        history.require(stage == "0" and path not in staged, "unmerged or repeated index path")
        staged[path] = (mode, oid)
    history.require(set(staged) == expected, "current package Git index roster differs")
    unchanged = set(original) - {row["archive_path"] for row in copies} - {
        PACKAGE + "/README.md", PACKAGE + "/" + CHECKER}
    copied = {row["path"]: row["archive_path"] for row in copies}
    for name, (mode, oid) in staged.items():
        raw = history.local_file(root, name).read_bytes()
        source = copied.get(name, name)
        original_mode = original[source]["mode"] if source in original else "100644"
        history.require(mode == original_mode and oid == blob_id(raw),
                        "current staged bytes or mode differ: " + name)
        if name in unchanged or name in copied:
            history.require(oid == original[source]["blob"],
                            "retained original index blob differs: " + name)
    return staged


def fixed_inputs(root, index):
    root = root.resolve()
    index = index if index.is_absolute() else root / index
    history.require(index == root / PACKAGE / INDEX_NAME,
                    "W1 archive index outside the fixed package")
    captured = history.local_file(root, PACKAGE + "/" + INDEX_NAME).read_bytes()
    data = document(captured)
    history.require(data["source_commit"] == COMMIT and data["source_tree"] == TREE,
                    "W1 archive is not the fixed original snapshot")
    prefix = PACKAGE + "/"
    history.require(data["scopes"] == [prefix + name for name in SCOPES],
                    "W1 archive must cover the seven complete original scopes")
    try:
        original = history.tree_rows(root, COMMIT, [PACKAGE])
    except ValueError as error:
        # `git ls-tree -l` can return a literal BAD size for a missing blob.
        # Refuse the unavailable original snapshot with an explicit boundary.
        raise history.Invalid("original W1 snapshot unavailable or invalid: " + str(error)) from error
    history.require(len(original) == ORIGINAL_FILES
                    and sum(row["bytes"] for row in original.values()) == ORIGINAL_BYTES,
                    "original W1 package denominator differs")
    archived = {row["path"]: row for row in data["files"]}
    expected_archived = {name for name in original
                         if any(name.startswith(prefix + scope + "/") for scope in SCOPES)}
    history.require(set(archived) == expected_archived
                    and len(data["files"]) == len(archived) == ARCHIVED_FILES
                    and type(data["file_count"]) is int and data["file_count"] == ARCHIVED_FILES
                    and type(data["total_bytes"]) is int and data["total_bytes"] == ARCHIVED_BYTES,
                    "original W1 archived file roster differs")
    payload = {name for name in archived if name.endswith(".tar.xz")}
    small = set(archived) - payload
    history.require(len(payload) == PAYLOAD_FILES
                    and sum(original[name]["bytes"] for name in payload) == PAYLOAD_BYTES
                    and len(small) == SMALL_FILES,
                    "W1 archive payload or retained record denominator differs")
    manifests = {row["path"]: row for row in data["historical_manifests"]}
    history.require(set(manifests) == {prefix + name for name in MANIFESTS}
                    and len(data["historical_manifests"]) == len(MANIFESTS),
                    "original checker, README, FILE_INDEX or SHA256SUMS binding missing")
    changed = {prefix + "README.md", prefix + CHECKER}
    preserved = {row["path"] for row in data["preserved_files"]}
    history.require(preserved == set(original) - set(archived) - changed
                    and len(preserved) == len(data["preserved_files"]),
                    "all original nonarchived records and validation archive must remain")
    copies = {row["path"]: row["archive_path"] for row in data["retained_copies"]}
    expected_copies = {prefix + "retained-" + name[len(prefix):]: name for name in small}
    history.require(copies == expected_copies and len(data["retained_copies"]) == SMALL_FILES,
                    "all original small W1 records must remain exact retained copies")
    wanted = (set(original) - set(archived)) | set(copies) | {prefix + INDEX_NAME}
    history.require(current_files(root) == wanted,
                    "current W1 package has missing or extra paths")
    for name, (oid, size, sha256) in CONTROL_PINS.items():
        row = original[prefix + name]
        raw = original_bytes(root, row)
        history.require((row["blob"], len(raw), digest(raw)) == (oid, size, sha256),
                        "original W1 control differs: " + name)
    checker = original_bytes(root, original[prefix + CHECKER])
    history.require(original[prefix + CHECKER]["blob"] == CHECKER_BLOB
                    and digest(checker) == CHECKER_SHA256,
                    "original W1 checker differs")
    history.require(history.local_file(root, prefix + CHECKER).read_bytes() == current_source(checker),
                    "original functions or unconditional archive dispatch changed")
    inventory = document(original_bytes(root, original[prefix + "FILE_INDEX.json"]))
    history.require(inventory["schema"] == "pon-w1-complete-work-evidence-files-v1"
                    and inventory["runs"] == RUNS
                    and inventory["files_exclude"] == ["FILE_INDEX.json", "SHA256SUMS"]
                    and len(inventory["files"]) == ORIGINAL_FILES - 2
                    and inventory["payload_files"] == ORIGINAL_FILES - 2,
                    "original 170-entry W1 FILE_INDEX differs")
    for flag in ("original_zip_containers_included", "new_native_execution_by_archive_verification"):
        history.require(inventory[flag] is False, "original W1 inventory promotes " + flag)
    report, _ = history.validate(root, index)
    history.require(history.local_file(root, prefix + INDEX_NAME).read_bytes() == captured,
                    "W1 archive index changed during validation")
    staged = tracked_state(root, wanted, original, data["retained_copies"])
    return root, data, original, copies, checker, report, captured, staged


def validate(root, index):
    root, data, original, copies, checker, report, captured, staged = fixed_inputs(root, index)
    prefix = PACKAGE + "/"
    archived = {row["path"] for row in data["files"]}
    reverse = {old: new for new, old in copies.items()}
    changed = {prefix + "README.md", prefix + CHECKER}
    before = {name: digest(history.local_file(root, name).read_bytes()) for name in current_files(root)}
    with tempfile.TemporaryDirectory(prefix="trnm-w1-complete-view-") as temporary:
        view = Path(temporary) / "original"
        view.mkdir()
        private_hashes = {}
        for name, row in original.items():
            if name in reverse:
                raw = history.local_file(root, reverse[name]).read_bytes()
            elif name in archived or name in changed:
                raw = original_bytes(root, row)
            else:
                raw = history.local_file(root, name).read_bytes()
            history.require(len(raw) == row["bytes"] and blob_id(raw) == row["blob"],
                            "private original W1 view differs: " + name)
            relative = name[len(prefix):]
            target = view / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(int(row["mode"], 8) & 0o777)
            private_hashes[relative] = digest(raw)
        history.require((view / CHECKER).read_bytes() == checker, "private original checker changed")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env.update(PATH="", PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
                   GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")
        child = subprocess.run([sys.executable, "-I", "-B", str(view / CHECKER), str(view)],
                               cwd=view, env=env, capture_output=True, timeout=300)
        if child.returncode != 0:
            print(json.dumps({"result": "FAIL", "original_checker_exit": child.returncode,
                              "stdout": child.stdout.decode("utf-8", "replace"),
                              "stderr": child.stderr.decode("utf-8", "replace")}, sort_keys=True),
                  file=sys.stderr)
            raise history.Invalid("unchanged original W1 evidence verifier failed")
        actual = document(child.stdout)
        expected = {"result": "PASS_RETAINED_BYTES", "runs": RUNS,
                    "archives_reopened": ARCHIVES, "members_verified": MEMBERS,
                    "member_bytes_verified": MEMBER_BYTES,
                    "original_zip_containers_included": False, "new_native_execution": False,
                    "work_hardness_or_service_qualification": False}
        history.require(actual == expected and child.stderr == b"",
                        "original W1 verifier did not verify the complete expected denominator")
        private_after = {}
        for path in view.rglob("*"):
            history.require(not path.is_symlink(), "private original view gained a symlink")
            if path.is_file():
                private_after[path.relative_to(view).as_posix()] = digest(path.read_bytes())
            else:
                history.require(path.is_dir(), "private original view gained a special file")
        history.require(private_after == private_hashes,
                        "original W1 verifier changed its private evidence view")
        observation = {"original_checker_exit": child.returncode,
                       "original_observation": actual,
                       "original_stdout_sha256": digest(child.stdout),
                       "original_stderr_sha256": digest(child.stderr)}
    after = {name: digest(history.local_file(root, name).read_bytes()) for name in current_files(root)}
    history.require(before == after and history.local_file(root, prefix + INDEX_NAME).read_bytes() == captured,
                    "retained W1 evidence changed during original verification")
    history.require(tracked_state(root, set(after), original, data["retained_copies"]) == staged,
                    "current W1 Git index changed during verification")
    return dict(report, **observation, current_and_original_tracking_verified=True,
                retained_files_and_index_bytes_unchanged=True,
                removed_payload_files=PAYLOAD_FILES, removed_payload_bytes=PAYLOAD_BYTES,
                original_package_files=ORIGINAL_FILES, original_package_bytes=ORIGINAL_BYTES,
                original_manifest_entries=ORIGINAL_FILES - 2, original_sha256sums_entries=ORIGINAL_FILES - 1,
                original_checker_executed=True, original_checker_sha256=CHECKER_SHA256,
                original_archives_verified=ARCHIVES, original_archive_members_rehashed=MEMBERS,
                original_member_bytes_rehashed=MEMBER_BYTES,
                original_zip_bytes_reverified=False, archive_members_extracted=False,
                network_fetches=0, current_runtime_tests_executed=0,
                current_work_or_service_qualification=False, whole_chain_native=False)


ERRORS = (history.Invalid, KeyError, TypeError, OSError, UnicodeError, ValueError,
          subprocess.TimeoutExpired)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root, args.manifest), sort_keys=True))
        return 0
    except ERRORS as error:
        print("W1 complete archive check failed: " + str(error), file=sys.stderr)
        return 2


def current_cli(package):
    """Preserve the original positional directory argument, with no fallback."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=package)
    args = parser.parse_args()
    try:
        package = package.resolve()
        history.require(args.directory.resolve() == package,
                        "archived verifier directory must identify its fixed package")
        root = package.parents[1]
        print(json.dumps(validate(root, package / INDEX_NAME), sort_keys=True))
        return 0
    except ERRORS as error:
        print("W1 complete archive check failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
