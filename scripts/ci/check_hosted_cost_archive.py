#!/usr/bin/env python3
"""Verify the frozen eight-sample package through its exact original byte view.

The 32 hosted TAR/XZ files or parts are historical Git objects. Five small
hosted-cost records remain byte-identical current copies. The original verifier
still checks all twelve concatenated archives, every member and all five
original package sections. Its temporary receipt never replaces an old receipt.
This is byte verification, not execution of a work or service experiment.
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


PACKAGE = "evidence/pon-work-security-eight-samples-20261101"
INDEX_NAME = "HOSTED_COST_ARCHIVE.json"
COMMIT = "893210a45b44742edfe2510fea1d92e9974b5f95"
TREE = "a2d04b29621bb78504244471aacac3be3bc78d1d"
CHECKER = "verify_evidence.py"
CHECKER_BLOB = "1ce2d4723c9351f3025f16ce49d344f19ccb6646"
CHECKER_SHA256 = "ee96dd6aebf2817762831393d687f3b650c93545a3ea18ddf6f17f7d8a1c68b6"
ORIGINAL_FILES = 210
ORIGINAL_BYTES = 245358947
ARCHIVED_FILES = 37
ARCHIVED_BYTES = 181012739
PAYLOAD_FILES = 32
PAYLOAD_BYTES = 180351232
MEMBERS = 808
MEMBER_BYTES = 3762781104
SMALL_RECORDS = frozenset({"ARCHIVES.json", "analyze-hosted-cost.py",
                           "hosted-cost-analysis.json", "hosted-cost-analysis.log",
                           "hosted-cost-analysis.md"})
MANIFESTS = frozenset({"README.md", CHECKER, "INDEX.json", "verification-receipt.json"})
SECTIONS = frozenset({"hosted-cost", "local-v2", "cache-benchmark",
                      "hosted-service", "top-level-index"})
MAIN_MARKER = b'\nif __name__ == "__main__":\n'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    def bad_constant(value):
        raise history.Invalid("invalid JSON constant: " + value)
    return json.loads(raw, object_pairs_hook=history.unique, parse_constant=bad_constant)


def original_bytes(root, row):
    raw = history.git(root, "cat-file", "blob", row["blob"])
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    history.require(actual == row["blob"] and len(raw) == row["bytes"],
                    "original blob differs: " + row["path"])
    return raw


def current_files(root, package):
    found = set()
    for path in (root / package).rglob("*"):
        history.require(not path.is_symlink(), "symlink in current hosted-cost evidence")
        if path.is_file():
            found.add(path.relative_to(root).as_posix())
        else:
            history.require(path.is_dir(), "special file in current hosted-cost evidence")
    return found


def fixed_inputs(root, index):
    root = root.resolve()
    index = index.absolute()
    expected = root / PACKAGE / INDEX_NAME
    history.require(index == expected, "hosted-cost index outside fixed package")
    captured = history.local_file(root, PACKAGE + "/" + INDEX_NAME).read_bytes()
    data = document(captured)
    history.require(data["source_commit"] == COMMIT and data["source_tree"] == TREE,
                    "hosted-cost archive is not the fixed original snapshot")
    history.require(data["scopes"] == [PACKAGE + "/hosted-cost"],
                    "archive must cover the whole original hosted-cost directory")
    original = history.tree_rows(root, COMMIT, [PACKAGE])
    history.require(len(original) == ORIGINAL_FILES
                    and sum(row["bytes"] for row in original.values()) == ORIGINAL_BYTES,
                    "original package denominator differs")
    prefix = PACKAGE + "/"
    archived = {row["path"]: row for row in data["files"]}
    expected_archived = {name for name in original if name.startswith(prefix + "hosted-cost/")}
    history.require(set(archived) == expected_archived
                    and len(data["files"]) == len(archived) == ARCHIVED_FILES
                    and data["file_count"] == ARCHIVED_FILES
                    and data["total_bytes"] == ARCHIVED_BYTES,
                    "original hosted-cost file roster differs")
    small = {prefix + "hosted-cost/" + name for name in SMALL_RECORDS}
    payload = set(archived) - small
    history.require(len(payload) == PAYLOAD_FILES
                    and sum(original[name]["bytes"] for name in payload) == PAYLOAD_BYTES
                    and all(".tar.xz" in name for name in payload),
                    "hosted archive payload denominator differs")
    manifests = {row["path"]: row for row in data["historical_manifests"]}
    history.require(set(manifests) == {prefix + name for name in MANIFESTS}
                    and len(data["historical_manifests"]) == len(MANIFESTS),
                    "original checker, README, index or receipt binding missing")
    preserved = {row["path"] for row in data["preserved_files"]}
    history.require(preserved == set(original) - set(archived) - {prefix + "README.md", prefix + CHECKER},
                    "original non-hosted evidence must remain byte-identical")
    copies = {row["path"]: row["archive_path"] for row in data["retained_copies"]}
    expected_copies = {prefix + "retained-hosted-cost/" + name: prefix + "hosted-cost/" + name
                       for name in SMALL_RECORDS}
    history.require(copies == expected_copies and len(data["retained_copies"]) == len(SMALL_RECORDS),
                    "five original small hosted-cost records must remain exact copies")
    wanted = (set(original) - set(archived)) | set(copies) | {prefix + INDEX_NAME}
    history.require(current_files(root, PACKAGE) == wanted,
                    "current hosted-cost package has missing or extra paths")
    tracked = {name.decode() for name in history.git(root, "ls-files", "-z", "--", PACKAGE).split(b"\0") if name}
    history.require(tracked == wanted, "current hosted-cost file roster is not exactly tracked")
    checker = original_bytes(root, original[prefix + CHECKER])
    history.require(original[prefix + CHECKER]["blob"] == CHECKER_BLOB
                    and digest(checker) == CHECKER_SHA256,
                    "original hosted-cost checker differs")
    current = history.local_file(root, prefix + CHECKER).read_bytes()
    history.require(checker.count(MAIN_MARKER) == current.count(MAIN_MARKER) == 1
                    and checker.partition(MAIN_MARKER)[0] == current.partition(MAIN_MARKER)[0],
                    "original byte-verification functions changed")
    inventory = document(original_bytes(root, original[prefix + "INDEX.json"]))
    history.require(inventory["schema"] == "pon-eight-sample-evidence-inventory-v1",
                    "original package index schema differs")
    for flag in ("qualified_work_cost", "public_service_qualified", "production_activation"):
        history.require(inventory[flag] is False, "original package promotes " + flag)
    history.require(len(inventory["files"]) == ORIGINAL_FILES - 2,
                    "original 208-entry package manifest differs")
    report, _ = history.validate(root, index)
    history.require(history.local_file(root, prefix + INDEX_NAME).read_bytes() == captured,
                    "hosted-cost index changed during validation")
    return root, data, original, copies, checker, report, captured


def validate(root, index):
    root, data, original, copies, checker, report, captured = fixed_inputs(root, index)
    archived = {row["path"] for row in data["files"]}
    prefix = PACKAGE + "/"
    reverse = {old: new for new, old in copies.items()}
    changed = {prefix + "README.md", prefix + CHECKER}
    before = {name: digest(history.local_file(root, name).read_bytes())
              for name in current_files(root, PACKAGE)}
    with tempfile.TemporaryDirectory(prefix="trnm-hosted-cost-view-") as temporary:
        view = Path(temporary) / "original"
        view.mkdir()
        for name, row in original.items():
            if name in reverse:
                raw = history.local_file(root, reverse[name]).read_bytes()
            elif name in archived or name in changed:
                raw = original_bytes(root, row)
            else:
                raw = history.local_file(root, name).read_bytes()
            oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            history.require(oid == row["blob"] and len(raw) == row["bytes"],
                            "private original view differs: " + name)
            target = view / name[len(prefix):]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(int(row["mode"], 8) & 0o777)
        history.require((view / CHECKER).read_bytes() == checker, "private checker changed")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env.update(PATH="", PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
                   GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")
        historical_receipt = (view / "verification-receipt.json").read_bytes()
        child = subprocess.run([sys.executable, "-I", "-B", str(view / CHECKER), "--root", str(view)],
                               cwd=view, env=env, capture_output=True, timeout=300)
        receipt_path = view / "verification-receipt.json"
        actual_raw = receipt_path.read_bytes()
        actual = document(actual_raw)
        if child.returncode != 0 or actual.get("result") != "PASS":
            # Preserve the actual failed checker result in the caller's log;
            # it must not disappear when the private byte view is removed.
            print(json.dumps({"result": "FAIL", "original_checker_exit": child.returncode,
                              "original_observation": actual,
                              "stdout": child.stdout.decode("utf-8", "replace"),
                              "stderr": child.stderr.decode("utf-8", "replace")}, sort_keys=True),
                  file=sys.stderr)
            raise history.Invalid("unchanged original evidence verifier failed")
        history.require(actual_raw != historical_receipt, "original checker did not write a new observation")
        history.require(actual["script"] == {"name": CHECKER, "bytes": len(checker), "sha256": CHECKER_SHA256},
                        "executed original checker identity differs")
        history.require(actual["native_execution_performed"] is False
                        and actual["semantic_work_or_service_qualification"] is False
                        and actual["archive_extraction_performed"] is False,
                        "original verifier exceeded historical byte scope")
        sections = actual["sections"]
        history.require(set(sections) == SECTIONS and all(s["result"] == "PASS" for s in sections.values())
                        and actual["failures"] == [] and actual["complete_top_level_inventory_verified"] is True,
                        "original package sections were not completely verified")
        archives = sections["hosted-cost"]["archives"]
        history.require(len(archives) == 12
                        and sum(a["parts_verified"] for a in archives) == PAYLOAD_FILES
                        and sum(a["regular_members"] for a in archives) == MEMBERS
                        and sum(a["uncompressed_bytes"] for a in archives) == MEMBER_BYTES
                        and all(a["exact_member_set"] is True
                                and a["every_member_sha256_and_size_verified"] is True
                                and a["original_zip_container_reverified"] is False for a in archives),
                        "original hosted archive/member denominator differs")
        history.require(sections["top-level-index"]["files_verified"] == ORIGINAL_FILES - 2,
                        "original top-level manifest was not fully verified")
        observation = {"original_checker_exit": child.returncode,
                       "original_report_sha256": digest(actual_raw), "original_observation": actual,
                       "original_stdout_sha256": digest(child.stdout),
                       "original_stderr_sha256": digest(child.stderr)}
    after = {name: digest(history.local_file(root, name).read_bytes())
             for name in current_files(root, PACKAGE)}
    history.require(before == after and history.local_file(root, prefix + INDEX_NAME).read_bytes() == captured,
                    "retained evidence changed during original verification")
    tracked_after = {name.decode() for name in history.git(root, "ls-files", "-z", "--", PACKAGE).split(b"\0") if name}
    history.require(tracked_after == set(after), "current tracking changed during original verification")
    return dict(report, **observation, current_and_original_tracking_verified=True,
                removed_payload_files=PAYLOAD_FILES, removed_payload_bytes=PAYLOAD_BYTES,
                original_package_files=ORIGINAL_FILES, original_package_bytes=ORIGINAL_BYTES,
                original_manifest_entries=ORIGINAL_FILES - 2, original_checker_executed=True,
                original_archive_parts_rehashed=PAYLOAD_FILES, original_archives_verified=12,
                original_archive_members_rehashed=MEMBERS, original_member_bytes_rehashed=MEMBER_BYTES,
                original_zip_bytes_reverified=False, archive_members_extracted=False,
                network_fetches=0, current_runtime_tests_executed=0,
                current_work_or_service_qualification=False, whole_chain_native=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root, args.manifest), sort_keys=True))
        return 0
    except (history.Invalid, KeyError, TypeError, OSError, UnicodeError, ValueError,
            subprocess.TimeoutExpired) as error:
        print("Hosted-cost archive check failed: " + str(error), file=sys.stderr)
        return 2


def current_cli(package):
    """Keep the original verifier's --root argument while routing archived bytes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=package)
    args = parser.parse_args()
    root = package.resolve().parents[1]
    try:
        history.require(args.root.resolve() == package.resolve(),
                        "archived verifier --root must identify its fixed package")
        print(json.dumps(validate(root, package / INDEX_NAME), sort_keys=True))
        return 0
    except (history.Invalid, KeyError, TypeError, OSError, UnicodeError, ValueError,
            subprocess.TimeoutExpired) as error:
        print("Hosted-cost archive check failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
