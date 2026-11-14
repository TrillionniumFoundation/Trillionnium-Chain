#!/usr/bin/env python3
"""Inspect or stage raw account-boundary evidence outside the source checkouts.

This is an evidence copier, not a test runner or an acceptance gate. It never
runs Git, Cargo, remote commands, or a collected script. Inspect is the default;
only --stage creates a delivery tree. Original files are never rewritten.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
from typing import Any

PLAN_SCHEMA = "trnm-account-authorization-delivery-plan-v1"
MANIFEST_SCHEMA = "trnm-account-authorization-delivery-manifest-v1"
INDEX_SCHEMA = "trnm-account-authorization-delivery-record-index-v1"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,100}\Z")
RECEIPTS = ("context.json", "result.json", "stdout.log", "stderr.log")
GENERATED = {"manifest.json", "manifest.sha256", "record-index.json",
             "binary-identities.json", "README.md"}
MAX_JSON_BYTES = 64 * 1024 * 1024
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
EMPTY_RESULT_CLASS = "INCOMPLETE_EMPTY_RESULT"
EMPTY_RESULT_KEY = ("desktop", "cdd984808a088e6c2e13b1e1ae6630a94d500c89",
                    "node-retained-all-targets")
EMPTY_RESULT_INPUT = "desktop-node-retained"
EMPTY_RESULT_JOB = "1a1c8980187-135c4-111"
EMPTY_RESULT_SCHEMA = "desktop-node-incomplete-evidence-export-v1"


class EvidenceError(Exception):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_json(data: bytes, name: str) -> Any:
    if len(data) > MAX_JSON_BYTES:
        raise EvidenceError(f"JSON exceeds inspection bound: {name}")
    try:
        return json.loads(data, object_pairs_hook=duplicate_rejecting_object)
    except (UnicodeError, ValueError) as error:
        raise EvidenceError(f"invalid JSON in {name}: {error}") from error


def relative(value: str) -> str:
    if (not value or value.startswith("/") or "\\" in value
            or any(c in value for c in "\x00\r\n")
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise EvidenceError(f"unsafe relative path: {value!r}")
    return PurePosixPath(value).as_posix()


def absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise EvidenceError(f"input path must be absolute: {value}")
    return path


def fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def hash_file(path: Path) -> dict[str, Any]:
    """Hash only a regular non-symlink file, with a stable descriptor identity."""
    if not stat.S_ISREG(path.lstat().st_mode):
        raise EvidenceError(f"not a regular file: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"not a regular opened file: {path}")
        digest = hashlib.sha256()
        magic = b""
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            if not magic:
                magic = data[:4]
            digest.update(data)
        after = os.fstat(stream.fileno())
    if fingerprint(before) != fingerprint(after) or fingerprint(after) != fingerprint(path.lstat()):
        raise EvidenceError(f"file changed while hashing: {path}")
    return {
        "bytes": before.st_size,
        "sha256": digest.hexdigest(),
        "mode": stat.S_IMODE(before.st_mode),
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "device": before.st_dev,
        "inode": before.st_ino,
        "elf": magic == b"\x7fELF",
        "stat_stable_during_hash": True,
    }


def read_pinned_json(path: Path, info: dict[str, Any]) -> Any:
    if info["bytes"] > MAX_JSON_BYTES:
        raise EvidenceError(f"JSON exceeds inspection bound: {path}")
    data = path.read_bytes()
    if len(data) != info["bytes"] or hashlib.sha256(data).hexdigest() != info["sha256"]:
        raise EvidenceError(f"JSON changed after inventory: {path}")
    return parse_json(data, str(path))


def outside_sources(path: Path, protected_roots: list[Path]) -> None:
    for root in protected_roots:
        if within(path, root):
            raise EvidenceError(f"output is inside a protected source checkout: {path}")


def within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def no_qualifications() -> dict[str, bool]:
    return {
        "production_qualification_granted": False,
        "whole_chain_pq_qualification_granted": False,
        "full_ci_acceptance_granted": False,
        "new_test_execution_claimed": False,
        "ignored_or_filtered_tests_counted_as_passed": False,
        "failed_records_reclassified_as_passed": False,
        "source_cohorts_combined_for_acceptance": False,
        "incomplete_records_counted_as_terminal": False,
        "incomplete_results_synthesized": False,
    }


class Collection:
    def __init__(self, plan_path: Path, readme: Path | None):
        self.plan_path = plan_path
        self.plan_info = hash_file(plan_path)
        self.plan = read_pinned_json(plan_path, self.plan_info)
        if self.plan.get("schema") != PLAN_SCHEMA:
            raise EvidenceError("unsupported delivery plan schema")
        self.sources = self.plan["source_trees"]
        if not self.sources or any(not HEX40.fullmatch(k) or not HEX40.fullmatch(v)
                                   for k, v in self.sources.items()):
            raise EvidenceError("source_trees must map exact commits to exact trees")
        self.current = self.plan["current_source_commit"]
        if self.current not in self.sources:
            raise EvidenceError("current source is absent from source_trees")
        if self.plan.get("require_terminal_records", True) is not True:
            raise EvidenceError("ordinary incomplete records must remain blocked")
        self.protected = [absolute(value) for value in self.plan["protected_source_roots"]]
        if not self.protected:
            raise EvidenceError("protected_source_roots must name the frozen source checkout")
        self.limit = self.plan.get("large_file_threshold_bytes", 64 * 1024 * 1024)
        if type(self.limit) is not int or self.limit <= 0:
            raise EvidenceError("invalid large_file_threshold_bytes")
        self.readme = readme
        self.files: dict[str, dict[str, Any]] = {}
        self.by_source_path: dict[str, list[str]] = defaultdict(list)
        self.blocks: list[dict[str, str]] = []
        self.large: list[dict[str, Any]] = []
        self.incomplete: list[dict[str, Any]] = []
        self.input_snapshots: list[tuple[Path, set[str]]] = []
        self.records: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.raw_results: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.bundle_record_expectations: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.identities: list[dict[str, Any]] = []
        self.inventory: dict[str, Any] = {}
        self.recorders: set[str] = set()
        self.binary_inputs: list[tuple[str, dict[str, Any]]] = []
        self.missing_optional_support: list[str] = []
        self.empty_result_exceptions: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.used_empty_result_exceptions: set[tuple[str, str, str]] = set()
        self.empty_result_projections: list[dict[str, Any]] = []
        self.bundle_origins: dict[str, str] = {}
        for exception in self.plan.get("incomplete_record_archive_exceptions", []):
            if not isinstance(exception, dict):
                raise EvidenceError("incomplete archive exception must be an object")
            key = (exception.get("host"), exception.get("source_commit"), exception.get("id"))
            if (key != EMPTY_RESULT_KEY or key in self.empty_result_exceptions
                    or exception.get("input_id") != EMPTY_RESULT_INPUT
                    or exception.get("origin_job_id") != EMPTY_RESULT_JOB
                    or exception.get("classification") != EMPTY_RESULT_CLASS
                    or exception.get("result_staged_basename") != "result.json.empty"
                    or exception.get("archive_only") is not True
                    or exception.get("counts_as_terminal") is not False
                    or exception.get("qualification_granted") is not False):
                raise EvidenceError("unreviewed or duplicate incomplete-record archive exception")
            pins = exception.get("receipts")
            if not isinstance(pins, dict) or set(pins) != set(RECEIPTS):
                raise EvidenceError("incomplete archive exception requires all four original receipts")
            for name, pin in pins.items():
                if (not isinstance(pin, dict) or set(pin) != {"bytes", "sha256"}
                        or type(pin["bytes"]) is not int or pin["bytes"] < 0
                        or not isinstance(pin["sha256"], str) or not HEX64.fullmatch(pin["sha256"])):
                    raise EvidenceError(f"invalid incomplete receipt pin: {name}")
            for name in ("result.json", "stdout.log"):
                if pins[name] != {"bytes": 0, "sha256": EMPTY_SHA256}:
                    raise EvidenceError(f"original incomplete receipt must remain exactly empty: {name}")
            if pins["context.json"]["bytes"] == 0 or pins["stderr.log"]["bytes"] == 0:
                raise EvidenceError("original incomplete context and stderr must be present and nonempty")
            self.empty_result_exceptions[key] = exception
        self.approved_large = {
            (item["path"], item["bytes"], item["sha256"])
            for item in self.plan.get("approved_large_files", [])
        }

    def block(self, code: str, detail: str) -> None:
        self.blocks.append({"code": code, "detail": detail})

    def add_file(self, source: Path, destination: str, metadata: dict[str, Any],
                 expected: dict[str, Any] | None = None) -> dict[str, Any]:
        destination = relative(destination)
        if destination in GENERATED and destination != "README.md":
            raise EvidenceError(f"input collides with a generated file: {destination}")
        info = hash_file(source)
        if expected:
            for key in ("bytes", "sha256"):
                if key in expected and info[key] != expected[key]:
                    raise EvidenceError(f"pinned {key} mismatch: {source}")
        entry = {"path": destination, "original_path": str(source), **metadata, **info}
        previous = self.files.get(destination)
        if previous:
            identity_keys = ("original_path", "bytes", "sha256", "device", "inode",
                             "mtime_ns", "ctime_ns", "host", "source_commit")
            if any(previous.get(key) != entry.get(key) for key in identity_keys):
                raise EvidenceError(f"destination collision: {destination}")
            previous["observed_roles"] = sorted(set(previous.get("observed_roles", [previous["role"]]))
                                                 | {entry["role"]})
            return previous
        self.files[destination] = entry
        self.by_source_path[str(source)].append(destination)
        if info["elf"]:
            self.block("BINARY_PAYLOAD_FORBIDDEN", str(source))
        if info["bytes"] > self.limit:
            approved = (str(source), info["bytes"], info["sha256"]) in self.approved_large
            self.large.append({"path": destination, "original_path": str(source),
                               "bytes": info["bytes"], "sha256": info["sha256"],
                               "explicit_exact_byte_approval": approved})
            if not approved:
                self.block("LARGE_FILE_REVIEW_REQUIRED", f"{source}: {info['bytes']} bytes {info['sha256']}")
        return entry

    def walk(self, root: Path) -> list[Path]:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise EvidenceError(f"input tree is not a plain directory: {root}")
        files: list[Path] = []
        for current, dirs, names in os.walk(root, followlinks=False):
            for name in sorted(dirs):
                path = Path(current) / name
                if not stat.S_ISDIR(path.lstat().st_mode):
                    raise EvidenceError(f"non-directory/symlink in tree: {path}")
                if name == ".git" or name == "target" or name.startswith("target-"):
                    raise EvidenceError(f"Git/Cargo target directory is not evidence: {path}")
            for name in sorted(names):
                path = Path(current) / name
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise EvidenceError(f"non-regular file in evidence: {path}")
                files.append(path)
        return sorted(files)

    def collect_tree(self, item: dict[str, Any]) -> None:
        label, host, source = item["id"], item["host"], item["source_commit"]
        if not LABEL.fullmatch(label) or not LABEL.fullmatch(host) or source not in self.sources:
            raise EvidenceError(f"invalid input identity: {label}")
        root = absolute(item["path"])
        destination = relative(item["destination"])
        expected_prefix = f"hosts/{host}/sources/{source}/"
        if not destination.startswith(expected_prefix):
            raise EvidenceError(f"input destination must preserve host/source: {label}")
        if not root.exists():
            self.block("MISSING_INPUT", f"{label}: {root}")
            return
        members = self.walk(root)
        self.input_snapshots.append((root, {str(p) for p in members}))
        metadata = {"host": host, "source_commit": source, "source_tree": self.sources[source],
                    "input_id": label, "role": item["kind"]}
        for path in members:
            self.add_file(path, destination + "/" + path.relative_to(root).as_posix(), metadata)
        if item["kind"] == "bundle":
            self.check_bundle(item, root, metadata)
        elif item["kind"] != "record-tree":
            raise EvidenceError(f"unsupported input kind: {item['kind']}")
        found_roots = item.get("record_roots", [])
        if not found_roots:
            self.block("NO_RECORD_ROOT", label)
        for name in found_roots:
            directory = root if name == "." else root / relative(name)
            if not directory.is_dir():
                self.block("MISSING_RECORD_ROOT", str(directory))
                continue
            for record_dir in sorted(directory.iterdir()):
                if record_dir.is_dir():
                    self.read_record(record_dir, root, destination, metadata)

    def check_bundle(self, item: dict[str, Any], root: Path, metadata: dict[str, Any]) -> None:
        manifest_name = relative(item["manifest"])
        manifest_path = root / manifest_name
        manifest_destination = item["destination"] + "/" + manifest_name
        if manifest_destination not in self.files:
            raise EvidenceError(f"bundle manifest missing: {manifest_path}")
        manifest = read_pinned_json(manifest_path, self.files[manifest_destination])
        if manifest.get("schema") not in item["accepted_manifest_schemas"]:
            raise EvidenceError(f"unreviewed imported manifest schema: {manifest_path}")
        if manifest.get("host") != item["host"]:
            raise EvidenceError(f"import host differs: {manifest_path}")
        source = manifest.get("source_commit", manifest.get("source_identity_before", {}).get("head"))
        if source != item["source_commit"]:
            raise EvidenceError(f"import source differs: {manifest_path}")
        for key in ("source_identity_before", "source_identity_after",
                    "source_identity_before_export", "source_identity_after_export"):
            if key in manifest:
                identity = manifest[key]
                if (identity.get("head") != source
                        or identity.get("tree") != self.sources[source]
                        or identity.get("status_porcelain") != ""):
                    raise EvidenceError(f"import source identity is not exact and clean: {manifest_path}")
        if item.get("origin_job") is not None and manifest.get("origin_job_id") != item["origin_job"]:
            raise EvidenceError(f"import origin job differs: {manifest_path}")
        if isinstance(manifest.get("origin_job_id"), str):
            self.bundle_origins[item["id"]] = manifest["origin_job_id"]
        if manifest["schema"] == EMPTY_RESULT_SCHEMA:
            if (item["id"] != EMPTY_RESULT_INPUT
                    or (item["host"], source) != EMPTY_RESULT_KEY[:2]
                    or manifest.get("origin_job_id") != EMPTY_RESULT_JOB
                    or manifest.get("complete_command_ids") != ["node-retained-preflight"]
                    or manifest.get("incomplete_command_ids") != [EMPTY_RESULT_KEY[2]]
                    or manifest.get("absent_command_ids") != ["node-retained-source-after"]):
                raise EvidenceError("incomplete bundle identity or terminal declaration differs")
            for name in ("records", "record_results"):
                declarations = manifest.get(name, {})
                if not isinstance(declarations, dict) or EMPTY_RESULT_KEY[2] in declarations:
                    raise EvidenceError("incomplete result cannot have a terminal result declaration")
            incomplete = manifest.get("incomplete_records")
            if not isinstance(incomplete, dict) or set(incomplete) != {EMPTY_RESULT_KEY[2]}:
                raise EvidenceError("missing exact incomplete-record declaration")
            declaration = incomplete[EMPTY_RESULT_KEY[2]]
            if (not isinstance(declaration, dict)
                    or declaration.get("classification") != EMPTY_RESULT_CLASS
                    or declaration.get("terminal_return_code_reconstructed") is not False
                    or any(name in declaration for name in ("pass", "returncode", "result", "finished_utc"))):
                raise EvidenceError("incomplete declaration must not synthesize a terminal result")
            observations = manifest.get("observations", {})
            absent = observations.get("source_after_directory", {})
            runtime = observations.get("runtime_status", {})
            if (absent.get("exists") is not False or absent.get("result_available") is not False
                    or absent.get("execution_not_proven") is not True
                    or runtime.get("job_id") != EMPTY_RESULT_JOB
                    or runtime.get("outcome") != "unknown"
                    or runtime.get("status_authoritative") is not False
                    or runtime.get("terminal_publication_confirmed") is not False
                    or observations.get("test_execution_not_established") is not True):
                raise EvidenceError("incomplete origin and absent source-after must remain explicit observations")
        elif manifest.get("incomplete_command_ids"):
            raise EvidenceError("incomplete declaration requires its explicit reviewed bundle schema")
        entries = manifest.get("files", manifest.get("entries"))
        if not isinstance(entries, list) or not entries:
            raise EvidenceError(f"empty or unsupported import file table: {manifest_path}")
        prefix = item.get("member_prefix", "")
        if prefix and (not prefix.endswith("/") or relative(prefix[:-1]) != prefix[:-1]):
            raise EvidenceError("invalid member_prefix")
        seen: set[str] = set()
        for row in entries:
            member = relative(row["archive_member"])
            if prefix:
                if not member.startswith(prefix):
                    raise EvidenceError(f"import member lacks fixed prefix: {member}")
                member = relative(member[len(prefix):])
            if member in seen:
                raise EvidenceError(f"duplicate import member: {member}")
            seen.add(member)
            target = item["destination"] + "/" + member
            entry = self.files.get(target)
            if not entry or entry["bytes"] != row["bytes"] or entry["sha256"] != row["sha256"]:
                raise EvidenceError(f"import member missing or changed: {member}")
            entry["import_manifest"] = manifest_destination
            entry["archive_member"] = row["archive_member"]
            entry["remote_original_path"] = row.get("original_path", row.get("remote_source"))
        extras = {manifest_name, *item.get("extra_metadata_members", [])}
        archive = item.get("archive")
        transfer = item.get("transfer_report")
        archive_info = None
        archive_members_verified = False
        transfer_data: dict[str, Any] = {}
        if transfer:
            transfer_path = absolute(transfer["path"])
            transfer_entry = self.add_file(transfer_path, transfer["destination"],
                                           dict(metadata, role="transfer-report"), transfer)
            transfer_data = read_pinned_json(transfer_path, transfer_entry)
            if within(transfer_path, root):
                extras.add(transfer_path.relative_to(root).as_posix())
        if archive:
            archive_path = absolute(archive["path"])
            pinned = archive.get("sha256")
            if not pinned:
                self.block("ARCHIVE_PLAN_PIN_REQUIRED", str(archive_path))
                pin_key = archive.get("transfer_sha256_field", "archive_sha256")
                pinned = transfer_data.get(pin_key)
            if not isinstance(pinned, str) or not HEX64.fullmatch(pinned):
                raise EvidenceError(f"archive requires an exact transfer hash: {archive_path}")
            archive_info = self.add_file(archive_path, archive["destination"],
                                         dict(metadata, role="original-import-archive"), {"sha256": pinned})
            if within(archive_path, root):
                extras.add(archive_path.relative_to(root).as_posix())
            expected_members = {
                name: self.files[item["destination"] + "/" + name]
                for name in seen | {manifest_name}
            }
            unapproved_large = any(
                row["bytes"] > self.limit
                and (row["original_path"], row["bytes"], row["sha256"]) not in self.approved_large
                for row in [archive_info, *expected_members.values()]
            )
            if not unapproved_large:
                self.check_archive(archive_path, archive_info, prefix, expected_members)
                archive_members_verified = True
        else:
            self.block("MISSING_ORIGINAL_ARCHIVE", item["id"])
        present = {p.relative_to(root).as_posix() for p in self.walk(root)}
        unexplained = present - seen - extras
        if unexplained:
            raise EvidenceError(f"unlisted import members ({item['id']}): {sorted(unexplained)}")
        self.imports.append({
            "id": item["id"], "host": item["host"], "source_commit": source,
            "manifest_path": manifest_destination, "manifest_sha256": self.files[manifest_destination]["sha256"],
            "original_members_verified": len(seen), "unlisted_original_members": [],
            "archive": None if archive_info is None else {
                k: archive_info[k] for k in ("path", "bytes", "sha256")},
            "archive_reextracted_by_this_helper": False,
            "archive_streamed_and_every_member_compared": archive_members_verified,
            "archive_manifest_bound_to_current_manifest": archive_members_verified,
            "unexecuted_command_observations": manifest.get("unexecuted_command_observations", []),
            "absent_command_ids": manifest.get("absent_command_ids", []),
            "nonterminal_observations": (manifest["observations"]
                                         if manifest["schema"] == EMPTY_RESULT_SCHEMA else None),
            "qualification_granted": False,
        })
        declared = manifest.get("records")
        if isinstance(declared, dict):
            for identifier, report in declared.items():
                self.bundle_record_expectations.append({
                    "host": item["host"], "source_commit": source, "id": identifier,
                    "bundle_prefix": item["destination"] + "/", "declared": report,
                })
        else:
            for identifier in manifest.get("complete_command_ids", []):
                self.bundle_record_expectations.append({
                    "host": item["host"], "source_commit": source, "id": identifier,
                    "bundle_prefix": item["destination"] + "/",
                    "declared": manifest.get("record_results", {}).get(identifier, {}),
                })
        for identifier in manifest.get("incomplete_command_ids", []):
            self.bundle_record_expectations.append({
                "host": item["host"], "source_commit": source, "id": identifier,
                "bundle_prefix": item["destination"] + "/",
                "declared": manifest["incomplete_records"][identifier],
                "expected_incomplete_classification": EMPTY_RESULT_CLASS,
            })
        self.binary_inputs.append((manifest_destination, manifest))

    def check_archive(self, path: Path, info: dict[str, Any], prefix: str,
                      expected: dict[str, dict[str, Any]]) -> None:
        """Bind the pinned archive to every current member, without extracting."""
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        seen_names: set[str] = set()
        seen_files: set[str] = set()
        try:
            with os.fdopen(descriptor, "rb") as source:
                before = os.fstat(source.fileno())
                if fingerprint(before) != (info["device"], info["inode"], info["bytes"],
                                           info["mtime_ns"], info["ctime_ns"]):
                    raise EvidenceError(f"archive changed before member inspection: {path}")
                with tarfile.open(fileobj=source, mode="r|*") as archive:
                    for member in archive:
                        name = relative(member.name.rstrip("/") if member.isdir() else member.name)
                        if name in seen_names:
                            raise EvidenceError(f"duplicate tar member: {name}")
                        seen_names.add(name)
                        if member.isdir():
                            if prefix and name != prefix[:-1] and not name.startswith(prefix):
                                raise EvidenceError(f"tar directory outside fixed prefix: {name}")
                            continue
                        if not member.isfile():
                            raise EvidenceError(f"link/special tar member: {name}")
                        if prefix:
                            if not name.startswith(prefix):
                                raise EvidenceError(f"tar file outside fixed prefix: {name}")
                            name = relative(name[len(prefix):])
                        expected_file = expected.get(name)
                        if expected_file is None or member.size != expected_file["bytes"]:
                            raise EvidenceError(f"unexpected tar file/size: {name}")
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            raise EvidenceError(f"cannot read regular tar file: {name}")
                        digest = hashlib.sha256()
                        count = 0
                        with extracted:
                            for data in iter(lambda: extracted.read(1024 * 1024), b""):
                                digest.update(data)
                                count += len(data)
                        if count != expected_file["bytes"] or digest.hexdigest() != expected_file["sha256"]:
                            raise EvidenceError(f"archive member bytes differ from current original: {name}")
                        seen_files.add(name)
                after = os.fstat(source.fileno())
                if fingerprint(before) != fingerprint(after) or fingerprint(after) != fingerprint(path.lstat()):
                    raise EvidenceError(f"archive changed during member inspection: {path}")
        except tarfile.TarError as error:
            raise EvidenceError(f"invalid archive {path}: {error}") from error
        if seen_files != set(expected):
            raise EvidenceError(f"archive does not cover all original members: {sorted(set(expected) - seen_files)}")

    def approve_empty_result(self, key: tuple[str, str, str], metadata: dict[str, Any],
                             evidence: dict[str, dict[str, Any] | None]) -> bool:
        exception = self.empty_result_exceptions.get(key)
        if (exception is None or metadata["input_id"] != EMPTY_RESULT_INPUT
                or self.bundle_origins.get(metadata["input_id"]) != EMPTY_RESULT_JOB):
            self.block("UNAPPROVED_EMPTY_RESULT", repr(key))
            return False
        if key in self.used_empty_result_exceptions:
            self.block("DUPLICATE_INCOMPLETE_ARCHIVE_EXCEPTION", repr(key))
            return False
        for name in RECEIPTS:
            actual = evidence[name]
            if actual is None or any(actual[field] != exception["receipts"][name][field]
                                     for field in ("bytes", "sha256")):
                self.block("INCOMPLETE_ARCHIVE_RECEIPT_MISMATCH", repr((key, name)))
                return False
        self.used_empty_result_exceptions.add(key)
        return True

    def read_record(self, directory: Path, root: Path, destination: str,
                    metadata: dict[str, Any]) -> None:
        identifier = directory.name
        prefix = destination + "/" + directory.relative_to(root).as_posix()
        evidence = {name: self.files.get(prefix + "/" + name) for name in RECEIPTS}
        if not evidence["context.json"] and not evidence["result.json"]:
            self.block("UNRECOGNIZED_RECORD_DIRECTORY", str(directory))
            return
        context = (read_pinned_json(directory / "context.json", evidence["context.json"])
                   if evidence["context.json"] else None)
        source = metadata["source_commit"]
        if (not isinstance(context, dict) or context.get("source_commit") != source
                or context.get("source_tree") != self.sources[source]):
            self.block("RECORD_SOURCE_MISMATCH", str(directory))
            return
        if isinstance(context.get("cwd"), str) and Path(context["cwd"]).is_absolute():
            self.protected.append(Path(context["cwd"]))
        if isinstance(context.get("recorder_sha256"), str):
            self.recorders.add(context["recorder_sha256"])
        key = metadata["host"], source, identifier
        result_info = evidence["result.json"]
        empty_result = result_info is not None and result_info["bytes"] == 0
        result = (read_pinned_json(directory / "result.json", result_info)
                  if result_info is not None and not empty_result else None)
        classification = "INCOMPLETE"
        computed = None
        approved_incomplete = False
        if result is not None:
            missing = [name for name, value in evidence.items() if value is None]
            valid = (isinstance(result, dict) and not missing and result.get("id") == identifier
                     and result.get("source_head_before") == source
                     and result.get("argv") == context.get("argv")
                     and isinstance(result.get("finished_utc"), str)
                     and type(result.get("pass")) is bool
                     and (type(result.get("returncode")) is int
                          or (result.get("returncode") is None and bool(result.get("launch_error")))))
            if valid:
                try:
                    dt.datetime.fromisoformat(result["finished_utc"].replace("Z", "+00:00"))
                except ValueError:
                    valid = False
            if valid:
                for stream in ("stdout", "stderr"):
                    if result.get(stream + "_sha256") != evidence[stream + ".log"]["sha256"]:
                        valid = False
                computed = (result["returncode"] == 0 and result.get("launch_error") is None
                            and result.get("source_head_after") == source
                            and result.get("source_status_after") == "")
                valid = valid and result["pass"] == computed
            if not valid:
                classification = "INVALID_RECEIPT"
                self.block("INVALID_RECEIPT", str(directory))
            else:
                classification = "PASS" if computed else "FAIL"
        else:
            if empty_result:
                classification = EMPTY_RESULT_CLASS
                approved_incomplete = self.approve_empty_result(key, metadata, evidence)
            entry = {"host": metadata["host"], "source_commit": source,
                     "id": identifier, "path": prefix, "classification": classification,
                     "result_exists": result_info is not None,
                     "result_bytes": result_info["bytes"] if result_info is not None else None,
                     "archival_exception_verified": approved_incomplete,
                     "counts_as_terminal": False, "outcome": "UNKNOWN",
                     "qualification_granted": False}
            self.incomplete.append(entry)
            if not approved_incomplete:
                self.block("INCOMPLETE_RECORD", str(directory))
        files = [self.files[name] for name in sorted(self.files) if name.startswith(prefix + "/")]
        record = {
            "host": metadata["host"], "source_commit": source, "source_tree": self.sources[source],
            "id": identifier, "classification": classification,
            "completed_result": classification in ("PASS", "FAIL"),
            "computed_pass": computed if classification in ("PASS", "FAIL") else None,
            "recorded_pass": result.get("pass") if isinstance(result, dict) else None,
            "returncode": result.get("returncode") if isinstance(result, dict) else None,
            "finished_utc": result.get("finished_utc") if isinstance(result, dict) else None,
            "argv": context.get("argv"), "paths": [prefix],
            "receipt_hashes": {name: value["sha256"] for name, value in evidence.items() if value},
            "receipt_sizes": {name: value["bytes"] for name, value in evidence.items() if value},
            "staged_receipt_paths": {name: [prefix + "/" + name]
                                     for name, value in evidence.items() if value},
            "native_and_other_raw_files": len(files),
            "all_file_hashes": {entry["path"][len(prefix) + 1:]: entry["sha256"] for entry in files},
            "original_file_hashes": {entry["path"][len(prefix) + 1:]: entry["sha256"] for entry in files},
            "archival_exception_verified": approved_incomplete,
            "source_identity_intact": (result.get("source_head_after") == source
                                        and result.get("source_status_after") == "") if isinstance(result, dict) else None,
            "qualification_granted": False,
        }
        if approved_incomplete:
            self.empty_result_projections.append({
                "key": key, "original_path": prefix + "/result.json",
                "staged_path": prefix + "/result.json.empty",
                "bytes": result_info["bytes"], "sha256": result_info["sha256"],
                "original_archive_member": result_info.get("archive_member"),
                "origin_job_id": EMPTY_RESULT_JOB, "classification": EMPTY_RESULT_CLASS,
                "original_bytes_preserved": True, "counts_as_terminal": False,
            })
        if isinstance(result, dict):
            previous_result = self.raw_results.get(key)
            if previous_result is not None and previous_result != result:
                self.block("CONFLICTING_RAW_RESULTS", repr(key))
            self.raw_results[key] = result
        old = self.records.get(key)
        if old:
            path_fields = {"paths", "staged_receipt_paths"}
            comparable = {k: v for k, v in record.items() if k not in path_fields}
            if comparable != {k: v for k, v in old.items() if k not in path_fields}:
                self.block("CONFLICTING_RECORD_COPIES", repr(key))
            else:
                old["paths"].append(prefix)
                for name, paths in record["staged_receipt_paths"].items():
                    old["staged_receipt_paths"].setdefault(name, []).extend(paths)
        else:
            self.records[key] = record

    def support(self, item: dict[str, Any]) -> None:
        path = absolute(item["path"])
        if not path.exists():
            if item.get("required", True):
                self.block("MISSING_SUPPORT", str(path))
            else:
                self.missing_optional_support.append(str(path))
            return
        sources = item.get("applicable_sources", [])
        if any(source not in self.sources for source in sources):
            raise EvidenceError(f"support has unknown applicable source: {path}")
        entry = self.add_file(path, item["destination"], {
            "host": item.get("host", "coordination"),
            "applicable_sources": sources, "role": item.get("role", "supporting-snapshot"),
            "input_id": "support",
        }, item)
        if item.get("scan_binary_identities"):
            self.binary_inputs.append((entry["path"], read_pinned_json(path, entry)))

    def check_inventory(self) -> None:
        item = self.plan["validation_inventory"]
        path = absolute(item["path"])
        entry = self.add_file(path, item["destination"], {
            "host": "coordination", "applicable_sources": sorted(self.sources),
            "role": "cross-host-cross-source-inventory-snapshot", "input_id": "inventory",
        })
        self.inventory = read_pinned_json(path, entry)
        self.binary_inputs.append((entry["path"], self.inventory))
        expected_keys = set()
        for observed in self.inventory.get("records", []):
            result = observed.get("raw_result", {})
            key = (observed["host"], observed["source_commit"], observed.get("id", result.get("id")))
            if key in expected_keys:
                self.block("DUPLICATE_INVENTORY_RECORD", repr(key))
            expected_keys.add(key)
            actual = self.records.get(key)
            if not actual:
                self.block("INVENTORY_RECORD_NOT_COLLECTED", repr(key))
                continue
            if actual["classification"] != observed.get("classification"):
                self.block("INVENTORY_CLASSIFICATION_DIFFERS", repr(key))
            for name, digest in observed.get("receipt_hashes", {}).items():
                if actual["receipt_hashes"].get(name) != digest:
                    self.block("INVENTORY_RECEIPT_HASH_DIFFERS", repr((key, name)))
        for key, record in self.records.items():
            record["listed_in_inventory_snapshot"] = key in expected_keys
        for required in self.plan.get("required_records", []):
            key = (required["host"], required["source_commit"], required["id"])
            if key not in self.records or not self.records[key]["completed_result"]:
                self.block("REQUIRED_RECORD_NOT_TERMINAL", repr(key))

    def check_bundle_records(self) -> None:
        for expected in self.bundle_record_expectations:
            key = (expected["host"], expected["source_commit"], expected["id"])
            record = self.records.get(key)
            incomplete_class = expected.get("expected_incomplete_classification")
            matches = (record is not None
                       and any(path.startswith(expected["bundle_prefix"]) for path in record["paths"]))
            if matches and incomplete_class is not None:
                matches = (key == EMPTY_RESULT_KEY and not record["completed_result"]
                           and record["classification"] == incomplete_class
                           and record["archival_exception_verified"] is True)
            elif matches:
                matches = record["completed_result"]
            if not matches:
                self.block("BUNDLE_DECLARED_RECORD_MISSING", repr(key))
                continue
            declaration = expected["declared"]
            if "result" in declaration and declaration["result"] != self.raw_results.get(key):
                self.block("BUNDLE_DECLARED_RESULT_DIFFERS", repr(key))
            for field in ("pass", "returncode", "finished_utc"):
                if field in declaration and declaration[field] != self.raw_results.get(key, {}).get(field):
                    self.block("BUNDLE_DECLARED_RESULT_DIFFERS", repr((key, field)))
            for stream, suffix in (("context", ".json"), ("result", ".json"),
                                   ("stdout", ".log"), ("stderr", ".log")):
                digest = declaration.get(stream + "_sha256")
                if digest and digest != record["receipt_hashes"].get(stream + suffix):
                    self.block("BUNDLE_DECLARED_RECEIPT_HASH_DIFFERS", repr((key, stream)))
                if (stream + "_bytes" in declaration
                        and declaration[stream + "_bytes"] != record["receipt_sizes"].get(stream + suffix)):
                    self.block("BUNDLE_DECLARED_RECEIPT_SIZE_DIFFERS", repr((key, stream)))

    def project_empty_result_receipts(self) -> None:
        """Change only the reviewed staging name; input and archive bytes stay exact."""
        for key in self.empty_result_exceptions:
            if key not in self.used_empty_result_exceptions:
                self.block("REQUIRED_INCOMPLETE_ARCHIVE_NOT_OBSERVED", repr(key))
        for projection in self.empty_result_projections:
            old_path, new_path = projection["original_path"], projection["staged_path"]
            if new_path in self.files:
                self.block("INCOMPLETE_RECEIPT_PROJECTION_COLLISION", new_path)
                continue
            entry = self.files.get(old_path)
            if (entry is None or entry["bytes"] != 0 or entry["sha256"] != EMPTY_SHA256
                    or not entry.get("import_manifest") or not entry.get("archive_member")):
                self.block("INCOMPLETE_RECEIPT_PROJECTION_MISMATCH", old_path)
                continue
            del self.files[old_path]
            entry["path"] = new_path
            entry["staged_name_projection"] = {
                "original_logical_receipt": "result.json", "original_payload_path": old_path,
                "staged_payload_path": new_path,
                "reason": "The exact preserved empty result is not JSON; only its staged name differs.",
                "original_bytes_preserved": True,
                "original_archive_member_unchanged": entry["archive_member"],
            }
            self.files[new_path] = entry
            paths = self.by_source_path[entry["original_path"]]
            self.by_source_path[entry["original_path"]] = [new_path if p == old_path else p for p in paths]
            record = self.records[projection["key"]]
            record["staged_receipt_paths"]["result.json"] = [new_path]
            original_hash = record["all_file_hashes"].pop("result.json")
            record["all_file_hashes"]["result.json.empty"] = original_hash
            record["receipt_name_projection"] = dict(entry["staged_name_projection"])
            for item in self.incomplete:
                if (item["host"], item["source_commit"], item["id"]) == projection["key"]:
                    item["logical_result_name"] = "result.json"
                    item["staged_result_path"] = new_path
                    item["result_sha256"] = EMPTY_SHA256
            projection["applied_to_staging_index"] = True
            projection["logical_receipt_name"] = "result.json"

    def collect_binary_observations(self) -> None:
        def visit(value: Any, pointer: str, evidence: str, host: str | None,
                  source: str | None) -> None:
            if isinstance(value, dict):
                host = value.get("host", host)
                candidate_source = value.get("source_commit")
                if isinstance(candidate_source, str) and HEX40.fullmatch(candidate_source):
                    source = candidate_source
                if pointer.startswith("/desktop_node_test_binary") or pointer.startswith("/desktop_environment_preparation"):
                    host, source = "desktop", self.current
                digest = value.get("sha256")
                if (isinstance(digest, str) and HEX64.fullmatch(digest)
                        and isinstance(value.get("path"), str) and type(value.get("bytes")) is int
                        and any(value.get(key) is True for key in ("elf", "executable", "post_run_hash"))):
                    self.identities.append({
                        "host": host, "source_commit": source, "evidence_path": evidence,
                        "json_pointer": pointer, "recorded_identity": value,
                        "binary_copied": False, "hash_remeasured_by_this_helper": False,
                        "scope": "Preserved recorded measurement; not an at-execution signature or a new execution.",
                    })
                for key, child in sorted(value.items()):
                    escaped = key.replace("~", "~0").replace("/", "~1")
                    visit(child, pointer + "/" + escaped, evidence, host, source)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, pointer + "/" + str(index), evidence, host, source)
        for evidence, value in self.binary_inputs:
            info = self.files[evidence]
            visit(value, "", evidence, info.get("host"), info.get("source_commit"))

    def collect(self) -> dict[str, Any]:
        for item in self.plan["inputs"]:
            try:
                self.collect_tree(item)
            except (EvidenceError, OSError, KeyError, TypeError) as error:
                self.block("INPUT_ERROR", f"{item.get('id')}: {error}")
        self.check_bundle_records()
        for item in self.plan.get("support_files", []):
            try:
                self.support(item)
            except (EvidenceError, OSError, KeyError, TypeError) as error:
                self.block("SUPPORT_ERROR", str(error))
        self.add_file(self.plan_path, "support/delivery-evidence-plan.json", {
            "host": "coordination", "applicable_sources": sorted(self.sources),
            "role": "assembly-plan", "input_id": "plan",
        }, self.plan_info)
        self.add_file(Path(__file__).resolve(), "support/prepare_delivery_evidence.py", {
            "host": "coordination", "applicable_sources": sorted(self.sources),
            "role": "assembly-helper", "input_id": "helper",
        })
        if self.readme:
            self.add_file(self.readme, "README.md", {
                "host": "coordination", "applicable_sources": sorted(self.sources),
                "role": "human-reviewed-final-readme", "input_id": "readme",
            })
        try:
            self.check_inventory()
        except (EvidenceError, OSError, KeyError, TypeError) as error:
            self.block("INVENTORY_ERROR", str(error))
        self.collect_binary_observations()
        # Original manifests, archives and receipts have all been checked using
        # their original names. Only now apply the one explicit staging alias.
        self.project_empty_result_receipts()
        counts: dict[str, dict[str, dict[str, int]]] = {}
        grouped: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for key, record in self.records.items():
            grouped[key[:2]][record["classification"]] += 1
        for (host, source), counter in sorted(grouped.items()):
            counts.setdefault(host, {})[source] = dict(sorted(counter.items()))
        payload_hashes = {entry["sha256"] for entry in self.files.values()}
        payload_entries = [{key: self.files[name][key] for key in ("path", "bytes", "sha256")}
                           for name in sorted(self.files)]
        payload_digest = hashlib.sha256(canonical_json(payload_entries)).hexdigest()
        return {
            "schema": INDEX_SCHEMA,
            "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "assembly_only": True, "current_source_commit": self.current,
            "source_trees": self.sources, "interpretation": no_qualifications(),
            "counts_by_host_and_source": counts,
            "terminal_record_count": sum(r["completed_result"] for r in self.records.values()),
            "terminal_pass_record_count": sum(r["classification"] == "PASS" for r in self.records.values()),
            "terminal_fail_record_count": sum(r["classification"] == "FAIL" for r in self.records.values()),
            "incomplete_record_count": len(self.incomplete),
            "approved_archival_incomplete_record_count": sum(
                item["archival_exception_verified"] for item in self.incomplete),
            "incomplete_records": self.incomplete,
            "incomplete_receipt_name_projections": self.empty_result_projections,
            "records": [self.records[k] for k in sorted(self.records)],
            "import_verification": self.imports,
            "payload_file_count": len(self.files),
            "payload_bytes": sum(entry["bytes"] for entry in self.files.values()),
            "payload_sha256": payload_digest,
            "payload_digest_definition": "SHA-256 of UTF-8 canonical_json(sorted [{path,bytes,sha256}]); excludes generated assembly indices and final manifest/seal.",
            "payload_files": [self.files[name] for name in sorted(self.files)],
            "recorded_binary_identity_count": len(self.identities),
            "recorded_binary_identity_observations": self.identities,
            "large_files": self.large,
            "missing_optional_support": self.missing_optional_support,
            "unavailable_recorded_harness_hashes": sorted(self.recorders - payload_hashes),
            "unavailable_harness_note": "Historical recorder hashes remain in original contexts; a current script is not relabeled as an earlier version.",
            "staging_blockers": self.blocks,
            "can_stage_selected_inputs": not self.blocks and self.readme is not None,
            "readme_supplied": self.readme is not None,
        }

    def check_unchanged(self) -> None:
        for root, original in self.input_snapshots:
            if {str(path) for path in self.walk(root)} != original:
                raise EvidenceError(f"input tree membership changed: {root}")
        for entry in self.files.values():
            actual = hash_file(Path(entry["original_path"]))
            if any(actual[key] != entry[key] for key in ("bytes", "sha256", "device", "inode", "mtime_ns", "ctime_ns")):
                raise EvidenceError(f"input changed after collection: {entry['original_path']}")

    def check_output_location(self, output: Path, *, directory: bool) -> None:
        outside_sources(output, self.protected)
        # Include not-yet-received inputs: inspection must not create an apparent
        # package or inject a derived file into a future raw evidence tree.
        for item in self.plan["inputs"]:
            root = absolute(item["path"])
            if within(output, root) or (directory and within(root, output)):
                raise EvidenceError(f"output overlaps an input tree: {root}")
        for entry in self.files.values():
            original = Path(entry["original_path"])
            if original.resolve() == output.resolve() or (directory and within(original, output)):
                raise EvidenceError("output overlaps an original evidence file")

    def stage(self, output: Path, index: dict[str, Any], expected_payload: str | None) -> None:
        if self.blocks:
            raise EvidenceError("staging blocked; inspect staging_blockers first")
        if not self.readme:
            raise EvidenceError("--stage requires an explicit, human-written --readme")
        if not expected_payload or expected_payload != index["payload_sha256"]:
            raise EvidenceError("--stage requires --expected-payload-sha256 from the reviewed inspection")
        self.check_output_location(output, directory=True)
        if output.exists():
            raise EvidenceError(f"refusing existing output: {output}")
        self.check_unchanged()
        output.mkdir(parents=True, exist_ok=False)
        # A failed run leaves its partial directory for diagnosis. It is never
        # silently deleted or resumed, and lacks the final manifest.sha256 seal.
        for name in sorted(self.files):
            entry = self.files[name]
            destination = output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = Path(entry["original_path"])
            descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as incoming, destination.open("xb") as outgoing:
                opened = os.fstat(incoming.fileno())
                if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                        entry["device"], entry["inode"], entry["bytes"], entry["mtime_ns"], entry["ctime_ns"]):
                    raise EvidenceError(f"source changed before copy: {source}")
                for data in iter(lambda: incoming.read(1024 * 1024), b""):
                    outgoing.write(data)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            copied = hash_file(destination)
            if copied["bytes"] != entry["bytes"] or copied["sha256"] != entry["sha256"]:
                raise EvidenceError(f"copy verification failed: {destination}")
        self.check_unchanged()
        derived = {
            "record-index.json": index,
            "binary-identities.json": {
                "schema": "trnm-account-authorization-recorded-binary-identities-v1",
                "scope": "Original recorded hashes only; no binary copied or re-executed.",
                "observations": self.identities, "interpretation": no_qualifications(),
            },
        }
        manifest_files = [self.files[name] for name in sorted(self.files)]
        for name, data in derived.items():
            encoded = canonical_json(data)
            write_new(output / name, encoded, self.protected)
            manifest_files.append({"path": name, "bytes": len(encoded),
                                   "sha256": hashlib.sha256(encoded).hexdigest(),
                                   "role": "derived-assembly-index", "original_path": None})
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "delivery_name": self.plan["delivery_name"],
            "current_source_commit": self.current, "source_trees": self.sources,
            "scope": "All selected raw evidence and explicit supporting snapshots; no source or historical fixture rewritten.",
            "interpretation": no_qualifications(),
            "raw_bytes_preserved_and_read_back": True,
            "source_metadata_note": "mode, mtime_ns, ctime_ns, device and inode describe the original observed input, not the staged file permissions.",
            "reviewed_payload_sha256": index["payload_sha256"],
            "all_selected_records_terminal": not self.incomplete,
            "contains_explicit_incomplete_archive_exception": bool(self.used_empty_result_exceptions),
            "incomplete_records_never_count_as_terminal_or_qualification": True,
            "incomplete_receipt_name_projections": self.empty_result_projections,
            "file_count": len(manifest_files),
            "total_file_bytes": sum(entry["bytes"] for entry in manifest_files),
            "files": sorted(manifest_files, key=lambda entry: entry["path"]),
            "hash_scheme": {
                "algorithm": "SHA-256",
                "paths": "relative POSIX paths beneath this delivery directory",
                "manifest_excludes": ["manifest.json", "manifest.sha256"],
                "sidecar": "manifest.sha256 hashes only the exact manifest.json bytes; no self-hash cycle",
            },
        }
        encoded = canonical_json(manifest)
        write_new(output / "manifest.json", encoded, self.protected)
        write_new(output / "manifest.sha256", (hashlib.sha256(encoded).hexdigest() + "  manifest.json\n").encode(), self.protected)


def write_new(path: Path, data: bytes, protected_roots: list[Path]) -> None:
    outside_sources(path, protected_roots)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--readme", type=Path, help="final README supplied by the reviewing owner")
    parser.add_argument("--inspect-report", type=Path, help="write a new outside-repo inspection JSON")
    parser.add_argument("--stage", type=Path, help="explicitly create a fresh outside-repo evidence tree")
    parser.add_argument("--expected-payload-sha256", help="exact payload digest from the reviewed inspection; required with --stage")
    args = parser.parse_args()
    if not args.plan.is_absolute() or (args.readme and not args.readme.is_absolute()):
        parser.error("--plan and --readme must be absolute paths")
    for output in (args.inspect_report, args.stage):
        if output is not None and not output.is_absolute():
            parser.error("output paths must be absolute")
    try:
        collection = Collection(args.plan, args.readme)
        index = collection.collect()
        collection.check_unchanged()
        if args.inspect_report:
            collection.check_output_location(args.inspect_report, directory=False)
            write_new(args.inspect_report, canonical_json(index), collection.protected)
        summary = {key: index[key] for key in (
            "schema", "current_source_commit", "counts_by_host_and_source",
            "terminal_record_count", "terminal_pass_record_count", "terminal_fail_record_count",
            "incomplete_record_count", "approved_archival_incomplete_record_count",
            "payload_file_count", "payload_bytes",
            "payload_sha256", "large_files", "staging_blockers", "readme_supplied", "can_stage_selected_inputs")}
        if args.stage:
            collection.stage(args.stage, index, args.expected_payload_sha256)
            summary["staged_directory"] = str(args.stage)
            summary["manifest_sha256"] = hash_file(args.stage / "manifest.json")["sha256"]
        summary["interpretation"] = no_qualifications()
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2))
        return 2 if collection.blocks else 0
    except (EvidenceError, OSError, KeyError, TypeError) as error:
        print(json.dumps({"error": str(error), "staged_directory": str(args.stage) if args.stage else None,
                          "partial_output_must_not_be_treated_as_complete": True,
                          "interpretation": no_qualifications()}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
