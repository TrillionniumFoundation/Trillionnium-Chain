#!/usr/bin/env python3
"""Materialize declared evidence references without authenticating their claims.

Only exact SHA-256-named local files are read. Exit 0 means a bounded report was
produced, including missing/corrupt material; every report remains HOLD. Neither
matching bytes nor their declared dates prove signatures, context, custody,
deployment, physical observations or independent administration. No network I/O,
credentials, clock substitution or changes to the V1 accounting schema occur.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import stat
from pathlib import Path

import pon_decentralization_audit as D

SCHEMA = "trnm-decentralization-evidence-materialization-v1"
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_REFERENCE_USES = 32768
CHUNK_BYTES = 64 * 1024
REFERENCE_FIELDS = {"evidence_sha256", "inventory_evidence_sha256", "unit_definition_sha256"}


def checked_path(value):
    value = os.fspath(value)
    D.require(isinstance(value, str) and value and "\x00" not in value
              and len(os.fsencode(value)) <= 4096 and ".." not in value.split("/"), "UNSAFE_PATH")
    return Path(os.path.abspath(value))


def identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def snapshot(info):
    # atime is deliberately excluded: merely reading a file can update it.
    return (*identity(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_directory(path):
    """Open every ancestor without following symlinks; retain a directory FD.

    The caller rechecks the lineage after its scan. Reads remain relative to the
    opened directory even if a name is concurrently replaced. A local privileged
    adversary controlling the kernel/filesystem is outside this byte reader.
    """
    D.require(os.name == "posix" and all(hasattr(os, flag) for flag in
              ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
              and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
              and os.stat in os.supports_follow_symlinks, "SECURE_FILE_OPERATIONS_UNAVAILABLE")
    path = checked_path(path)
    D.require(len(path.parts) <= 128, "PATH_DEPTH_BOUND")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    lineage = [identity(os.fstat(fd))]
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            lineage.append(identity(os.fstat(fd)))
        return fd, path, lineage
    except BaseException:
        os.close(fd)
        raise


def check_directory(path, lineage):
    fd, _, current = open_directory(path)
    try:
        D.require(current == lineage, "DIRECTORY_LINEAGE_CHANGED")
    finally:
        os.close(fd)


def named_snapshot(directory_fd, name):
    try:
        return snapshot(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
    except FileNotFoundError:
        return None


def read_regular(directory_fd, name, maximum, *, collect=False, missing_ok=False):
    """Check type/link count, stream with a hard cap, then recheck name and FD."""
    before = named_snapshot(directory_fd, name)
    if before is None:
        D.require(missing_ok, "INPUT_MISSING")
        return None
    D.require(stat.S_ISREG(before[2]), "NONREGULAR_OR_SYMLINK_FILE")
    D.require(before[5] == 1, "HARDLINK_FILE")
    D.require(0 <= before[6] <= maximum, "FILE_BYTE_BOUND")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        D.require(snapshot(os.fstat(fd)) == before, "FILE_CHANGED_BEFORE_READ")
        hasher, size, chunks = hashlib.sha256(), 0, []
        while True:
            block = os.read(fd, min(CHUNK_BYTES, maximum - size + 1))
            if not block:
                break
            size += len(block)
            D.require(size <= maximum, "FILE_BYTE_BOUND")
            hasher.update(block)
            if collect:
                chunks.append(block)
        D.require(size == before[6] and snapshot(os.fstat(fd)) == before
                  and named_snapshot(directory_fd, name) == before, "FILE_CHANGED_DURING_READ")
        return {"sha256": hasher.hexdigest(), "bytes": size, "snapshot": before,
                "raw": b"".join(chunks) if collect else None}
    finally:
        os.close(fd)


def reference_uses(value):
    uses, absent, pending, count = collections.defaultdict(list), [], [("", value)], 0
    while pending:
        path, item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
                if key in REFERENCE_FIELDS:
                    count += 1
                    D.require(count <= MAX_REFERENCE_USES, "REFERENCE_USE_BOUND")
                    if child is None:
                        absent.append(pointer)
                    else:
                        D.digest(child, "EVIDENCE_REFERENCE")
                        uses[child].append(pointer)
                else:
                    pending.append((pointer, child))
        elif isinstance(item, list):
            pending.extend((path + "/" + str(i), child) for i, child in enumerate(item))
    return {key: sorted(paths) for key, paths in sorted(uses.items())}, sorted(absent)


def check_installed_policy():
    """Keep the two command-line readers on the same exact installed policy."""
    policy_path = Path(__file__).resolve().parents[1] / "config/pon/decentralization-audit-v1.json"
    directory_fd, directory, lineage = open_directory(policy_path.parent)
    try:
        source = read_regular(directory_fd, policy_path.name, D.MAX_BYTES, collect=True)
        D.require(D.parse_json(source["raw"]) == D.POLICY, "INSTALLED_POLICY_BINDING")
        check_directory(directory, lineage)
    finally:
        os.close(directory_fd)


def materialize(input_path, expected_input_sha256, artifact_dir):
    """Library API uses the frozen code policy; the CLI also checks its installed file."""
    D.digest(expected_input_sha256, "EXPECTED_INPUT_SHA256")
    input_path = checked_path(input_path)
    input_fd, input_parent, input_lineage = open_directory(input_path.parent)
    artifact_fd = None
    try:
        source = read_regular(input_fd, input_path.name, D.MAX_BYTES, collect=True)
        D.require(source["sha256"] == expected_input_sha256, "INPUT_SHA256_MISMATCH")
        value = D.parse_json(source["raw"])
        D.exact(value, {"audit", "registry"}, "INPUT_FIELDS")
        # Reuse the existing strict schema, registry digest, context, quorum and
        # reference validation. No alternate authority or acceptance calculation.
        accounting = D.evaluate(value["audit"], value["registry"])
        uses, absent = reference_uses(value)
        audit, registry = value["audit"], value["registry"]
        start, end = audit["window"]["start_unix_ms"], audit["window"]["end_unix_ms"]
        registry_current = registry["valid_from_unix_ms"] <= start and end <= registry["valid_until_unix_ms"]
        artifact_fd, artifact_path, artifact_lineage = open_directory(artifact_dir)
        directory_before = snapshot(os.fstat(artifact_fd))
        rows, observed, inodes, total = [], {}, set(), 0
        gaps = {key: [] for key in ("missing", "hash_mismatch", "revoked", "unknown",
                                   "expired_for_audit_window", "not_yet_valid_for_audit_window")}
        for declared in sorted(registry["evidence"], key=lambda row: row["sha256"]):
            sha256 = D.digest(declared["sha256"], "ARTIFACT_NAME")
            result = read_regular(artifact_fd, sha256, min(MAX_ARTIFACT_BYTES, MAX_TOTAL_BYTES - total),
                                  missing_ok=True)
            observed[sha256] = None if result is None else result["snapshot"]
            if result is None:
                material_status = "missing"
            else:
                inode = result["snapshot"][:2]
                D.require(inode not in inodes, "DUPLICATE_ARTIFACT_INODE")
                inodes.add(inode)
                total += result["bytes"]
                material_status = "matched" if result["sha256"] == sha256 else "hash_mismatch"
            if material_status in gaps:
                gaps[material_status].append(sha256)
            if declared["status"] in ("revoked", "unknown"):
                gaps[declared["status"]].append(sha256)
            expired = declared["valid_until_unix_ms"] < end
            future = declared["valid_from_unix_ms"] > start
            if expired:
                gaps["expired_for_audit_window"].append(sha256)
            if future:
                gaps["not_yet_valid_for_audit_window"].append(sha256)
            rows.append({**declared, "uses": uses.get(sha256, []), "material_status": material_status,
                         "observed_bytes": None if result is None else result["bytes"],
                         "observed_sha256": None if result is None else result["sha256"],
                         "declared_reference_current": registry_current and declared["status"] == "current"
                                                       and not expired and not future})
        # Recheck earlier and initially missing files too, after the whole scan.
        for sha256, before in observed.items():
            D.require(named_snapshot(artifact_fd, sha256) == before, "ARTIFACT_CHANGED_DURING_SCAN")
        D.require(snapshot(os.fstat(artifact_fd)) == directory_before, "ARTIFACT_DIRECTORY_CHANGED")
        D.require(named_snapshot(input_fd, input_path.name) == source["snapshot"], "INPUT_CHANGED_DURING_SCAN")
        check_directory(input_parent, input_lineage)
        check_directory(artifact_path, artifact_lineage)
        matched = sum(row["material_status"] == "matched" for row in rows)
        return {
            "schema": SCHEMA, "status": "HOLD",
            "materialization_status": "empty" if not rows else "bytes_complete" if matched == len(rows) else "incomplete",
            "input_sha256": source["sha256"], "input_bytes": source["bytes"],
            "audit_sha256": accounting["audit_sha256"], "control_registry_sha256": accounting["control_registry_sha256"],
            "policy_sha256": accounting["policy_sha256"], "context": audit["context"], "window": audit["window"],
            "accounting_report_sha256": D.canonical_sha256(accounting),
            "accounting_findings": accounting["findings"],
            "limits": {"input_bytes": D.MAX_BYTES, "artifact_bytes": MAX_ARTIFACT_BYTES,
                       "total_artifact_bytes": MAX_TOTAL_BYTES, "reference_uses": MAX_REFERENCE_USES,
                       "report_bytes": MAX_REPORT_BYTES},
            "declared_artifact_count": len(rows), "matched_artifact_count": matched,
            "total_artifact_bytes_read": total, "all_declared_material_bytes_matched": bool(rows) and matched == len(rows),
            "registry_window_covers_audit": registry_current, "material_gaps": gaps,
            "absent_reference_uses": absent, "materials": rows,
            "materialization_findings": (["DEPLOYMENT_EVIDENCE_MISSING"] if not rows else [])
                                        + (["MATERIAL_BYTES_INCOMPLETE"] if matched != len(rows) else []),
            "evidence_references_authenticated": False, "signatures_verified": False,
            "claim_contents_verified": False, "context_contents_verified": False,
            "deployment_evidence_verified": False, "independent_administration_verified": False,
            "permissionless_utility_accepted": False, "public_network_ready": False, "production_activation": False,
            "scope": "Exact local bytes and declared windows only; no signature, context-content, claim, custody or deployment authentication.",
        }
    finally:
        if artifact_fd is not None:
            os.close(artifact_fd)
        os.close(input_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="existing V1 registry/audit JSON; read without following symlinks")
    parser.add_argument("--expected-input-sha256", required=True, help="externally fixed digest of the exact input bytes")
    parser.add_argument("--artifact-dir", required=True, help="local directory containing bare lowercase SHA-256 filenames")
    parser.add_argument("--output", help="create a new report outside the artifact directory; default stdout")
    args = parser.parse_args()
    try:
        check_installed_policy()
        if args.output:
            output, artifact_path = checked_path(args.output), checked_path(args.artifact_dir)
            D.require(output != checked_path(args.input), "OUTPUT_OVERWRITES_INPUT")
            D.require(output != artifact_path and artifact_path not in output.parents, "OUTPUT_INSIDE_ARTIFACT_DIR")
        report = materialize(args.input, args.expected_input_sha256, args.artifact_dir)
        encoded = D.canonical_bytes(report, MAX_REPORT_BYTES - 1) + b"\n"
        if args.output:
            directory_fd, _, _ = open_directory(output.parent)
            try:
                fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
                with os.fdopen(fd, "wb") as target:
                    target.write(encoded)
            finally:
                os.close(directory_fd)
        else:
            print(encoded.decode("ascii"), end="")
    except (ValueError, OSError) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
