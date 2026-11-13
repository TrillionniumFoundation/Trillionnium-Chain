#!/usr/bin/env python3
"""Preserve an official GitHub CI ZIP and safely extract verified original bytes.

This is an intake check, not a scientific-success classifier. Missing reports,
failed native processes, and partial observations are retained without repair.
The caller separately downloads the ZIP and saves the GitHub artifact metadata.
No native executable is run, no Git object is changed, and no API is called.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile


def require(value, message):
    if not value:
        raise ValueError(message)


def sha256(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def load_json(path):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def new_json(path, value):
    with path.open("xb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
    path.chmod(0o444)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(len(args.head) == 40 and all(c in "0123456789abcdef" for c in args.head), "full source SHA required")
    require(not args.out.exists(), "output must be absent")
    metadata = load_json(args.metadata)
    artifacts = metadata.get("artifacts", [metadata])
    matches = [row for row in artifacts if row["id"] == args.artifact_id]
    require(len(matches) == 1, "artifact identity must occur exactly once")
    artifact = matches[0]
    require(artifact["workflow_run"]["id"] == args.run_id, "run ID mismatch")
    require(artifact["workflow_run"]["head_sha"] == args.head, "source SHA mismatch")
    require(artifact["digest"].startswith("sha256:"), "platform SHA-256 absent")
    expected = artifact["digest"].removeprefix("sha256:")
    before = args.archive.stat()
    require(stat.S_ISREG(before.st_mode), "archive must be regular")
    require(before.st_size == artifact["size_in_bytes"], "archive byte count mismatch")
    observed = sha256(args.archive)
    require(observed == expected, "archive SHA-256 mismatch")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix=args.out.name + ".unpublished-", dir=args.out.parent))
    try:
        raw = temp / "originals"
        raw.mkdir()
        with zipfile.ZipFile(args.archive) as source:
            entries = source.infolist()
            names = [entry.filename for entry in entries]
            require(len(names) == len(set(names)), "duplicate ZIP members")
            regular = []
            for entry in entries:
                path = PurePosixPath(entry.filename)
                require(not path.is_absolute() and ".." not in path.parts and "\\" not in entry.filename,
                        "unsafe ZIP path")
                require(path.parts and path.parts[0] not in ("", "."), "empty ZIP path")
                mode = entry.external_attr >> 16
                require(not stat.S_ISLNK(mode), "ZIP symlink is not a raw regular file")
                if not entry.is_dir():
                    require(not stat.S_IFMT(mode) or stat.S_ISREG(mode), "ZIP special member")
                    regular.append(entry)
            total = sum(entry.file_size for entry in regular)
            require(shutil.disk_usage(temp).free > total + 16 * 1024 * 1024,
                    "insufficient space for full original member bytes")
            index = {}
            for entry in regular:
                target = raw.joinpath(*PurePosixPath(entry.filename).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                digest, count = hashlib.sha256(), 0
                with source.open(entry) as stream, target.open("xb") as output:
                    while block := stream.read(1024 * 1024):
                        output.write(block)
                        digest.update(block)
                        count += len(block)
                require(count == entry.file_size, "ZIP uncompressed byte count mismatch")
                target.chmod(0o444)
                index[entry.filename] = {"bytes": count, "sha256": digest.hexdigest(), "zip_crc32": f"{entry.CRC:08x}"}
            # ZipExtFile verifies each CRC while consuming every member above.
        after = args.archive.stat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "archive changed during intake")
        source_identity = None
        if "source.json" in index:
            source_identity = load_json(raw / "source.json")
            require(source_identity.get("tested_commit") == args.head, "source.json tested commit mismatch")
        report_names = sorted(name for name in index if name.endswith("/native/report.json"))
        report_projections = []
        for name in report_names:
            try:
                value = load_json(raw / name)
                report_projections.append({"member": name, "read_status": "READ",
                    "qualification": value.get("qualification"),
                    "first_divergence": value.get("first_divergence"),
                    "health_gate_passed": value.get("health_gate_passed"),
                    "pressure_controls_executed": value.get("pressure_controls_executed")})
            except (OSError, ValueError, TypeError) as error:
                report_projections.append({"member": name, "read_status": "ERROR", "error": str(error)})
        new_json(temp / "RAW_SHA256.json", index)
        receipt = {"schema": "sp27-ci-original-archive-intake-v1", "artifact_id": args.artifact_id,
            "run_id": args.run_id, "source_head": args.head, "archive": str(args.archive.resolve()),
            "archive_bytes": before.st_size, "archive_sha256": observed,
            "platform_artifact_url": artifact.get("url"), "platform_archive_url": artifact.get("archive_download_url"),
            "metadata": {"path": str(args.metadata.resolve()), "sha256": sha256(args.metadata)},
            "zip_file_members": len(index), "uncompressed_file_bytes": total, "all_file_crc_verified": True,
            "source_identity": source_identity, "report_projections": report_projections,
            "original_extraction": str((args.out / "originals").resolve()),
            "extract_file_mode": "0444", "native_experiments_executed": 0,
            "scientific_success_determined": False, "missing_or_failed_report_repaired": False,
            "script_sha256": sha256(Path(__file__))}
        new_json(temp / "INTAKE_RECEIPT.json", receipt)
        require(not args.out.exists(), "output appeared during intake")
        os.rename(temp, args.out)
        temp = None
        print(json.dumps({"run_id": args.run_id, "artifact_id": args.artifact_id,
            "archive_sha256": observed, "file_members": len(index), "reports": report_projections,
            "receipt": str(args.out / "INTAKE_RECEIPT.json"), "originals": str(args.out / "originals")}, sort_keys=True))
    finally:
        if temp is not None:
            shutil.rmtree(temp)


if __name__ == "__main__":
    main()
