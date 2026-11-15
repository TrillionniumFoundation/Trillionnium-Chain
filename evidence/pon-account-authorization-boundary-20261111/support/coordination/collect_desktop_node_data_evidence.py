#!/usr/bin/env python3
"""Export the separate data-volume Node queue after its four real terminal records exist.

This writes only a new task-owned evidence archive outside the source repository.
The caller must separately verify the parent durable job is terminal first.
"""
from pathlib import Path
import datetime as dt
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile

HEAD = "cdd984808a088e6c2e13b1e1ae6630a94d500c89"
SOURCE = Path("/home/qian-qi/chain-pq-profile-boundary-20261111-a418-final")
RECORDS = Path("/home/qian-qi/chain-pq-a418-final-records")
ARCHIVE = Path("/home/qian-qi/chain-pq-a418-final-ci-tools/desktop-node-retained-data-evidence-v1.tar.gz")
RECORD_IDS = ("node-retained-data-preflight", "node-retained-data-source-before", "node-retained-data-all-targets", "node-retained-data-source-after")
PARENT_JOB_ID = "1a1c8ba754b-135c4-1d3"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode):
        raise RuntimeError("not a regular source file: " + str(path))
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_stable(path):
    before = identity(path)
    data = path.read_bytes()
    if identity(path) != before or len(data) != before[2]:
        raise RuntimeError("file changed while reading: " + str(path))
    return data, before


def git(*args):
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=SOURCE, text=True).strip()


def source_identity():
    return {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "status_porcelain": git("status", "--porcelain=v1", "--untracked-files=all")}


def main():
    if ARCHIVE.exists():
        raise RuntimeError("create-only archive already exists")
    before = source_identity()
    selected = []
    summaries = {}
    record_tree_paths = {}
    observed_directories = []
    for record_id in RECORD_IDS:
        root = RECORDS / "validation" / HEAD / record_id
        result_data, _ = read_stable(root / "result.json")
        context_data, _ = read_stable(root / "context.json")
        result = json.loads(result_data)
        context = json.loads(context_data)
        if result["id"] != record_id or context["source_commit"] != HEAD or result["source_head_before"] != HEAD:
            raise RuntimeError("record source/id differs: " + record_id)
        if not result.get("finished_utc") or not isinstance(result.get("pass"), bool):
            raise RuntimeError("record is not terminal: " + record_id)
        expected_pass = (result["returncode"] == 0 and result["launch_error"] is None
                         and result["source_head_after"] == HEAD and not result["source_status_after"])
        if result["pass"] != expected_pass or result["qualification_granted"] is not False:
            raise RuntimeError("result flag contradicts original facts: " + record_id)
        for stream in ("stdout", "stderr"):
            data, _ = read_stable(root / (stream + ".log"))
            if digest(data) != result[stream + "_sha256"]:
                raise RuntimeError("record log hash differs: " + record_id + "/" + stream)
        summaries[record_id] = {"returncode": result["returncode"], "pass": result["pass"],
                                "finished_utc": result["finished_utc"],
                                "context_sha256": digest(context_data), "result_sha256": digest(result_data)}
        tree_paths = sorted(root.rglob("*"))
        record_tree_paths[root] = [str(path) for path in tree_paths]
        observed_directories.append(root)
        for path in tree_paths:
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                observed_directories.append(path)
                continue
            if not stat.S_ISREG(mode):
                raise RuntimeError("unexpected special evidence entry: " + str(path))
            selected.append((path, "primary/" + path.relative_to(RECORDS).as_posix()))

    # These exact task-owned files provide command, environment and source context.
    # No caches, credentials, targets, or arbitrary home files are selected.
    for name in ("environment.json", "run_validation.py", "node-retained-data-source-before.json", "node-retained-data-source-after.json"):
        path = RECORDS / name
        if path.exists():
            selected.append((path, "primary/" + name))

    snapshots = []
    seen = set()
    for path, name in sorted(selected, key=lambda item: item[1]):
        if name in seen:
            raise RuntimeError("duplicate archive member: " + name)
        seen.add(name)
        data, original_identity = read_stable(path)
        entry = {"remote_source": str(path), "archive_member": name,
                 "bytes": len(data), "sha256": digest(data)}
        snapshots.append((path, name, data, original_identity, entry))

    after = source_identity()
    if before != after:
        raise RuntimeError("source identity changed during export")
    directory_inventory = []
    for directory in observed_directories:
        prefix = "primary/" + directory.relative_to(RECORDS).as_posix() + "/"
        descendants = [entry for _, name, _, _, entry in snapshots if name.startswith(prefix)]
        directory_inventory.append({"remote_directory": str(directory),
                                    "archive_prefix": prefix,
                                    "recursive_regular_files": len(descendants),
                                    "recursive_file_bytes": sum(entry["bytes"] for entry in descendants)})
    manifest = {
        "schema": "desktop-primary-evidence-export-v1",
        "host": "desktop", "source_commit": HEAD,
        "captured_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "complete_command_ids": list(RECORD_IDS),
        "record_results": summaries,
        "origin_job_id": PARENT_JOB_ID,
        "source_status_during_export": after["status_porcelain"],
        "source_identity_before_export": before, "source_identity_after_export": after,
        "entries": [entry for _, _, _, _, entry in snapshots],
        "directory_inventory": directory_inventory,
        "running_lanes_excluded": [],
        "read_only_source_and_original_records": True,
        "terminal_failures_preserved": True,
        "acceptance_granted": False,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        for _, name, data, original_identity, _ in snapshots:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = 0o444
            item.mtime = original_identity[3] // 1_000_000_000
            tar.addfile(item, io.BytesIO(data))
        item = tarfile.TarInfo("export-manifest.json")
        item.size = len(manifest_bytes)
        item.mode = 0o444
        tar.addfile(item, io.BytesIO(manifest_bytes))
    for path, _, data, original_identity, _ in snapshots:
        reread, reread_identity = read_stable(path)
        if reread_identity != original_identity or reread != data:
            raise RuntimeError("original evidence changed before publication: " + str(path))
    for root, original_paths in record_tree_paths.items():
        if [str(path) for path in sorted(root.rglob("*"))] != original_paths:
            raise RuntimeError("evidence tree membership changed before publication: " + str(root))
    if source_identity() != after:
        raise RuntimeError("source identity changed before publication")
    archive_bytes = buffer.getvalue()
    with ARCHIVE.open("xb") as output:
        output.write(archive_bytes)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(ARCHIVE, 0o444)
    actual, _ = read_stable(ARCHIVE)
    if actual != archive_bytes:
        raise RuntimeError("written archive bytes differ")
    print(json.dumps({"archive": str(ARCHIVE), "bytes": len(actual),
                      "sha256": digest(actual), "manifest_sha256": digest(manifest_bytes),
                      "original_file_count": len(snapshots), "record_results": summaries,
                      "directory_inventory": directory_inventory,
                      "source_identity": after, "acceptance_granted": False}, sort_keys=True))


if __name__ == "__main__":
    main()
