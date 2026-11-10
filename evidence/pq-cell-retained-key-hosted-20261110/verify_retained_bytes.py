#!/usr/bin/env python3
"""Check observer bytes and manifest relationships; execute no native tests."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parent
SOURCE = "a4c594fc9d5f43d0d2b7ae7e0835d0e1514dc667"
TREE = "b621fde199f0e52a8410f765fbda0d633a32d5ff"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe(path):
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("unsafe retained path")
    if relative.parts[0] == "publication":
        raise ValueError("publication is outside this observer manifest")
    value = ROOT / relative
    if value.is_symlink() or not value.is_file():
        raise ValueError("missing or symlinked retained file: " + path)
    return value


def verify():
    mapping = json.loads((ROOT / "lossless-map.json").read_bytes())
    if mapping["schema"] != "pq-cell-hosted-lossless-map-v1":
        raise ValueError("unknown lossless map")
    decoded = {}
    stored_paths = set()
    for row in mapping["source_files"]:
        logical, stored = row["source_path"], row["stored_path"]
        if logical in decoded or stored in stored_paths:
            raise ValueError("duplicate retained path")
        stored_paths.add(stored)
        raw = safe(stored).read_bytes()
        if len(raw) != row["stored_bytes"] or sha(raw) != row["stored_sha256"]:
            raise ValueError("changed stored bytes: " + stored)
        if row["encoding"] == "gzip":
            raw = gzip.decompress(raw)
        elif row["encoding"] != "identity":
            raise ValueError("unknown retained encoding")
        if len(raw) != row["source_bytes"] or sha(raw) != row["source_sha256"]:
            raise ValueError("changed uncompressed bytes: " + logical)
        decoded[logical] = raw
    if len(decoded) != 18:
        raise ValueError("incomplete original observer scope")
    for row in mapping["metadata_files"]:
        raw = safe(row["path"]).read_bytes()
        if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
            raise ValueError("changed delivery metadata: " + row["path"])

    original = json.loads(decoded["manifest.json"])
    if original["head"] != SOURCE or original["tree"] != TREE:
        raise ValueError("original source identity changed")
    for row in original["files"]:
        raw = decoded[row["path"]]
        if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
            raise ValueError("original manifest mismatch: " + row["path"])
    supplement = json.loads(decoded["supplement-manifest.json"])
    if supplement["original_manifest_unchanged_sha256"] != sha(decoded["manifest.json"]):
        raise ValueError("original/supplement relationship changed")
    for row in supplement["files"]:
        raw = decoded[row["path"]]
        if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
            raise ValueError("supplement mismatch: " + row["path"])

    zip_members = 0
    for group in ("failed-control", "successful-component"):
        with zipfile.ZipFile(io.BytesIO(decoded[group + ".zip"])) as archive:
            for path, raw in decoded.items():
                if (path.startswith(group + "/")
                        and not path.endswith(".phases.jsonl")):
                    if archive.read(Path(path).name) != raw:
                        raise ValueError("original ZIP member mismatch: " + path)
                    zip_members += 1
    phase_lines = [line.split(b"TRNM_PQ_PHASE_DIAGNOSTIC ", 1)[1]
                   for line in decoded["failed-control/native-41.log"].splitlines(keepends=True)
                   if line.startswith(b"TRNM_PQ_PHASE_DIAGNOSTIC ")]
    if b"".join(phase_lines) != decoded["failed-control/native-41.phases.jsonl"]:
        raise ValueError("derived phase lines differ from the complete original log")

    receipts = 0
    for path, raw in decoded.items():
        if not path.endswith(".json"):
            continue
        record = json.loads(raw)
        if record.get("schema") != "trnm-pq-native-command-v1":
            continue
        if record["before"] != record["after"]:
            raise ValueError("source endpoints differ: " + path)
        if (record["before"]["tested_commit"] != SOURCE
                or record["before"]["tested_tree"] != TREE):
            raise ValueError("wrong execution source: " + path)
        log_path = (Path(path).parent / record["log_file"]).as_posix()
        log = decoded[log_path]
        if len(log) != record["log_bytes"] or sha(log) != record["log_sha256"]:
            raise ValueError("receipt log mismatch: " + path)
        receipts += 1
    if receipts != 5:
        raise ValueError("incomplete selected receipt set")
    return {"result": "PASS", "source": SOURCE, "original_files": len(decoded),
            "selected_receipts": receipts, "original_zip_members_compared": zip_members,
            "phase_lines_compared": len(phase_lines), "native_tests_rerun": False,
            "independent_execution_authentication": False,
            "whole_chain_pq_qualified": False}


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
