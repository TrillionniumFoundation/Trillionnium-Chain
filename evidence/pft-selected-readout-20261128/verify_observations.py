#!/usr/bin/env python3
"""Verify transport and reconstruct exact retained observations; run no workload."""
import base64
import hashlib
import json
from pathlib import Path
import zlib

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify():
    manifest = json.loads((HERE / "OBSERVATION_MANIFEST.json").read_text())
    with (HERE / "RAW_OBSERVATIONS.json.zlib.b64").open("rb") as stream:
        encoded = stream.read(2 * 1024 * 1024 + 1)
    require(len(encoded) <= 2 * 1024 * 1024, "encoded observation limit")
    require(sha(encoded) == manifest["archive_file_sha256"], "archive file hash")
    compressed = base64.b64decode(encoded.strip(), validate=True)
    require(sha(compressed) == manifest["archive_zlib_sha256"], "compressed hash")
    inflater = zlib.decompressobj()
    raw = inflater.decompress(compressed, 8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024 and inflater.eof
            and not inflater.unused_data and not inflater.unconsumed_tail, "archive bounds")
    require(sha(raw) == manifest["archive_json_sha256"], "archive JSON hash")
    archive = json.loads(raw)
    require(archive["schema"] == "chain-exact-observation-archive-v2", "archive schema")
    require(archive["files"] == manifest["raw_files"], "original file roster")
    restored = {}

    def restore(digest, active=frozenset()):
        if digest in restored:
            return restored[digest]
        require(digest not in active and len(active) < 4, "cyclic snapshot delta")
        row = archive["blobs"][digest]
        if row["encoding"] == "utf8":
            value = row["text"].encode("utf-8")
        else:
            require(row["encoding"] == "sha256-map-delta-v1", "blob encoding")
            require(row["indent"] in (None, 2) and row["suffix"] in ("", "\n"), "JSON format")
            source = json.loads(restore(row["base"], active | {digest}))
            for key in row["remove"]:
                del source[key]
            source.update(row["put"])
            value = (json.dumps(source, sort_keys=True, indent=row["indent"])
                     + row["suffix"]).encode("utf-8")
        require(sha(value) == digest, "original raw blob hash")
        restored[digest] = value
        return value

    for row in archive["files"].values():
        require(len(restore(row["sha256"])) == row["bytes"], "original byte length")
    require(len(archive["files"]) == manifest["raw_file_count"], "original file count")
    require(set(restored) == set(archive["blobs"]), "unreferenced blob")
    return {"raw_files_checked": len(archive["files"]),
            "exact_transport_verified": True, "workloads_rerun": False,
            "source_attested": False, "qualification_granted": False}


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
