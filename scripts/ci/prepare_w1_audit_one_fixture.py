#!/usr/bin/env python3
"""Restore one explicitly selected, fixed historical W1 fixture; execute nothing."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile
import zlib

ARTIFACT_ID = 12784520070
RUN_ID = 40608715148
SOURCE_SHA = "a54dc7355f58f40784b5a71fe7e73c4062a14951"
ARCHIVE_BYTES = 80366759
ARCHIVE_SHA256 = "bae22e7fab8f5475dc396a4225292f90e582a92558fecf1710e30da0b0d76ecc"
ASSETS = {
    "guest.bin": {"bytes": 291592, "sha256": "b8f32cd9c1b1edbb0cde04acf9aab146b7ff1aeeeaee0188e4d6e80d077b0c0a"},
    "input.bin": {"bytes": 49640, "sha256": "4babd290b10f7a68be27c2adf3b97448bb7bef04dba8bcb97f914acf4ac69020"},
    "receipt.bin": {"bytes": 15862780, "sha256": "0a5336a797c51829ed25d4ec2f1a03f4f56fda4c737a230b493d4abbe96f0ec8"},
}
OBJECTS = {
    "guest.bin": {"bytes": 111927, "sha256": "3110497b22927e6cd522b2af988ced45e2e83b7a5fdc539d8f9d79c9c2812a5c", "chunks": [
        {"file": "3110497b22927e6cd522b2af988ced45e2e83b7a5fdc539d8f9d79c9c2812a5c.gz", "bytes": 111927, "sha256": "3110497b22927e6cd522b2af988ced45e2e83b7a5fdc539d8f9d79c9c2812a5c"}]},
    "input.bin": {"bytes": 14057, "sha256": "b2efce56e8cbc2b2987511a2f2ea9e5e8fb41c3544b7cc51160ef6a3e02861c3", "chunks": [
        {"file": "b2efce56e8cbc2b2987511a2f2ea9e5e8fb41c3544b7cc51160ef6a3e02861c3.gz", "bytes": 14057, "sha256": "b2efce56e8cbc2b2987511a2f2ea9e5e8fb41c3544b7cc51160ef6a3e02861c3"}]},
    "receipt.bin": {"bytes": 13906979, "sha256": "0503d0e802eebd8ca0c5cfd5f54d66085c7dfe3f1fb4f523d568809c0a3b0056", "chunks": [
        {"file": "dfa0e6f7a5117456451fbf4e834d41b7608b868f3f0173addfc9c8b9e763665c.gz.part", "bytes": 7000000, "sha256": "dfa0e6f7a5117456451fbf4e834d41b7608b868f3f0173addfc9c8b9e763665c"},
        {"file": "286ec10c307a80343892bbd4b63fa612ea84a5b96dd986ea1142efe0952782c5.gz.part", "bytes": 6906979, "sha256": "286ec10c307a80343892bbd4b63fa612ea84a5b96dd986ea1142efe0952782c5"}]},
}
MAX_MEMBERS = 4096
MAX_TOTAL_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ASSET_BYTES = 128 * 1024 * 1024
MAX_OBJECT_MANIFEST_BYTES = 16 * 1024
MAX_TOTAL_OBJECT_BYTES = 32 * 1024 * 1024
MAX_TOTAL_OBJECT_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_OBJECT_CHUNK_BYTES = 7000000
MAX_CHUNKS_PER_OBJECT = 2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def object_manifest(assets=ASSETS, objects=OBJECTS):
    return {
        "schema": "pon-w1-durable-gzip-objects-v2",
        "compression": {"format": "gzip", "level": 9, "mtime": 0, "single_member": True},
        "chunking": {"ordered_concatenation": "original-gzip-bytes",
                     "max_chunk_bytes": MAX_OBJECT_CHUNK_BYTES,
                     "max_chunks_per_object": MAX_CHUNKS_PER_OBJECT},
        "historical_origin": {"repository": "TrillionniumFoundation/Trillionnium-Chain",
                              "artifact_id": ARTIFACT_ID, "run_id": RUN_ID,
                              "source_sha": SOURCE_SHA, "archive_bytes": ARCHIVE_BYTES,
                              "archive_sha256": ARCHIVE_SHA256},
        "assets": {name: {**assets[name], "object": objects[name]} for name in sorted(assets)},
        "new_proof_generated": False, "proof_verified_by_manifest": False,
        "historical_zip_verified_when_reading_objects": False,
    }


def manifest_bytes(assets=ASSETS, objects=OBJECTS):
    return (json.dumps(object_manifest(assets, objects), sort_keys=True, indent=2) + "\n").encode()


def write_assets(out, retained):
    # All bytes must pass before an output directory or file is created.
    out.mkdir(mode=0o700)
    for name, raw in retained.items():
        with (out / name).open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def binding(source, assets, **extra):
    return {"schema": "pon-w1-historical-fixture-binding-v2", "source": source,
            "artifact_id": ARTIFACT_ID, "run_id": RUN_ID, "source_sha": SOURCE_SHA,
            "archive_bytes": ARCHIVE_BYTES, "archive_sha256": ARCHIVE_SHA256,
            "assets": assets, "historical_zip_verified_this_run": source == "archive",
            "proof_verified": False, "new_proof_generated": False,
            "consensus_authority": False, **extra}


def read_bound_object(directory, name, expected_bytes, cap):
    require(type(expected_bytes) is int and 0 < expected_bytes <= cap, "object size budget")
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size == expected_bytes,
                "object type or fixed byte count")
        raw = stream.read(expected_bytes + 1)
        require(len(raw) == expected_bytes, "object byte count changed")
        require(identity(before) == identity(os.fstat(stream.fileno()))
                == identity(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                "object changed during read")
    return raw


def restore_objects(directory, out, assets=ASSETS, objects=OBJECTS):
    require(set(assets) == set(ASSETS) == set(objects), "closed three-asset set")
    require(sum(row["bytes"] for row in assets.values()) <= MAX_TOTAL_OBJECT_EXPANDED_BYTES,
            "expanded object budget")
    require(sum(row["bytes"] for row in objects.values()) <= MAX_TOTAL_OBJECT_BYTES,
            "compressed object budget")
    chunks = []
    for row in objects.values():
        require(set(row) == {"bytes", "sha256", "chunks"}
                and type(row["bytes"]) is int and 0 < row["bytes"] <= MAX_TOTAL_OBJECT_BYTES
                and isinstance(row["sha256"], str) and len(row["sha256"]) == 64
                and all(c in "0123456789abcdef" for c in row["sha256"]), "whole object pins")
        require(type(row["chunks"]) is list and 1 <= len(row["chunks"]) <= MAX_CHUNKS_PER_OBJECT,
                "closed object chunk count")
        suffix = ".gz" if len(row["chunks"]) == 1 else ".gz.part"
        for chunk in row["chunks"]:
            require(set(chunk) == {"file", "bytes", "sha256"}
                    and type(chunk["bytes"]) is int and 0 < chunk["bytes"] <= MAX_OBJECT_CHUNK_BYTES,
                    "object chunk size budget")
            require(isinstance(chunk["sha256"], str) and len(chunk["sha256"]) == 64
                    and all(c in "0123456789abcdef" for c in chunk["sha256"])
                    and chunk["file"] == chunk["sha256"] + suffix, "canonical chunk filename")
            chunks.append(chunk)
        require(sum(chunk["bytes"] for chunk in row["chunks"]) == row["bytes"],
                "whole object and chunk byte counts differ")
    expected_manifest = manifest_bytes(assets, objects)
    expected_names = {"manifest.json"} | {row["file"] for row in chunks}
    require(len(expected_names) == 1 + len(chunks), "distinct chunk filenames")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    retained = {}
    try:
        seen = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                require(entry.name in expected_names and entry.name not in seen,
                        "unexpected object-directory entry")
                seen.add(entry.name)
        require(seen == expected_names, "incomplete object directory")
        raw_manifest = read_bound_object(fd, "manifest.json", len(expected_manifest),
                                         MAX_OBJECT_MANIFEST_BYTES)
        require(raw_manifest == expected_manifest, "object manifest differs from exact pins")
        for name in sorted(assets):
            pin, object_pin = assets[name], objects[name]
            require(type(pin["bytes"]) is int and 0 < pin["bytes"] <= MAX_ASSET_BYTES,
                    "asset size budget")
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw, compressed_hash = bytearray(), hashlib.sha256()
            # Concatenate only these exact ordered chunks into one bounded gzip
            # decoder. No complete compressed receipt or implicit fallback is made.
            for index, chunk in enumerate(object_pin["chunks"]):
                encoded = read_bound_object(fd, chunk["file"], chunk["bytes"], MAX_OBJECT_CHUNK_BYTES)
                require(digest(encoded) == chunk["sha256"], "compressed chunk hash")
                compressed_hash.update(encoded)
                raw.extend(decoder.decompress(encoded, pin["bytes"] - len(raw) + 1))
                require(len(raw) <= pin["bytes"] and not decoder.unused_data
                        and not decoder.unconsumed_tail
                        and (not decoder.eof or index == len(object_pin["chunks"]) - 1),
                        "gzip shape or expansion budget")
            require(compressed_hash.hexdigest() == object_pin["sha256"], "compressed object hash")
            require(len(raw) == pin["bytes"] and decoder.eof, "gzip shape or expansion budget")
            require(digest(raw) == pin["sha256"], "expanded asset hash")
            retained[name] = raw
    finally:
        os.close(fd)
    write_assets(out, retained)
    return binding("objects", assets, object_manifest_sha256=digest(expected_manifest),
                   compressed_bytes=sum(row["bytes"] for row in objects.values()),
                   object_packaging_schema="pon-w1-durable-gzip-objects-v2",
                   chunks_verified=len(chunks), whole_compressed_objects_verified=True)


def restore_archive(archive, out, assets=ASSETS, archive_bytes=ARCHIVE_BYTES,
                    archive_sha256=ARCHIVE_SHA256):
    require(type(archive_bytes) is int and 0 < archive_bytes <= ARCHIVE_BYTES,
            "fixed historical archive budget")
    fd = os.open(archive, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    retained = {}
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size == archive_bytes,
                "historical archive type or fixed byte count")
        h = hashlib.sha256()
        remaining = archive_bytes
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            require(bool(block), "archive truncated during read")
            h.update(block)
            remaining -= len(block)
        require(not stream.read(1), "archive grew during read")
        require(h.hexdigest() == archive_sha256, "historical ZIP hash")
        stream.seek(0)
        with zipfile.ZipFile(stream) as zipped:
            entries = zipped.infolist()
            require(len(entries) <= MAX_MEMBERS, "archive entry budget")
            require(sum(row.file_size for row in entries) <= MAX_TOTAL_EXPANDED_BYTES,
                    "archive expansion budget")
            names = set()
            for info in entries:
                name = info.filename
                path = PurePosixPath(name)
                require(name and not path.is_absolute() and ".." not in path.parts
                        and str(path) == name.rstrip("/") and "\\" not in name
                        and name not in names, "noncanonical or duplicate archive member")
                names.add(name)
                mode = stat.S_IFMT(info.external_attr >> 16)
                require(mode in (0, stat.S_IFREG, stat.S_IFDIR), "special archive entry")
                require(not info.flag_bits & 1, "encrypted archive member")
            for name, pin in assets.items():
                require(name in names, "missing exact root asset")
                info = zipped.getinfo(name)
                require(not info.is_dir() and info.file_size == pin["bytes"]
                        and info.file_size <= MAX_ASSET_BYTES
                        and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG),
                        "asset byte count or type")
                with zipped.open(info) as member:
                    raw = member.read(pin["bytes"] + 1)
                require(len(raw) == pin["bytes"] and digest(raw) == pin["sha256"],
                        "historical asset hash or bytes")
                retained[name] = raw
        require(identity(before) == identity(os.fstat(stream.fileno()))
                == identity(os.stat(archive, follow_symlinks=False)), "archive changed during read")
    write_assets(out, retained)
    return binding("archive", assets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--objects", type=Path)
    source.add_argument("--archive", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = (restore_objects(args.objects, args.out) if args.objects is not None
              else restore_archive(args.archive, args.out))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
