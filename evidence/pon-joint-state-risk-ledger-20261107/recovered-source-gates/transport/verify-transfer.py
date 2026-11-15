#!/usr/bin/env python3
"""Verify the retained byte copy; --extract permits new-only extraction."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def clean_path(name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name, "noncanonical path")
    require(all(part not in ("", ".", "..") for part in path.parts), "unsafe path")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extract", action="store_true")
    args = parser.parse_args()
    transport = Path(__file__).resolve().parent
    root = transport.parent
    receipt = json.loads((transport / "download-receipt.json").read_text())
    meta = receipt["archive"]
    archive = transport / Path(meta["archive_path"]).name
    raw = archive.read_bytes()
    require(len(raw) == meta["archive_bytes"], "archive byte count")
    require(digest(raw) == meta["archive_sha256"], "archive digest")

    chunks = [json.loads(line) for line in (transport / "chunks.jsonl").read_text().splitlines()]
    cursor = 0
    for chunk in chunks:
        require(chunk["version"] == receipt["pinned_version"], "chunk version")
        require(chunk.get("path", meta["archive_path"]) == meta["archive_path"], "chunk path")
        require(chunk["size"] == len(raw), "chunk total byte count")
        require(chunk["offset"] == cursor, "chunk discontinuity")
        end = chunk["next_offset"]
        require(cursor < end <= len(raw), "chunk range")
        require(digest(raw[cursor:end]) == chunk["chunk_sha256"], "chunk digest")
        require(chunk["eof"] == (end == len(raw)), "chunk EOF")
        cursor = end
    require(cursor == len(raw), "incomplete chunk coverage")

    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)), "duplicate tar members")
        for member in members:
            clean_path(member.name)
            require(member.isdir() or member.isfile(), "nonregular tar member")
        manifest_raw = tar.extractfile("remote-copy-manifest.json").read()
        require(digest(manifest_raw) == meta["manifest_sha256"], "manifest digest")
        manifest = json.loads(manifest_raw)
        selected = manifest["selected_directories"]
        require(selected == meta["selected_directories"], "selected directories")
        require(manifest["all_source_files_rechecked_after_copy"] is True, "remote copy recheck")
        files = manifest["files"]
        expected_files = {entry["path"]: entry for entry in files}
        expected_dirs = set(manifest["directories"])
        require(len(expected_files) == len(files) == meta["source_file_count"], "source file count")
        require(manifest["source_file_count"] == len(files), "manifest file count")
        require(sum(entry["bytes"] for entry in files) == meta["source_bytes"] == manifest["source_bytes"], "source byte count")
        for name in set(expected_files) | expected_dirs:
            path = clean_path(name)
            require(path.parts[0] in selected, "outside selected directory")
        require({m.name for m in members if m.isdir()} == expected_dirs, "tar directory inventory")
        require({m.name for m in members if m.isfile()} == set(expected_files) | {"remote-copy-manifest.json"}, "tar file inventory")
        for name, entry in expected_files.items():
            data = tar.extractfile(name).read()
            require(len(data) == entry["bytes"] and digest(data) == entry["sha256"], "tar source file mismatch: " + name)

        if args.extract:
            require(all(not (root / name).exists() for name in selected), "source directory already exists")
            require(not (root / "remote-copy-manifest.json").exists(), "local manifest already exists")
            for name in sorted(expected_dirs, key=lambda x: (len(PurePosixPath(x).parts), x)):
                (root / name).mkdir(mode=0o700)
            for name in sorted(expected_files):
                with (root / name).open("xb") as target:
                    target.write(tar.extractfile(name).read())
                (root / name).chmod(0o600)
            with (root / "remote-copy-manifest.json").open("xb") as target:
                target.write(manifest_raw)

    require((root / "remote-copy-manifest.json").read_bytes() == manifest_raw, "local manifest mismatch")
    found_files, found_dirs = set(), set()
    for selected_dir in selected:
        require((root / selected_dir).is_dir(), "missing selected directory")
        for current, directories, names in os.walk(root / selected_dir, followlinks=False):
            current_path = Path(current)
            require(stat.S_ISDIR(current_path.lstat().st_mode), "non-directory in tree")
            found_dirs.add(current_path.relative_to(root).as_posix())
            for name in directories:
                require(stat.S_ISDIR((current_path / name).lstat().st_mode), "symlink or special directory")
            for name in names:
                path = current_path / name
                require(stat.S_ISREG(path.lstat().st_mode), "nonregular local source file")
                relative = path.relative_to(root).as_posix()
                found_files.add(relative)
                require(relative in expected_files, "unexpected local file")
                entry = expected_files[relative]
                data = path.read_bytes()
                require(len(data) == entry["bytes"] and digest(data) == entry["sha256"], "local source file mismatch: " + relative)
    require(found_files == set(expected_files), "local file inventory")
    require(found_dirs == expected_dirs, "local directory inventory")
    print(json.dumps({
        "schema": "hepta-runtime-evidence-copy-verification-v1",
        "result": "PASS",
        "source_file_count": len(found_files),
        "source_directory_count": len(found_dirs),
        "source_bytes": meta["source_bytes"],
        "archive_bytes": len(raw),
        "archive_sha256": digest(raw),
        "manifest_sha256": digest(manifest_raw),
        "chunk_count": len(chunks),
        "all_chunk_versions_pinned": True,
        "all_chunk_hashes_match": True,
        "archive_and_manifest_hashes_match_remote_receipt": True,
        "exact_physical_source_tree_matches_manifest": True,
        "symlinks_or_special_files": False,
        "raw_source_bytes_preserved": True,
        "gitignore_used_for_inventory": False,
        "execution_attestation": False,
        "actual_work_or_native_security_qualification": False,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
