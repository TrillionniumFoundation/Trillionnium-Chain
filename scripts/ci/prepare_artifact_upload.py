#!/usr/bin/env python3
"""Copy an entire observation tree to safe names with a lossless path manifest.

Original files and all of their bytes stay unchanged. This packaging step does
not turn failed or partial execution evidence into a passing observation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys

FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
DIRECTORY_FLAGS = FLAGS | os.O_DIRECTORY
CHUNK_BYTES = 1024 * 1024


class ArtifactMapError(ValueError):
    pass


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def _open_directory(path):
    path = Path(path).absolute()
    if path.anchor != "/" or ".." in path.parts:
        raise ArtifactMapError("unsafe directory path")
    fd = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _snapshot(root_fd):
    rows = {"": _identity(os.fstat(root_fd))}

    def visit(directory_fd, prefix):
        for name in sorted(os.listdir(directory_fd), key=os.fsencode):
            relative = prefix + name
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            rows[relative] = _identity(metadata)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, DIRECTORY_FLAGS, dir_fd=directory_fd)
                try:
                    if _identity(os.fstat(child)) != rows[relative]:
                        raise ArtifactMapError("changing directory: " + relative)
                    visit(child, relative + "/")
                finally:
                    os.close(child)
            elif not stat.S_ISREG(metadata.st_mode):
                raise ArtifactMapError("symlink or special artifact refused: " + relative)

    visit(root_fd, "")
    return rows


def _copy_regular(root_fd, relative, snapshot, destination):
    """Stream the frozen observed size through no-follow, nonblocking fds."""
    descriptors = []
    parent = root_fd
    try:
        parts = relative.split("/")
        for index, component in enumerate(parts[:-1]):
            parent = os.open(component, DIRECTORY_FLAGS, dir_fd=parent)
            descriptors.append(parent)
            if _identity(os.fstat(parent)) != snapshot["/".join(parts[:index + 1])]:
                raise ArtifactMapError("changing artifact ancestor: " + relative)
        fd = os.open(parts[-1], FLAGS, dir_fd=parent)
        descriptors.append(fd)
        expected = snapshot[relative]
        if _identity(os.fstat(fd)) != expected or not stat.S_ISREG(expected[2]):
            raise ArtifactMapError("changing or nonregular artifact: " + relative)
        remaining = expected[3]
        digest = hashlib.sha256()
        with destination.open("xb") as output:
            while remaining:
                chunk = os.read(fd, min(remaining, CHUNK_BYTES))
                if not chunk:
                    raise ArtifactMapError("truncated artifact: " + relative)
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise ArtifactMapError("growing artifact: " + relative)
        if (_identity(os.fstat(fd)) != expected
                or _identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) != expected):
            raise ArtifactMapError("changed artifact: " + relative)
        return {"original_path": relative, "bytes": expected[3],
                "sha256": digest.hexdigest(), "original_mode": stat.S_IMODE(expected[2])}
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def prepare_upload(source, output):
    source, output = Path(source).absolute(), Path(output).absolute()
    if output == source or source in output.parents:
        raise ArtifactMapError("upload output must be outside the original observation tree")
    source_fd = _open_directory(source)
    created = False
    try:
        before = _snapshot(source_fd)
        files = sorted((name for name, identity in before.items()
                        if stat.S_ISREG(identity[2])), key=os.fsencode)
        if not files:
            raise ArtifactMapError("no regular artifact files")
        # Check ancestors before mkdir; an existing output, even an empty one,
        # is refused rather than merged with possibly stale observations.
        parent_fd = _open_directory(output.parent)
        try:
            os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        created = True
        (output / "files").mkdir(mode=0o700)
        records = []
        for index, relative in enumerate(files):
            mapped = f"files/{index:08d}.bin"
            record = _copy_regular(source_fd, relative, before, output / mapped)
            record["mapped_path"] = mapped
            records.append(record)
        if _snapshot(source_fd) != before:
            raise ArtifactMapError("observation tree changed while packaging")
        named_fd = _open_directory(source)
        try:
            if _identity(os.fstat(named_fd)) != before[""]:
                raise ArtifactMapError("original observation directory changed")
        finally:
            os.close(named_fd)
        manifest = {
            "schema": "trnm-artifact-path-map-v1",
            "scope": "lossless relative-path mapping; original execution outcomes remain unchanged",
            "file_count": len(records), "total_bytes": sum(row["bytes"] for row in records),
            "files": records,
        }
        with (output / "artifact-path-map-v1.json").open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, ensure_ascii=True, sort_keys=True, indent=2)
            stream.write("\n")
        return manifest
    except BaseException:
        if created:
            shutil.rmtree(output)
        raise
    finally:
        os.close(source_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest = prepare_upload(args.source, args.output)
    except (ArtifactMapError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"schema": manifest["schema"], "file_count": manifest["file_count"],
                      "total_bytes": manifest["total_bytes"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
