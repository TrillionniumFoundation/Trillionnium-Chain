#!/usr/bin/env python3
"""Evidence helpers for the separately scheduled M15 static native fixture.

This records observed local build inputs. It does not certify independent
builder custody, a production deployment, or an existing native gate.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tomllib


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(raw):
    return list(hashlib.sha256(raw).digest())


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fingerprint(path, maximum=4 * 1024**3):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError(f"bounded regular file required: {path}")
        result = hashlib.sha256()
        size = 0
        while block := os.read(fd, 1024**2):
            size += len(block)
            if size > maximum:
                raise ValueError(f"file grew beyond bound: {path}")
            result.update(block)
        if size != before.st_size or identity(before) != identity(os.fstat(fd)):
            raise ValueError(f"held file changed: {path}")
        if identity(before) != identity(os.stat(path, follow_symlinks=False)):
            raise ValueError(f"named file changed: {path}")
        return {"path": str(path), "sha256": result.hexdigest(), "bytes": size,
                "identity": list(identity(before))}
    finally:
        os.close(fd)


def read(path, maximum=16 * 1024**2):
    record = fingerprint(path, maximum)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if list(identity(os.fstat(fd))) != record["identity"]:
            raise ValueError("input changed before bounded read")
        chunks, total = [], 0
        while block := os.read(fd, min(1024**2, maximum + 1 - total)):
            chunks.append(block)
            total += len(block)
            if total > maximum:
                raise ValueError("bounded input grew")
        raw = b"".join(chunks)
        if sha(raw) != record["sha256"] or list(identity(os.fstat(fd))) != record["identity"]:
            raise ValueError("input changed during bounded read")
        if list(identity(os.stat(path, follow_symlinks=False))) != record["identity"]:
            raise ValueError("named input changed during bounded read")
        return raw
    finally:
        os.close(fd)


def create(path, raw, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def copy_exact(source, destination, maximum, expected=None):
    source, destination = Path(source), Path(destination)
    before = fingerprint(source, maximum)
    if expected is not None and before["sha256"] != expected:
        raise ValueError("source digest differs from declared artifact")
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    destination_fd = None
    result = hashlib.sha256()
    size = 0
    try:
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o500)
        if list(identity(os.fstat(source_fd))) != before["identity"]:
            raise ValueError("copy source identity changed")
        while block := os.read(source_fd, 1024**2):
            size += len(block)
            if size > maximum:
                raise ValueError("copy exceeds exact bound")
            result.update(block)
            remaining = memoryview(block)
            while remaining:
                n = os.write(destination_fd, remaining)
                if n <= 0:
                    raise OSError("short artifact write")
                remaining = remaining[n:]
        if size != before["bytes"] or result.hexdigest() != before["sha256"]:
            raise ValueError("copied source bytes changed")
        if list(identity(os.fstat(source_fd))) != before["identity"]:
            raise ValueError("copied source identity changed")
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)
    after = fingerprint(destination, maximum)
    if after["sha256"] != before["sha256"] or after["bytes"] != before["bytes"]:
        raise ValueError("artifact copy readback differs")
    return after


def git(repo, *arguments):
    return subprocess.check_output(["git", "-C", str(repo), *arguments])


def full_source(repo, expected_commit, expected_tree):
    repo = Path(repo)
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    if (head, tree) != (expected_commit, expected_tree):
        raise ValueError("source HEAD/tree differs from explicit reviewed input")
    if git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("source checkout is not clean")
    rows, nodes = [], {}
    for entry in git(repo, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if not entry:
            continue
        prefix, name = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        path = name.decode()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("unexpanded submodule or unsupported tracked mode")
        actual = repo / path
        if mode == "120000":
            raw = os.fsencode(os.readlink(actual))
        else:
            info = os.stat(actual, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("tracked regular source replaced")
            if bool(info.st_mode & 0o111) != (mode == "100755"):
                raise ValueError("tracked executable mode differs")
            raw = read(actual, 512 * 1024**2)
        actual_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if actual_blob != blob:
            raise ValueError(f"actual tracked bytes differ: {path}")
        row = {"path": path, "mode": mode, "git_blob": blob, "sha256": sha(raw), "bytes": len(raw)}
        rows.append(row)
        node = nodes
        parts = path.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = (mode, blob)

    def merkle(node):
        raw = bytearray()
        for name in sorted(node, key=lambda n: (n + "/" if isinstance(node[n], dict) else n).encode()):
            value = node[name]
            mode, oid = ("40000", merkle(value)) if isinstance(value, dict) else value
            raw.extend(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
        return hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

    if merkle(nodes) != tree:
        raise ValueError("full actual source Merkle does not reconstruct HEAD")
    return {"head": head, "tree": tree, "files": sorted(rows, key=lambda r: r["path"]),
            "origin": git(repo, "remote", "get-url", "origin").decode().strip(),
            "branch": git(repo, "symbolic-ref", "--short", "HEAD").decode().strip()}


def package_inventory(directory):
    root = Path(directory)
    rows, total = [], 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        for name in directories:
            if (Path(current) / name).is_symlink():
                raise ValueError("package source directory symlink")
        for name in sorted(files):
            path = Path(current) / name
            value = fingerprint(path, 512 * 1024**2)
            total += value["bytes"]
            rows.append({"path": path.relative_to(root).as_posix(),
                         "sha256": value["sha256"], "bytes": value["bytes"]})
            if len(rows) > 200000 or total > 8 * 1024**3:
                raise ValueError("package source closure exceeds bound")
    return sorted(rows, key=lambda r: r["path"])


def git_package_pin(directory, source, locked):
    expected = source.rsplit("#", 1)[-1]
    if len(expected) != 40 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("complete immutable Cargo Git revision required")
    if locked is None or locked.get("source") != source:
        raise ValueError("Cargo Git source is not the original locked dependency")
    root = Path(git(directory, "rev-parse", "--show-toplevel").decode().strip())
    if git(root, "rev-parse", "HEAD").decode().strip() != expected:
        raise ValueError("actual Cargo Git checkout differs from locked revision")
    prefix = Path(directory).relative_to(root).as_posix()
    for entry in git(root, "ls-tree", "-rz", "HEAD", "--", prefix).split(b"\0"):
        if not entry:
            continue
        fields, path = entry.split(b"\t", 1)
        mode, kind, blob = fields.decode().split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("unexpanded dependency Git object")
        actual = root / path.decode()
        data = os.fsencode(os.readlink(actual)) if mode == "120000" else read(actual, 512 * 1024**2)
        if mode != "120000":
            if bool(os.stat(actual, follow_symlinks=False).st_mode & 0o111) != (mode == "100755"):
                raise ValueError("dependency tracked executable mode changed")
        observed = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if observed != blob:
            raise ValueError("actual dependency source differs from its pinned Git blob")
    return {"source": source, "head": expected, "tracked_package_prefix": prefix}


def production_closure(repo, metadata, source):
    packages = {p["id"]: p for p in metadata["packages"]}
    lock = tomllib.loads(read(Path(repo) / "trillionnium/Cargo.lock").decode())
    locked = {(p["name"], p["version"], p.get("source")): p for p in lock["package"]}
    roots = [p["id"] for p in packages.values()
             if p["name"] == "trnm-pon-node" and Path(p["manifest_path"]).is_relative_to(repo)]
    if len(roots) != 1:
        raise ValueError("exact Node package is ambiguous")
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    selected, pending, direct = set(), [roots[0]], set()
    while pending:
        package = pending.pop()
        if package in selected:
            continue
        selected.add(package)
        for edge in nodes[package]["deps"]:
            kinds = {item["kind"] for item in edge["dep_kinds"]}
            if None in kinds or "build" in kinds:
                pending.append(edge["pkg"])
                if package == roots[0] and None in kinds:
                    direct.add(edge["pkg"])
    closures, sbom = [], []
    for package_id in sorted(selected):
        package = packages[package_id]
        directory = Path(package["manifest_path"]).parent
        if directory.is_relative_to(repo):
            prefix = directory.relative_to(repo).as_posix().rstrip("/") + "/"
            rows = [r for r in source["files"] if r["path"].startswith(prefix)]
            if not rows:
                raise ValueError("local production package has no actual tracked input")
            source_identity = {"kind": "tracked-workspace", "head": source["head"], "prefix": prefix}
            package_checksum = digest(canonical(rows))
        else:
            rows = package_inventory(directory)
            source_identity = {"kind": "cargo-source", "source": package["source"]}
            checksums = directory / ".cargo-checksum.json"
            if str(package["source"]).startswith("registry+"):
                manifest = json.loads(read(checksums))
                expected = manifest["package"]
                pinned = locked.get((package["name"], package["version"], package["source"]))
                if not pinned or pinned.get("checksum") != expected:
                    raise ValueError("registry source differs from the original locked checksum")
                if not isinstance(expected, str) or len(expected) != 64:
                    raise ValueError("registry archive checksum absent")
                actual = {r["path"]: r["sha256"] for r in rows}
                for name, value in manifest["files"].items():
                    if actual.get(name) != value:
                        raise ValueError("registry package file checksum mismatch")
                package_checksum = list(bytes.fromhex(expected))
            else:
                if not str(package["source"]).startswith("git+"):
                    raise ValueError("unidentified external production source")
                pinned = locked.get((package["name"], package["version"], package["source"]))
                source_identity = {"kind": "verified-git-package",
                                   **git_package_pin(directory, package["source"], pinned)}
                package_checksum = digest(canonical(rows))
        closure = {"id": package_id, "source": source_identity, "files": rows}
        closures.append(closure)
        sbom.append({"package_name": package["name"], "package_version": package["version"],
                     "source_digest": digest(canonical(source_identity)),
                     "package_checksum": package_checksum,
                     "license_expression": package.get("license") or "NOASSERTION",
                     "direct_production_dependency": package_id in direct})
    return closures, sorted(sbom, key=lambda p: (p["package_name"], p["package_version"], p["source_digest"]))


def elf_static(path, maximum):
    """Additional bounded build check; the Rust parser remains authoritative."""
    import struct
    expected = fingerprint(path, maximum)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if list(identity(os.fstat(fd))) != expected["identity"]:
            raise ValueError("ELF changed before header read")
        header = os.pread(fd, 64, 0)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("expected little-endian ELF64")
        if struct.unpack_from("<H", header, 16)[0] not in {2, 3}:
            raise ValueError("expected executable or static PIE ELF")
        if struct.unpack_from("<H", header, 18)[0] != 62:
            raise ValueError("static native suite requires x86_64 ELF")
        offset = struct.unpack_from("<Q", header, 32)[0]
        stride, count = struct.unpack_from("<HH", header, 54)
        if stride != 56 or count == 0 or count > 4096 or offset + stride * count > expected["bytes"]:
            raise ValueError("invalid bounded ELF program headers")
        for index in range(count):
            entry = os.pread(fd, stride, offset + index * stride)
            if len(entry) != stride:
                raise ValueError("short ELF program header")
            kind = struct.unpack_from("<I", entry)[0]
            if kind == 3:
                raise ValueError("PT_INTERP is forbidden")
            if kind == 2:
                start = struct.unpack_from("<Q", entry, 8)[0]
                size = struct.unpack_from("<Q", entry, 32)[0]
                if start + size > expected["bytes"] or size % 16 or size > 1024**2:
                    raise ValueError("invalid bounded ELF dynamic segment")
                for position in range(start, start + size, 16):
                    value = os.pread(fd, 16, position)
                    if len(value) != 16:
                        raise ValueError("short ELF dynamic entry")
                    tag = struct.unpack_from("<Q", value)[0]
                    if tag in {1, 15, 29}:
                        raise ValueError("DT_NEEDED/RPATH/RUNPATH is forbidden")
                    if tag == 0:
                        break
        if list(identity(os.fstat(fd))) != expected["identity"]:
            raise ValueError("ELF changed during inspection")
        return expected
    finally:
        os.close(fd)
