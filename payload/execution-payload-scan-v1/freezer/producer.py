#!/usr/bin/env python3
"""Freeze one root-pinned execution evidence descriptor; never run source or Git."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

ROOT = Path("/private/tmp/chain-consolidation-20261114-root")
PAYLOAD = ROOT / "execution-receipts-followup-v1"
SELF = ROOT / "execution-manifest-freezer-preparation-v1/freeze_execution_payload_v2.py"
MAX_FILES = 10000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def require(condition, message):
    if not condition:
        raise ValueError(message)

def exact_keys(value, names, message):
    require(type(value) is dict and set(value) == set(names), message)

def uint(value, maximum, message):
    require(type(value) is int and 0 <= value <= maximum, message)
    return value

def digest(value):
    require(type(value) is str and SHA256.fullmatch(value) is not None, "invalid SHA256")
    return value

def absolute(value):
    require(type(value) is str and value.startswith("/") and not value.startswith("//") and "\x00" not in value, "invalid absolute path")
    parsed = PurePosixPath(value)
    require(str(parsed) == value and ".." not in parsed.parts, "noncanonical absolute path")
    return Path(value)

def relative(value):
    require(type(value) is str and value and "\x00" not in value and "\\" not in value, "invalid relative payload path")
    parsed = PurePosixPath(value)
    require(not parsed.is_absolute() and str(parsed) == value and value != "." and ".." not in parsed.parts, "unsafe payload path")
    return value

def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]

def open_directory(path):
    path = absolute(str(path))
    fd = os.open("/", DIR_FLAGS)
    chain = [(Path("/"), os.fstat(fd))]
    current = Path("/")
    try:
        for component in path.parts[1:]:
            child = os.open(component, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            current = current / component
            chain.append((current, os.fstat(fd)))
        return fd, chain
    except BaseException:
        os.close(fd)
        raise

def verify_chain(chain):
    for path, previous in chain:
        current = path.lstat()
        require(stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == (previous.st_dev, previous.st_ino), "directory component changed or became a symlink")
    require(chain[-1][0].resolve(strict=True) == chain[-1][0], "noncanonical directory components")

def read_regular(path, cap, expected_bytes=None, expected_sha=None, retain=False):
    path = absolute(str(path))
    parent, chain = open_directory(path.parent)
    fd = None
    chunks = []
    total = 0
    hasher = hashlib.sha256()
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap, "unsafe or oversized regular file")
        if expected_bytes is not None:
            require(before.st_size == expected_bytes, "declared file size differs")
        while True:
            chunk = os.read(fd, 262144)
            if not chunk:
                break
            total += len(chunk)
            require(total <= cap and total <= before.st_size, "file grew during read")
            hasher.update(chunk)
            if retain:
                chunks.append(chunk)
        after = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(identity(before) == identity(after) == identity(named) and total == before.st_size, "file changed during read")
        verify_chain(chain)
        require(path.resolve(strict=True) == path and identity(path.lstat()) == identity(after), "file path identity changed")
        actual = hasher.hexdigest()
        if expected_sha is not None:
            require(actual == expected_sha, "declared SHA256 differs")
        return {"path":str(path), "bytes":total, "sha256":actual, "identity":identity(after)}, b"".join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)

def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result

def decode(raw):
    def nonfinite(value):
        raise ValueError("nonfinite JSON value")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_unique, parse_constant=nonfinite)

def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

def put(directory, name, data):
    require("/" not in name and name not in ("", ".", ".."), "unsafe output name")
    parent, chain = open_directory(directory)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(fd)
        verify_chain(chain)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
    info, _ = read_regular(directory / name, max(len(data), 1), len(data), hashlib.sha256(data).hexdigest())
    return {key:info[key] for key in ("path","bytes","sha256")}

def load_groups(descriptor, snapshots):
    require(type(descriptor) is list and 0 < len(descriptor) <= MAX_FILES, "descriptor must be a bounded nonempty array")
    files = {}
    groups = []
    origins = {}
    group_paths = set()
    total_bytes = 0
    for group in descriptor:
        exact_keys(group, ("path","count","bytes","sha256"), "descriptor group fields differ")
        path = absolute(group["path"])
        require(path != PAYLOAD and not path.is_relative_to(PAYLOAD), "group manifest must be outside payload")
        require(str(path) not in group_paths, "duplicate group manifest")
        group_paths.add(str(path))
        count = uint(group["count"], MAX_FILES, "invalid group count")
        expected_bytes = uint(group["bytes"], MAX_TOTAL_BYTES, "invalid group payload bytes")
        require(count > 0, "empty group")
        info, raw = read_regular(path, MAX_JSON_BYTES, expected_sha=digest(group["sha256"]), retain=True)
        snapshots[str(path)] = info
        value = decode(raw)
        if type(value) is dict:
            exact_keys(value, ("files",), "group wrapper must contain only files")
            value = value["files"]
        require(type(value) is list and len(value) == count, "group file count differs")
        subtotal = 0
        for item in value:
            exact_keys(item, ("path","bytes","sha256","origin"), "strict file entry fields differ")
            name = relative(item["path"])
            size = uint(item["bytes"], MAX_FILE_BYTES, "invalid payload file size")
            checksum = digest(item["sha256"])
            origin = item["origin"]
            exact_keys(origin, ("host","path"), "origin fields differ")
            require(origin["host"] in ("mac","rog"), "unsupported origin host")
            origin_path = str(absolute(origin["path"]))
            origin_key = (origin["host"], origin_path)
            old = origins.get(origin_key)
            require(old is None or old == (size, checksum), "same origin has conflicting bytes or SHA256")
            origins[origin_key] = (size, checksum)
            require(name not in files, "duplicate union payload path")
            files[name] = {"path":name,"bytes":size,"sha256":checksum,
                           "origin":{"host":origin["host"],"path":origin_path}}
            subtotal += size
            total_bytes += size
            require(len(files) <= MAX_FILES and total_bytes <= MAX_TOTAL_BYTES, "union payload bounds exceeded")
        require(subtotal == expected_bytes, "group payload byte sum differs")
        groups.append({"path":str(path),"count":count,"bytes":subtotal,"sha256":info["sha256"],"manifest_bytes":info["bytes"]})
    directories = {""}
    for name in files:
        for parent in PurePosixPath(name).parents:
            if str(parent) != ".":
                directories.add(str(parent))
    require(not (set(files) & directories), "file/directory prefix conflict")
    return files, directories, groups, total_bytes, len(origins)

def inventory(expected, directories):
    root_fd, root_chain = open_directory(PAYLOAD)
    os.close(root_fd)
    verify_chain(root_chain)
    actual_files = {}
    actual_dirs = {}
    inodes = set()
    queue = [""]
    total = 0
    while queue:
        relative_dir = queue.pop()
        path = PAYLOAD / relative_dir
        fd, chain = open_directory(path)
        try:
            before = os.fstat(fd)
            require(stat.S_ISDIR(before.st_mode), "non-directory in payload tree")
            actual_dirs[relative_dir] = identity(before)
            with os.scandir(fd) as entries:
                children = sorted(entries, key=lambda entry:entry.name)
            for entry in children:
                name = entry.name if not relative_dir else relative_dir + "/" + entry.name
                info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    require(name in directories, "extra payload directory")
                    queue.append(name)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and name in expected, "extra, linked, symlink or special payload entity")
                    require(info.st_size == expected[name]["bytes"] and info.st_size <= MAX_FILE_BYTES, "physical file size differs")
                    inode = (info.st_dev,info.st_ino)
                    require(inode not in inodes, "duplicate actual file inode")
                    inodes.add(inode)
                    actual_files[name] = identity(info)
                    total += info.st_size
                    require(len(actual_files) <= MAX_FILES and total <= MAX_TOTAL_BYTES, "physical payload bounds exceeded")
            require(identity(os.fstat(fd)) == identity(before), "directory changed during enumeration")
            verify_chain(chain)
        finally:
            os.close(fd)
    require(set(actual_files) == set(expected) and set(actual_dirs) == directories, "physical payload roster differs")
    return {"files":actual_files,"directories":actual_dirs,"total_bytes":total}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True)
    parser.add_argument("--descriptor-sha256", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    require(__debug__ and os.environ.get("PYTHONOPTIMIZE","0") in ("","0"), "optimized execution forbidden")
    descriptor_path = absolute(args.descriptor)
    require(descriptor_path.is_relative_to(ROOT) and not descriptor_path.is_relative_to(PAYLOAD), "descriptor must be external to payload under ROOT")
    descriptor_sha = digest(args.descriptor_sha256)
    output_dir = absolute(args.output_dir)
    require(output_dir.parent == ROOT and output_dir != PAYLOAD, "output must be a new direct ROOT child")
    require(Path(__file__) == SELF, "unexpected producer path")
    root_fd, root_chain = open_directory(ROOT)
    try:
        os.mkdir(output_dir.name, mode=0o700, dir_fd=root_fd)
        verify_chain(root_chain)
    finally:
        os.close(root_fd)
    state = {"schema":"trnm-execution-manifest-freezer-receipt-v1","status":"HOLD",
             "payload_root":str(PAYLOAD),"descriptor_path":str(descriptor_path),"descriptor_sha256":descriptor_sha,
             "output_dir":str(output_dir),"payload_mutated":False,"origin_paths_dereferenced":False,
             "source_or_Git_access":False,"network_requests":False,"tests_or_lanes_run":False,"errors":[]}
    snapshots = {}
    try:
        producer_info, producer_raw = read_regular(SELF, MAX_JSON_BYTES, retain=True)
        snapshots[str(SELF)] = producer_info
        state["producer_copy"] = put(output_dir, "producer.py", producer_raw)
        descriptor_info, descriptor_raw = read_regular(descriptor_path, MAX_JSON_BYTES, expected_sha=descriptor_sha, retain=True)
        snapshots[str(descriptor_path)] = descriptor_info
        descriptor = decode(descriptor_raw)
        state["descriptor_copy"] = put(output_dir, "descriptor.json", descriptor_raw)
        files, directories, groups, total, origin_count = load_groups(descriptor, snapshots)
        state["groups"] = groups
        state["file_count"] = len(files)
        state["total_bytes"] = total
        state["unique_origin_count"] = origin_count
        before = inventory(files, directories)
        require(before["total_bytes"] == total, "physical union bytes differ")
        verified = {}
        for name in sorted(files):
            row = files[name]
            info, _ = read_regular(PAYLOAD / name, MAX_FILE_BYTES, row["bytes"], row["sha256"])
            require(info["identity"] == before["files"][name], "payload identity changed before/during hash")
            verified[name] = info["identity"]
        after = inventory(files, directories)
        require(after == before and verified == after["files"], "payload roster or identity changed during freeze")
        for path, previous in snapshots.items():
            current, _ = read_regular(Path(path), MAX_JSON_BYTES, previous["bytes"], previous["sha256"])
            require(current == previous, "producer, descriptor or group manifest changed")
        manifest = {"schema":"trnm-frozen-execution-payload-manifest-v1","payload_root":str(PAYLOAD),
                    "file_count":len(files),"total_bytes":total,"files":[files[name] for name in sorted(files)]}
        manifest_raw = encode(manifest)
        require(len(manifest_raw) <= MAX_JSON_BYTES, "frozen manifest exceeds 16MiB")
        state["manifest"] = put(output_dir, "frozen-execution-payload-manifest-v1.json", manifest_raw)
        state["physical_exact_roster_verified"] = True
        state["all_file_content_sha256_verified"] = True
        state["stable_payload_file_and_directory_identities"] = True
        state["all_fixed_inputs_unchanged"] = True
        state["status"] = "FROZEN"
    except Exception as error:
        state["errors"].append({"type":type(error).__name__,"message":str(error)})
    summary = put(output_dir, "summary.json", encode(state))
    print(json.dumps({"status":state["status"],"summary":summary,"manifest":state.get("manifest"),"errors":state["errors"]}, sort_keys=True), flush=True)
    return 0 if state["status"] == "FROZEN" else 1

if __name__ == "__main__":
    raise SystemExit(main())
