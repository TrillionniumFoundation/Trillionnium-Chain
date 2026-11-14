#!/usr/bin/env python3
"""Read only explicitly listed, hash-pinned execution payload bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PREPARE_ROOT = Path("/private/tmp/chain-execution-payload-credential-scanner-20261114-v1")
PAYLOAD_PARENT = Path("/private/tmp/chain-consolidation-20261114-root")
PATTERN_SOURCE_SHA256 = "5c292f6554bbf1345d6e58a3c64cf9099230223fc9c70f217a575f6f20ee7368"
PATTERNS = {'github_classic_token': b'\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b', 'github_fine_grained_token': b'\\bgithub_pat_[A-Za-z0-9_]{20,255}\\b', 'aws_access_key_id': b'\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b', 'slack_token': b'\\b(?:xox[baprs]-[A-Za-z0-9-]{10,255}|xapp-[A-Za-z0-9-]{10,255})\\b', 'private_key_header': b'-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----'}
MAX_FILES = 10000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class ScanError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise ScanError(code)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ScanError("ARGUMENTS_INVALID")


def plain_string(value):
    return (type(value) is str and value != "" and "\\" not in value
            and all(ord(c) >= 32 and ord(c) != 127 for c in value))


def absolute_path(value):
    require(plain_string(value) and value.startswith("/")
            and not value.startswith("//"), "ABSOLUTE_PATH_REQUIRED")
    path = Path(value)
    require(str(path) == value and all(p not in (".", "..", ".git")
                                      for p in path.parts), "NONCANONICAL_PATH")
    return path


def relative_path(value):
    require(plain_string(value) and not value.startswith("/"), "RELATIVE_PATH_REQUIRED")
    parts = value.split("/")
    require(all(p not in ("", ".", "..", ".git") for p in parts)
            and Path(value).as_posix() == value, "UNSAFE_RELATIVE_PATH")
    return parts


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def directory_fd(path):
    fd = os.open("/", DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def relative_file_fd(root_fd, parts):
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], FILE_FLAGS, dir_fd=fd)
        return leaf
    finally:
        os.close(fd)


def checked_file_stat(fd, size_limit, expected_size=None):
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "REGULAR_SINGLE_LINK_REQUIRED")
    require(0 <= st.st_size <= size_limit, "FILE_SIZE_LIMIT")
    if expected_size is not None:
        require(st.st_size == expected_size, "FILE_SIZE_MISMATCH")
    return st


def read_exact_snapshot(fd, before):
    size = before.st_size
    data = bytearray(size)
    offset = 0
    while offset < size:
        chunk = os.read(fd, min(1024 * 1024, size - offset))
        require(bool(chunk), "TRUNCATED_FILE")
        data[offset:offset + len(chunk)] = chunk
        offset += len(chunk)
    require(os.read(fd, 1) == b"", "FILE_GREW")
    require(identity(os.fstat(fd)) == identity(before), "FILE_CHANGED_DURING_READ")
    return data


def absolute_snapshot(path, limit):
    parent = directory_fd(path.parent)
    try:
        fd = relative_file_fd(parent, [path.name])
        try:
            before = checked_file_stat(fd, limit)
            raw = read_exact_snapshot(fd, before)
            return raw, identity(before)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "MANIFEST_DUPLICATE_KEY")
        value[key] = item
    return value


def invalid_constant(value):
    raise ScanError("MANIFEST_NONFINITE_NUMBER")


def validate_manifest(raw):
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=invalid_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ScanError("MANIFEST_INVALID_JSON") from None
    require(type(data) is dict, "MANIFEST_OBJECT_REQUIRED")
    base = {"payload_root", "file_count", "total_bytes", "files"}
    require(set(data) in (base, base | {"schema"}), "MANIFEST_FIELDS")
    if "schema" in data:
        require(data["schema"] == "trnm-frozen-execution-payload-manifest-v1",
                "MANIFEST_SCHEMA")
    payload = absolute_path(data["payload_root"])
    require(payload.parent == PAYLOAD_PARENT
            and re.fullmatch(r"execution-receipts-[A-Za-z0-9._-]+", payload.name)
            is not None, "PAYLOAD_ROOT_SCOPE")
    require(type(data["file_count"]) is int and 0 < data["file_count"] <= MAX_FILES,
            "FILE_COUNT_LIMIT")
    require(type(data["total_bytes"]) is int
            and 0 <= data["total_bytes"] <= MAX_TOTAL_BYTES, "TOTAL_BYTE_LIMIT")
    rows = data["files"]
    require(type(rows) is list and len(rows) == data["file_count"], "FILE_COUNT_MISMATCH")
    names = set()
    total = 0
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "bytes", "sha256", "origin"},
                "FILE_RECORD_FIELDS")
        relative_path(row["path"])
        require(row["path"] not in names, "DUPLICATE_PAYLOAD_PATH")
        names.add(row["path"])
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_FILE_BYTES,
                "PAYLOAD_FILE_BYTE_LIMIT")
        require(type(row["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None,
                "FILE_DIGEST_FORMAT")
        origin = row["origin"]
        require(type(origin) is dict and set(origin) == {"host", "path"}
                and origin["host"] in ("mac", "rog"), "ORIGIN_FIELDS")
        absolute_path(origin["path"])  # Metadata only: never open origin paths.
        total += row["bytes"]
    for name in names:
        parts = name.split("/")
        require(not any("/".join(parts[:i]) in names for i in range(1, len(parts))),
                "FILE_DIRECTORY_PREFIX_CONFLICT")
    require(total == data["total_bytes"], "TOTAL_BYTE_MISMATCH")
    return data, payload, rows


def new_run_directory(value):
    path = absolute_path(value)
    require(path.parent == PREPARE_ROOT
            and re.fullmatch(r"run-[A-Za-z0-9._-]+", path.name) is not None,
            "EVIDENCE_DIRECTORY_SCOPE")
    parent = directory_fd(path.parent)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        fd = os.open(path.name, DIR_FLAGS, dir_fd=parent)
        return path, fd
    finally:
        os.close(parent)


def new_text_file(run_fd, name):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=run_fd)
    return os.fdopen(fd, "w", encoding="utf-8")


def write_result(run_fd, name, value):
    raw = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with new_text_file(run_fd, name) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    encoded = raw.encode("utf-8")
    return {"path": name, "size": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest()}


def main():
    parser = Parser(description=__doc__, add_help=False)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--evidence-dir", required=True)
    run_fd = None
    root_fd = None
    result = {
        "status": "FAILED", "coverage_complete": False, "review_required": False,
        "scope": "Only explicit frozen manifest files; raw bytes, no archive or pack decompression.",
        "all_secrets_absence_proved": False, "automatic_hit_classification": False,
        "pattern_source_sha256": PATTERN_SOURCE_SHA256,
        "regex_flags": [], "counts": {name: 0 for name in PATTERNS},
        "files_scanned": 0, "bytes_scanned": 0,
        "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES,
                   "total_bytes": MAX_TOTAL_BYTES, "manifest_bytes": MAX_MANIFEST_BYTES},
    }
    exit_code = 2
    try:
        args = parser.parse_args()
        manifest_path = absolute_path(args.manifest)
        require(re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256) is not None,
                "MANIFEST_DIGEST_FORMAT")
        run_path, run_fd = new_run_directory(args.evidence_dir)
        raw, manifest_identity = absolute_snapshot(manifest_path, MAX_MANIFEST_BYTES)
        manifest_digest = hashlib.sha256(raw).hexdigest()
        require(manifest_digest == args.manifest_sha256, "MANIFEST_SHA256_MISMATCH")
        data, payload, rows = validate_manifest(raw)
        require(not run_path.is_relative_to(payload), "OUTPUT_INSIDE_PAYLOAD")
        result["manifest"] = {"path": str(manifest_path), "size": len(raw),
                              "sha256": manifest_digest}
        result["payload_root"] = str(payload)
        root_fd = directory_fd(payload)
        root_identity = os.fstat(root_fd)
        compiled = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}
        versions = {}
        inode_names = set()
        with new_text_file(run_fd, "coverage.jsonl") as coverage, \
                new_text_file(run_fd, "hits.jsonl") as hits:
            for row in rows:
                fd = relative_file_fd(root_fd, relative_path(row["path"]))
                try:
                    before = checked_file_stat(fd, MAX_FILE_BYTES, row["bytes"])
                    inode = (before.st_dev, before.st_ino)
                    require(inode not in inode_names, "DUPLICATE_PAYLOAD_FILE_IDENTITY")
                    inode_names.add(inode)
                    snapshot = read_exact_snapshot(fd, before)
                    digest = hashlib.sha256(snapshot).hexdigest()
                    require(digest == row["sha256"], "PAYLOAD_SHA256_MISMATCH")
                    for category, pattern in compiled.items():
                        count = 0
                        for match in pattern.finditer(snapshot):
                            if count == 0:
                                meta = {"category": category, "path": row["path"],
                                        "size": row["bytes"], "sha256": digest}
                                hits.write(json.dumps(meta, sort_keys=True)[:-1] + ', "offsets": [')
                            if count:
                                hits.write(", ")
                            hits.write(str(match.start()))
                            count += 1
                            result["counts"][category] += 1
                            result["review_required"] = True
                        if count:
                            hits.write('], "count": ' + str(count) + "}\n")
                    require(identity(os.fstat(fd)) == identity(before),
                            "PAYLOAD_CHANGED_DURING_SCAN")
                    versions[row["path"]] = identity(before)
                    coverage.write(json.dumps({"path": row["path"], "size": row["bytes"],
                                               "sha256": digest}, sort_keys=True) + "\n")
                    result["files_scanned"] += 1
                    result["bytes_scanned"] += row["bytes"]
                    del snapshot
                finally:
                    os.close(fd)
            coverage.flush()
            hits.flush()
            os.fsync(coverage.fileno())
            os.fsync(hits.fileno())
        # Reopen only listed paths; do not enumerate the payload directory.
        for row in rows:
            fd = relative_file_fd(root_fd, relative_path(row["path"]))
            try:
                after = checked_file_stat(fd, MAX_FILE_BYTES, row["bytes"])
                require(identity(after) == versions[row["path"]], "PAYLOAD_FINAL_IDENTITY_CHANGED")
            finally:
                os.close(fd)
        fresh_root = directory_fd(payload)
        try:
            root_after = os.fstat(fresh_root)
            require((root_after.st_dev, root_after.st_ino)
                    == (root_identity.st_dev, root_identity.st_ino), "PAYLOAD_ROOT_CHANGED")
        finally:
            os.close(fresh_root)
        final_manifest, final_identity = absolute_snapshot(manifest_path, MAX_MANIFEST_BYTES)
        require(final_identity == manifest_identity
                and hashlib.sha256(final_manifest).hexdigest() == args.manifest_sha256,
                "MANIFEST_CHANGED")
        require(result["files_scanned"] == data["file_count"]
                and result["bytes_scanned"] == data["total_bytes"], "COVERAGE_MISMATCH")
        result["coverage_complete"] = True
        any_hit = any(result["counts"].values())
        result["status"] = "REVIEW_REQUIRED" if any_hit else "NO_PATTERN_HITS_IN_DECLARED_SCOPE"
        exit_code = 3 if any_hit else 0
    except ScanError as error:
        result["failure_code"] = error.code
    except Exception as error:
        result["failure_code"] = type(error).__name__
    finally:
        if result["review_required"]:
            result["status"] = "REVIEW_REQUIRED"
        if root_fd is not None:
            os.close(root_fd)
        if run_fd is not None:
            try:
                receipt = write_result(run_fd, "summary.json", result)
                receipt["path"] = str(run_path / receipt["path"])
                print(json.dumps({"status": result["status"], "summary": receipt},
                                 sort_keys=True))
            except Exception as error:
                print(json.dumps({"status": "FAILED",
                                  "failure_code": type(error).__name__}, sort_keys=True))
                exit_code = 2
            finally:
                os.close(run_fd)
        else:
            print(json.dumps({"status": "FAILED",
                              "failure_code": result.get("failure_code", "ARGUMENTS_INVALID")},
                             sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
