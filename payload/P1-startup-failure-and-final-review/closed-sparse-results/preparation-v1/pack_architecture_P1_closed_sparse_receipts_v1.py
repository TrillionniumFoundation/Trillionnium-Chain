#!/usr/bin/env python3
"""Capture ONLY four closed diagnostic directories. Never execute their producers."""
import hashlib
import json
import os
from pathlib import PurePosixPath
import stat
import time
import zipfile

BASE = "/home/qian-qi/chain-final-consolidation-20261114-root"
OUT = BASE + "/closed-P1-sparse-checkout-results-package-v1"
SELF = BASE + "/pack_architecture_P1_closed_sparse_receipts_v1.py"
INVENTORY = json.loads("{\n  \"scope\": [\n    \"final-repository-truth-offline-6a8cd5-v1\",\n    \"P1-index-flag-diagnostic-v1\",\n    \"P1-sparse-checkout-precorrection-v1\",\n    \"P1-sparse-checkout-correction-v1\"\n  ],\n  \"file_count\": 95,\n  \"total_bytes\": 12624662,\n  \"roots\": [\n    {\n      \"directory\": \"/home/qian-qi/chain-final-consolidation-20261114-root/final-repository-truth-offline-6a8cd5-v1\",\n      \"file_count\": 35,\n      \"bytes\": 24402,\n      \"directories\": [\n        \".\",\n        \"ci-observations\",\n        \"tmp\"\n      ],\n      \"files\": [\n        {\n          \"path\": \"initial-status.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"verify-source-after.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"pre-update-preflight.stdout\",\n          \"bytes\": 177\n        },\n        {\n          \"path\": \"local-bundle-list-heads.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"fetched-commit.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"conformance-environment.stdout\",\n          \"bytes\": 223\n        },\n        {\n          \"path\": \"fast-forward-ancestry.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"verify-source-after.stderr\",\n          \"bytes\": 839\n        },\n        {\n          \"path\": \"fetch-exact-local-bundle.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"conformance-environment.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"initial-head.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"preflight-audit.stdout\",\n          \"bytes\": 177\n        },\n        {\n          \"path\": \"initial-status.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"local-bundle-verify.stderr\",\n          \"bytes\": 133\n        },\n        {\n          \"path\": \"verify-source-before.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"fetched-commit.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"fast-forward-ancestry.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"rust-version.stdout\",\n          \"bytes\": 36\n        },\n        {\n          \"path\": \"fetched-tree.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"preflight-audit.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"verify-source-before.stderr\",\n          \"bytes\": 839\n        },\n        {\n          \"path\": \"cargo-version.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"local-bundle-verify.stdout\",\n          \"bytes\": 190\n        },\n        {\n          \"path\": \"fast-forward.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"summary.json\",\n          \"bytes\": 20640\n        },\n        {\n          \"path\": \"rust-version.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"pre-update-preflight.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"fast-forward.stdout\",\n          \"bytes\": 738\n        },\n        {\n          \"path\": \"fetched-tree.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"fetch-exact-local-bundle.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"runtime-environment.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"initial-head.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"local-bundle-list-heads.stdout\",\n          \"bytes\": 46\n        },\n        {\n          \"path\": \"cargo-version.stdout\",\n          \"bytes\": 36\n        },\n        {\n          \"path\": \"runtime-environment.stdout\",\n          \"bytes\": 205\n        }\n      ]\n    },\n    {\n      \"directory\": \"/home/qian-qi/chain-final-consolidation-20261114-root/P1-index-flag-diagnostic-v1\",\n      \"file_count\": 22,\n      \"bytes\": 4199223,\n      \"directories\": [\n        \".\"\n      ],\n      \"files\": [\n        {\n          \"path\": \"config-core.fsmonitor.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"status.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"index-path.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"index-path.stdout\",\n          \"bytes\": 11\n        },\n        {\n          \"path\": \"config-core.preloadindex.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"tree.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"config-core.preloadindex.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"producer.py\",\n          \"bytes\": 2445\n        },\n        {\n          \"path\": \"config-core.sparsecheckout.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"head.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"status.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"ls-files-v.stdout\",\n          \"bytes\": 4191866\n        },\n        {\n          \"path\": \"config-core.sparsecheckout.stdout\",\n          \"bytes\": 31\n        },\n        {\n          \"path\": \"config-core.fsmonitor.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"head.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"config-core.ignorestat.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"tree.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"ls-files-v.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"summary.json\",\n          \"bytes\": 4788\n        },\n        {\n          \"path\": \"config-core.untrackedcache.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"config-core.ignorestat.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"config-core.untrackedcache.stdout\",\n          \"bytes\": 0\n        }\n      ]\n    },\n    {\n      \"directory\": \"/home/qian-qi/chain-final-consolidation-20261114-root/P1-sparse-checkout-precorrection-v1\",\n      \"file_count\": 5,\n      \"bytes\": 4133,\n      \"directories\": [\n        \".\"\n      ],\n      \"files\": [\n        {\n          \"path\": \"producer.py\",\n          \"bytes\": 2249\n        },\n        {\n          \"path\": \"sparse-checkout.original\",\n          \"bytes\": 241\n        },\n        {\n          \"path\": \"summary.json\",\n          \"bytes\": 1227\n        },\n        {\n          \"path\": \"config.worktree.original\",\n          \"bytes\": 58\n        },\n        {\n          \"path\": \"two-tree-entries.stdout\",\n          \"bytes\": 358\n        }\n      ]\n    },\n    {\n      \"directory\": \"/home/qian-qi/chain-final-consolidation-20261114-root/P1-sparse-checkout-correction-v1\",\n      \"file_count\": 33,\n      \"bytes\": 8396904,\n      \"directories\": [\n        \".\"\n      ],\n      \"files\": [\n        {\n          \"path\": \"head-before.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"sparse-config-after.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"tree-before.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"flags-after.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"object-present-0.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"head-after.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"verified-source.json\",\n          \"bytes\": 423\n        },\n        {\n          \"path\": \"producer.py\",\n          \"bytes\": 4191\n        },\n        {\n          \"path\": \"preflight-audit.stdout\",\n          \"bytes\": 177\n        },\n        {\n          \"path\": \"disable-sparse-checkout.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"status-after.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"head-before.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"tree-after.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"original-verify-source.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"sparse-config-after.stdout\",\n          \"bytes\": 6\n        },\n        {\n          \"path\": \"preflight-audit.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"object-present-1.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"object-present-1.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"info--sparse-checkout.before\",\n          \"bytes\": 241\n        },\n        {\n          \"path\": \"summary.json\",\n          \"bytes\": 7489\n        },\n        {\n          \"path\": \"original-verify-source.stdout\",\n          \"bytes\": 423\n        },\n        {\n          \"path\": \"status-before.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"config.worktree.before\",\n          \"bytes\": 58\n        },\n        {\n          \"path\": \"tree-after.stdout\",\n          \"bytes\": 41\n        },\n        {\n          \"path\": \"head-after.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"flags-before.stdout\",\n          \"bytes\": 4191866\n        },\n        {\n          \"path\": \"disable-sparse-checkout.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"status-after.stdout\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"object-present-0.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"tree-before.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"flags-before.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"status-before.stderr\",\n          \"bytes\": 0\n        },\n        {\n          \"path\": \"flags-after.stdout\",\n          \"bytes\": 4191866\n        }\n      ]\n    }\n  ],\n  \"active_full_v2_read\": false\n}\n")
SUMMARY_PINS = json.loads("{\"/home/qian-qi/chain-final-consolidation-20261114-root/final-repository-truth-offline-6a8cd5-v1/summary.json\":{\"bytes\":20640,\"sha256\":\"de19c39a28328ac3f53b849b37e75962b0005cbf6b1980670857c583bfedfbc9\"},\"/home/qian-qi/chain-final-consolidation-20261114-root/P1-index-flag-diagnostic-v1/summary.json\":{\"bytes\":4788,\"sha256\":\"a81f116ef48cb1fa1a50d9d17b343be473c6c8102d47119bfbae1d0381443ea1\"},\"/home/qian-qi/chain-final-consolidation-20261114-root/P1-sparse-checkout-precorrection-v1/summary.json\":{\"bytes\":1227,\"sha256\":\"c52c88e84a3141ad3f3d0f391fbd07043ba1067f187cd34c8b907e93cce23fb8\"},\"/home/qian-qi/chain-final-consolidation-20261114-root/P1-sparse-checkout-correction-v1/summary.json\":{\"bytes\":7489,\"sha256\":\"ecb2bdae4daa5d9a4d38a1734ab9bc8f63acc9fdd89053c44019e5ce8845a7a3\"}}")
FILE_CAP = 16 * 1024 * 1024
TOTAL_CAP = 64 * 1024 * 1024
DFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
RFLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
WFLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

def require(ok, message):
    if not ok:
        raise ValueError(message)

def fp(s):
    return {"dev": s.st_dev, "ino": s.st_ino, "mode": s.st_mode,
            "nlink": s.st_nlink, "size": s.st_size,
            "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}

def canonical_parts(path):
    p = PurePosixPath(path)
    require(p.is_absolute() and str(p) == path, "noncanonical absolute path")
    parts = p.parts[1:]
    require(all(x not in ("", ".", "..", ".git") and "\\" not in x
                and all(ord(c) >= 32 and ord(c) != 127 for c in x) for x in parts),
            "unsafe path component")
    return parts

def safe_relative(path):
    p = PurePosixPath(path)
    require(not p.is_absolute() and str(p) == path and path != ".", "unsafe relative path")
    require(all(x not in ("", ".", "..", ".git") and "\\" not in x
                and all(ord(c) >= 32 and ord(c) != 127 for c in x) for x in p.parts),
            "unsafe relative component")
    return p.parts

def open_dir(path):
    parts = canonical_parts(path)
    fd = os.open("/", DFLAGS)
    try:
        for part in parts:
            nxt = os.open(part, DFLAGS, dir_fd=fd)
            s = os.fstat(nxt)
            require(stat.S_ISDIR(s.st_mode), "not directory")
            require(fp(s) == fp(os.stat(part, dir_fd=fd, follow_symlinks=False)), "directory changed")
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise

def read_relative(root_fd, rel, expected=None, cap=FILE_CAP):
    parts = safe_relative(rel)
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, DFLAGS, dir_fd=parent)
            require(fp(os.fstat(nxt)) == fp(os.stat(part, dir_fd=parent, follow_symlinks=False)),
                    "parent replaced")
            os.close(parent)
            parent = nxt
        name = parts[-1]
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "not single-link regular file")
        require(0 <= before.st_size <= cap, "file cap")
        if expected is not None:
            require(fp(before) == expected, "file differs from snapshot")
        fd = os.open(name, RFLAGS, dir_fd=parent)
        try:
            require(fp(os.fstat(fd)) == fp(before), "open identity mismatch")
            chunks = []
            size = 0
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                size += len(block)
                require(size <= cap and size <= before.st_size, "file grew")
                chunks.append(block)
            require(size == before.st_size, "file shortened")
            require(fp(os.fstat(fd)) == fp(before), "file changed during read")
            require(fp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == fp(before),
                    "path changed during read")
            data = b"".join(chunks)
            return data, fp(before)
        finally:
            os.close(fd)
    finally:
        os.close(parent)

def read_absolute(path, cap=FILE_CAP):
    parts = canonical_parts(path)
    parent = "/" + "/".join(parts[:-1])
    fd = open_dir(parent)
    try:
        return read_relative(fd, parts[-1], cap=cap)
    finally:
        os.close(fd)

def snapshot(root_fd):
    files, directories = {}, {}
    def walk(fd, prefix):
        initial = fp(os.fstat(fd))
        require(stat.S_ISDIR(initial["mode"]), "directory mode changed")
        directories[prefix or "."] = initial
        names = sorted(os.listdir(fd))
        for name in names:
            safe_relative(name)
            rel = name if not prefix else prefix + "/" + name
            item = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(item.st_mode):
                child = os.open(name, DFLAGS, dir_fd=fd)
                try:
                    require(fp(os.fstat(child)) == fp(item), "directory replaced")
                    walk(child, rel)
                    require(fp(os.stat(name, dir_fd=fd, follow_symlinks=False)) == fp(item),
                            "child directory changed")
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1,
                        "symlink, special, or hardlink in scope")
                require(0 <= item.st_size <= FILE_CAP, "file exceeds cap")
                files[rel] = fp(item)
        require(names == sorted(os.listdir(fd)) and initial == fp(os.fstat(fd)),
                "directory changed during inventory")
    walk(root_fd, "")
    return {"files": files, "directories": directories}

def write_new(path, data):
    fd = os.open(path, WFLAGS, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)

def json_bytes(obj):
    return (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode()

def item(path, data, origin, fingerprint=None):
    row = {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
           "origin": origin}
    if fingerprint is not None:
        row["source_fingerprint"] = fingerprint
    return row

def add_member(archive, name, data):
    safe_relative(name)
    zi = zipfile.ZipInfo(name, (2026, 11, 14, 0, 0, 0))
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.create_system = 3
    zi.external_attr = (stat.S_IFREG | 0o600) << 16
    archive.writestr(zi, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)

def main():
    require(os.path.abspath(__file__) == SELF, "unexpected producer path")
    producer, producer_fp = read_absolute(SELF)
    roots = INVENTORY["roots"]
    require(INVENTORY["file_count"] == 95 and INVENTORY["total_bytes"] == 12624662,
            "unexpected prior inventory")
    require([r["directory"] for r in roots] ==
            [BASE + "/" + x for x in INVENTORY["scope"]], "scope mismatch")
    require(len(roots) == 4 and "final-repository-truth-offline-6a8cd5-v2"
            not in INVENTORY["scope"], "active run forbidden")
    base_fd = open_dir(BASE)
    source_fds = {}
    before = {}
    try:
        for root in roots:
            name = PurePosixPath(root["directory"]).name
            fd = os.open(name, DFLAGS, dir_fd=base_fd)
            require(fp(os.fstat(fd)) == fp(os.stat(name, dir_fd=base_fd, follow_symlinks=False)),
                    "source root replaced")
            source_fds[name] = fd
            got = snapshot(fd)
            expected = {x["path"]: x["bytes"] for x in root["files"]}
            require({p: v["size"] for p, v in got["files"].items()} == expected,
                    "inventory files changed")
            require(sorted(got["directories"]) == sorted(root["directories"]),
                    "inventory directories changed")
            before[name] = got
        count = sum(len(x["files"]) for x in before.values())
        total = sum(v["size"] for x in before.values() for v in x["files"].values())
        require(count == 95 and total == 12624662 and total <= TOTAL_CAP, "inventory total mismatch")
        os.mkdir(PurePosixPath(OUT).name, 0o700, dir_fd=base_fd)
        out_fd = open_dir(OUT)
        os.close(out_fd)
        write_new(OUT + "/producer.py", producer)
        inventory_raw = json_bytes(INVENTORY)
        write_new(OUT + "/inventory-input.json", inventory_raw)
        rows = []
        source_hashes = {}
        zip_path = OUT + "/original-closed-P1-sparse-receipts-v1.zip"
        zip_fd = os.open(zip_path, WFLAGS, 0o600)
        with os.fdopen(zip_fd, "wb") as target:
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for name in sorted(source_fds):
                    for rel, expected in sorted(before[name]["files"].items()):
                        data, identity = read_relative(source_fds[name], rel, expected=expected)
                        absolute = BASE + "/" + name + "/" + rel
                        row = item("originals/" + name + "/" + rel, data,
                                   {"host": "rog", "path": absolute}, identity)
                        if absolute in SUMMARY_PINS:
                            require({"bytes": row["bytes"], "sha256": row["sha256"]} ==
                                    SUMMARY_PINS[absolute], "closed summary changed")
                        rows.append(row)
                        source_hashes[absolute] = row["sha256"]
                        add_member(archive, row["path"], data)
                after = {}
                for name in sorted(source_fds):
                    for rel, expected in sorted(before[name]["files"].items()):
                        data, _ = read_relative(source_fds[name], rel, expected=expected)
                        require(hashlib.sha256(data).hexdigest() ==
                                source_hashes[BASE + "/" + name + "/" + rel],
                                "source bytes changed after packaging")
                    after[name] = snapshot(source_fds[name])
                    require(after[name] == before[name], "source snapshot changed")
                    require(fp(os.stat(name, dir_fd=base_fd, follow_symlinks=False)) ==
                            before[name]["directories"]["."], "source root path changed")
                closure = {
                    "schema": "trnm-P1-closed-sparse-originals-capture-v1",
                    "status": "ALL_95_ORIGINAL_FILES_AND_DIRECTORY_IDENTITIES_STABLE",
                    "source_file_count": count, "source_total_bytes": total,
                    "source_before": before, "source_after": after,
                    "source_before_after_identical": True,
                    "source_sha256_reopened_after_packaging": source_hashes,
                    "summary_pins": SUMMARY_PINS,
                    "first_lane_status_preserved": "failed",
                    "first_lane_test_command_started": False,
                    "first_lane_missing_source_sidecars_not_fabricated": True,
                    "correction_status_preserved": "FULL_CHECKOUT_RESTORED_AND_ORIGINAL_SOURCE_VERIFIED",
                    "active_full_v2_read": False, "test_commands_executed": False,
                    "git_commands_executed": False, "source_or_git_mutation": False,
                    "scope": "Four explicit completed evidence directories only; no source or restored ZIP bodies.",
                    "producer": item("producer.py", producer, {"host": "rog", "path": SELF}, producer_fp),
                    "utc_capture": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
                closure_raw = json_bytes(closure)
                write_new(OUT + "/capture-closure.json", closure_raw)
                for name, raw, origin in (
                    ("producer.py", producer, SELF),
                    ("inventory-input.json", inventory_raw, OUT + "/inventory-input.json"),
                    ("capture-closure.json", closure_raw, OUT + "/capture-closure.json"),
                ):
                    rows.append(item("package/" + name, raw, {"host": "rog", "path": origin}))
                    add_member(archive, rows[-1]["path"], raw)
                rows.sort(key=lambda x: x["path"])
                index = {
                    "schema": "trnm-P1-closed-sparse-originals-zip-index-v1",
                    "file_count": len(rows), "total_bytes": sum(x["bytes"] for x in rows),
                    "original_file_count": count, "original_total_bytes": total,
                    "empty_original_directories": [
                        {"host": "rog", "path": BASE + "/" + name + "/" + rel}
                        for name, snap in sorted(before.items()) for rel in sorted(snap["directories"])
                        if rel != "." and not any(p == rel or p.startswith(rel + "/")
                                                 for p in snap["files"])
                    ],
                    "files": rows
                }
                index_raw = json_bytes(index)
                require(index["total_bytes"] + len(index_raw) <= TOTAL_CAP, "aggregate package cap")
                write_new(OUT + "/EVIDENCE_INDEX.json", index_raw)
                add_member(archive, "EVIDENCE_INDEX.json", index_raw)
            target.flush()
            os.fsync(target.fileno())
        expected_rows = rows + [item("EVIDENCE_INDEX.json", index_raw,
                                      {"host": "rog", "path": OUT + "/EVIDENCE_INDEX.json"})]
        with zipfile.ZipFile(zip_path, "r") as archive:
            infos = archive.infolist()
            require(len(infos) == len(expected_rows), "zip count mismatch")
            require(len({x.filename for x in infos}) == len(infos), "duplicate zip members")
            require(set(archive.namelist()) == {x["path"] for x in expected_rows}, "zip roster mismatch")
            for row in expected_rows:
                info = archive.getinfo(row["path"])
                require(not info.is_dir() and info.file_size == row["bytes"] <= FILE_CAP,
                        "zip member size/type mismatch")
                data = archive.read(row["path"])
                require(len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"],
                        "zip CRC/bytes/SHA mismatch")
        for name, fd in source_fds.items():
            require(snapshot(fd) == before[name], "final source identity changed")
            require(fp(os.stat(name, dir_fd=base_fd, follow_symlinks=False)) ==
                    before[name]["directories"]["."], "final root path changed")
        zip_raw, zip_fp = read_absolute(zip_path, cap=TOTAL_CAP)
        summary = {
            "schema": "trnm-P1-closed-sparse-package-summary-v1",
            "status": "SOURCE_RAW_PACKAGE_VERIFIED",
            "original_files": count, "original_bytes": total,
            "zip_members": len(expected_rows), "zip_member_bytes": sum(x["bytes"] for x in expected_rows),
            "zip": item(PurePosixPath(zip_path).name, zip_raw, {"host": "rog", "path": zip_path}, zip_fp),
            "index": item("EVIDENCE_INDEX.json", index_raw, {"host": "rog", "path": OUT + "/EVIDENCE_INDEX.json"}),
            "producer": item("producer.py", producer, {"host": "rog", "path": SELF}, producer_fp),
            "source_before_after_identical": True,
            "every_member_crc_bytes_sha256_verified": True,
            "first_lane_failure_preserved": True,
            "active_full_v2_read": False, "tests_rerun": False,
            "stage_written": False, "source_or_git_mutation": False
        }
        write_new(OUT + "/summary.json", json_bytes(summary))
        print(json.dumps(summary, sort_keys=True))
    finally:
        for fd in source_fds.values():
            os.close(fd)
        os.close(base_fd)

if __name__ == "__main__":
    main()
