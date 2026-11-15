#!/usr/bin/env python3
"""Stream-check the frozen PoN evidence containers and their exact member sets.

No archive is extracted and no native executable, test or cost experiment runs.
Split hosted archives are concatenated virtually in the index's explicit order.
Only verification-receipt.json is written. Exclude that output and INDEX.json
itself from the optional top-level INDEX.json to avoid self-reference.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib

CHUNK = 1024 * 1024
JSON_LIMIT = 32 * 1024 * 1024
RECEIPT = "verification-receipt.json"
HEX256 = re.compile(r"[0-9a-f]{64}\Z")


class VerificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def natural(value, label):
    require(type(value) is int and value >= 0, f"{label}: nonnegative integer required")
    return value


def digest_value(value, label):
    require(type(value) is str and HEX256.fullmatch(value), f"{label}: lowercase SHA-256 required")
    return value


def safe_name(value):
    require(type(value) is str and value, "nonempty relative path required")
    require("\\" not in value and "\0" not in value, f"non-POSIX path: {value!r}")
    require(not value.startswith("/") and not re.match(r"[A-Za-z]:", value),
            f"absolute path forbidden: {value!r}")
    require(all(part not in ("", ".", "..") for part in value.split("/")),
            f"noncanonical/traversing path: {value!r}")
    return value


def regular_path(base, name):
    name = safe_name(name)
    current = base
    parts = name.split("/")
    for index, part in enumerate(parts):
        current = current / part
        mode = current.lstat().st_mode
        require(not stat.S_ISLNK(mode), f"symlink forbidden: {current}")
        require(stat.S_ISREG(mode) if index == len(parts) - 1 else stat.S_ISDIR(mode),
                f"regular file/directory required: {current}")
    return current


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def decode_json(raw):
    return json.loads(raw, object_pairs_hook=no_duplicate_keys)


def read_json(base, name):
    path = regular_path(base, name)
    require(path.stat().st_size <= JSON_LIMIT, f"JSON size bound exceeded: {name}")
    with path.open("rb") as source:
        raw = source.read(JSON_LIMIT + 1)
    require(len(raw) <= JSON_LIMIT, f"JSON size bound exceeded while reading: {name}")
    return decode_json(raw), hashlib.sha256(raw).hexdigest()


def hash_stream(source):
    digest, size = hashlib.sha256(), 0
    while block := source.read(CHUNK):
        digest.update(block)
        size += len(block)
    return size, digest.hexdigest()


def verify_file(base, record, size_key="bytes"):
    name = safe_name(record["path"])
    expected_size = natural(record[size_key], name)
    expected_sha = digest_value(record["sha256"], name)
    path = regular_path(base, name)
    require(path.stat().st_size == expected_size, f"file size differs: {name}")
    with path.open("rb") as source:
        actual_size, actual_sha = hash_stream(source)
    require((actual_size, actual_sha) == (expected_size, expected_sha),
            f"file SHA/size differs: {name}")
    return {"path": name, "bytes": actual_size, "sha256": actual_sha}


def member_map(records):
    require(type(records) is list, "indexed members must be a list")
    result = {}
    for row in records:
        require(type(row) is dict, "member record must be an object")
        name = safe_name(row["path"])
        require(name not in result, f"duplicate indexed member: {name}")
        natural(row["bytes"], name)
        digest_value(row["sha256"], name)
        result[name] = row
    return result


class ConcatenatedReader(io.RawIOBase):
    """Non-seeking, bounded-memory concatenation; only one part is open."""

    def __init__(self, paths):
        super().__init__()
        self.paths = iter(paths)
        self.current = None

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.closed:
            raise ValueError("read of closed concatenation")
        view = memoryview(buffer)
        if not view:
            return 0
        while True:
            if self.current is None:
                path = next(self.paths, None)
                if path is None:
                    return 0
                self.current = path.open("rb")
            count = self.current.readinto(view)
            if count:
                return count
            self.current.close()
            self.current = None

    def close(self):
        if self.current is not None:
            self.current.close()
            self.current = None
        super().close()


def verify_container_parts(base, parts, total_size, total_sha):
    require(type(parts) is list and parts, "nonempty explicit archive parts required")
    natural(total_size, "archive size")
    digest_value(total_sha, "archive SHA")
    combined, total, seen, paths = hashlib.sha256(), 0, set(), []
    for row in parts:
        name = safe_name(row["path"])
        require(name not in seen, f"duplicate archive part: {name}")
        seen.add(name)
        expected_size = natural(row["bytes"], name)
        expected_sha = digest_value(row["sha256"], name)
        path = regular_path(base, name)
        require(path.stat().st_size == expected_size, f"part size differs: {name}")
        digest, size = hashlib.sha256(), 0
        with path.open("rb") as source:
            while block := source.read(CHUNK):
                digest.update(block)
                combined.update(block)
                size += len(block)
                total += len(block)
        require((size, digest.hexdigest()) == (expected_size, expected_sha),
                f"part SHA/size differs: {name}")
        paths.append(path)
    require((total, combined.hexdigest()) == (total_size, total_sha),
            "concatenated archive SHA/size differs")
    return paths


def verify_tar(paths, expected):
    """Read every regular TAR member, including past zero padding, to EOF."""
    seen, total = set(), 0
    with ExitStack() as stack:
        joined = stack.enter_context(ConcatenatedReader(paths))
        buffered = stack.enter_context(io.BufferedReader(joined, CHUNK))
        decompressed = stack.enter_context(lzma.LZMAFile(buffered, "rb"))
        archive = stack.enter_context(tarfile.open(fileobj=decompressed, mode="r|", ignore_zeros=True))
        for member in archive:
            name = safe_name(member.name)
            require(name not in seen, f"duplicate TAR member: {name}")
            require(member.isfile() and not member.issparse(),
                    f"non-regular/sparse TAR member forbidden: {name}")
            require(name in expected, f"unindexed TAR member: {name}")
            row = expected[name]
            require(member.size == row["bytes"], f"TAR member size differs: {name}")
            source = archive.extractfile(member)
            require(source is not None, f"unreadable TAR member: {name}")
            with source:
                size, digest = hash_stream(source)
            require((size, digest) == (row["bytes"], row["sha256"]),
                    f"TAR member SHA/size differs: {name}")
            total += size
            seen.add(name)
        # Force complete decompression, including the XZ integrity check.
        require(decompressed.read(1) == b"", "unread decompressed archive tail")
    require(seen == set(expected), f"missing TAR members: {sorted(set(expected) - seen)}")
    return {"regular_members": len(seen), "uncompressed_bytes": total,
            "exact_member_set": True, "every_member_sha256_and_size_verified": True,
            "extracted_files": 0}


def api_artifacts(root):
    doc, digest = read_json(root / "hosted-service", "all-artifacts-api.json")
    records = doc["artifacts"]
    require(type(records) is list, "API artifacts list required")
    by_id = {}
    for row in records:
        identity = natural(row["id"], "artifact id")
        require(identity not in by_id, f"duplicate API artifact id: {identity}")
        by_id[identity] = row
    return by_id, digest


def verify_hosted_cost(root):
    base = root / "hosted-cost"
    doc, index_sha = read_json(base, "ARCHIVES.json")
    api, api_sha = api_artifacts(root)
    archives = doc["archives"]
    require(type(archives) is list and len(archives) == 12, "exactly twelve hosted cost archives required")
    seen_ids, seen_parts, rows = set(), set(), []
    for row in archives:
        identity = natural(row["artifact_id"], "cost artifact id")
        require(identity not in seen_ids and identity in api, f"duplicate/unknown cost artifact: {identity}")
        seen_ids.add(identity)
        remote = api[identity]
        require(remote["name"] == row["artifact_name"]
                and remote["size_in_bytes"] == row["original_zip_bytes"]
                and remote["digest"] == "sha256:" + row["original_zip_sha256"],
                f"original hosted ZIP metadata differs from saved API: {identity}")
        archive_name = safe_name(row["archive_name"])
        parts = row["parts"]
        require(type(parts) is list and parts, f"archive parts required: {identity}")
        wanted = ([archive_name] if len(parts) == 1 else
                  [archive_name + f".part{index:02d}" for index in range(1, len(parts) + 1)])
        require([p["path"] for p in parts] == wanted, f"archive part order/names differ: {identity}")
        require(not seen_parts.intersection(wanted), "archive part reused by two artifacts")
        seen_parts.update(wanted)
        paths = verify_container_parts(base, parts, row["archive_bytes"], row["archive_sha256"])
        actual = verify_tar(paths, member_map(row["members"]))
        rows.append({"artifact_id": identity, "artifact_name": row["artifact_name"],
                     "archive_name": archive_name, "archive_bytes": row["archive_bytes"],
                     "archive_sha256": row["archive_sha256"], "parts_verified": len(parts),
                     "part_paths_in_concatenation_order": wanted,
                     "original_zip_metadata_matches_saved_api": True,
                     "original_zip_container_reverified": False, **actual})
        print(f"hosted-cost {identity}: {actual['regular_members']} members PASS", flush=True)
    require(read_json(base, "ARCHIVES.json")[1] == index_sha, "hosted cost index changed while reading")
    return {"index_sha256": index_sha, "saved_api_sha256": api_sha, "archives": rows,
            "scope": "Recompressed TAR/XZ containers and exact indexed members verified. Original cost ZIP bytes are not stored here; only their metadata is compared with the saved API."}


def verify_local_v2(root):
    base = root / "local-v2"
    doc, index_sha = read_json(base, "RAW_INDEX.json")
    expected = member_map(doc["raw_files"])
    archives = doc["archives"]
    require(len(expected) == 71 and type(archives) is list and len(archives) == 6,
            "exactly seventy-one local raw files in six archives required")
    names, seen_members, rows = set(), set(), []
    for row in archives:
        name = safe_name(row["path"])
        require(name not in names, f"duplicate local archive: {name}")
        names.add(name)
        require(type(row["members"]) is list, "local member-name list required")
        selected = {}
        for member in row["members"]:
            member = safe_name(member)
            require(member in expected and member not in selected and member not in seen_members,
                    f"missing/repeated local member: {member}")
            selected[member] = expected[member]
        seen_members.update(selected)
        paths = verify_container_parts(base, [row], row["bytes"], row["sha256"])
        actual = verify_tar(paths, selected)
        rows.append({"archive": name, "bytes": row["bytes"], "sha256": row["sha256"], **actual})
        print(f"local-v2 {name}: {actual['regular_members']} members PASS", flush=True)
    require(seen_members == set(expected), "local archive union does not cover every indexed raw file")
    require(read_json(base, "RAW_INDEX.json")[1] == index_sha, "local raw index changed while reading")
    return {"index_sha256": index_sha, "source": doc["source"], "raw_files_verified": len(expected),
            "exact_disjoint_archive_partition": True, "archives": rows}


def verify_cache(root):
    base = root / "cache-benchmark"
    doc, index_sha = read_json(base, "INDEX.json")
    files = member_map(doc["files"])
    for row in files.values():
        verify_file(base, row)
    archive = doc["archive"]
    require(archive["path"] in files, "cache archive absent from cache file index")
    require(all(archive[k] == files[archive["path"]][k] for k in ("bytes", "sha256")),
            "cache archive identity differs across index sections")
    paths = verify_container_parts(base, [archive], archive["bytes"], archive["sha256"])
    actual = verify_tar(paths, member_map(archive["members"]))
    seen_receipts = set()
    for command in doc["commands"]:
        name = safe_name(command["receipt"])
        require(name not in seen_receipts and name in files, f"duplicate/unindexed command receipt: {name}")
        seen_receipts.add(name)
        receipt, unused = read_json(base, name)
        require(receipt["command"] == command["command"]
                and receipt["exit_code"] == command["exit_code"], f"cache command receipt differs: {name}")
        encoded = json.dumps(command["command"], separators=(",", ":"), ensure_ascii=False).encode()
        require(hashlib.sha256(encoded).hexdigest() == command["command_sha256"],
                f"cache command digest differs: {name}")
    require(read_json(base, "INDEX.json")[1] == index_sha, "cache index changed while reading")
    print(f"cache-benchmark: {len(files)} files, {actual['regular_members']} archive members PASS", flush=True)
    return {"index_sha256": index_sha, "files_verified": len(files),
            "command_receipts_verified": len(seen_receipts), "archive": actual}


def verify_service_zip(base, lane, api):
    receipt_name = lane + "-zip-receipt.json"
    receipt, receipt_sha = read_json(base, receipt_name)
    identity = natural(receipt["id"], "service artifact id")
    require(identity in api, "service artifact absent from API")
    remote = api[identity]
    require(remote["size_in_bytes"] == receipt["size"]
            and remote["digest"] == "sha256:" + receipt["sha256"], "service ZIP differs from saved API")
    require(remote["name"].startswith("w1-fresh-service-" + lane + "-"), "service artifact lane name differs")
    container = verify_file(base, {"path": str(identity) + ".zip", "bytes": receipt["size"],
                                   "sha256": receipt["sha256"]})
    expected = {}
    for row in receipt["members"]:
        name = safe_name(row["path"])
        require(name not in expected, f"duplicate ZIP receipt member: {name}")
        natural(row["size"], name)
        crc = natural(row["crc32"], name)
        require(crc <= 0xffffffff, f"invalid indexed CRC: {name}")
        expected[name] = row
    seen, actual, total = set(), {}, 0
    with zipfile.ZipFile(regular_path(base, container["path"])) as archive:
        for member in archive.infolist():
            # ZipInfo.filename truncates at NUL; reject the original spelling too.
            require(safe_name(member.orig_filename) == member.filename,
                    "ZIP original filename differs from parsed filename")
            name = safe_name(member.filename)
            mode = stat.S_IFMT(member.external_attr >> 16)
            require(not member.is_dir() and mode == stat.S_IFREG and not member.flag_bits & 1,
                    f"non-regular/encrypted ZIP member forbidden: {name}")
            require(name not in seen and name in expected, f"duplicate/unindexed ZIP member: {name}")
            row = expected[name]
            require((member.file_size, member.CRC) == (row["size"], row["crc32"]),
                    f"ZIP header size/CRC differs: {name}")
            digest, size, crc = hashlib.sha256(), 0, 0
            with archive.open(member) as source:
                while block := source.read(CHUNK):
                    digest.update(block)
                    crc = zlib.crc32(block, crc)
                    size += len(block)
            require((size, crc) == (row["size"], row["crc32"]), f"ZIP payload size/CRC differs: {name}")
            actual[name] = {"bytes": size, "sha256": digest.hexdigest(), "crc32": crc}
            seen.add(name)
            total += size
        require(seen == set(expected), "ZIP missing indexed members")

        def embedded_json(name):
            require(name in actual and actual[name]["bytes"] <= JSON_LIMIT,
                    f"bounded embedded JSON required: {name}")
            return decode_json(archive.read(name))

        before, after = embedded_json("source-before.json"), embedded_json("source-after.json")
        require(before == after and before["kind"] == lane, "service outer source identities differ")
        require(remote["workflow_run"]["head_sha"] == before["candidate"],
                "service workflow head differs from candidate source")
        artifact_prefix = f"w1-fresh-service-{lane}-{before['tested_commit']}-"
        require(re.fullmatch(re.escape(artifact_prefix) + r"[1-9][0-9]*", remote["name"]),
                "complete service artifact name differs from tested source")
        if lane == "head":
            require(before["tested_commit"] == before["candidate"],
                    "head service did not test its candidate source")
        else:
            require(before["tested_commit"] == before["prospective_merge"],
                    "merge service did not test its prospective merge source")
        manifest = embedded_json("fresh-service/manifest.json")
        require(manifest["source_before"] == manifest["source_after"], "service inner source identity changed")
        require((manifest["source_before"]["commit"], manifest["source_before"]["tree"])
                == (before["tested_commit"], before["tested_tree"]), "service outer/inner source differs")
        for name, digest in manifest["files"].items():
            full_name = "fresh-service/" + safe_name(name)
            require(full_name in actual and actual[full_name]["sha256"] == digest,
                    f"service embedded manifest SHA differs: {full_name}")
        require(actual["fresh-service/public_v3_from_zero"]["sha256"]
                == manifest["binary_sha256_before"] == manifest["binary_sha256_after"], "service ELF differs")
    if lane == "prospective-merge":
        merge, unused = read_json(base, "prospective-merge-api.json")
        require(merge["sha"] == before["tested_commit"] and merge["tree"]["sha"] == before["tested_tree"]
                and [p["sha"] for p in merge["parents"]] == [before["base"], before["candidate"]],
                "ordered service merge parents/tree differ from saved API")
    print(f"hosted-service {lane}: {len(seen)} ZIP members PASS", flush=True)
    return {"lane": lane, "artifact_id": identity, "artifact_name": remote["name"],
            "receipt_sha256": receipt_sha, "container": container, "regular_members": len(seen),
            "uncompressed_bytes": total, "every_member_payload_crc32_verified": True,
            "exact_member_set": True, "embedded_manifest_sha256_files_verified": len(manifest["files"]),
            "source_before_and_after": before, "binary_sha256": manifest["binary_sha256_before"],
            "extracted_files": 0}


def verify_hosted_service(root):
    api, api_sha = api_artifacts(root)
    return {"saved_api_sha256": api_sha,
            "archives": [verify_service_zip(root / "hosted-service", lane, api)
                         for lane in ("head", "prospective-merge")]}


def all_regular_files(root):
    names = set()
    for directory, children, files in os.walk(root, followlinks=False):
        for name in children:
            require(not (Path(directory) / name).is_symlink(), "directory symlink in evidence tree")
        for name in files:
            path = Path(directory) / name
            require(stat.S_ISREG(path.lstat().st_mode), f"non-regular evidence file: {path}")
            names.add(path.relative_to(root).as_posix())
    return names


def verify_top_index(root):
    if not (root / "INDEX.json").exists():
        return {"present": False, "checked": False,
                "scope": "All requested existing subindexes verified; complete top-level inventory was not available."}
    doc, index_sha = read_json(root, "INDEX.json")
    files = member_map(doc["files"])
    require("INDEX.json" not in files and RECEIPT not in files,
            "top INDEX must exclude itself and verification-receipt.json to avoid self-reference")
    require(set(files) == all_regular_files(root) - {"INDEX.json", RECEIPT},
            "top INDEX does not cover the exact complete evidence file set (excluding index/receipt)")
    total = 0
    for row in files.values():
        total += verify_file(root, row)["bytes"]
    require(read_json(root, "INDEX.json")[1] == index_sha, "top index changed while reading")
    print(f"top INDEX: {len(files)} files PASS", flush=True)
    return {"present": True, "checked": True, "index_sha256": index_sha,
            "files_verified": len(files), "bytes_verified": total, "exact_file_set": True,
            "excluded_self_references": ["INDEX.json", RECEIPT]}


def write_receipt(root, result):
    destination = root / RECEIPT
    if destination.exists() or destination.is_symlink():
        require(stat.S_ISREG(destination.lstat().st_mode), "receipt destination must be a regular file")
    fd, temporary = tempfile.mkstemp(prefix=".verification-receipt-", suffix=".tmp", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(result, output, ensure_ascii=False, indent=2)
            output.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    require(root.is_dir(), "evidence root must be a directory")
    started = time.monotonic_ns()
    with Path(__file__).open("rb") as source:
        script_size, script_sha = hash_stream(source)
    result = {"schema": "pon-frozen-evidence-byte-verification-v1", "result": "FAIL",
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "script": {"name": Path(__file__).name, "bytes": script_size, "sha256": script_sha},
              "python": sys.version, "read_chunk_bytes": CHUNK,
              "archive_extraction_performed": False, "temporary_archive_reassembly_bytes": 0,
              "native_execution_performed": False, "semantic_work_or_service_qualification": False,
              "receipt_excluded_from_its_own_hashes": True, "sections": {}, "failures": []}
    operations = [("hosted-cost", verify_hosted_cost), ("local-v2", verify_local_v2),
                  ("cache-benchmark", verify_cache), ("hosted-service", verify_hosted_service),
                  ("top-level-index", verify_top_index)]
    for name, operation in operations:
        try:
            result["sections"][name] = {"result": "PASS", **operation(root)}
        except (VerificationError, OSError, ValueError, KeyError, TypeError, EOFError,
                tarfile.TarError, lzma.LZMAError, zipfile.BadZipFile) as error:
            message = f"{type(error).__name__}: {error}"
            result["sections"][name] = {"result": "FAIL", "error": message}
            result["failures"].append({"section": name, "error": message})
            print(f"{name}: FAIL: {message}", file=sys.stderr, flush=True)
    result["result"] = "FAIL" if result["failures"] else "PASS"
    top = result["sections"]["top-level-index"]
    result["complete_top_level_inventory_verified"] = top.get("checked") is True and top["result"] == "PASS"
    result["verification_scope"] = ("subindexes and complete top-level file inventory"
                                    if result["complete_top_level_inventory_verified"] else
                                    "requested existing subindexes; top-level completeness not established")
    result["finished_utc"] = datetime.now(timezone.utc).isoformat()
    result["elapsed_ns"] = time.monotonic_ns() - started
    write_receipt(root, result)
    print(json.dumps({"result": result["result"], "scope": result["verification_scope"],
                      "receipt": str(root / RECEIPT), "elapsed_ns": result["elapsed_ns"]}), flush=True)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
