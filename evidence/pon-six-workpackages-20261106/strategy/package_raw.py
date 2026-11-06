#!/usr/bin/env python3
"""Losslessly package complete native observations and verify every raw member.

The original per-command gzip files remain in an explicitly named workspace
retention directory. The published archive contains the exact uncompressed
native stdout/stderr, pinned ELF, declarations, receipts and all readbacks.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

# At most 2 MiB after base64 encoding for the repository connector.
PART_BYTES = 1536 * 1024


def sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            result.update(data)
    return result.hexdigest()


def write(path, value):
    with Path(path).open("w") as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")


class HashingRead:
    def __init__(self, source):
        self.source, self.digest, self.size = source, hashlib.sha256(), 0

    def read(self, size=-1):
        data = self.source.read(size)
        self.digest.update(data)
        self.size += len(data)
        return data


def verify(index_path):
    index_path = Path(index_path)
    index = json.loads(index_path.read_text())
    expected = {member["name"]: member for member in index["members"]}
    if len(expected) != len(index["members"]):
        raise ValueError("duplicate archive member declaration")
    with tempfile.TemporaryFile() as combined:
        digest = hashlib.sha256()
        total = 0
        for number, part in enumerate(index["parts"]):
            if number != part["number"] or Path(part["file"]).name != part["file"]:
                raise ValueError("part identity/order")
            path = index_path.parent / part["file"]
            if path.stat().st_size != part["bytes"] or sha(path) != part["sha256"]:
                raise ValueError("archive part digest/size")
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    total += len(block)
                    combined.write(block)
        if digest.hexdigest() != index["archive_sha256"] or total != index["archive_bytes"]:
            raise ValueError("assembled archive digest/size")
        combined.seek(0)
        process = subprocess.Popen(["zstd", "-d", "-q", "-c"], stdin=combined, stdout=subprocess.PIPE)
        seen = set()
        try:
            with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                for member in archive:
                    if not member.isfile() or member.name not in expected or member.name in seen:
                        raise ValueError("unknown/non-file/duplicate member")
                    declared = expected[member.name]
                    if member.size != declared["bytes"] or member.mode != declared["mode"]:
                        raise ValueError("member size/mode")
                    reader = HashingRead(archive.extractfile(member))
                    while reader.read(1024 * 1024):
                        pass
                    if reader.size != declared["bytes"] or reader.digest.hexdigest() != declared["sha256"]:
                        raise ValueError("raw member digest/size")
                    seen.add(member.name)
            # Drain tar's final record padding before waiting on the producer.
            while process.stdout.read(1024 * 1024):
                pass
            if process.wait() != 0 or seen != set(expected):
                raise ValueError("incomplete decompression/member coverage")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    return dict(verified_members=len(seen), verified_parts=len(index["parts"]),
                archive_sha256=index["archive_sha256"], raw_member_bytes=sum(m["bytes"] for m in expected.values()))


def package(capture, retained):
    capture, retained = Path(capture).resolve(strict=True), Path(retained).resolve()
    parent = capture.parent
    index_path = parent / "raw-archive-index.json"
    if index_path.exists() or retained.exists():
        raise ValueError("new archive/index and workspace retention directory required")
    manifest = json.loads((capture / "manifest.json").read_text())
    if manifest["planned"] != 48 or manifest["observed_commands"] != 48 or len(manifest["commands"]) != 48:
        raise ValueError("this package requires all 48 retained observed commands, including any failures")
    if manifest["unobserved_planned_commands"]:
        raise ValueError("declared observation coverage is inconsistent")
    sources = []
    absent_metadata = []
    for command in manifest["commands"]:
        name = command["name"]
        if re.fullmatch(r"[a-z0-9-]+", name) is None:
            raise ValueError("unsafe command path")
        for filename in ("stdout.jsonl", "stderr.log"):
            observation = command["archives"][filename]
            path = capture / name / observation["file"]
            if sha(path) != observation["sha256"] or path.stat().st_size != observation["bytes"]:
                raise ValueError("original gzip has changed")
            field = "stdout_sha256" if filename == "stdout.jsonl" else "stderr_sha256"
            if observation["raw_sha256"] != command["process"][field]:
                raise ValueError("native observation digest differs from original gzip")
            sources.append((path, f"{capture.name}/{name}/{filename}",
                            observation["raw_bytes"], observation["raw_sha256"], True, 0o644))
        for filename in ("process.json", "readback.json"):
            path = capture / name / filename
            if filename == "readback.json" and not path.exists():
                absent_metadata.append(str(path.relative_to(capture)))
                continue
            sources.append((path, f"{capture.name}/{name}/{filename}", path.stat().st_size, sha(path), False, 0o644))
    for filename in ("declaration.json", "manifest.json", "grid-readback.json", "preflight.log", "pinned-native"):
        path = capture / filename
        if filename == "grid-readback.json" and not path.exists():
            absent_metadata.append(filename)
            continue
        sources.append((path, f"{capture.name}/{filename}", path.stat().st_size, sha(path), False,
                        0o755 if filename == "pinned-native" else 0o644))
    full = parent / "raw-observations.tar.zst.temporary"
    members = []
    with full.open("xb") as output:
        compressor = subprocess.Popen(["zstd", "-q", "-10", "-T2", "--long=27", "-c"],
                                      stdin=subprocess.PIPE, stdout=output)
        try:
            with tarfile.open(fileobj=compressor.stdin, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for path, name, size, expected_sha, compressed, mode in sources:
                    opener = gzip.open if compressed else open
                    with opener(path, "rb") as source:
                        raw = HashingRead(source)
                        info = tarfile.TarInfo(name)
                        info.size, info.mode, info.mtime = size, mode, 0
                        archive.addfile(info, raw)
                        if raw.read(1) or raw.size != size or raw.digest.hexdigest() != expected_sha:
                            raise ValueError("source raw digest/size changed while packaging")
                    members.append(dict(name=name, bytes=size, sha256=expected_sha, mode=mode))
            compressor.stdin.close()
            if compressor.wait() != 0:
                raise ValueError("zstd compression failed")
        finally:
            if compressor.poll() is None:
                compressor.kill()
                compressor.wait()
    parts = []
    with full.open("rb") as source:
        while data := source.read(PART_BYTES):
            part = parent / f"raw-observations.tar.zst.part-{len(parts):03d}"
            with part.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            parts.append(dict(number=len(parts), file=part.name, bytes=len(data), sha256=sha(part)))
    index = dict(schema="pon-w1-preparation-lossless-archive-v4", archive_sha256=sha(full),
        archive_bytes=full.stat().st_size, compression="zstd-10-long27-USTAR",
        part_max_bytes=PART_BYTES, parts=parts, members=members,
        native_stdout_stderr_scope="exact uncompressed original process bytes; historical gzip transport SHA remains in manifest",
        original_gzip_workspace_retention=str(retained),
        original_capture_complete=manifest["complete"],
        original_source_unchanged=manifest["source_unchanged"],
        original_binary_unchanged=manifest["binary_unchanged"],
        absent_metadata=absent_metadata, qualification_status="HOLD")
    write(index_path, index)
    verified = verify(index_path)
    write(parent / "raw-archive-verification.json", verified)
    # Move only after the archive has independently round-tripped every member.
    # The complete original gzip bytes are retained, not deleted or overwritten.
    retained.mkdir()
    for path, _, _, _, compressed, _ in sources:
        if compressed or path.name == "pinned-native":
            target = retained / path.relative_to(capture)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(path, target)
    shutil.move(full, retained / "assembled-raw-observations.tar.zst")
    print(json.dumps(verified, sort_keys=True))


def resplit(index_path, retained):
    """Change only transport part boundaries; retain the entire prior transport."""
    index_path, retained = Path(index_path).resolve(strict=True), Path(retained).resolve()
    if retained.exists():
        raise ValueError("new prior-parts retention directory required")
    verify(index_path)
    index = json.loads(index_path.read_text())
    parts = []
    with tempfile.TemporaryFile() as combined:
        for previous in index["parts"]:
            with (index_path.parent / previous["file"]).open("rb") as source:
                shutil.copyfileobj(source, combined)
        combined.seek(0)
        while data := combined.read(PART_BYTES):
            name = f"raw-observations.tar.zst.part-{len(parts):03d}"
            path = index_path.parent / (name + ".new")
            with path.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            parts.append(dict(number=len(parts), file=name, bytes=len(data), sha256=sha(path)))
    retained.mkdir()
    shutil.copy2(index_path, retained / index_path.name)
    verification_path = index_path.parent / "raw-archive-verification.json"
    if verification_path.exists():
        shutil.copy2(verification_path, retained / verification_path.name)
    for previous in index["parts"]:
        shutil.move(index_path.parent / previous["file"], retained / previous["file"])
    for part in parts:
        (index_path.parent / (part["file"] + ".new")).rename(index_path.parent / part["file"])
    index["parts"], index["part_max_bytes"] = parts, PART_BYTES
    write(index_path, index)
    verified = verify(index_path)
    write(verification_path, verified)
    print(json.dumps(verified, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--resplit", type=Path)
    parser.add_argument("--retain-prior-parts", type=Path)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--retain-original-gzip", type=Path)
    args = parser.parse_args()
    if args.verify is not None:
        if any(value is not None for value in (args.capture, args.retain_original_gzip, args.resplit, args.retain_prior_parts)):
            parser.error("verify is read-only and separate from packaging")
        print(json.dumps(verify(args.verify), sort_keys=True))
    elif args.resplit is not None and args.retain_prior_parts is not None:
        if args.capture is not None or args.retain_original_gzip is not None:
            parser.error("resplit changes only an existing archive's transport")
        resplit(args.resplit, args.retain_prior_parts)
    elif args.capture is not None and args.retain_original_gzip is not None:
        if args.resplit is not None or args.retain_prior_parts is not None:
            parser.error("resplit requires both existing index and retention directory")
        package(args.capture, args.retain_original_gzip)
    else:
        parser.error("provide --verify; or --capture and --retain-original-gzip; or --resplit and --retain-prior-parts")


if __name__ == "__main__":
    main()
