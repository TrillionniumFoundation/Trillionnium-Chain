#!/usr/bin/env python3
"""Verify every retained hosted member, optionally restoring an absent directory.

This checks historical file bytes. It does not execute a receiver or reproduce
an original ZIP's transport encoding, permissions or runtime ownership.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--bundle", type=Path,
                        default=Path(__file__).parent / "hosted/all-member-records.zip")
    parser.add_argument("--extract", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    if args.extract is not None:
        require(not args.extract.exists() and not args.extract.is_symlink(),
                "extraction output must be absent")
    fixture = "formal/pon-nakamoto-v1/w1_node_adapter_research/fixtures/node-input-v1/"
    allowed = {fixture + name for name in
               ("packet.bin", "statement.bin", "sha.proof.bin", "arith.proof.bin")}
    with zipfile.ZipFile(args.bundle) as archive:
        entries = archive.infolist()
        require(len(entries) < 1000, "bundle entry bound")
        require(sum(row.file_size for row in entries) < 64 * 1024**2,
                "bundle expanded-byte bound")
        require(len({row.filename for row in entries}) == len(entries),
                "duplicate bundle entry")
        index = json.loads(archive.read("index.json"))
        require(index["schema"] == "trnm-w1-receiver-retained-artifacts-v1",
                "unknown bundle schema")
        candidate = index["candidate"]
        require(re.fullmatch(r"[0-9a-f]{40}", candidate), "candidate identity")
        objects = {}
        for digest, reference in index["objects"].items():
            require(re.fullmatch(r"[0-9a-f]{64}", digest), "object identity")
            if reference["kind"] == "git":
                require(reference["commit"] == candidate and reference["path"] in allowed,
                        "unexpected immutable input reference")
                data = subprocess.check_output(
                    ["git", "--no-replace-objects", "show",
                     candidate + ":" + reference["path"]], cwd=repo)
            else:
                require(reference["kind"] == "bundle"
                        and reference["path"] == "objects/" + digest,
                        "unexpected inline object reference")
                data = archive.read(reference["path"])
            require(len(data) == reference["bytes"]
                    and hashlib.sha256(data).hexdigest() == digest,
                    "retained object differs: " + digest)
            objects[digest] = data
        members, seen, restored = [], set(), []
        for source in index["archives"]:
            label = source["label"]
            require(label in ("push", "pr"), "unexpected source archive label")
            for row in source["members"]:
                name = PurePosixPath(row["path"])
                require(not name.is_absolute() and ".." not in name.parts
                        and str(name) == row["path"], "noncanonical member path")
                key = (label, row["path"])
                require(key not in seen, "duplicate source member")
                seen.add(key)
                data = objects[row["sha256"]]
                require(len(data) == row["bytes"], "source member length")
                members.append((label, name, data))
            restored.append({"label": label, "run_id": source["run_id"],
                             "members": len(source["members"]),
                             "original_zip_sha256": source["original_zip_sha256"]})
        # Validate every member before creating any output. Restored files are
        # ordinary diagnostic files, never a recreated live owner or Node.
        if args.extract is not None:
            args.extract.mkdir(parents=True, exist_ok=False)
            for label, name, data in members:
                target = args.extract / label / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    output.write(data)
        print(json.dumps({"schema": "trnm-w1-retained-member-verification-v1",
                          "candidate": candidate, "verified_member_files": len(members),
                          "unique_objects": len(objects), "archives": restored,
                          "extracted": args.extract is not None,
                          "original_zip_container_reconstructed": False,
                          "receiver_executed": False, "qualification": "HOLD_NO_GO"},
                         indent=2))


if __name__ == "__main__":
    main()
