#!/usr/bin/env python3
"""Copy one fixed evidence roster into a new execution-stage prefix."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

CONTROL = Path("/private/tmp/chain-external-source-capsule-provenance-materialization-20261114-v1")
STAGE = Path("/private/tmp/chain-consolidation-20261114-root/execution-receipts-followup-v1")
PREFIX = "external-source-capsule-provenance"
CAP = 40 * 1024 * 1024

def digest(data):
    return hashlib.sha256(data).hexdigest()

def stable_read(path, expected_bytes=None, expected_sha=None, retain=False):
    path = Path(path)
    if path.resolve() != path:
        raise ValueError("noncanonical evidence path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    chunks = []
    sha = hashlib.sha256()
    total = 0
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or first.st_size > 100 * 1024 * 1024:
            raise ValueError("unsafe or excessive evidence input")
        while True:
            block = os.read(fd, 262144)
            if not block:
                break
            total += len(block)
            sha.update(block)
            if retain:
                chunks.append(block)
        last = os.fstat(fd)
    finally:
        os.close(fd)
    fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if fields(first) != fields(last) or total != first.st_size:
        raise ValueError("evidence changed while reading")
    if expected_bytes is not None and total != expected_bytes:
        raise ValueError("evidence byte count differs")
    if expected_sha is not None and sha.hexdigest() != expected_sha:
        raise ValueError("evidence SHA256 differs")
    return {"bytes": total, "sha256": sha.hexdigest(), "identity": list(fields(last))}, b"".join(chunks)

def relative_path(value):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts) or str(path) != value:
        raise ValueError("unsafe relative evidence path")
    return path

def put(path, raw):
    with path.open("xb") as handle:
        handle.write(raw)
    info, _ = stable_read(path, len(raw), digest(raw))
    return {"path": str(path), "bytes": info["bytes"], "sha256": info["sha256"]}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE", "0") not in ("", "0"):
        raise ValueError("optimized execution forbidden")
    if len(args.plan_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.plan_sha256):
        raise ValueError("invalid fixed plan SHA256")
    _, raw = stable_read(CONTROL / "plan.json", expected_sha=args.plan_sha256, retain=True)
    plan = json.loads(raw)
    if plan["schema"] != "trnm-external-source-provenance-materialization-plan-v1":
        raise ValueError("wrong fixed plan schema")
    if plan["stage"] != str(STAGE) or plan["prefix"] != PREFIX or plan["max_new_bytes"] != CAP:
        raise ValueError("unexpected target scope")
    if STAGE.resolve() != STAGE or not STAGE.is_dir() or os.path.lexists(STAGE / PREFIX):
        raise ValueError("stage invalid or create-only prefix already exists")
    if os.path.lexists(CONTROL / "materialization-summary.json") or os.path.lexists(CONTROL / "files.json"):
        raise ValueError("materialization is single-shot")
    state = {"schema": "trnm-external-source-capsule-provenance-materialization-v1",
             "status": "HOLD", "plan_sha256": args.plan_sha256, "stage": str(STAGE), "prefix": PREFIX,
             "source_tests_or_lanes_run": False, "Git_or_ref_operations": False,
             "network_requests": False, "running_import_result_included": False,
             "protected_existing_count": 0, "protected_existing_bytes": 0,
             "copied_count": 0, "copied_bytes": 0, "errors": []}
    copied = []
    def save():
        (CONTROL / "materialization-summary.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    save()
    try:
        rows = plan["files"]
        if len({row["path"] for row in rows}) != len(rows):
            raise ValueError("duplicate new target path")
        total = sum(row["bytes"] for row in rows)
        if total != plan["total_bytes"] or total > CAP:
            raise ValueError("new evidence exceeds its fixed byte cap")
        baseline = []
        manifests_before = {}
        for item in plan["protected_manifests"]:
            info, content = stable_read(item["path"], item["bytes"], item["sha256"], retain=True)
            manifests_before[item["path"]] = info
            listed = json.loads(content)
            if not isinstance(listed, list) or len(listed) != item["file_count"]:
                raise ValueError("protected manifest shape/count differs")
            baseline.extend(listed)
        if len(baseline) != 1131 or sum(x["bytes"] for x in baseline) != 93118483 or len({x["path"] for x in baseline}) != 1131:
            raise ValueError("protected fixed baseline differs")
        protected = {}
        for row in baseline:
            if set(row) != {"path", "bytes", "sha256", "origin"}:
                raise ValueError("protected manifest record schema differs")
            relative_path(row["path"])
            if row["path"].split("/")[0] == PREFIX:
                raise ValueError("new prefix overlaps protected baseline")
            info, _ = stable_read(STAGE / row["path"], row["bytes"], row["sha256"])
            protected[row["path"]] = info
        state["protected_existing_count"] = len(baseline)
        state["protected_existing_bytes"] = sum(x["bytes"] for x in baseline)
        for row in rows:
            relative_path(row["path"])
            if not row["path"].startswith(PREFIX + "/") or set(row["origin"]) != {"host", "path"}:
                raise ValueError("new row escapes exact prefix/origin schema")
            stable_read(row["source"], row["bytes"], row["sha256"])
        state["all_inputs_preverified_before_target_writes"] = True
        state["prechecked_new_bytes"] = total
        save()
        (STAGE / PREFIX).mkdir(mode=0o700)
        for row in rows:
            _, data = stable_read(row["source"], row["bytes"], row["sha256"], retain=True)
            target = STAGE / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.parent.resolve() != target.parent or not target.parent.is_relative_to(STAGE / PREFIX):
                raise ValueError("new target parent changed")
            put(target, data)
            copied.append({key: row[key] for key in ("path", "bytes", "sha256", "origin")})
            state["copied_count"] = len(copied)
            state["copied_bytes"] += len(data)
        observed = set()
        for parent, dirs, names in os.walk(STAGE / PREFIX, followlinks=False):
            for directory in dirs:
                if (Path(parent) / directory).is_symlink():
                    raise ValueError("unexpected symlink in new prefix")
            for name in names:
                observed.add(str((Path(parent) / name).relative_to(STAGE)))
        if observed != {x["path"] for x in copied}:
            raise ValueError("new prefix file roster differs")
        for row in copied:
            stable_read(STAGE / row["path"], row["bytes"], row["sha256"])
        for row in baseline:
            info, _ = stable_read(STAGE / row["path"], row["bytes"], row["sha256"])
            if info != protected[row["path"]]:
                raise ValueError("protected evidence identity/content changed")
        for item in plan["protected_manifests"]:
            info, _ = stable_read(item["path"], item["bytes"], item["sha256"])
            if info != manifests_before[item["path"]]:
                raise ValueError("protected manifest changed")
        state["protected_existing_1131_unchanged"] = True
        files_raw = (json.dumps(sorted(copied, key=lambda x: x["path"]), sort_keys=True, indent=2) + "\n").encode()
        state["files"] = put(CONTROL / "files.json", files_raw)
        state["status"] = "MATERIALIZED_AND_HASH_VERIFIED"
    except Exception as error:
        state["errors"].append({"type": type(error).__name__, "message": str(error)})
        state["partial_files"] = put(CONTROL / "files.partial.json",
                                    (json.dumps(copied, sort_keys=True, indent=2) + "\n").encode())
    finally:
        save()
    summary = (CONTROL / "materialization-summary.json").read_bytes()
    print(json.dumps({"summary": str(CONTROL / "materialization-summary.json"),
                      "bytes": len(summary), "sha256": digest(summary), "status": state["status"],
                      "copied_count": state["copied_count"], "copied_bytes": state["copied_bytes"],
                      "files": state.get("files"), "errors": state["errors"]}, sort_keys=True, indent=2), flush=True)
    return 0 if state["status"] == "MATERIALIZED_AND_HASH_VERIFIED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
