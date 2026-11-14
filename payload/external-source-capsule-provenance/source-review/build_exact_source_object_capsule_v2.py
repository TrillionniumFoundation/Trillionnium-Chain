#!/usr/bin/env python3
"""Build only the 940 reviewed missing source objects in an isolated directory."""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import time

BASE = Path("/private/tmp/chain-external-lane-readonly-review-20261114-v1")
OUT = Path("/private/tmp/chain-external-evidence-source-object-capsule-20261114-v2")
COMPLETE = Path("/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git")
FILTERED = Path("/private/tmp/chain-external-evidence-three-sources-20261114-v2/repository.git")
PINS = {
    "missing": (BASE / "rog-object-reuse-review-v1/missing-object-providers-and-paths.json", 763704, "f6cc4f4d428ffc24451d00f80638e2ef5975be61d324e6507b4670293209221e"),
    "oids": (BASE / "rog-object-reuse-review-v1/rog-missing-940.oids", 38540, "99ab7fe2da03663e272c5b8781299fbe3db9c2f8edc04e0e1a611c7395e49035"),
    "union": (BASE / "fourteen-object-union-v1/object-inventory.json", 1350771, "b0dd151583f907666e366887fb27de834922e3f1b87c7a9bb747c3124b870102"),
    "rog": (BASE / "rog-object-reuse-review-v1/rog-summary.json", 9715, "c0c9a295e5231d4023a04ca6617a3a1e3917368221475a1d0b3c8350df06f49e"),
    "rog_presence": (BASE / "rog-object-reuse-review-v1/rog-object-presence.stdout", 197100, "7f774953bb7cbbb06a1af7fb6ec6ff65001f5e820ad3119237df288f17e72b4a"),
    "first22": (Path("/private/tmp/chain-external-missing-blobs-20261114-v2/summary.json"), 48128, "427cfd0dbe3ddb855fa981bbef07749c956018cf48bcbbebecd09d9c29ceb097"),
    "next18": (BASE / "remaining-explicit-18-v1/summary.json", 22626, "592ef9baa78eab009705798b0d3be2c9f344b38bbd2da9fd3b6951595892ce7a"),
}
EXPECTED_COUNTS = {"commit": 14, "tree": 319, "blob": 607}
EXPECTED_RAW_BYTES = 9204616

def sha(data):
    return hashlib.sha256(data).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stable_read(path, expected_size=None, expected_sha=None):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise ValueError("not a regular single-link input")
    if expected_size is not None and s.st_size != expected_size:
        raise ValueError("input byte count mismatch")
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        data = handle.read()
        after = os.fstat(handle.fileno())
    fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if fields(before) != fields(after) or len(data) != s.st_size:
        raise ValueError("input changed during read")
    if expected_sha is not None and sha(data) != expected_sha:
        raise ValueError("input SHA256 mismatch")
    return data

def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE", "0") not in ("", "0"):
        raise ValueError("optimization forbidden")
    raw = {name: stable_read(path, size, digest) for name, (path, size, digest) in PINS.items()}
    missing = json.loads(raw["missing"])["objects"]
    fixed_oids = raw["oids"].decode("ascii").splitlines()
    if len(missing) != 940 or fixed_oids != sorted(set(fixed_oids)):
        raise ValueError("incorrect object count/order")
    if [row["oid"] for row in missing] != fixed_oids:
        raise ValueError("manifest/OID roster disagreement")
    if {kind: sum(row["type"] == kind for row in missing) for kind in EXPECTED_COUNTS} != EXPECTED_COUNTS:
        raise ValueError("type roster disagreement")
    union = json.loads(raw["union"])
    rog = json.loads(raw["rog"])
    first, second = json.loads(raw["first22"]), json.loads(raw["next18"])
    if first["status"] != "HOLD" or len(first["objects"]) != 22:
        raise ValueError("original partial receipt changed")
    if second["status"] != "ALL_18_CONTENT_ADDRESSES_VERIFIED" or len(second["objects"]) != 18:
        raise ValueError("remaining blob receipt incomplete")
    fetched = {}
    for receipt, name in ((first, "first22"), (second, "next18")):
        for row in receipt["objects"]:
            if row["oid"] in fetched or row["type"] != "blob" or row["git_sha1_verified"] is not True:
                raise ValueError("duplicate/unverified fetched blob")
            fetched[row["oid"]] = (row, name)
    needed_blobs = {row["oid"] for row in missing if row["bytes"] is None}
    if set(fetched) != needed_blobs or len(fetched) != 40:
        raise ValueError("fetched object set differs from exact unknown subset")
    if os.path.lexists(OUT):
        raise ValueError("create-only capsule directory exists")
    os.umask(0o077)
    OUT.mkdir(mode=0o700)
    (OUT / "raw-objects").mkdir()
    (OUT / "receipts").mkdir()
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("GIT_TRACE") or name in ("GIT_CURL_VERBOSE", "GIT_ALLOW_PROTOCOL"):
            env.pop(name)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        if name in env:
            raise ValueError("unexpected Git override " + name)
    env.update(
        GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0", GIT_PROTOCOL_FROM_USER="0",
        GIT_TRACE2="0", GIT_TRACE2_EVENT="0", GIT_TRACE2_PERF="0",
        PYTHONDONTWRITEBYTECODE="1", PYTHONOPTIMIZE="0",
    )
    flags = ["git", "--no-replace-objects", "-c", "protocol.allow=never",
             "-c", "protocol.http.allow=never", "-c", "protocol.https.allow=never",
             "-c", "protocol.ssh.allow=never", "-c", "protocol.file.allow=never"]
    state = {
        "schema": "trnm-external-source-object-capsule-build-v2", "status": "RUNNING",
        "started_at": now(), "steps": [], "errors": [],
        "git_shared_object_ref_source_writes": False, "rog_import": False,
        "network_calls": 0, "parent_edges_traversed": 0, "tests_run": False,
    }
    def save():
        (OUT / "build-summary.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    def put(path, data):
        with path.open("xb") as handle:
            handle.write(data)
        return {"path": str(path), "bytes": len(data), "sha256": sha(data)}
    def run(label, argv, data=None, timeout=60, cap=20000000, allowed=(0,)):
        begin = time.monotonic()
        process = subprocess.Popen(argv, cwd=OUT, env=env, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        row = {"label": label, "argv": argv, "cwd": str(OUT), "owned_pid": process.pid,
               "owned_pgid": process.pid, "started_at": now(), "timeout_seconds": timeout}
        try:
            stdout, stderr = process.communicate(data, timeout=timeout)
            code = process.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate(timeout=10)
            code = 124
        row.update(exit=code, finished_at=now(), seconds=time.monotonic() - begin,
                   stdout=put(OUT / "receipts" / (label + ".stdout"), stdout),
                   stderr=put(OUT / "receipts" / (label + ".stderr"), stderr))
        state["steps"].append(row)
        save()
        if code not in allowed or len(stdout) > cap or len(stderr) > 65536:
            raise ValueError("bounded local command failed: " + label)
        return stdout, stderr, code
    records = {}
    def accept(row, data, provider):
        oid, kind = row["oid"], row["type"]
        if oid in records or (row["bytes"] is not None and row["bytes"] != len(data)):
            raise ValueError("duplicate or wrong object size")
        address = hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if address != oid:
            raise ValueError("source content address mismatch")
        info = put(OUT / "raw-objects" / oid, data)
        records[oid] = {"oid": oid, "type": kind, "bytes": len(data), "sha256": info["sha256"],
                        "git_sha1_verified": True, "provider": provider, "declared_paths": row["declared_paths"]}
    save()
    try:
        for provider, gitdir in (("complete.git", COMPLETE), ("filtered-bare", FILTERED)):
            selected = [row for row in missing if row["bytes"] is not None and provider in row["providers"]]
            listing = "".join(row["oid"] + "\n" for row in selected).encode()
            expected_bytes = sum(row["bytes"] for row in selected)
            stream, stderr, _ = run(
                "provider-" + provider.replace(".", "-"),
                flags + ["--git-dir=" + str(gitdir), "cat-file", "--batch"],
                listing, cap=expected_bytes + len(selected) * 100,
            )
            if stderr:
                raise ValueError("unexpected provider stderr")
            source = io.BytesIO(stream)
            for row in selected:
                header = source.readline().decode("ascii").strip().split()
                if header != [row["oid"], row["type"], str(row["bytes"])]:
                    raise ValueError("provider header differs from reviewed metadata")
                data = source.read(row["bytes"])
                if len(data) != row["bytes"] or source.read(1) != b"\n":
                    raise ValueError("truncated provider object")
                accept(row, data, {"kind": "Git object database", "name": provider, "path": str(gitdir)})
            if source.read():
                raise ValueError("trailing unrequested provider object")
        for row in missing:
            if row["bytes"] is not None:
                continue
            fetched_row, receipt_name = fetched[row["oid"]]
            path = Path(fetched_row["path"])
            expected_parent = (Path("/private/tmp/chain-external-missing-blobs-20261114-v2/blobs")
                               if receipt_name == "first22" else BASE / "remaining-explicit-18-v1/blobs")
            if path != expected_parent / row["oid"]:
                raise ValueError("fetched source path outside reviewed provider")
            data = stable_read(path, fetched_row["bytes"], fetched_row["sha256"])
            accept(row, data, {"kind": "verified explicit blob read", "receipt": receipt_name,
                               "receipt_sha256": PINS[receipt_name][2], "path": str(path)})
        if sorted(records) != fixed_oids or sum(x["bytes"] for x in records.values()) != EXPECTED_RAW_BYTES:
            raise ValueError("complete capsule body roster mismatch")
        staging = OUT / "staging.git"
        run("init-private-bare", flags + ["init", "--bare", str(staging)], cap=4096)
        for kind in ("blob", "tree", "commit"):
            ordered = [oid for oid in fixed_oids if records[oid]["type"] == kind]
            paths = "".join(str(OUT / "raw-objects" / oid) + "\n" for oid in ordered).encode()
            stdout, stderr, _ = run(
                "stage-" + kind,
                flags + ["--git-dir=" + str(staging), "hash-object", "-w", "--no-filters", "-t", kind, "--stdin-paths"],
                paths, cap=len(ordered) * 41 + 1,
            )
            if stderr or stdout != "".join(oid + "\n" for oid in ordered).encode():
                raise ValueError("Git independently computed a different content address")
        capsule_oid_file = put(OUT / "capsule.oids", raw["oids"])
        stdout, stderr, _ = run(
            "pack-exact-940",
            flags + ["--git-dir=" + str(staging), "pack-objects", "--window=0", "--no-reuse-delta",
                     "--no-reuse-object", "--threads=1", str(OUT / "source-objects")],
            raw["oids"], timeout=120, cap=4096,
        )
        pack_id = stdout.decode("ascii").strip()
        if stderr or not re.fullmatch("[0-9a-f]{40}", pack_id):
            raise ValueError("unexpected pack result")
        pack = OUT / ("source-objects-" + pack_id + ".pack")
        idx = OUT / ("source-objects-" + pack_id + ".idx")
        pack_bytes = stable_read(pack)
        index_bytes = stable_read(idx)
        if pack_bytes[:4] != b"PACK" or struct.unpack(">II", pack_bytes[4:12]) != (2, 940):
            raise ValueError("pack header count/version mismatch")
        if len(pack_bytes) > EXPECTED_RAW_BYTES + 1000000:
            raise ValueError("unexpected packed byte growth")
        if hashlib.sha1(pack_bytes[:-20]).digest() != pack_bytes[-20:] or pack_bytes[-20:].hex() != pack_id:
            raise ValueError("pack trailer identity mismatch")
        verify, verify_err, _ = run("verify-pack", flags + ["verify-pack", "-v", str(idx)], timeout=120, cap=300000)
        if verify_err:
            raise ValueError("verify-pack stderr")
        seen = {}
        for line in verify.decode("ascii").splitlines():
            fields = line.split()
            if fields and re.fullmatch("[0-9a-f]{40}", fields[0]):
                if len(fields) != 5 or fields[1] not in EXPECTED_COUNTS:
                    raise ValueError("delta or unexpected pack representation")
                oid = fields[0]
                if oid in seen or oid not in records or fields[1] != records[oid]["type"] or int(fields[2]) != records[oid]["bytes"]:
                    raise ValueError("pack member differs from manifest")
                seen[oid] = {"packed_bytes": int(fields[3]), "offset": int(fields[4])}
        if sorted(seen) != fixed_oids:
            raise ValueError("pack contains missing or extra objects")
        refs, refs_err, refs_code = run("private-refs-after", flags + ["--git-dir=" + str(staging), "show-ref"], cap=1024, allowed=(1,))
        if refs or refs_err or refs_code != 1:
            raise ValueError("unexpected private ref")
        existing = []
        for line in raw["rog_presence"].decode("ascii").splitlines():
            fields = line.split()
            if len(fields) == 3:
                existing.append({"oid": fields[0], "type": fields[1], "bytes": int(fields[2])})
        if len(existing) != 2972 or len(existing) + len(records) != 3912:
            raise ValueError("source closure partition mismatch")
        manifest = {
            "schema": "trnm-external-evidence-source-object-capsule-v1",
            "status": "EXACT_940_NONDELTA_PACK_VERIFIED", "created_at": now(),
            "source_map": union["source_map"], "parent_edges_traversed": 0,
            "complete_parent_history": False, "full_history_bundle": False,
            "object_count": 940, "object_types": EXPECTED_COUNTS, "total_raw_bytes": EXPECTED_RAW_BYTES,
            "pack_compression_dependencies_self_contained": True, "thin_pack": False, "delta_objects": 0,
            "source_tree_content_requires_existing_rog_objects": True,
            "existing_required_count": 2972, "existing_required_raw_bytes": 500212866,
            "existing_required_objects": existing, "rog_observation_source": rog["source_before"],
            "capsule_oids": capsule_oid_file,
            "objects": [dict(records[oid], pack=seen[oid]) for oid in fixed_oids],
            "pack": {"path": str(pack), "bytes": len(pack_bytes), "sha256": sha(pack_bytes), "git_pack_sha1": pack_id},
            "index": {"path": str(idx), "bytes": len(index_bytes), "sha256": sha(index_bytes)},
            "inputs": {name: {"path": str(path), "bytes": size, "sha256": digest} for name, (path, size, digest) in PINS.items()},
            "no_shared_git_writes": True, "no_rog_import": True, "no_network_calls": True,
        }
        manifest_info = put(OUT / "manifest.json", (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode())
        readme = (
            "Exact historical source-object capsule\n\n"
            "Contains only the 940 OIDs missing in the recorded ROG object inventory. "
            "The non-delta pack has no external compression bases. The full 14-root source closure "
            "also requires the 2,972 already present objects listed in manifest.json. "
            "Parent commits outside this declared source closure are deliberately not included. "
            "This is not a complete-history bundle and creates no source branch or authorization.\n\n"
            "No ROG import has been performed. The original materializer and complete external lane "
            "must still validate the fixed source after root reviews and imports these objects.\n"
        ).encode()
        readme_info = put(OUT / "README.txt", readme)
        state.update(status="EXACT_940_NONDELTA_PACK_VERIFIED", manifest=manifest_info,
                     pack=manifest["pack"], index=manifest["index"], readme=readme_info,
                     object_count=940, total_raw_bytes=EXPECTED_RAW_BYTES,
                     content_addresses_verified=940, pack_members_verified=940, private_refs_empty=True)
    except Exception as error:
        state["status"] = "HOLD"
        state["errors"].append({"type": type(error).__name__, "message": str(error)})
    finally:
        state["finished_at"] = now()
        save()
    summary_raw = (OUT / "build-summary.json").read_bytes()
    print(json.dumps({"summary": {"path": str(OUT / "build-summary.json"), "bytes": len(summary_raw),
                                  "sha256": sha(summary_raw)}, "status": state["status"],
                      "manifest": state.get("manifest"), "pack": state.get("pack"),
                      "index": state.get("index"), "errors": state["errors"]}, indent=2), flush=True)
    return 0 if state["status"] == "EXACT_940_NONDELTA_PACK_VERIFIED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
