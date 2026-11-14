#!/usr/bin/env python3
"""Read exactly 40 reviewed historical blobs; no Git object/ref/source writes."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import time

BASE = Path("/private/tmp/chain-external-lane-readonly-review-20261114-v1")
INPUT = BASE / "rog-object-reuse-review-v1/missing-blob-40-provenance.json"
INPUT_SHA = "6817e87670b86144316a7b69565e6af6affa140281c96cec89ce2f460a6dd4dd"
ROSTER_SHA = "93819aea3db8ab5ff580751b1a19aae6c3d9b97adb44138a9343ae795101a9b0"
OUT = Path("/private/tmp/chain-external-missing-blobs-20261114-v2")
SOURCES = {
    "242906bae4f281c738c60adbd2c053d2ded1eae5",
    "30b85c34d1be404dcccd9f415286bb43b00f64ea",
    "50e158640d8278ca94dbecb6539dab96c6a9fb84",
}
SINGLE_BLOB_CAP = 4 * 1024 * 1024
TOTAL_BLOB_CAP = 32 * 1024 * 1024
SINGLE_JSON_CAP = 6 * 1024 * 1024
TOTAL_JSON_CAP = 48 * 1024 * 1024
STDERR_CAP = 65536
BATCH_SECONDS = 600
PER_READ_SECONDS = 60

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def read_input():
    s = INPUT.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size != 14188:
        raise ValueError("input must be the reviewed single-link regular file")
    with INPUT.open("rb") as handle:
        before = os.fstat(handle.fileno())
        raw = handle.read()
        after = os.fstat(handle.fileno())
    fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if fields(before) != fields(after) or sha256(raw) != INPUT_SHA:
        raise ValueError("input identity changed")
    data = json.loads(raw)
    objects = data["objects"]
    oids = [row["oid"] for row in objects]
    if len(objects) != 40 or oids != sorted(set(oids)):
        raise ValueError("reviewed roster count/order mismatch")
    if sha256("".join(oid + "\n" for oid in oids).encode()) != ROSTER_SHA:
        raise ValueError("reviewed OID list changed")
    for row in objects:
        if row["type"] != "blob" or row["bytes"] is not None or row["providers"]:
            raise ValueError("unexpected reviewed provider/type/size")
        if not row["declared_paths"] or any(x["source"] not in SOURCES for x in row["declared_paths"]):
            raise ValueError("blob is outside the three reviewed trees")
    return raw, objects

def write_new(path, data):
    with path.open("xb") as handle:
        handle.write(data)
    return {"path": str(path), "bytes": len(data), "sha256": sha256(data)}

def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE", "0") not in ("", "0"):
        raise ValueError("optimization forbidden")
    raw, objects = read_input()
    if os.path.lexists(OUT):
        raise ValueError("create-only output already exists")
    os.umask(0o077)
    OUT.mkdir(mode=0o700)
    (OUT / "raw").mkdir()
    (OUT / "blobs").mkdir()
    write_new(OUT / "reviewed-input.original.json", raw)
    executable = shutil.which("gh")
    if executable is None:
        raise ValueError("gh unavailable; no fallback installed")
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("GIT_TRACE") or name in ("GIT_CURL_VERBOSE", "GH_DEBUG"):
            env.pop(name)
    env.update(GH_PROMPT_DISABLED="1", PYTHONDONTWRITEBYTECODE="1", PYTHONOPTIMIZE="0")
    state = {
        "schema": "trnm-exact-historical-blob-read-v2",
        "status": "RUNNING",
        "started_at": now(),
        "input_sha256": INPUT_SHA,
        "roster_sha256": ROSTER_SHA,
        "requested_count": 40,
        "single_blob_cap": SINGLE_BLOB_CAP,
        "total_blob_cap": TOTAL_BLOB_CAP,
        "single_json_cap": SINGLE_JSON_CAP,
        "total_json_cap": TOTAL_JSON_CAP,
        "batch_seconds": BATCH_SECONDS,
        "per_read_seconds": PER_READ_SECONDS,
        "steps": [],
        "objects": [],
        "errors": [],
        "decoded_total_bytes": 0,
        "json_total_bytes": 0,
        "remote_writes": False,
        "git_object_ref_source_writes": False,
        "automatic_retry": False,
        "implicit_lazy_fetch": False,
        "lane_run": False,
    }
    def save():
        (OUT / "summary.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    save()
    deadline = time.monotonic() + BATCH_SECONDS
    try:
        for row in objects:
            if time.monotonic() >= deadline:
                raise TimeoutError("whole read budget exhausted before next request")
            oid = row["oid"]
            endpoint = "repos/TrillionniumFoundation/Trillionnium-Chain/git/blobs/" + oid
            argv = [executable, "api", "--hostname", "github.com", "--method", "GET", endpoint]
            stdout_path = OUT / "raw" / (oid + ".stdout")
            stderr_path = OUT / "raw" / (oid + ".stderr")
            begin = time.monotonic()
            process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, start_new_session=True,
            )
            step = {
                "oid": oid, "argv": argv,
                "url": "https://api.github.com/" + endpoint,
                "owned_pid": process.pid, "owned_pgid": process.pid,
                "started_at": now(), "stdout_path": str(stdout_path), "stderr_path": str(stderr_path),
            }
            state["active_owned_process"] = {"pid": process.pid, "pgid": process.pid, "oid": oid}
            save()
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            counts = {"stdout": 0, "stderr": 0}
            limits = {"stdout": min(SINGLE_JSON_CAP, TOTAL_JSON_CAP - state["json_total_bytes"]), "stderr": STDERR_CAP}
            stopped = None
            end = min(deadline, begin + PER_READ_SECONDS)
            handles = {"stdout": stdout_path.open("xb"), "stderr": stderr_path.open("xb")}
            try:
                while selector.get_map():
                    if time.monotonic() >= end:
                        stopped = "timeout"
                        break
                    for key, _ in selector.select(min(0.25, max(0.001, end - time.monotonic()))):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        name = key.data
                        remaining = limits[name] - counts[name]
                        if len(data) > remaining:
                            handles[name].write(data[:max(remaining, 0)])
                            counts[name] += max(remaining, 0)
                            stopped = name + "_byte_cap"
                            break
                        handles[name].write(data)
                        counts[name] += len(data)
                    if stopped:
                        break
                if stopped:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                    stopped = stopped or "owned_process_not_terminal"
            finally:
                selector.close()
                for handle in handles.values():
                    handle.close()
                process.stdout.close()
                process.stderr.close()
            out, err = stdout_path.read_bytes(), stderr_path.read_bytes()
            state["json_total_bytes"] += len(out)
            step.update(
                exit=process.returncode if stopped is None else (124 if stopped == "timeout" else 125),
                actual_process_exit=process.returncode,
                stopped_reason=stopped, capture_complete=stopped is None,
                elapsed_seconds=time.monotonic() - begin, finished_at=now(),
                stdout_bytes=len(out), stdout_sha256=sha256(out),
                stderr_bytes=len(err), stderr_sha256=sha256(err),
            )
            state["steps"].append(step)
            state["active_owned_process"] = None
            save()
            print(json.dumps({"completed_requests": len(state["steps"]), "oid": oid, "exit": step["exit"]}), flush=True)
            if stopped or process.returncode != 0:
                raise RuntimeError("one explicit blob read failed; no retry")
            value = json.loads(out)
            if value.get("sha") != oid or value.get("encoding") != "base64":
                raise ValueError("API object identity or encoding mismatch")
            size = value.get("size")
            if type(size) is not int or not 0 <= size <= SINGLE_BLOB_CAP:
                raise ValueError("API blob size exceeds bound")
            if state["decoded_total_bytes"] + size > TOTAL_BLOB_CAP:
                raise ValueError("aggregate decoded blob bound exceeded")
            encoded = value.get("content")
            if not isinstance(encoded, str):
                raise ValueError("missing encoded blob")
            blob = base64.b64decode(encoded.replace("\n", ""), validate=True)
            if len(blob) != size:
                raise ValueError("decoded size mismatch")
            address = hashlib.sha1(b"blob " + str(size).encode() + b"\0" + blob).hexdigest()
            if address != oid:
                raise ValueError("Git content address mismatch")
            info = write_new(OUT / "blobs" / oid, blob)
            state["decoded_total_bytes"] += len(blob)
            state["objects"].append({
                "oid": oid, "type": "blob", "bytes": size, "sha256": info["sha256"],
                "path": info["path"], "provider": step["url"],
                "git_sha1_verified": True, "declared_paths": row["declared_paths"],
                "raw_response_sha256": step["stdout_sha256"],
            })
            save()
        state["status"] = "ALL_40_CONTENT_ADDRESSES_VERIFIED"
    except Exception as error:
        state["status"] = "HOLD"
        state["errors"].append({"type": type(error).__name__, "message": str(error)})
    finally:
        state["finished_at"] = now()
        save()
    output = (OUT / "summary.json").read_bytes()
    print(json.dumps({
        "summary": str(OUT / "summary.json"), "bytes": len(output), "sha256": sha256(output),
        "status": state["status"], "verified_count": len(state["objects"]),
        "decoded_total_bytes": state["decoded_total_bytes"], "json_total_bytes": state["json_total_bytes"],
    }, indent=2), flush=True)
    return 0 if state["status"] == "ALL_40_CONTENT_ADDRESSES_VERIFIED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
