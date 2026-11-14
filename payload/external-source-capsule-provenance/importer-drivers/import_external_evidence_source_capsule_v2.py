#!/usr/bin/env python3
"""Root-only, one-shot import of a reviewed historical source-object capsule."""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import time

BASE = Path("/home/qian-qi/chain-final-consolidation-20261114-root")
SOURCE = BASE / "source"
INPUT_DIR = BASE / "external-evidence-object-capsule-input-v1"
PACK_NAME = "source-objects-c58cdc5b6d8ceb69d2550e44e1e25f0154c91371.pack"
PACK_BYTES = 2487542
PACK_SHA256 = "c0d9caf64494bec9d99f3b80a82fbcb0f36c1972aa0efd7da8741d3ba421865c"
PACK_SHA1 = "c58cdc5b6d8ceb69d2550e44e1e25f0154c91371"
MANIFEST_BYTES = 1439371
MANIFEST_SHA256 = "ac4f97386c73d337d3059df746ed1650bc75e0697aa7a12f28589e86817c02e7"
CAPSULE_OIDS_SHA256 = "99ab7fe2da03663e272c5b8781299fbe3db9c2f8edc04e0e1a611c7395e49035"
CLOSURE_OIDS_SHA256 = "780ab6e86e2124105704c0f6dea3b81d88a2a241c09de53ad6efc6a23fab002d"
CAPSULE_RAW_BYTES = 9204616
CLOSURE_RAW_BYTES = 509417482
HEX40 = re.compile(r"[0-9a-f]{40}")

def sha(data):
    return hashlib.sha256(data).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stable_bytes(path, cap, expected_size=None, expected_sha=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or first.st_size > cap:
            raise ValueError("unsafe or excessive regular-file input")
        chunks, total = [], 0
        while True:
            block = os.read(fd, min(262144, cap + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > cap:
                raise ValueError("file exceeded cap")
        last = os.fstat(fd)
    finally:
        os.close(fd)
    fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if fields(first) != fields(last) or total != first.st_size:
        raise ValueError("file changed while reading")
    data = b"".join(chunks)
    if expected_size is not None and len(data) != expected_size:
        raise ValueError("fixed byte count mismatch")
    if expected_sha is not None and sha(data) != expected_sha:
        raise ValueError("fixed SHA256 mismatch")
    return data

def fingerprint(path):
    if not os.path.lexists(path):
        return {"exists": False}
    data = stable_bytes(path, 8388608)
    return {"exists": True, "bytes": len(data), "sha256": sha(data)}

def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--pack-path", required=True, type=Path)
    parser.add_argument("--manifest-path", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    for value in (args.expected_head, args.expected_tree):
        if not HEX40.fullmatch(value):
            parser.error("expected head/tree must be full lowercase SHA1 values")
    if args.pack_path != INPUT_DIR / PACK_NAME or args.manifest_path != INPUT_DIR / "manifest.json":
        parser.error("input paths must be the reviewed fixed files in the root input directory")
    if args.evidence_dir.parent != BASE or not re.fullmatch(r"external-evidence-object-import-[A-Za-z0-9._-]+", args.evidence_dir.name):
        parser.error("evidence directory must be a new direct child of BASE with the import prefix")
    return args

def main():
    args = parse_args()
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE", "0") not in ("", "0"):
        raise ValueError("optimized execution forbidden")
    if BASE.resolve() != BASE or SOURCE.resolve() != SOURCE or INPUT_DIR.resolve() != INPUT_DIR:
        raise ValueError("unexpected symlinked root/input/source directory")
    if not SOURCE.is_dir() or not INPUT_DIR.is_dir() or os.path.lexists(args.evidence_dir):
        raise ValueError("source/input missing or create-only evidence directory exists")
    os.umask(0o077)
    ev = args.evidence_dir
    ev.mkdir(mode=0o700)
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("GIT_TRACE") or name in ("GIT_CURL_VERBOSE", "GIT_ALLOW_PROTOCOL"):
            env.pop(name)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                 "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_SHALLOW_FILE",
                 "GIT_NAMESPACE", "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE"):
        if name in env:
            raise ValueError("unexpected Git override " + name)
    env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0",
               GIT_TERMINAL_PROMPT="0", GIT_PROTOCOL_FROM_USER="0",
               GIT_TRACE2="0", GIT_TRACE2_EVENT="0", GIT_TRACE2_PERF="0",
               PYTHONDONTWRITEBYTECODE="1", PYTHONOPTIMIZE="0")
    git = ["git", "--no-replace-objects", "-C", str(SOURCE),
           "-c", "protocol.allow=never", "-c", "protocol.http.allow=never",
           "-c", "protocol.https.allow=never", "-c", "protocol.ssh.allow=never",
           "-c", "protocol.file.allow=never"]
    state = {
        "schema": "trnm-root-external-source-capsule-import-v2", "status": "HOLD",
        "started_at": now(), "expected_head": args.expected_head, "expected_tree": args.expected_tree,
        "source": str(SOURCE), "steps": [], "errors": [], "import_attempted": False,
        "import_exit": None, "source_before": None, "source_after": None,
        "source_unchanged": False, "raw_object_readback_complete": False,
        "fourteen_tree_closure_verified": False, "automatic_retry": False,
        "network_calls": 0, "ref_or_worktree_mutations_requested": False,
        "configuration_mutations_requested": False, "lane_run": False,
        "driver_path": str(Path(__file__).resolve()),
        "driver_sha256": sha(stable_bytes(Path(__file__), 1048576)),
    }
    def save():
        (ev / "summary.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    def put(name, data):
        path = ev / name
        with path.open("xb") as handle:
            handle.write(data)
        return {"path": str(path), "bytes": len(data), "sha256": sha(data)}
    def run(label, argv, data=None, timeout=60, cap=4194304, allowed=(0,), enforce=True):
        begin = time.monotonic()
        process = subprocess.Popen(argv, cwd=SOURCE, env=env, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        row = {"label": label, "argv": argv, "cwd": str(SOURCE), "owned_pid": process.pid,
               "owned_pgid": process.pid, "started_at": now(), "timeout_seconds": timeout}
        state["active_owned_process"] = {"label": label, "pid": process.pid, "pgid": process.pid}
        save()
        timed_out = False
        try:
            out, err = process.communicate(data, timeout=timeout)
            code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = process.communicate(timeout=10)
            code = 124
        row.update(exit=code, actual_process_exit=process.returncode, timeout=timed_out,
                   finished_at=now(), elapsed_seconds=time.monotonic() - begin,
                   stdout=put(label + ".stdout", out), stderr=put(label + ".stderr", err))
        state["steps"].append(row)
        state["active_owned_process"] = None
        save()
        if enforce and (code not in allowed or len(out) > cap or len(err) > 65536):
            raise ValueError("bounded command failed: " + label)
        return code, out, err
    def git_read(label, argv, **kwargs):
        return run(label, git + argv, **kwargs)
    def boolean_config(label, key):
        code, out, err = git_read(label, ["config", "--type=bool", "--get", key], allowed=(0, 1), cap=1024)
        if err or (code == 0 and out not in (b"true\n", b"false\n")) or (code == 1 and out):
            raise ValueError("invalid effective Boolean setting " + key)
        return None if code == 1 else out == b"true\n"
    def snapshot(label):
        values = {}
        for field, argv in (
            ("head", ["rev-parse", "--verify", "HEAD"]),
            ("tree", ["rev-parse", "--verify", "HEAD^{tree}"]),
            ("git_dir", ["rev-parse", "--absolute-git-dir"]),
            ("common_dir", ["rev-parse", "--path-format=absolute", "--git-common-dir"]),
            ("object_format", ["rev-parse", "--show-object-format"]),
            ("shallow", ["rev-parse", "--is-shallow-repository"]),
        ):
            _, out, err = git_read(label + "-" + field, argv, cap=8192)
            if err:
                raise ValueError("snapshot stderr: " + field)
            values[field] = out.decode("utf-8").strip()
        _, status, err = git_read(label + "-status", ["status", "--porcelain=v1"], cap=8388608)
        if err:
            raise ValueError("status read failed")
        _, refs, err = git_read(label + "-refs", ["for-each-ref", "--format=%(refname) %(objectname)"], cap=8388608)
        if err:
            raise ValueError("refs read failed")
        values.update(clean=not status, status_sha256=sha(status), refs_sha256=sha(refs), refs_bytes=len(refs))
        values["replacement_refs"] = [x for x in refs.decode().splitlines() if x.startswith("refs/replace/")]
        common, workgit = Path(values["common_dir"]), Path(values["git_dir"])
        for path in (common, workgit):
            if not path.is_absolute() or path.resolve() != path or not path.is_relative_to(BASE):
                raise ValueError("Git directory outside the authorized root")
        _, objects_raw, err = git_read(label + "-objects-path", ["rev-parse", "--path-format=absolute", "--git-path", "objects"], cap=8192)
        objects = Path(objects_raw.decode().strip())
        if err or objects.resolve() != objects or not objects.is_relative_to(BASE):
            raise ValueError("unexpected object database location")
        values["objects_dir"] = str(objects)
        values["local_metadata"] = {
            "config": fingerprint(common / "config"),
            "config_worktree": fingerprint(workgit / "config.worktree"),
            "shallow": fingerprint(common / "shallow"),
            "alternates": fingerprint(objects / "info/alternates"),
            "http_alternates": fingerprint(objects / "info/http-alternates"),
            "grafts": fingerprint(common / "info/grafts"),
        }
        code, names, err = git_read(label + "-promisor-keys",
            ["config", "--name-only", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$"],
            allowed=(0, 1), cap=65536)
        if err or (code == 1 and names):
            raise ValueError("incomplete partial-clone setting read")
        partial = {}
        for key in names.decode().splitlines():
            partial[key] = boolean_config(label + "-promisor-" + str(len(partial)), key) if key.lower().endswith(".promisor") else "partial-clone-setting-present"
        values["partial_clone_settings"] = partial
        packdir = objects / "pack"
        packdir_stat = packdir.lstat()
        if (not stat.S_ISDIR(packdir_stat.st_mode) or packdir.resolve() != packdir
                or not packdir.is_relative_to(BASE)):
            raise ValueError("unsafe pack directory")
        values["pack_directory_identity"] = {
            "path": str(packdir), "device": packdir_stat.st_dev, "inode": packdir_stat.st_ino,
        }
        values["promisor_markers"] = sorted(p.name for p in packdir.iterdir() if p.name.endswith(".promisor")) if packdir.is_dir() else []
        values["fsck_policy"] = {
            "fetch": boolean_config(label + "-fetch-fsck", "fetch.fsckObjects"),
            "transfer": boolean_config(label + "-transfer-fsck", "transfer.fsckObjects"),
            "receive": boolean_config(label + "-receive-fsck", "receive.fsckObjects"),
        }
        if values["head"] != args.expected_head or values["tree"] != args.expected_tree or not values["clean"]:
            raise ValueError("source head/tree/clean fence failed")
        if values["object_format"] != "sha1" or values["shallow"] not in ("true", "false"):
            raise ValueError("unsupported object format/shallow observation")
        if values["replacement_refs"] or values["promisor_markers"] or any(v is not False for v in partial.values()):
            raise ValueError("replacement or promisor state present")
        if values["local_metadata"]["grafts"].get("bytes", 0):
            raise ValueError("nonempty graft replacement state")
        return values
    def stream_all_objects(expected):
        ordered = sorted(expected)
        raw = "".join(oid + "\n" for oid in ordered).encode()
        input_info = put("readback-3912.oids", raw)
        if len(ordered) != 3912 or sha(raw) != CLOSURE_OIDS_SHA256:
            raise ValueError("readback object scope changed")
        protocol_cap = sum(len(f"{oid} {expected[oid]['type']} {expected[oid]['bytes']}\n".encode())
                           + expected[oid]["bytes"] + 1 for oid in ordered)
        stdin_file = open(input_info["path"], "rb")
        argv = git + ["cat-file", "--batch"]
        process = subprocess.Popen(argv, cwd=SOURCE, env=env, stdin=stdin_file,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffer = bytearray()
        errors = bytearray()
        transcript_sha = hashlib.sha256()
        transcript_bytes = 0
        deadline = time.monotonic() + 600
        begin = time.monotonic()
        rows, commits = [], {}
        failure = None
        def fill():
            nonlocal transcript_bytes
            if time.monotonic() >= deadline:
                raise TimeoutError("fixed object readback exceeded 600 seconds")
            if not selector.get_map():
                return False
            for key, _ in selector.select(min(0.25, max(0.001, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    transcript_bytes += len(chunk)
                    if transcript_bytes > protocol_cap:
                        raise ValueError("readback exceeded exact protocol byte bound")
                    transcript_sha.update(chunk)
                    buffer.extend(chunk)
                else:
                    errors.extend(chunk)
                    if len(errors) > 65536:
                        raise ValueError("readback stderr cap exceeded")
            return True
        def take(count):
            while not buffer:
                if not fill():
                    raise ValueError("truncated readback stream")
            amount = min(count, len(buffer))
            data = bytes(buffer[:amount])
            del buffer[:amount]
            return data
        try:
            for oid in ordered:
                header = bytearray()
                while not header.endswith(b"\n"):
                    header.extend(take(1))
                    if len(header) > 160:
                        raise ValueError("readback header exceeds bound")
                meta = expected[oid]
                if header.decode("ascii").split() != [oid, meta["type"], str(meta["bytes"])]:
                    raise ValueError("missing or different readback object " + oid)
                oid_hash = hashlib.sha1(meta["type"].encode() + b" " + str(meta["bytes"]).encode() + b"\0")
                body_sha = hashlib.sha256()
                remaining = meta["bytes"]
                body = bytearray() if meta["type"] == "commit" else None
                while remaining:
                    data = take(min(65536, remaining))
                    remaining -= len(data)
                    oid_hash.update(data)
                    body_sha.update(data)
                    if body is not None:
                        body.extend(data)
                if take(1) != b"\n" or oid_hash.hexdigest() != oid:
                    raise ValueError("readback Git content address mismatch " + oid)
                if "sha256" in meta and body_sha.hexdigest() != meta["sha256"]:
                    raise ValueError("capsule object SHA256 readback mismatch " + oid)
                rows.append({"oid": oid, "type": meta["type"], "bytes": meta["bytes"],
                             "sha256": body_sha.hexdigest(), "git_sha1_verified": True})
                if body is not None:
                    commits[oid] = bytes(body)
            while selector.get_map():
                fill()
                if buffer:
                    raise ValueError("unrequested trailing object bytes")
            process.wait(timeout=5)
            if process.returncode != 0 or errors or transcript_bytes != protocol_cap:
                raise ValueError("readback child/stream incomplete")
        except Exception as error:
            failure = {"type": type(error).__name__, "message": str(error)}
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        finally:
            selector.close()
            stdin_file.close()
            process.stdout.close()
            process.stderr.close()
            record = {"label": "stream-readback-exact-3912", "argv": argv, "cwd": str(SOURCE),
                      "owned_pid": process.pid, "owned_pgid": process.pid,
                      "exit": process.returncode, "elapsed_seconds": time.monotonic() - begin,
                      "stdout_bytes": transcript_bytes, "stdout_sha256": transcript_sha.hexdigest(),
                      "stdout_retained": False, "stdout_retention_reason": "each exact body was streamed and hashed; 509 MB is not duplicated",
                      "stderr": put("readback-3912.stderr", bytes(errors)),
                      "verified_count": len(rows), "failure": failure}
            state["steps"].append(record)
            state["readback_objects"] = put("readback-3912.json", (json.dumps(rows, sort_keys=True, indent=2) + "\n").encode())
            save()
        if failure:
            raise ValueError("exact object readback failed: " + failure["message"])
        state["raw_object_readback_complete"] = True
        return commits

    manifest = None
    capsule = {}
    expected = {}
    before = None
    save()
    try:
        _, version, _ = git_read("git-version", ["--version"], cap=8192)
        state["git_version"] = version.decode().strip()
        before = snapshot("source-before")
        state["source_before"] = before
        save()
        run("project-preflight", ["bash", "scripts/project-preflight.sh"], cap=1048576)
        after_preflight = snapshot("source-after-preflight")
        if after_preflight != before:
            raise ValueError("preflight changed a fenced source state")
        policy = before["fsck_policy"]
        effective_fsck = policy["fetch"] if policy["fetch"] is not None else policy["transfer"]
        state["effective_fetch_transfer_fsck"] = bool(effective_fsck)
        if effective_fsck:
            raise ValueError("configured fetch/transfer fsck policy requires a separate parent-connectivity review; no policy override performed")
        manifest_raw = stable_bytes(args.manifest_path, MANIFEST_BYTES, MANIFEST_BYTES, MANIFEST_SHA256)
        pack_raw = stable_bytes(args.pack_path, PACK_BYTES, PACK_BYTES, PACK_SHA256)
        manifest = json.loads(manifest_raw)
        if manifest["schema"] != "trnm-external-evidence-source-object-capsule-v1" or manifest["status"] != "EXACT_940_NONDELTA_PACK_VERIFIED":
            raise ValueError("wrong reviewed capsule schema/status")
        capsule = {row["oid"]: row for row in manifest["objects"]}
        existing = {row["oid"]: row for row in manifest["existing_required_objects"]}
        if len(capsule) != 940 or len(existing) != 2972 or set(capsule) & set(existing):
            raise ValueError("capsule/existing object partition invalid")
        expected = dict(existing)
        expected.update(capsule)
        for oid, row in expected.items():
            if not HEX40.fullmatch(oid) or row["type"] not in ("commit", "tree", "blob") or type(row["bytes"]) is not int or row["bytes"] < 0:
                raise ValueError("invalid reviewed object metadata")
        if sum(r["bytes"] for r in capsule.values()) != CAPSULE_RAW_BYTES or sum(r["bytes"] for r in expected.values()) != CLOSURE_RAW_BYTES:
            raise ValueError("reviewed raw byte totals differ")
        capsule_oids = "".join(oid + "\n" for oid in sorted(capsule)).encode()
        closure_oids = "".join(oid + "\n" for oid in sorted(expected)).encode()
        if sha(capsule_oids) != CAPSULE_OIDS_SHA256 or sha(closure_oids) != CLOSURE_OIDS_SHA256:
            raise ValueError("reviewed object rosters differ")
        put("manifest.original.json", manifest_raw)
        validated = put("validated.pack", pack_raw)
        put("capsule-940.oids", capsule_oids)
        put("closure-3912.oids", closure_oids)
        if pack_raw[:4] != b"PACK" or struct.unpack(">II", pack_raw[4:12]) != (2, 940):
            raise ValueError("pack header differs")
        if hashlib.sha1(pack_raw[:-20]).digest() != pack_raw[-20:] or pack_raw[-20:].hex() != PACK_SHA1:
            raise ValueError("pack trailer identity differs")
        _, meta_raw, err = git_read("existing-object-presence", ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                                    data=closure_oids, cap=400000)
        lines = meta_raw.decode("ascii").splitlines()
        if err or len(lines) != 3912:
            raise ValueError("incomplete pre-import object presence check")
        already_present, missing = [], []
        for oid, line in zip(sorted(expected), lines):
            fields = line.split()
            if fields == [oid, "missing"]:
                missing.append(oid)
                if oid not in capsule:
                    raise ValueError("required existing object is absent; capsule cannot repair " + oid)
            elif fields == [oid, expected[oid]["type"], str(expected[oid]["bytes"])]:
                already_present.append(oid)
            else:
                raise ValueError("existing immutable object metadata differs " + oid)
        state["object_presence_before"] = {
            "present_count": len(already_present), "missing_count": len(missing),
            "capsule_objects_already_present": sum(oid in capsule for oid in already_present),
            "new_objects_are_permitted": True,
        }
        idx = ev / "validated.idx"
        _, out, err = git_read("rebuild-index", ["index-pack", "--max-input-size=" + str(PACK_BYTES),
                                               "-o", str(idx), validated["path"]], timeout=120, cap=8192)
        if err or out.decode("ascii").strip() != PACK_SHA1:
            raise ValueError("independent index rebuild identity differs")
        _, listing, err = git_read("verify-independent-pack", ["verify-pack", "-v", str(idx)], timeout=120, cap=300000)
        members = {}
        if err:
            raise ValueError("independent verify-pack reported stderr")
        for line in listing.decode("ascii").splitlines():
            fields = line.split()
            if fields and HEX40.fullmatch(fields[0]):
                if len(fields) != 5 or fields[0] in members or fields[0] not in capsule:
                    raise ValueError("delta, duplicate or foreign pack member")
                meta = capsule[fields[0]]
                if fields[1] != meta["type"] or int(fields[2]) != meta["bytes"]:
                    raise ValueError("pack member type/size differs")
                members[fields[0]] = True
        if set(members) != set(capsule):
            raise ValueError("independent pack object roster incomplete")
        state["rebuilt_index"] = {"path": str(idx), **fingerprint(idx)}
        state["independent_940_members_verified"] = True
        if snapshot("source-before-import") != before:
            raise ValueError("source/config/refs fence changed before import")
        stable_bytes(args.pack_path, PACK_BYTES, PACK_BYTES, PACK_SHA256)
        stable_bytes(args.manifest_path, MANIFEST_BYTES, MANIFEST_BYTES, MANIFEST_SHA256)
        import_bytes = stable_bytes(ev / "validated.pack", PACK_BYTES, PACK_BYTES, PACK_SHA256)
        state["import_attempted"] = True
        save()
        code, out, err = git_read("import-index-pack", ["index-pack", "--stdin", "--max-input-size=" + str(PACK_BYTES)],
                                  data=import_bytes, timeout=120, cap=65536, enforce=False)
        state["import_exit"] = code
        state["import_stdout_identity_valid"] = out == ("pack\t" + PACK_SHA1 + "\n").encode()
        state["import_stderr_empty"] = not err
        save()
        if code != 0 or not state["import_stdout_identity_valid"] or err:
            raise ValueError("one import command did not finish with the exact normal result")
    except Exception as error:
        state["errors"].append({"phase": "prepare_or_import", "type": type(error).__name__, "message": str(error)})
    finally:
        if state["import_attempted"] and expected:
            try:
                commits = stream_all_objects(expected)
                roots = manifest["source_map"]
                if len(roots) != 14:
                    raise ValueError("root count mismatch")
                union = set()
                for commit, tree in sorted(roots.items()):
                    body = commits.get(commit)
                    if body is None or not body.startswith(("tree " + tree + "\n").encode()) or b"\n\n" not in body:
                        raise ValueError("declared commit/tree mapping differs")
                    union.update((commit, tree))
                    _, listing, err = git_read("root-tree-" + commit[:12], ["ls-tree", "-r", "-t", "-z", tree], cap=2097152)
                    if err or not listing.endswith(b"\0"):
                        raise ValueError("root recursive tree read incomplete")
                    for entry in listing[:-1].split(b"\0"):
                        descriptor, path = entry.split(b"\t", 1)
                        mode, kind, oid = descriptor.decode("ascii").split()
                        if not path or mode == "160000" or oid not in expected or kind != expected[oid]["type"]:
                            raise ValueError("unexpected tree closure member")
                        union.add(oid)
                if union != set(expected):
                    raise ValueError("14 root trees do not produce the exact 3912-object closure")
                state["fourteen_tree_closure_verified"] = True
            except Exception as error:
                state["errors"].append({"phase": "readback", "type": type(error).__name__, "message": str(error)})
        try:
            state["source_after"] = snapshot("source-after")
            state["source_unchanged"] = before is not None and state["source_after"] == before
        except Exception as error:
            state["errors"].append({"phase": "source_after", "type": type(error).__name__, "message": str(error)})
        if (not state["errors"] and state["import_exit"] == 0 and state["source_unchanged"]
                and state["raw_object_readback_complete"] and state["fourteen_tree_closure_verified"]):
            state["status"] = "IMPORTED_AND_VERIFIED"
        state["finished_at"] = now()
        save()
    final = (ev / "summary.json").read_bytes()
    print(json.dumps({"summary": str(ev / "summary.json"), "bytes": len(final), "sha256": sha(final),
                      "status": state["status"], "import_attempted": state["import_attempted"],
                      "import_exit": state["import_exit"], "source_unchanged": state["source_unchanged"],
                      "errors": state["errors"]}, indent=2), flush=True)
    return 0 if state["status"] == "IMPORTED_AND_VERIFIED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
