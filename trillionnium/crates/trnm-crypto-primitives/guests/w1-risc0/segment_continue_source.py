"""Frozen failed-run evidence and exact same-session continuation inputs.

These checks establish provenance, not STARK validity. The unchanged native
assembler must verify the entire 62-segment proof before receipt acceptance.
"""
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
POLICY = HERE / "segment-continuation.json"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXTRACTED = 16 * 1024 * 1024
MAX_EVIDENCE_FILES = 512
MAX_EVIDENCE_DIRECTORIES = 32
MAX_EVIDENCE_DEPTH = 4
MAX_EVIDENCE_PATH_BYTES = 256
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def path_under(root, name):
    rel = PurePosixPath(name)
    require(isinstance(name, str) and name and not rel.is_absolute()
            and ".." not in rel.parts and "\\" not in name
            and str(rel) == name, "unsafe relative path")
    path = root
    for part in rel.parts:
        path = path / part
        require(not path.is_symlink(), "symlink in retained inputs")
    return path


def checked_bytes(path, cap, expected=None, *, dir_fd=None, observed=None):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                          dir_fd=dir_fd), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= cap,
                "regular file / byte budget required")
        if observed is not None:
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (observed.st_dev, observed.st_ino, observed.st_size,
                        observed.st_mtime_ns, observed.st_ctime_ns), "directory entry changed before reading")
        data = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    require(len(data) <= cap and before.st_size == after.st_size == len(data)
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns, "input changed while reading")
    if expected is not None:
        require(set(expected) == {"bytes", "sha256"}
                and type(expected["bytes"]) is int
                and len(data) == expected["bytes"]
                and sha(data) == expected["sha256"], "retained file hash/size differs")
    return data


def bounded_file_index(directory):
    """Walk owned directory descriptors with all limits checked before a read.

    Metadata is provenance only. No inventory can qualify a segment proof.
    """
    result, counters = {}, {"files": 0, "directories": 0, "bytes": 0}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def visit(fd, prefix, depth):
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode), "real evidence directory required")
        counters["directories"] += 1
        require(counters["directories"] <= MAX_EVIDENCE_DIRECTORIES,
                "evidence directory count budget")
        with os.scandir(fd) as entries:
            for entry in entries:
                name = f"{prefix}/{entry.name}" if prefix else entry.name
                require(len(os.fsencode(name)) <= MAX_EVIDENCE_PATH_BYTES,
                        "evidence path byte budget")
                require(depth + 1 <= MAX_EVIDENCE_DEPTH, "evidence depth budget")
                item = entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(item.st_mode), "symlink in actual continuation evidence")
                if stat.S_ISDIR(item.st_mode):
                    child = os.open(entry.name, flags, dir_fd=fd)
                    try:
                        opened = os.fstat(child)
                        require((opened.st_dev, opened.st_ino) == (item.st_dev, item.st_ino),
                                "directory entry changed before traversal")
                        visit(child, name, depth + 1)
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(item.st_mode), "regular evidence file required")
                    counters["files"] += 1
                    require(counters["files"] <= MAX_EVIDENCE_FILES, "evidence file count budget")
                    require(0 <= item.st_size <= MAX_EVIDENCE_FILE_BYTES,
                            "evidence file byte budget")
                    require(counters["bytes"] + item.st_size <= MAX_EVIDENCE_BYTES,
                            "continuation evidence byte budget")
                    data = checked_bytes(entry.name, MAX_EVIDENCE_FILE_BYTES,
                                         dir_fd=fd, observed=item)
                    counters["bytes"] += len(data)
                    result[name] = {"bytes": len(data), "sha256": sha(data)}
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                "evidence directory changed during traversal")

    root = os.open(directory, flags)
    try:
        visit(root, "", 0)
    finally:
        os.close(root)
    return dict(sorted(result.items()))


def read(path, cap=1024 * 1024):
    return decode(checked_bytes(path, cap))


def write_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def write_json(path, value):
    write_bytes(path, (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode())


def check_policy(policy):
    require(set(policy) == {"schema", "origin", "archive_manifest", "unchanged_source_files",
        "session_sha256", "total_segments", "original_completed_indexes", "shards", "budgets",
        "complete_receipt_reuse", "partial_receipts_are_complete_proofs", "consensus_authority",
        "segment_asset_source", "fresh_execution_role"},
        "unknown continuation policy field")
    require(policy["schema"] == "pon-w1-frozen-session-continuation-policy-v2", "policy namespace")
    require(policy["segment_asset_source"] == "retained-original-byte-identical-session"
            and policy["fresh_execution_role"] == "independent-full-relation-cross-check",
            "original trace ownership differs")
    origin = policy["origin"]
    require(origin["repository"] == "TrillionniumFoundation/Trillionnium-Chain"
            and origin["source_sha"] == "5d957878ea82b09b555c713976f5157fde1089a0"
            and origin["source_tree"] == "aeba742e5523ef10136ce800ab217cc571f34f4a"
            and origin["run_id"] == 40511022475 and origin["run_attempt"] == 1
            and origin["job_id"] == 122212651078 and origin["artifact_id"] == 12743386213
            and origin["conclusion"] == "failure"
            and origin["archive_sha256"] == "d862b93d949612e6fc764d82622d507b208743bc8e6b6701dbf481802b040e8b",
            "this policy permits only the reviewed actual failed run")
    require(policy["total_segments"] == 62
            and policy["original_completed_indexes"] == list(range(26))
            and policy["shards"] == [{"id": 0, "indexes": list(range(26, 44))},
                                    {"id": 1, "indexes": list(range(44, 62))}],
            "only two fixed disjoint missing-segment shards are authorized")
    require(policy["budgets"] == {"workers_per_shard": 2, "rayon_threads_per_worker": 2,
        "segment_seconds": 300, "work_stop_seconds": 3500, "outer_phase_seconds": 3600,
        "new_fixed_shard_count": 2, "automatic_retry": False}, "changed continuation budget")
    for key in ["complete_receipt_reuse", "partial_receipts_are_complete_proofs", "consensus_authority"]:
        require(policy[key] is False, "partial continuation has no proof/consensus authority")


def load_policy(root=ROOT, policy_path=POLICY):
    policy = read(policy_path)
    check_policy(policy)
    pins = policy["unchanged_source_files"]
    require(len(pins) == 30, "complete original source pin set required")
    for name, expected in pins.items():
        checked_bytes(path_under(root, name), 2 * 1024 * 1024, expected)
    item = policy["archive_manifest"]
    require(set(item) == {"path", "bytes", "sha256"}, "archive manifest descriptor")
    manifest = decode(checked_bytes(path_under(root, item["path"]), 1024 * 1024,
                                   {"bytes": item["bytes"], "sha256": item["sha256"]}))
    return policy, manifest


def original_members(policy, manifest, root=ROOT):
    require(manifest["schema"] == "pon-w1-complete-original-artifact-v1"
            and manifest["archive_sha256"] == policy["origin"]["archive_sha256"]
            and manifest["archive_bytes"] == 8139466
            and manifest["uncompressed_bytes"] == 10934918
            and manifest["all_original_members_retained"] is True
            and len(manifest["parts"]) == 32 and len(manifest["members"]) == 315,
            "original complete artifact inventory changed")
    chunks, seen = [], set()
    for index, item in enumerate(manifest["parts"]):
        require(set(item) == {"path", "bytes", "sha256"}
                and item["path"].endswith(f"/part-{index:03d}.bin")
                and item["path"] not in seen, "archive part order/duplication")
        seen.add(item["path"])
        chunks.append(checked_bytes(path_under(root, item["path"]), 256 * 1024,
                                   {"bytes": item["bytes"], "sha256": item["sha256"]}))
    blob = b"".join(chunks)
    require(len(blob) == manifest["archive_bytes"] <= MAX_ARCHIVE
            and sha(blob) == manifest["archive_sha256"], "original ZIP bytes changed")
    result = {}
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        infos = archive.infolist()
        require(len(infos) == 315 and len({i.filename for i in infos}) == 315,
                "ZIP duplicate/missing member")
        require(sum(i.file_size for i in infos) == manifest["uncompressed_bytes"] <= MAX_EXTRACTED,
                "ZIP extraction byte budget")
        require(set(i.filename for i in infos) == set(manifest["members"]), "ZIP member inventory")
        for item in infos:
            path_under(Path("/nonexistent-retained-root"), item.filename)
            require(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16)
                    and item.file_size <= 8 * 1024 * 1024, "ZIP regular member/size")
            data = archive.read(item)
            expected = manifest["members"][item.filename]
            require(len(data) == expected["bytes"] and sha(data) == expected["sha256"],
                    "original ZIP member bytes differ")
            result[item.filename] = data
    check_original(policy, result)
    return result


def require_closed_phase(phase, success):
    require(phase.get("schema") == "pon-w1-actual-process-v2"
            and phase.get("child_reaped") is True and phase.get("owned_process_group_empty") is True
            and phase.get("subreaper_enabled") is True and phase.get("cleanup_errors") == [],
            "unclosed original process group")
    require(type(phase.get("returncode")) is int, "missing actual phase returncode")
    if success:
        require(phase["returncode"] == phase.get("child_returncode") == 0
                and phase.get("timed_out") is False and phase.get("leader_exited_before_group") is False,
                "phase did not succeed")
    for key in ["wall_seconds", "user_cpu_seconds", "system_cpu_seconds"]:
        value = phase.get(key)
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                "unavailable actual phase cost")
    if success:
        timeout = phase.get("timeout_seconds")
        require(type(timeout) in (int, float) and math.isfinite(timeout)
                and timeout > 0 and phase["wall_seconds"] <= timeout,
                "successful phase exceeded its original outer wall budget")


def check_original(policy, files):
    origin = policy["origin"]
    for name in ["source-before.json", "source-after.json"]:
        require(decode(files[name]) == origin["source_identity"], "original source identity changed")
    identity = origin["source_identity"]
    require(identity["tested_commit"] == origin["source_sha"]
            and identity["tested_tree"] == origin["source_tree"]
            and identity["tracked_worktree_verified"] is True, "original exact source unavailable")
    phase = decode(files["prove.process.json"])
    require_closed_phase(phase, False)
    require(phase["source_sha"] == origin["source_sha"] and phase["returncode"] == 1
            and phase["timeout_seconds"] == 3600 and phase["timed_out"] is False,
            "original failed outcome must remain failed")
    attempt = decode(files["segmented/attempt.json"])
    require(sorted(attempt["completed_segment_indexes"]) == policy["original_completed_indexes"]
            and attempt["real_composite_stark_verified"] is False
            and attempt["partial_receipts_are_complete_proofs"] is False
            and attempt["direct_children_missing_terminal"] == []
            and "TimeoutError" in attempt["error"] and "receipt.bin" not in files,
            "original partial outcome changed")
    index = decode(files["segmented-evidence-index.json"])
    require(index["phase"] == phase and index["source_sha"] == origin["source_sha"], "original index phase")
    expected_names = {name.removeprefix("segmented/") for name in files if name.startswith("segmented/")}
    require(set(index["files"]) == expected_names, "original segmented index coverage")
    for name, expected in index["files"].items():
        data = files["segmented/" + name]
        require(len(data) == expected["bytes"] and sha(data) == expected["sha256"], "original indexed bytes")
    require(sha(files["segmented/session/session.json"]) == policy["session_sha256"], "session identity")
    session = decode(files["segmented/session/session.json"])
    require(len(session["segments"]) == 62 and session["full_w1_guest_executed"] is True
            and session["user_cycles"] == 13364385 and session["segment_po2_limit"] == 18,
            "full original W1 session required")
    for i in range(26):
        check_receipt(i, session, files[f"segmented/receipts/segment-{i}.bin"],
                      decode(files[f"segmented/receipts/segment-{i}.json"]))
        terminal = decode(files[f"segmented/steps/segment-{i}.terminal.json"])
        require(terminal["source_sha"] == origin["source_sha"]
                and terminal["returncode"] == 0 and terminal["child_reaped"] is True,
                "original segment did not actually finish")


def check_receipt(index, session, data, report):
    item = session["segments"][index]
    require(report["schema"] == "pon-w1-real-segment-proof-v1"
            and report["index"] == item["index"] == index
            and report["po2"] == item["po2"] == 18
            and report["segment_sha256"] == item["sha256"]
            and report["receipt_bytes"] == len(data) <= 2 * 1024 * 1024
            and report["receipt_sha256"] == sha(data)
            and report["hashfn"] == "poseidon2" and report["real_segment_stark_verified"] is True,
            "missing/foreign segment proof record")
    for key in ["complete_w1_proof_verified", "dev_mode", "additional_grinding", "povw_requested", "consensus_authority"]:
        require(report[key] is False, "segment scope/profile differs")


def extract_original(files, destination):
    destination.mkdir()
    for name, data in files.items():
        write_bytes(path_under(destination, name), data)


def compare_fresh_inputs(files, elf, input_path):
    require(checked_bytes(elf, 64 * 1024 * 1024) == files["guest.bin"]
            and checked_bytes(input_path, 2 * 1024 * 1024) == files["input.bin"],
            "fresh image/input differ from the actual original session")
    require(checked_bytes(HERE / "backend-manifest.json", 1024 * 1024) == files["backend-manifest.json"],
            "fresh backend profile differs")


def compare_fresh_session(files, directory):
    """Historical exact-rerun diagnostic, deliberately retained unchanged.

    A new SDK execution contains fresh guest-start memory entropy. This check
    correctly refuses it; it cannot select inputs for partial-proof recovery.
    """
    old = decode(files["segmented/session/session.json"])
    fresh = read(directory / "session.json")
    require(type(fresh.get("execute_and_export_wall_ns")) is int
            and fresh["execute_and_export_wall_ns"] > 0, "fresh export measurement unavailable")
    without_time = lambda value: {k: v for k, v in value.items() if k != "execute_and_export_wall_ns"}
    require(without_time(old) == without_time(fresh), "fresh execution is not the same original session")
    for name, data in files.items():
        if name.startswith("segmented/session/") and not name.endswith("session.json"):
            relative = name.removeprefix("segmented/session/")
            require(checked_bytes(path_under(directory, relative), 32 * 1024 * 1024) == data,
                    "fresh exported segment/claim changed")
    expected = {name.removeprefix("segmented/session/") for name in files if name.startswith("segmented/session/")}
    require(set(bounded_file_index(directory)) == expected,
            "fresh session has an unreviewed file")
    return fresh


def checked_original_session(files, directory):
    """Only the byte-identical retained execution may supply proof segments."""
    expected = {name.removeprefix("segmented/session/"): data
                for name, data in files.items() if name.startswith("segmented/session/")}
    require(set(bounded_file_index(directory)) == set(expected),
            "original proof session has an unreviewed or missing file")
    for name, data in expected.items():
        require(checked_bytes(path_under(directory, name), 32 * 1024 * 1024) == data,
                "original proof session bytes changed")
    return decode(expected["session.json"])


def check_independent_execution(files, directory):
    """Cross-check the full relation, never authorize fresh trace/receipt reuse.

    RISC Zero 3.0.6 initializes MEMORY_IMAGE_ENTROPY through SYS_RANDOM. A new
    execution can have the same complete claim with different segment states.
    The actual fresh files must match their own hashes and every original
    invariant; proof generation separately consumes checked_original_session.
    """
    old = decode(files["segmented/session/session.json"])
    fresh = read(directory / "session.json")
    require(type(fresh.get("execute_and_export_wall_ns")) is int
            and fresh["execute_and_export_wall_ns"] > 0, "fresh export measurement unavailable")

    def invariants(value):
        result = {k: v for k, v in value.items() if k != "execute_and_export_wall_ns"}
        result["segments"] = [{k: v for k, v in item.items() if k != "sha256"}
                              for item in value["segments"]]
        return result

    require(invariants(old) == invariants(fresh),
            "independent execution changed a complete relation invariant")
    indexed = bounded_file_index(directory)
    expected = {name.removeprefix("segmented/session/") for name in files
                if name.startswith("segmented/session/")}
    require(set(indexed) == expected, "independent execution has an unreviewed file")
    for item, original in zip(fresh["segments"], old["segments"], strict=True):
        require(set(item) == set(original), "fresh segment fields differ")
        require(indexed[item["file"]] == {"bytes": item["bytes"], "sha256": item["sha256"]},
                "independent execution segment bytes/hash changed")
    require(checked_bytes(directory / "session.claim.bin", 16 * 1024)
            == files["segmented/session/session.claim.bin"],
            "independent execution complete claim changed")
    return fresh
