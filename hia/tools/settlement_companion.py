"""Publish safe, bounded Settlement CI observations without reopening the full archive.

This exporter has no qualification authority. It reads exact fixed paths only
and writes one projected JSON document. The optional dispatch checkpoint reads
the call index, not captured byte streams, requests or environment records.
All input identities refer to the unchanged originals.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat

from hia.platform.service_settlement.qualification.integrity_roster import ROSTER


MAX_RECEIPT = 2 * 1024 * 1024
MAX_CURSOR_ROWS = 4096
MAX_CURSOR_ROW = 512
MAX_OUTPUT = 32 * 1024
STAGE_NAMES = ("preflight", "build", "runtime-loader", "native", "allocator-build",
               "allocator-loader", "allocator", "integrity")
STATUS = ("INCOMPLETE", "PASS", "FAIL")
CI_OUTCOMES = ("success", "failure", "cancelled", "skipped")
PINS = ("observations/source-before.json", "observations/source-after.json")
BINDING = "observations/binding.json"
CURSOR = "qualification/native/fixture-progress.jsonl"
CALL_INDEX = "qualification/native/calls.jsonl"
DISPATCH_FIXTURE = 319
MAX_CALL_ROWS = 32768
MAX_CALL_ROW = 128 * 1024
MAX_CALL_BYTES = 128 * 1024 * 1024
# Only synchronous PublicEngine.call timers enter the cursor total.
DISPATCH_METHODS = (
    "bytes_view", "consumption_receipt_id", "consumption_rollup_id",
    "engine_apply", "engine_clone", "engine_history_count", "engine_new",
    "engine_replay", "engine_state", "engine_state_copy", "engine_state_root",
    "engine_trust", "engine_validate_execution", "error_code", "error_display",
    "error_message", "operation_id", "owned_clone", "owned_drop", "owned_kind",
    "settlement_policy_hash",
)
DERIVED_CALL_RECORDS = frozenset({
    "bytes_view:view", "engine_history_count:scalar", "engine_state:view",
    "engine_state_root:view", "engine_trust:view", "error_code:scalar",
    "error_message:view",
})
INTEGRITY = "qualification/integrity/report.json"
INTEGRITY_SCHEMA = "trnm.hia.service-settlement-engine.integrity.v1"
ROOT_STATUS = {
    "qualification/report.json": "trnm.hia.service-settlement-engine.qualification.v1",
    "independent-readback/report.json": "trnm.hia.service-settlement-engine.readback.v1",
}
EXPECTED_NATIVE_SECONDS = 240
EXPECTED_CLEANUP_SECONDS = 3
DIRENT_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class Refused(ValueError):
    pass


def path_parts(path, *, absolute):
    parsed = PurePosixPath(path)
    if (parsed.is_absolute() != absolute or parsed.as_posix() != path
            or ".." in parsed.parts or "//" in path or path in ("/", ".")):
        raise Refused("unsafe-path")
    return parsed.parts[1:] if absolute else parsed.parts


@contextmanager
def descend(base, parts):
    current = os.dup(base)
    try:
        for part in parts:
            child = os.open(part, DIRENT_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        yield current
    finally:
        os.close(current)


@contextmanager
def safe_directory(path):
    parts = path_parts(path, absolute=True)
    base = os.open("/", DIRENT_FLAGS)
    try:
        with descend(base, parts) as fd:
            yield fd
    finally:
        os.close(base)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def signature(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink


def read_member(root, path, limit):
    parts = path_parts(path, absolute=False)
    with descend(root, parts[:-1]) as parent:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise Refused("unsafe-path")
            if not 0 <= before.st_size <= limit:
                raise Refused("over-byte-limit")
            with os.fdopen(fd, "rb", closefd=False) as file:
                raw = file.read(limit + 1)
            if len(raw) > limit:
                raise Refused("over-byte-limit")
            if (len(raw) != before.st_size or signature(before) != signature(os.fstat(fd))
                    or signature(before) != signature(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))):
                raise Refused("changed-while-reading")
            return raw
        finally:
            os.close(fd)


def strict_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refused("invalid-json")
            value[key] = item
        return value
    def constant(_):
        raise Refused("invalid-json")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)
    if not isinstance(value, dict):
        raise Refused("invalid-json")
    return value


def schema(row, name):
    if row.get("schema") != name:
        raise Refused("invalid-schema")


def scalar(value, *, nullable=False, signed=False):
    if value is None and nullable:
        return value
    if type(value) is not int or not (-(1 << 63) if signed else 0) <= value < 1 << 64:
        raise Refused("invalid-fields")
    return value


def pick_bool(row, key):
    value = row[key]
    if type(value) is not bool:
        raise Refused("invalid-fields")
    return value


def pick_status(row):
    value = row["status"]
    if value not in STATUS:
        raise Refused("invalid-fields")
    return value


def source_pin(row, head):
    schema(row, "trnm-ci-source-v1")
    if (row.get("kind") != "head" or row.get("tested_commit") != head
            or row.get("candidate") != head or not pick_bool(row, "tracked_worktree_verified")
            or not re.fullmatch(r"[0-9a-f]{40}", row["tested_tree"])):
        raise Refused("invalid-source-bind")
    return {"head": head, "tree": row["tested_tree"],
            "tracked_entries": scalar(row["tracked_entries"]),
            "tracked_bytes": scalar(row["tracked_bytes"])}


def binding_record(row, head, run_id, run_attempt):
    schema(row, "trnm.hia.additional-owner-ci-binding.v1")
    if (row["component"] != "settlement-engine" or row["head"] != head
            or row["run_id"] != run_id or row["run_attempt"] != run_attempt
            or row["status"] != "PASS"
            or not re.fullmatch(r"[0-9a-f]{40}", row["tree"])
            or not re.fullmatch(r"[0-9a-f]{64}", row["source_set_sha256"])):
        raise Refused("invalid-source-bind")
    return {key: row[key] for key in ("status", "head", "tree", "source_set_sha256")}


def driver_receipt(row, name):
    if row["name"] != name:
        raise Refused("invalid-fields")
    return {"stage": name, "started": pick_bool(row, "started"),
            "exit_code": scalar(row["exit_code"], nullable=True, signed=True),
            "elapsed_ns": scalar(row["elapsed_ns"]), "has_failure": row["failure"] is not None}


def process_record(row):
    schema(row, "trnm.hia.additional-owner-process.v1")
    names = [stage["name"] for stage in row["stages"]]
    if row["component"] != "settlement-engine" or names not in ([], ["qualification"], ["qualification", "readback"]):
        raise Refused("invalid-fields")
    return {"status": pick_status(row), "stages": [driver_receipt(stage, name)
                                                  for name, stage in zip(names, row["stages"])]}


def invocation_result(row):
    return {"exit_code": scalar(row["exit_code"], nullable=True, signed=True),
            "started_monotonic_ns": scalar(row["started_monotonic_ns"]),
            "completed_monotonic_ns": scalar(row["completed_monotonic_ns"])}


def stage_receipt(row, *, fixed_budget=False):
    schema(row, "trnm.service-settlement.owned-process.v1")
    result = {"status": pick_status(row), "started": pick_bool(row, "started"),
              "exit_code": scalar(row["exit_code"], nullable=True, signed=True),
              "timed_out": pick_bool(row, "timed_out"),
              "cleanup_complete": pick_bool(row, "cleanup_complete"),
              "execution_deadline_seconds": scalar(row["execution_deadline_seconds"]),
              "cleanup_deadline_seconds": scalar(row["cleanup_deadline_seconds"]),
              "original_deadline_monotonic_ns": scalar(row["original_deadline_monotonic_ns"])}
    if (result["cleanup_deadline_seconds"] != EXPECTED_CLEANUP_SECONDS
            or not 0 < result["execution_deadline_seconds"] <= EXPECTED_NATIVE_SECONDS
            or (fixed_budget and result["execution_deadline_seconds"] != EXPECTED_NATIVE_SECONDS)):
        raise Refused("invalid-deadline")
    for key in ("elapsed_ns", "observed_completed_monotonic_ns"):
        if key in row:
            result[key] = scalar(row[key])
    if "collector_exit_code" in row:
        result["collector_exit_code"] = scalar(row["collector_exit_code"], signed=True)
    return result


def root_status(row, schema_name):
    schema(row, schema_name)
    result = {"status": pick_status(row), "source_inputs_stable": pick_bool(row, "source_inputs_stable")}
    for key in ("finalized", "qualification_deadline_exceeded"):
        if key in row:
            result[key] = pick_bool(row, key)
    if "elapsed_ns" in row:
        result["elapsed_ns"] = scalar(row["elapsed_ns"])
    return result


def integrity_report(row):
    """Project the producer report, not the independent reader's decision."""
    status = pick_status(row)
    cases = row["cases"]
    if (status not in ("PASS", "FAIL") or not isinstance(cases, list)
            or not 0 <= len(cases) <= len(ROSTER)):
        raise Refused("invalid-integrity-report")
    # The legacy FAIL envelope has no schema; its cases are only an ordered
    # completed prefix. Do not guess a verdict for the first missing control.
    if status == "PASS":
        schema(row, INTEGRITY_SCHEMA)
        if (row["roster"] != ROSTER or len(cases) != len(ROSTER)
                or any(scalar(row[k]) != wanted for k, wanted in
                       (("passed", len(ROSTER)), ("failed", 0), ("not_run", 0)))):
            raise Refused("invalid-integrity-roster")
    elif "schema" in row:
        schema(row, INTEGRITY_SCHEMA)
    results = []
    for name, case in zip(ROSTER, cases):
        if (not isinstance(case, dict) or case.get("name") != name
                or case.get("result") not in ("PASS", "REJECTED")):
            raise Refused("invalid-integrity-roster")
        results.append(case["result"])
    cursor = len(results)
    return {
        "reported_status": status,
        "registered_controls": len(ROSTER),
        "results_in_roster_order": results,
        "unrecorded_controls": len(ROSTER) - cursor,
        "last_recorded_control": None if not cursor else ROSTER[cursor - 1],
        "first_unrecorded_control": None if cursor == len(ROSTER) else ROSTER[cursor],
        "establishes_reader_success": False,
    }


def progress_record(raw):
    # Complete lines alone advance the observed cursor; a process can die mid-write.
    lines = raw.split(b"\n")
    tail = lines.pop()
    if len(tail) > MAX_CURSOR_ROW or len(lines) > MAX_CURSOR_ROWS:
        raise Refused("invalid-cursor")
    known = ("stage_start", "fixture_start", "operation_start", "fixture_result",
             "fixture_cleanup", "fixture_done", "capture_finalize", "stage_done")
    base = {"phase", "wall_ns", "thread_cpu_ns"}
    counts = {"completed_fixtures", "completed_operations", "capture_records", "public_dispatch_wall_ns"}
    cursor = None
    for line in lines:
        if len(line) + 1 > MAX_CURSOR_ROW:
            raise Refused("invalid-cursor")
        row = strict_json(line)
        phase = row.get("phase")
        if phase not in known:
            raise Refused("invalid-cursor")
        keys = set(base)
        if phase != "stage_start":
            keys |= counts
        if phase.startswith("fixture_") or phase == "operation_start":
            keys.add("fixture_ordinal")
        if phase == "operation_start":
            keys |= {"operation_ordinal", "opcode"}
        if set(row) != keys:
            raise Refused("invalid-cursor")
        projected = {"phase": phase, **{key: scalar(row[key]) for key in keys - {"phase"}}}
        if ((phase == "stage_start") != (cursor is None)
                or (cursor is not None and (cursor["phase"] == "stage_done"
                    or projected["wall_ns"] < cursor["wall_ns"]
                    or projected["thread_cpu_ns"] < cursor["thread_cpu_ns"]))):
            raise Refused("invalid-cursor")
        cursor = projected
    return {"complete_rows": len(lines), "trailing_fragment_bytes": len(tail),
            "last_complete_row": cursor}


def dispatch_boundary(raw):
    # progress_record has independently validated this exact file's row shapes
    # and clocks. Require the complete ordered fixture prefix as well.
    phase, fixture, operations = "fixture_start", 1, 0
    counts = (0, 0)
    for line in raw.split(b"\n")[1:-1]:
        row = strict_json(line)
        current = row["phase"]
        observed = (row["capture_records"], row["public_dispatch_wall_ns"])
        if (row.get("fixture_ordinal") != fixture
                or row["completed_fixtures"] != fixture - (current != "fixture_done")
                or row["completed_operations"] != operations
                or any(now < last for now, last in zip(observed, counts))):
            raise Refused("invalid-dispatch-boundary")
        counts = observed
        if current == "operation_start" and phase == "operations":
            ordinal += 1
            if row["operation_ordinal"] != ordinal:
                raise Refused("invalid-dispatch-boundary")
            operations += 1
        elif current == "fixture_result" and phase == "operations":
            phase = "fixture_cleanup"
        elif current != phase:
            raise Refused("invalid-dispatch-boundary")
        elif current == "fixture_start":
            phase, ordinal = "operations", 0
        elif current == "fixture_cleanup":
            phase = "fixture_done"
        elif current == "fixture_done":
            if fixture == DISPATCH_FIXTURE:
                if (not 0 < counts[0] <= MAX_CALL_ROWS
                        or not 0 < counts[1] <= row["wall_ns"]):
                    raise Refused("invalid-dispatch-boundary")
                return row
            phase = "fixture_start"
            fixture += 1
    raise Refused("checkpoint-not-reached")


def dispatch_prefix(root, boundary):
    parts = path_parts(CALL_INDEX, absolute=False)
    rows = {method: {"calls": 0, "wall_ns": 0} for method in DISPATCH_METHODS}
    digest, size, elapsed = hashlib.sha256(), 0, 0
    with descend(root, parts[:-1]) as parent:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        with os.fdopen(fd, "rb") as file:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise Refused("unsafe-path")
            if not 0 <= before.st_size <= MAX_CALL_BYTES:
                raise Refused("over-byte-limit")
            for ordinal in range(boundary["capture_records"]):
                line = file.readline(MAX_CALL_ROW + 1)
                size += len(line)
                if len(line) > MAX_CALL_ROW or size > MAX_CALL_BYTES:
                    raise Refused("over-byte-limit")
                if not line.endswith(b"\n"):
                    raise Refused("incomplete-call-prefix")
                digest.update(line)
                row = strict_json(line)
                if scalar(row["ordinal"]) != ordinal:
                    raise Refused("invalid-call-ordinal")
                method = row["function"]
                if method in DERIVED_CALL_RECORDS:
                    if "native_call" in row or "elapsed_ns" in row:
                        raise Refused("invalid-call-record")
                    continue
                if row.get("native_call") is not True:
                    raise Refused("invalid-call-record")
                scalar(row["status"])
                cost = scalar(row["elapsed_ns"])
                if method == "private_proportional_fee":
                    continue
                if method == "owned_drop" and "owner" in row:
                    # Non-null drop bypasses PublicEngine.call.
                    if "owners" in row or scalar(row["owner"]) == 0:
                        raise Refused("invalid-call-record")
                    continue
                if method not in rows or not isinstance(row.get("owners"), list) or "owner" in row:
                    raise Refused("invalid-call-record")
                elapsed += cost
                if elapsed > boundary["public_dispatch_wall_ns"]:
                    raise Refused("dispatch-total-mismatch")
                rows[method]["calls"] += 1
                rows[method]["wall_ns"] += cost
            if (signature(before) != signature(os.fstat(fd))
                    or signature(before) != signature(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))):
                raise Refused("changed-while-reading")
    if elapsed != boundary["public_dispatch_wall_ns"]:
        raise Refused("dispatch-total-mismatch")
    return rows, {"bytes": size, "sha256": digest.hexdigest()}


def observe_dispatch(root, observations, source_after):
    cursor = observations[CURSOR]
    if cursor["availability"] != "observed":
        return {"availability": cursor["availability"]}
    if (source_after != "success" or any(observations[path]["availability"] != "observed" for path in PINS)
            or observations[PINS[0]]["projection"] != observations[PINS[1]]["projection"]):
        return {"availability": "source-unbound"}
    try:
        raw = read_member(root, CURSOR, MAX_CURSOR_ROWS * MAX_CURSOR_ROW)
        if identity(raw) != cursor["original"]:
            raise Refused("changed-while-reading")
        boundary = dispatch_boundary(raw)
        del raw
        rows, prefix = dispatch_prefix(root, boundary)
        if identity(read_member(root, CURSOR, MAX_CURSOR_ROWS * MAX_CURSOR_ROW)) != cursor["original"]:
            raise Refused("changed-while-reading")
    except ERRORS as error:
        return {"availability": error_state(error)}
    return {"availability": "observed", "establishes_execution_success": False,
            "boundary": boundary, "cursor": cursor["original"], "call_index_prefix": prefix,
            "public_methods": rows}


def error_state(error):
    if isinstance(error, Refused):
        return str(error)
    if isinstance(error, OSError):
        if error.errno == errno.ENOENT:
            return "missing"
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            return "unsafe-path"
        return "unreadable"
    # Never include exception text, paths, original keys or original bytes.
    return "invalid-json-or-fields"


ERRORS = (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError)


def observe(root, path, projector, *, is_cursor=False):
    try:
        limit = MAX_CURSOR_ROWS * MAX_CURSOR_ROW if is_cursor else MAX_RECEIPT
        raw = read_member(root, path, limit)
    except ERRORS as exc:
        return {"availability": error_state(exc)}
    original = identity(raw)
    try:
        row = projector(raw if is_cursor else strict_json(raw))
    except ERRORS as exc:
        return {"availability": error_state(exc), "original": original}
    return {"availability": "observed", "original": original, "projection": row}


def export(root_path, head, run_id, run_attempt, outcomes, job_status):
    if not re.fullmatch(r"[0-9a-f]{40}", head) or any(
            not re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run_id, run_attempt)):
        raise Refused("invalid-run-identity")
    if (any(outcome not in (*CI_OUTCOMES, "") for outcome in outcomes)
            or job_status not in ("success", "failure", "cancelled")):
        raise Refused("invalid-step-outcome")
    entries = {name: lambda row: source_pin(row, head) for name in PINS}
    entries[BINDING] = lambda row: binding_record(row, head, run_id, run_attempt)
    entries["observations/process.json"] = process_record
    entries.update({"observations/" + name + ".receipt.json":
                    lambda row, name=name: driver_receipt(row, name)
                    for name in ("qualification", "readback")})
    entries.update({"qualification/" + name + "-invocation-result.json": invocation_result
                    for name in ("original", "generator")})
    entries.update({"qualification/stages/" + name + "/receipt.json":
                    lambda row, name=name: stage_receipt(row, fixed_budget=name in ("native", "integrity"))
                    for name in STAGE_NAMES})
    entries.update({name: lambda row, expected=expected: root_status(row, expected)
                    for name, expected in ROOT_STATUS.items()})
    entries[CURSOR] = progress_record
    entries[INTEGRITY] = integrity_report
    try:
        with safe_directory(root_path) as root:
            observations = {name: observe(root, name, projector, is_cursor=name == CURSOR)
                            for name, projector in entries.items()}
            checkpoint = observe_dispatch(root, observations, outcomes[1])
    except ERRORS as exc:
        observations = {name: {"availability": error_state(exc)} for name in entries}
        checkpoint = {"availability": error_state(exc)}
    control = {"component": "settlement-engine", "head": head, "run_id": run_id, "run_attempt": run_attempt,
               "source_after_step": outcomes[1], "execution_step": outcomes[0], "binding_step": outcomes[2],
               "job_status_at_collection": job_status}
    control = {key: value if value != "" else None for key, value in control.items()}
    return {"schema": "trnm.hia.settlement-ci-companion.v1", "workflow": control,
            "qualifies_execution": False, "substitutes_full_original_archive": False,
            "observations": observations, "dispatch_checkpoint": checkpoint}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "output-dir", "head", "run-id", "run-attempt", "execution-outcome",
                 "source-after-outcome", "binding-outcome", "job-status"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = export(args.root, args.head, args.run_id, args.run_attempt,
                    (args.execution_outcome, args.source_after_outcome, args.binding_outcome), args.job_status)
    raw = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    if len(raw) > MAX_OUTPUT:
        raise Refused("companion-over-byte-limit")
    with safe_directory(args.output_dir) as output:
        with os.fdopen(os.open("summary.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                              | os.O_CLOEXEC, 0o600, dir_fd=output), "wb") as stream:
            stream.write(raw)


if __name__ == "__main__":
    main()
