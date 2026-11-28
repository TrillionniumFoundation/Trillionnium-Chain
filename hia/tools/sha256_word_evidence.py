"""Read the three exact SHA word captures without executing their images.

The general component job retains these files in addition to its ordinary
six-file envelope.  Every source, compiler input, native build, byte observation
and supervision record is joined to that same envelope before acceptance.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re

from hia.tools import qualify
from hia.tools.component_partition import canonical, need, same
from hia.platform.pq_auth.readback import process_receipt

PREFIX = "hia-observations/sha256-word-boundaries"
LABELS = ("complete-440", "child-deadline-control", "observer-deadline-control")
FILES = frozenset((
    "manifest.json", "compiler-input.hepta", "fixture.hepta", "production.hepta",
    "module.so", "native-compiler", "native_support.py", "observations.json",
    "receipt.json", "request.json", "stderr.raw", "stdout.raw", "supervision.json",
    "supervision.py", "test.py", "toolchain.lock.json", "toolchain.py", "worker.py",
))
SOURCES = {
    "production.hepta": "hia/src/crypto/sha256_stream.hepta",
    "test.py": "hia/tests/test_sha256_words.py",
    "native_support.py": "hia/tests/native_support.py",
    "supervision.py": "hia/platform/pq_auth/qualification/supervision.py",
    "toolchain.py": "hia/tools/toolchain.py",
    "toolchain.lock.json": "hia/toolchain.lock.json",
}
OBSERVATION_SCHEMA = "trnm.hia.sha256-word-boundary-observations.v2"
OWNER = SOURCES["test.py"]
CLAIMS = {"direct_machine_code": True, "self_hosted": True,
          "python_emitter_used": False, "fallback_used": False,
          "external_linker_used": True, "whole_native_delivery_qualified": False}


def artifact_files():
    return {PREFIX + "/" + label + "/" + name for label in LABELS for name in FILES}


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def document(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "Duplicate SHA evidence JSON field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    # This also refuses finite-looking exponent tokens that decode to infinity.
    canonical(value)
    return value


def clock(value):
    need(type(value) in (int, float) and math.isfinite(value) and value >= 0,
         "Invalid SHA observation clock")
    return value


def expected_answer(case):
    before = bytes((i * 73 + 19) & 255 for i in range(case["extent"]))
    after = bytearray(before)
    offset = case["offset"]
    fits = offset <= len(before) and 8 <= len(before) - offset
    output = b"\xa5" * 8
    if case["mode"] == 1 and offset < len(before):
        count = min(8, len(before) - offset)
        after[offset:offset + count] = case["value"].to_bytes(8, "little")[:count]
    outcome = {"status": "trapped", "signal": 4}
    if fits:
        outcome = {"status": "returned", "exit_code": 0}
        output = bytes(8) if case["mode"] else before[offset:offset + 8]
    return {**case, **outcome, "input_unchanged": True, "guards_unchanged": True,
            "output_hex": output.hex(), "work_before_hex": before.hex(),
            "work_after_hex": bytes(after).hex()}


def validate_process(value, label, worker):
    limit = 1 if label == "observer-deadline-control" else 30
    need(type(value) is dict and type(value.get("execution_limit_seconds")) is int
         and type(value.get("cleanup_limit_seconds")) in (int, float)
         and type(value.get("exit_code")) is int,
         "SHA process limits or exit status have invalid types")
    subreaper = value.get("subreaper")
    need(type(subreaper) is dict and set(subreaper) == {"active", "previous"}
         and type(subreaper["active"]) is int and subreaper["active"] == 1
         and type(subreaper["previous"]) is int and subreaper["previous"] in (0, 1),
         "SHA process subreaper observation is incomplete")
    argv = value.get("argv")
    need(type(argv) is list and len(argv) == 6 and type(argv[0]) is str
         and Path(argv[0]).is_absolute()
         and argv[1:] == ["-I", "-S", "-B", "-c", worker],
         "SHA observer command or exact worker changed")
    cwd = value.get("cwd")
    need(type(cwd) is str and Path(cwd).is_absolute()
         and value.get("environment_overridden") is False,
         "SHA observer environment or working directory changed")
    process_receipt(value, argv, cwd, limit, success=label == "complete-440")
    need(value.get("pid") is not None and value.get("launch_error") is None
         and value.get("execution_error") is None
         and all(value.get(key) is True for key in
                 ("cleanup_complete", "streams_complete", "direct_child_reaped", "group_absent"))
         and value["cleanup_seconds"] <= 3 and value["seconds"] <= limit + 3,
         "SHA observer cleanup is incomplete or exceeded its sole deadline")
    if label == "complete-440":
        need(value["adopted_reaped"] == [], "Unexpected native orphan in complete SHA run")
        return
    attempts = value["killpg_attempts"]
    need(len(attempts) == 1 and attempts[0]["errno"] == 0,
         "SHA deadline control omitted its one actual successful group kill")
    reaped = value["adopted_reaped"]
    need(len(reaped) == 1 and reaped[0]["exit_code"] == -9
         and os.waitstatus_to_exitcode(reaped[0]["wait_status"]) == -9,
         "SHA native child was not actually observed reaped after SIGKILL")
    if label == "child-deadline-control":
        need(value["outcome"] == "descendants-outlived-leader" and value["exit_code"] == 1
             and value["timed_out"] is False and value["descendants_outlived_leader"] is True
             and 2 <= value["execution_seconds"] <= 30,
             "SHA native child deadline was replaced by an outer failure")
    else:
        need(value["outcome"] == "timeout" and value["exit_code"] == -9
             and value["timed_out"] is True and value["descendants_outlived_leader"] is False
             and value["execution_finished_monotonic"] >= value["execution_deadline_monotonic"],
             "SHA observer deadline did not actually terminate its group")


def validate_events(raw, cases, label, artifact_sha256, supervision, progress):
    events = [document(line) for line in raw.splitlines()]
    need(raw.endswith(b"\n") and events, "Incomplete SHA observer raw stream")
    observed = progress(raw, cases)
    need(observed["parse_errors"] == [], "Malformed SHA progress stream")
    ready = {"event": "ready", "artifact_sha256": artifact_sha256, "cases": 440,
             "dumpable": 0, "child_cpu_limit_seconds": 1, "child_wall_limit_seconds": 2}
    need(same(observed["ready"], ready) and same(events[0], ready),
         "SHA runtime identity, dumpability or child budget differs")
    count = 440 if label == "complete-440" else 7
    need(len(observed["cases"]) == count and len(observed["states"]) == 440,
         "SHA complete or interrupted case roster differs")
    prior = supervision["started_monotonic"]
    for index, state in enumerate(observed["states"]):
        need(state["index"] == index and same(state["case"], cases[index]),
             "SHA progress case identity differs")
        if index >= count + (label != "complete-440"):
            need(set(state) == {"index", "case", "state"} and state["state"] == "not-started",
                 "SHA interrupted progress lost or executed a later case")
            continue
        started = state.get("started")
        need(type(started) is dict and set(started) ==
             {"event", "index", "pid", "started_monotonic", "deadline_monotonic"}
             and started["event"] == "started" and type(started["index"]) is int
             and started["index"] == index and type(started["pid"]) is int and started["pid"] > 1,
             "Unbound SHA child start")
        first = clock(started["started_monotonic"])
        need(prior <= first <= supervision["execution_finished_monotonic"]
             and clock(started["deadline_monotonic"]) == first + 2,
             "SHA child execution deadline changed")
        if index < count:
            completed = state.get("completed")
            need(state["state"] == "completed" and type(completed) is dict
                 and set(completed) == {"event", "index", "pid", "seconds", "answer"}
                 and completed["event"] == "completed" and type(completed["index"]) is int
                 and completed["index"] == index and completed["pid"] == started["pid"],
                 "Unbound SHA child completion")
            elapsed = clock(completed["seconds"])
            need(elapsed < 2 and first + elapsed <= supervision["execution_finished_monotonic"]
                 and same(completed["answer"], expected_answer(cases[index]))
                 and same(observed["cases"][index], completed["answer"]),
                 "SHA output, partial write, trap, guard or actual child time differs")
            prior = first + elapsed
        else:
            need(supervision["adopted_reaped"][0]["pid"] == started["pid"],
                 "SHA cleanup reaped a different native child")
            if label == "child-deadline-control":
                timeout = state.get("timeout")
                need(state["state"] == "child-timeout" and type(timeout) is dict
                     and set(timeout) == {"event", "index", "pid", "seconds"}
                     and timeout["event"] == "child-timeout" and type(timeout["index"]) is int
                     and timeout["index"] == 7 and timeout["pid"] == started["pid"]
                     and clock(timeout["seconds"]) >= 2
                     and first + timeout["seconds"] <= supervision["execution_finished_monotonic"],
                     "SHA child timeout event is missing or unbound")
            else:
                need(state["state"] == "started-unfinished" and "timeout" not in state,
                     "SHA observer timeout was turned into a completed child")
    if label == "complete-440":
        finish = {"event": "finished", "artifact_sha256": artifact_sha256,
                  "completed": 440, "host_compiler_modules_loaded": []}
        need(len(events) == 882 and same(observed["finished"], finish) and same(events[-1], finish),
             "SHA full run has no exact completion or loaded a hosted compiler")
    else:
        need(observed["finished"] is None and len(events) == (17 if label == "child-deadline-control" else 16),
             "SHA interrupted run was promoted or contains extra events")
    return observed


def validate(raw_files, value, sources, compiler, root):
    """Validate immutable captured bytes already fenced by the bundle reader."""
    from hia.tests import test_sha256_words as words

    need(Path(words.__file__).resolve() == root / OWNER, "Foreign SHA fixture owner imported")
    current = {name: qualify._read_bound(root / path, sources.get(path)) for name, path in SOURCES.items()}
    need(current["test.py"] == Path(words.__file__).read_bytes(), "SHA fixture owner changed")
    cases = words.native_cases()
    need(len(cases) == 440, "Current SHA word roster changed")
    functions = list(re.finditer(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", current["production.hepta"]))
    owned = {m.group(1).decode(): m.group(0) for m in functions}
    need(len(owned) == len(functions), "Ambiguous SHA production function ownership")
    composed = words.ENTRY.encode().rstrip() + b"\n" + b"".join(
        owned[name].rstrip() + b"\n" for name in ("tr_read", "tr_get", "tr_put"))
    header = b"hia-asm.v1 hepta.hia.program.v8 sha_word_boundary\n"
    need(composed.startswith(header), "Unexpected SHA fixture module")
    wire = b"hia-asm.v1 hepta.hia.program.v8 selfhost_elf\n" + composed[len(header):]
    manifest_source = json.dumps({"schema": "trnm.hia.component-includes.v1", "includes": {
        "src/words.hepta": [{"source": "src/crypto/sha256_stream.hepta", "functions": ["tr_read", "tr_get", "tr_put"]}]}}).encode()
    input_bytes = {"src/words.hepta": words.ENTRY.encode(), "components.json": manifest_source,
                   "src/crypto/sha256_stream.hepta": current["production.hepta"]}
    expected_inputs = [{"path": path, "sha256": identity(raw)["sha256"]} for path, raw in input_bytes.items()]
    builds = [build for build in value["builds"] if build.get("generated_fixture", {}).get("owner") == OWNER]
    need(len(builds) == 3, "Exactly three actual SHA fixture builds are required")
    for build in builds:
        qualify.validate_build_provenance(build, sources)
        need(build.get("source") is None and build.get("exports") == ["f0"]
             and same(build.get("claims"), CLAIMS)
             and same(build["chain_migration"]["inputs"], expected_inputs),
             "SHA build is not the exact generated production-helper fixture")
        need(same(build["generated_fixture"]["inputs"],
                  [{**row, "utf8": input_bytes[row["path"]].decode()} for row in expected_inputs]),
             "SHA generated fixture input bytes differ")
    lock = document(current["toolchain.lock.json"])
    observations, captured = {}, {}
    for label in LABELS:
        files = {name: raw_files[PREFIX + "/" + label + "/" + name] for name in FILES}
        manifest = document(files["manifest.json"])
        need(set(manifest) == {"schema", "cases", "exit_code", "source_unchanged", "files"}
             and manifest["schema"] == "trnm.hia.sha256-word-boundary-capture.v2"
             and type(manifest["cases"]) is int and manifest["cases"] == 440
             and manifest["source_unchanged"] is True
             and type(manifest["files"]) is dict and set(manifest["files"]) == FILES - {"manifest.json"},
             "SHA capture manifest is incomplete or has extra members")
        for name in FILES - {"manifest.json"}:
            need(same(manifest["files"][name], identity(files[name])), "SHA retained member bytes differ: " + name)
        need(all(files[name] == raw for name, raw in current.items())
             and files["fixture.hepta"] == words.ENTRY.encode() and files["worker.py"] == words.WORKER.encode()
             and files["compiler-input.hepta"] == wire
             and identity(files["native-compiler"])["sha256"] == compiler["compiler_sha256"],
             "SHA current source, compiler, fixture or actual compiler input differs")
        receipt = document(files["receipt.json"])
        image = identity(files["module.so"])
        need(receipt.get("schema") == "trnm.hia.selfhost-build.v1" and receipt.get("ok") is True
             and receipt.get("status") == "native_emitted_not_executed" and receipt.get("kind") == "shared"
             and receipt.get("exports") == ["f0"] and same(receipt.get("claims"), CLAIMS)
             and receipt.get("compiler_sha256") == compiler["compiler_sha256"]
             and receipt.get("compiler_wire_sha256") == identity(wire)["sha256"]
             and receipt.get("artifact_sha256") == image["sha256"] and type(receipt.get("artifact_bytes")) is int
             and receipt["artifact_bytes"] == image["bytes"]
             and receipt.get("borrowed_entry_profile") == "legacy-f0-private-buffers"
             and receipt.get("output_profile_selection") == "selfhost_elf",
             "SHA native compiler receipt or artifact differs")
        migration = receipt.get("chain_migration", {})
        need(migration.get("toolchain_repository") == lock["repository"]
             and migration.get("toolchain_revision") == lock["revision"]
             and migration.get("backend") == "selfhost" and migration.get("hosted_build_driver") is True
             and migration.get("whole_chain_native") is False
             and migration.get("source_sha256") == identity(words.ENTRY.encode())["sha256"]
             and migration.get("composed_source_sha256") == identity(composed)["sha256"]
             and same(migration.get("inputs"), expected_inputs)
             and any(same(build["chain_migration"], migration)
                     and build["artifact_sha256"] == image["sha256"]
                     and build["object_sha256"] == receipt.get("object_sha256")
                     and build["compiler_sha256"] == receipt["compiler_sha256"] for build in builds),
             "SHA capture is absent from the actual component build receipts")
        request = document(files["request.json"])
        fault = None if label == "complete-440" else {
            "mode": "child-pause" if label == "child-deadline-control" else "observer-and-child-pause", "index": 7}
        expected = {"library": receipt.get("output"), "sha256": image["sha256"], "cases": cases}
        if fault is not None:
            expected["fault"] = fault
        need(type(expected["library"]) is str and Path(expected["library"]).is_absolute()
             and same(request, expected), "SHA runtime request differs from its exact compiled image or roster")
        supervisor = document(files["supervision.json"])
        validate_process(supervisor, label, words.WORKER)
        need(type(manifest["exit_code"]) is int and manifest["exit_code"] == supervisor["exit_code"],
             "SHA capture return code differs from actual supervision")
        parsed = validate_events(files["stdout.raw"], cases, label, image["sha256"], supervisor, words.progress)
        if label == "child-deadline-control":
            need(files["stderr.raw"].startswith(b"Traceback (most recent call last):\n")
                 and files["stderr.raw"].endswith(b"TimeoutError: native fixed-width helper exceeded 2 seconds\n"),
                 "SHA child deadline failure stderr changed")
        else:
            need(files["stderr.raw"] == b"", "Unexpected SHA runtime stderr")
        observed = document(files["observations.json"])
        expected = {"schema": OBSERVATION_SCHEMA, "label": label,
                    "production_sha256": sources[SOURCES["production.hepta"]],
                    "artifact_sha256": image["sha256"], "requested_cases": 440,
                    "completed_cases": len(parsed["cases"]), "fault": fault,
                    "supervisor": supervisor, **parsed}
        need(same(observed, expected), "SHA observations differ from their complete raw event stream")
        observations[label] = observed
        captured[label] = {"label": label, "stdout_raw_hex": files["stdout.raw"].hex(),
                           "stderr_raw_hex": files["stderr.raw"].hex()}
    printed, raw_printed = {}, {}
    for line in raw_files["hia-observations/qualification.log"].splitlines():
        if OBSERVATION_SCHEMA.encode() not in line and b'"stdout_raw_hex"' not in line:
            continue
        start = line.find(b"{")
        need(start >= 0, "Missing SHA qualifier log JSON")
        row = document(line[start:])
        if row.get("schema") == OBSERVATION_SCHEMA:
            label = row.get("label")
            need(label in LABELS and label not in printed, "Duplicate or unknown SHA qualifier report")
            printed[label] = row
        elif row.get("label") in LABELS:
            label = row["label"]
            need(label not in raw_printed, "Duplicate SHA raw stream in qualifier log")
            raw_printed[label] = row
    need(same(printed, observations) and same(raw_printed, {label: captured[label] for label in LABELS[1:]}),
         "SHA retained captures differ from the actual enclosing qualification log")
    return {"status": "PASS", "completed_native_cases": 440, "deadline_controls": 2,
            "retained_files": 54, "actual_runtime_reexecuted": False}
