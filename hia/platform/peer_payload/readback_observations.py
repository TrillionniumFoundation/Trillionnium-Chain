"""Independent raw-input/output and complete-case validation; never runs product logic."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys

from .contract import HERE, ROOT, capture, corpus, document, identity, need, priority_cases
from .readback import check_identity, file_identity, history_names, native_receipt, STATUS


def integer(value, limit=240_000_000_000):
    need(type(value) is int and 0 <= value <= limit, "Missing or exceeded actual bounded time")
    return value


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "Malformed observation digest")
    return value


def unhex(value):
    need(type(value) is str and re.fullmatch(r"(?:[0-9a-f]{2})*", value), "Noncanonical hex observation")
    return bytes.fromhex(value)


def word(*values):
    return struct.pack("<" + "Q" * len(values), *values)


def number(raw, at=0):
    need(type(raw) is bytes and at >= 0 and at + 8 <= len(raw), "Truncated observed word")
    return struct.unpack_from("<Q", raw, at)[0]


def raw_rows(path):
    raw = capture(path)
    need(raw.endswith(b"\n"), "Incomplete line-flushed observation journal")
    rows = []
    for line in raw.splitlines():
        def unique(items):
            value = {}
            for key, item in items:
                need(key not in value, "Duplicate observation key")
                value[key] = item
            return value
        rows.append(json.loads(line, object_pairs_hook=unique,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON: " + value))))
    return rows


def private_outputs(raw, count):
    need(number(raw) == count, "Private reference omitted cases")
    offset, rows = 8, []
    for _ in range(count):
        code, length = number(raw, offset), number(raw, offset + 8)
        offset += 16
        need(code <= 0xffffffff and length <= 4096 and offset + length <= len(raw),
             "Private output is truncated or has an invalid return")
        rows.append((code, raw[offset:offset + length]))
        offset += length
    need(offset == len(raw), "Unexpected trailing private output")
    return rows


def child_success(directory, row, argv, *, cwd=None):
    need(document(directory / "process.json") == row and row.get("argv") == list(map(str, argv))
         and row.get("exit_code") == 0 and type(row["exit_code"]) is int
         and row.get("timed_out") is False and row.get("reaped") is True
         and row.get("cleanup") is None, "Private observation child failed or changed command")
    integer(row.get("elapsed_ns"))
    if cwd is not None:
        need(row.get("cwd") == str(cwd), "Private observation child cwd changed")
        need(type(row.get("deadline_monotonic")) in (int, float)
             and math.isfinite(row["deadline_monotonic"]) and row["deadline_monotonic"] > 0,
             "Private child deadline is nonfinite")
    for stream in ("stdout", "stderr"):
        check_identity(directory / (stream + ".raw"), row[stream])
    need(capture(directory / "stderr.raw") == b"", "Successful private child retained stderr")


def primitives(output, report, original):
    need(report.get("status") == "PASS" and report.get("codec_pairs") == 4472
         and report.get("priority_pairs") == 8 and report.get("replay_pairs") == 840
         and report.get("native_calls") == 5320 and report.get("host_business_logic_used") is False
         and report.get("original_functions_replaced") is False
         and report.get("failure") is None, "Complete primitive/reference comparison is missing")
    integer(report.get("elapsed_ns"))
    rows = raw_rows(output / "calls.jsonl")
    need(len(rows) == 5320 and len(report["original_calls"]) == 3
         and set(report["cases"]) == {"codec", "priority", "replay"}, "Private method roster changed")
    at, values = 0, {}
    for index, kind in enumerate(("codec", "priority", "replay")):
        cases = priority_cases() if kind == "priority" else corpus(kind)[1]
        payloads = [unhex(case["payload_hex"]) for case in cases]
        stdin = word(len(cases)) + b"".join(word(case["op"], len(raw)) + raw
                                           for case, raw in zip(cases, payloads, strict=True))
        directory = output / (kind + "-original")
        observed = report["original_calls"][index]
        child_success(directory, observed, [original, directory / "private-store"])
        need(capture(directory / "stdin.raw") == stdin and observed["input"] == identity(stdin)
             and observed["executable"] == file_identity(original), "Original private input/artifact was substituted")
        raw = capture(directory / "stdout.raw")
        wanted = private_outputs(raw, len(cases))
        need(capture(output / (kind + "-native.raw")) == raw
             and report["cases"][kind] == {"expected": len(cases), "completed": len(cases),
                                           "input": identity(stdin), "output": identity(raw)},
             "Native/reference complete raw streams disagree")
        for case, payload, (code, value), row in zip(cases, payloads, wanted, rows[at:at + len(cases)], strict=True):
            need(row.get("kind") == kind and row.get("name") == case["name"]
                 and row.get("input") == identity(payload) and row.get("code") == code
                 and unhex(row.get("output_hex")) == value, "Native primitive is missing or not paired to the original")
            integer(row.get("native_elapsed_ns"))
            values[(kind, case["name"])] = (code, value)
        at += len(cases)
    need([values[("priority", case["name"])][0] for case in priority_cases()]
         == [100, 100, 100, 100, 100, 100, 10, 10], "Actual wire-constructor error order changed")
    return values


def runtime(output, report, expected):
    need(report.get("status") == STATUS["runtime"] and report.get("codec_pairs") == 4472
         and report.get("priority_pairs") == 8 and report.get("replay_pairs") == 840
         and report.get("paired_native_calls") == 10640 and report.get("boundary_native_calls") == 21
         and report.get("guards_preserved") is True and report.get("command_writes_confined") is True
         and report.get("host_business_logic_used") is False and report.get("error") is None
         and report.get("private_arena_bytes") == 89722008, "Private runtime coverage or boundary changed")
    integer(report.get("elapsed_ns"))
    rows = document(output / "calls.json")
    roster = [(kind, row) for kind in ("codec", "priority", "replay")
              for row in (priority_cases() if kind == "priority" else corpus(kind)[1])]
    need(len(rows) == len(roster) == 5320, "Runtime pair roster is incomplete")
    for (kind, case), row in zip(roster, rows, strict=True):
        wanted = expected[(kind, case["name"])]
        need(row["kind"] == kind and row["name"] == case["name"]
             and row["input_sha256"] == identity(unhex(case["payload_hex"]))["sha256"]
             and (row["code"], unhex(row["output_hex"])) == wanted,
             "Runtime dispatch disagrees with the fresh original primitive")
        integer(row["runtime_elapsed_ns"])
    controls = []
    for field, lengths in ((0, (0, 1, 63)), (1, (0, 1, 143, 184, 191)), (2, (0, 1, 8192, 89722007))):
        controls.extend({"kind": "short-argument", "field": field, "bytes": length, "return": 206}
                        for length in lengths)
    controls += [{"kind": "unknown-dispatch", "operation": value, "return": 206} for value in (3, 2**64 - 1)]
    controls += [{"kind": "original-length-order", "bytes": length, "code": code}
                 for length, code in ((0, 2), (1, 2), (379, 2), ((64 << 20) + 1, 8), (2**64 - 1, 8))]
    controls += [{"kind": "namespace-before-length", "code": 10},
                 {"kind": "new-query-invalid-selector", "return": 2, "code": 100}]
    need(report["controls"] == controls, "Runtime negative boundary roster changed")
    selected = [row for row in corpus("replay")[1] if row["name"] == "first-frame"
                or row["name"] in {"prefix-" + str(n) for n in (2, 3, 4, 7, 8, 12, 16)}]
    need(len(selected) == 8 and len(report["readonly_queries"]) == 48
         and len(report["incremental_commit_replay_pairs"]) == 8, "Read/commit method roster changed")
    at = 0
    for case, commit in zip(selected, report["incremental_commit_replay_pairs"], strict=True):
        wal = unhex(case["payload_hex"])[136:]
        last = wal[-380:]
        outputs = {0: word(1, int.from_bytes(last[260:268], "big")), 1: word(1),
                   2: word(1, int.from_bytes(last[12:20], "big")) + last[348:380]}
        prior = None
        for operation in (0, 1, 2, 3, 5, 6):
            row = report["readonly_queries"][at]
            at += 1
            need(row["case"] == case["name"] and row["operation"] == operation
                 and row["code"] == (5 if operation == 3 else 0)
                 and unhex(row["output_hex"]) == outputs.get(operation, b""), "Read-only query semantics changed")
            current = digest(row["persistent_sha256"])
            need(row["persistent_after_sha256"] == current and (prior is None or current == prior),
                 "Read-only query changed cached metadata")
            prior = current
            integer(row["elapsed_ns"])
        code, summary = expected[("replay", case["name"])]
        need(code == 0 and commit["case"] == case["name"] and commit["records"] == len(wal) // 380
             and unhex(commit["summary_hex"]) == summary
             and commit["replayed_summary_hex"] == commit["summary_hex"]
             and digest(commit["index_sha256"]) == commit["replayed_index_sha256"],
             "Incremental commit does not match the fresh original summary and full index replay")


def allocations(output, report, expected):
    need(report.get("status") == STATUS["allocations"] and report.get("original_cases") == 840
         and report.get("paired_shapes") == 857 and report.get("actual_allocation_failures") == 840
         and report.get("zero_allocation_refusals") == 17 and report.get("sequential_native_calls") == 2571
         and report.get("parallel_threads") == 8 and report.get("parallel_native_calls") == 256
         and report.get("actual_abi_calls_started") == 2827
         and report.get("production_object_unchanged") is True
         and report.get("test_observer_supplies_business_logic") is False
         and report.get("failure") is None, "Allocation/lifetime coverage changed")
    calls = document(output / "calls.json")
    need(set(calls) == {"sequential", "parallel"} and len(calls["sequential"]) == 857
         and len(calls["parallel"]) == 8, "Allocation observation roster is partial")
    replay = corpus("replay")[1]
    wanted = [(row["name"], word(1) + unhex(row["payload_hex"]), 256) for row in replay]
    valid = word(1) + unhex(next(row["payload_hex"] for row in replay if row["name"] == "genesis-only"))
    wanted += [("capacity-" + str(n), valid, n) for n in (0, 1, 7, 8, 63, 71, 72, 79, 80, 81)]
    wanted += [("short-input-" + str(n), valid[:n], 256) for n in (0, 1, 7, 8, 135, 143)]
    wanted += [("unknown-op", word(2) + valid[8:], 256)]
    events = raw_rows(output / "abi.jsonl")
    need(len(events) == 5654, "Actual ABI journal is incomplete")
    begins, returned = {}, {}
    for row in events:
        need(type(row.get("index")) is int and 0 <= row["index"] < 2827,
             "ABI journal call index is invalid")
        if row.get("phase") == "begin":
            need(row["index"] not in begins, "Duplicate ABI begin")
            begins[row["index"]] = row
        else:
            need(row.get("phase") == "returned" and row["index"] in begins and row["index"] not in returned,
                 "Returned ABI call lacks a unique begin")
            returned[row["index"]] = row
    need(set(begins) == set(returned) == set(range(2827)), "Some native ABI calls never returned")

    def native_call(index, payload, capacity, observed):
        begin, end = begins[index], returned[index]
        sha = identity(payload)["sha256"]
        need(begin == {"phase": "begin", "index": index, "input_bytes": len(payload),
                       "input_sha256": sha, "capacity": capacity}
             and end["return"] == observed["return"] and end["elapsed_ns"] == observed["elapsed_ns"]
             and end["output_hex"] == observed["output_hex"] and end["guards_preserved"] is True
             and end["input_after_sha256"] == sha
             and end["scratch_after_sha256"] == identity(b"\x73" * 137)["sha256"],
             "ABI raw journal does not bind the claimed guarded native call")
        integer(end["elapsed_ns"])
        raw = unhex(end["output_hex"])
        need(type(end["return"]) is int and 0 <= end["return"] <= 0xffffffff and len(raw) == capacity,
             "Invalid native ABI return or extent")
        if end["return"]:
            need(raw == b"\xa5" * capacity, "Rejected native call published output")
        else:
            need(capacity >= 80 and number(raw) == 72 and raw[80:] == b"\xa5" * (capacity - 80),
                 "Successful native output exceeded its exact extent")

    previous = [0] * 9
    baseline = {}
    denied, refused = 0, 0
    for i, ((name, payload, capacity), row) in enumerate(zip(wanted, calls["sequential"], strict=True)):
        need((row["name"], row["capacity"], row["input_bytes"], row["input_sha256"])
             == (name, capacity, len(payload), identity(payload)["sha256"]), "Allocation fixture was substituted")
        before, after, final = row["before"], row["after"], row["final"]
        need(before == previous and all(type(x) is list and len(x) == 9
             and all(type(n) is int and n >= 0 for n in x) for x in (before, after, final)),
             "Allocation counters are discontinuous")
        for step, key in enumerate(("production", "observed", "allocation_denied")):
            native_call(i * 3 + step, payload, capacity, row[key])
        prod, observed, failure = row["production"], row["observed"], row["allocation_denied"]
        need((prod["return"], prod["output_hex"]) == (observed["return"], observed["output_hex"]),
             "Allocator observer replaced product behavior")
        allocated = after[0] - before[0]
        need(allocated in (0, 1) and after[1] - before[1] == allocated and after[4] == before[4]
             and after[2] == after[3] == after[5] == final[2] == final[3] == final[5] == 0
             and final[1] == after[1], "Allocation is leaked or released through an unknown pointer")
        if allocated:
            need(failure["return"] == 103 and final[0] - after[0] == final[4] - after[4] == 1,
                 "Actual allocator failure was not observed")
            denied += 1
        else:
            need(final == after and (failure["return"], failure["output_hex"])
                 == (observed["return"], observed["output_hex"]), "Preallocation refusal changed behavior")
            refused += 1
        if i < 840:
            code, result = expected[("replay", name)]
            need(prod["return"] == code and (code != 0 or unhex(prod["output_hex"])[8:80] == result),
                 "Allocation replay no longer matches the actual original parser")
            baseline[name] = prod
        previous = final
    need((denied, refused) == (840, 17), "Allocator denial/no-allocation counts changed")
    selected = [row for row in replay if row["name"] in
                {"genesis-only", "first-frame", "distinct-keys-31", "interleaved-18-keys"}]
    expected_events = Counter()
    for number_, row in enumerate(calls["parallel"]):
        need(row["thread"] == number_ and len(row["calls"]) == 32, "Eight concurrent lifetimes were not retained")
        for i, call in enumerate(row["calls"]):
            case = selected[(i + number_) % 4]
            need(call["name"] == case["name"] and call["return"] == baseline[case["name"]]["return"]
                 and call["output_hex"] == baseline[case["name"]]["output_hex"], "Concurrent private owner result changed")
            integer(call["elapsed_ns"])
            payload = word(1) + unhex(case["payload_hex"])
            expected_events[(identity(payload)["sha256"], len(payload), call["return"], call["output_hex"], call["elapsed_ns"])] += 1
    observed_events = Counter()
    for index in range(2571, 2827):
        begin, end = begins[index], returned[index]
        need(begin["capacity"] == 256 and end["guards_preserved"] is True
             and end["input_after_sha256"] == digest(begin["input_sha256"])
             and end["scratch_after_sha256"] == identity(b"\x73" * 137)["sha256"],
             "Concurrent native call corrupted a private argument")
        observed_events[(begin["input_sha256"], begin["input_bytes"], end["return"], end["output_hex"], end["elapsed_ns"])] += 1
    need(observed_events == expected_events, "Concurrent ABI transcript does not equal all eight thread results")
    final = report["allocation_counters"]
    need(len(final) == 9 and final[0] - previous[0] == final[1] - previous[1] == 256
         and final[4] == previous[4] == 840 and final[2] == final[3] == final[5] == 0
         and final[0] == final[1] + final[4], "Final native allocation ownership did not close")


def views(output, report, image):
    need(report.get("status") == "PASS" and report.get("image") == identity(image)
         and (report.get("accepted"), report.get("refused"), report.get("cases_completed")) == (3, 5, 8)
         and len(report["cases"]) == 8 and report.get("failure") is None, "View admission roster changed")
    for mode, (row, code) in enumerate(zip(report["cases"], (0, 78, 78, 78, 78, 0, 0, 78), strict=True)):
        stdout = b"VIEWPASS" if code == 0 else b""
        need(row["mode"] == mode and row["exit_code"] == code and unhex(row["stdout_hex"]) == stdout,
             "Wrong admitted/refused loader view")
        native_receipt(output / ("mode-" + str(mode)), row["receipt"], image, word(mode), stdout, code)


def fixture_values():
    cases = corpus("codec")[1]
    namespace = unhex(next(row["payload_hex"] for row in cases if row["name"] == "namespace-0"))
    frame = bytearray(unhex(next(row["payload_hex"] for row in cases if row["name"] == "frame-0"))[136:408])
    frame[208:224] = word(1, 0)
    return namespace, bytes(frame)


def changed_frame(original, **changes):
    positions = {"local": 0, "remote": 32, "scope": 64, "direction": 96, "epoch": 104,
        "run": 112, "network": 144, "session": 176, "generation": 208, "sequence": 216,
        "kind": 224, "length": 232, "fingerprint": 240}
    result = bytearray(original)
    for name, value in changes.items():
        raw = word(value) if type(value) is int else value
        offset = positions[name]
        result[offset:offset + len(raw)] = raw
    return bytes(result)


def requests(group, name, root, *, nested=False):
    """Independent complete request recipes, including every preserved case."""
    ns, frame = fixture_values()
    base, answer = root / "work", []
    path = base / "journal"

    def call(op, payload=b""):
        answer.append(word(op) + payload)

    def opened(path_=path, namespace=ns):
        raw = os.fsencode(path_)
        call(1, namespace + word(len(raw)) + raw)

    def f(**changes):
        return changed_frame(frame, **changes)

    if group == "syscalls":
        opened(); call(2, frame); call(3, frame); call(4); call(8); opened(); call(3, frame)
    elif group == "crash":
        opened(); call(3, frame); call(4); call(5)
    elif group == "public":
        if name == "public-sequence":
            opened(); call(5)
            key = frame[32:64] + frame[96:104]
            call(7, key); call(6, key + frame[176:208]); call(3, frame); call(2, frame); call(3, frame); call(2, frame)
            for field, value in (("fingerprint", bytes([88]) * 32), ("kind", 2), ("length", 7), ("session", bytes([89]) * 32)):
                call(3, f(**{field: value}))
            call(2, f(sequence=2)); call(2, f(sequence=1)); call(3, f(sequence=1))
            call(2, f(generation=2, session=bytes([90]) * 32)); call(2, f(generation=3, session=frame[176:208]))
            call(2, f(generation=2**64 - 1, session=bytes([91]) * 32))
            call(7, key); call(6, key + frame[176:208]); call(5); call(4); call(8); opened(); call(3, frame); call(5)
        elif name == "many-peers-two-directions":
            opened()
            for n in range(12):
                for direction in (1, 2):
                    remote, session = bytes([100 + n]) * 32, bytes([150 + n]) * 32
                    current = f(remote=remote, direction=direction, session=session)
                    call(2, current); call(3, current); call(2, f(remote=remote, direction=direction, session=session, sequence=1))
                    call(7, remote + word(direction)); call(6, remote + word(direction) + session)
            call(8); opened()
            for n in range(12):
                for direction in (1, 2):
                    remote, session = bytes([100 + n]) * 32, bytes([150 + n]) * 32
                    call(3, f(remote=remote, direction=direction, session=session)); call(7, remote + word(direction))
                    call(6, remote + word(direction) + session)
        elif name == "invalid-frames-and-context":
            opened()
            values = [("local", bytes(32)), ("remote", bytes(32)), ("remote", frame[:32]), ("scope", bytes(32)),
                ("direction", 0), ("direction", 3), ("run", bytes(32)), ("network", bytes(32)), ("session", bytes(32)),
                ("generation", 0), ("kind", 0), ("kind", 256), ("length", 8 * 1024 * 1024 + 1),
                ("fingerprint", bytes(32)), ("local", bytes([77]) * 32), ("scope", bytes([78]) * 32),
                ("run", bytes([79]) * 32), ("network", bytes([80]) * 32), ("epoch", number(ns, 128) ^ 1)]
            for field, value in values:
                call(2, f(**{field: value})); call(3, f(**{field: value}))
            call(2, frame); call(3, frame)
        elif name == "constructor-error-priority":
            opened()
            values = [{"direction": 0, "local": bytes(32)}, {"direction": 3, "remote": bytes(32)},
                {"direction": 2**64 - 1, "scope": bytes(32)}, {"kind": 256, "run": bytes(32)},
                {"kind": 2**64 - 1, "network": bytes(32)}, {"kind": 256, "session": bytes(32)},
                {"kind": 256, "local": bytes(32)}, {"direction": 0, "kind": 256, "run": bytes(32)}]
            for changes in values:
                call(2, f(**changes)); call(3, f(**changes))
            call(5); call(4); call(2, frame); call(3, frame); call(5)
        elif name.startswith("open-"):
            kind = name[5:]
            raw = os.fsencode(path)
            if kind == "namespace-zero": ns = bytes(32) + ns[32:]
            elif kind == "missing-parent": raw = os.fsencode(base / "missing/journal")
            elif kind == "relative": raw = b"journal"
            elif kind == "root": raw = b"/"
            elif kind == "empty": raw = b""
            elif kind == "dot-parent": raw = os.fsencode(base) + b"/./journal"
            elif kind == "double-slash": raw = os.fsencode(base).replace(b"/var/", b"//var//") + b"//journal"
            elif kind == "basename-dot": raw += b"/."
            elif kind == "basename-dotdot": raw = os.fsencode(base) + b"/journal/.."
            elif kind == "parent-dotdot": raw = os.fsencode(base) + b"/../work/journal"
            elif kind == "invalid-utf8": raw += b"\xff"
            elif kind == "nul-name": raw += b"\0x"
            elif kind == "nul-parent": raw = os.fsencode(base) + b"\0/journal"
            elif kind == "long-basename": raw = os.fsencode(base) + b"/" + b"a" * 256
            elif kind == "overlong-parent": raw = os.fsencode(base) + b"/" + b"a" * 4100 + b"/j"
            opened(raw, ns); call(5); call(4)
        elif name == "valid-prefix-rollback":
            opened(); call(2, frame); call(2, f(sequence=1)); call(4); call(3, frame); call(2, frame); call(3, frame); call(5)
        else:
            need(name in history_names("public"), "Unknown public fixture")
            opened(); call(2, frame)
            if name == "wal-truncated":
                call(3, frame); call(3, frame); call(2, frame); call(5); call(4)
            elif name in {"wal-mutated", "head-mutated"}:
                call(3, frame); call(3, frame); call(2, frame); call(5)
            else:
                call(4); call(3, frame)
    else:
        need(group == "boundaries" and name in history_names(group), "Unknown namespace-boundary fixture")
        if name.startswith("directory-entry-bound-") or name.startswith("basename-bound-"):
            if name.startswith("basename-bound-"): path = base / ("j" * int(name.rsplit("-", 1)[1]))
            opened(path); call(5); call(4); call(8); opened(path); call(5)
        elif name == "closed-store-namespace-mismatch":
            opened(); call(2, frame); call(8)
            altered = bytearray(ns); altered[32] ^= 1
            opened(path, bytes(altered)); call(5); call(4); opened(); call(3, frame); call(5)
        elif name.startswith("closed-store-missing-"):
            opened(); call(2, frame); call(8); opened(); call(5); call(3, frame); call(4)
        elif name.startswith("ancestor-"):
            kind = name[9:]
            path = base / ("alias/inner/journal" if kind == "symlink" else "outer/inner/journal")
            if kind == "create-nested": path = base / "outer/inner/new/deeper/journal"
            elif kind == "parent-not-directory": path = base / "outer/inner/file/journal"
            opened(path); call(5); call(4)
        else:
            kind = name[len("simultaneous-owner-"):]
            if nested:
                opened(); call(5)
                if kind == "close-releases":
                    opened(); call(3, frame); call(2, f(sequence=1)); call(5)
                elif kind == "second-namespace-does-not-evade-lock":
                    altered = bytearray(ns); altered[96] ^= 1
                    opened(path, bytes(altered)); call(5)
                elif kind == "independent-file":
                    opened(base / "other"); call(2, frame); call(3, frame)
                else:
                    need(kind == "renamed-lock-does-not-authorize-old-owner", "Unknown concurrent-owner fixture")
                    opened(); call(3, frame)
            else:
                opened(); call(2, frame)
                if kind == "close-releases": call(8)
                elif kind in {"second-namespace-does-not-evade-lock", "independent-file"}: call(3, frame)
                else: call(3, frame); call(2, f(sequence=1))
    call(9)
    return answer


def framed(values):
    return b"".join(word(len(value)) + value for value in values)


def parse_public(raw, inputs):
    at, result = 0, []
    for request in inputs:
        length = number(raw, at)
        at += 8
        need(88 <= length <= 65536 and at + length <= len(raw), "Public response is truncated or exceeds the ABI")
        body = raw[at:at + length]
        need(number(body, 80) == length - 88, "Public response payload length differs")
        code, errno, reason, inner, poison, count = struct.unpack_from("<6Q", body)
        need(poison in (0, 1) and code <= 206 and errno <= 4095, "Public response contains an invalid state")
        result.append({"op": number(request), "code": code, "errno": errno, "reason": reason,
            "inner": inner, "poison": poison, "count": count, "hash": body[48:80].hex(), "payload_hex": body[88:].hex()})
        at += length
    need(at == len(raw), "Public response count or trailing bytes changed")
    return result


def normalize_public(row, base):
    result = {key: value for key, value in row.items() if key != "poison"}
    if row["op"] == 5 and row["code"] == 0:
        data = unhex(row["payload_hex"])
        count = number(data)
        need(8 + count + 8 <= len(data), "Truncated public path getter")
        first, offset = data[8:8 + count], 8 + count
        count = number(data, offset)
        need(offset + 8 + count <= len(data), "Truncated head path getter")
        second, tail = data[offset + 8:offset + 8 + count], data[offset + 8 + count:]
        component = os.fsencode(base.parent.name)
        substitute = lambda value: b"/".join(b"$OWNER" if part == component else part for part in value.split(b"/"))
        first, second = substitute(first), substitute(second)
        result["payload_hex"] = (word(len(first)) + first + word(len(second)) + second + tail).hex()
    return result


def public_diagnostics(raw, rows, inputs, *, original):
    """Bind every original observer error line to its ordered binary response.

    public_reference.rs::error prints the outer CommitAmbiguous event before
    recursively printing its inner event. Its frame constructor also prints
    the two Scope errors before mapping them to the shared transport code.
    These are test-observer diagnostics, not native product stderr.
    """
    need(len(rows) == len(inputs), "Original diagnostic request/response count changed")
    if not original:
        need(raw == b"", "Unexpected native public child stderr")
        return
    fixed = {
        2: ("Truncated", "payload replay journal is truncated"),
        3: ("Corrupt", "payload replay journal is corrupt"),
        4: ("ContextMismatch", "payload replay context mismatch"),
        5: ("Replay", "authenticated payload frame was replayed"),
        6: ("StaleGeneration", "payload frame generation is stale"),
        7: ("SequenceGap", "payload frame sequence is not contiguous"),
        8: ("TooLarge", "payload replay journal exceeds its bound"),
        9: ("Poisoned", "payload replay owner is permanently poisoned"),
    }
    reasons = {
        1: "payload replay authority file identity changed",
        2: "payload replay parent directory is a symlink alias",
        3: "payload replay file is not a private single-link regular file",
        4: "payload replay authority path identity changed",
        5: "payload replay parent directory identity changed",
        6: "payload replay head path is not a private regular file",
        7: "payload replay head descriptor/path identity changed",
        8: "payload replay head is not private", 9: "payload replay path filename",
        10: "payload replay path has no parent", 11: "payload replay parent directory is not private",
        12: "payload replay head exists for a virgin journal",
        13: "payload replay journal path is not a private regular file",
        14: "payload replay authority path is a symlink", 15: "payload replay head appeared during virgin open",
        16: "payload replay head is not a private regular file",
        1001: "journal path must be absolute", 1002: "journal parent", 1003: "journal anchor filename",
        1004: "journal parent must be a directory", 1005: "journal parent must have private mode 0700",
        1006: "journal parent must be owned by the effective user",
        1007: "journal parent must not be a symlink alias",
        1008: "journal parent ancestry must not be group/world writable",
        1009: "journal parent ancestry must be root- or owner-controlled",
        1014: "journal parent must be a real directory", 1015: "journal parent has no existing ancestor",
    }
    # This fixed corpus runs on the pinned Linux/Rust host. Unknown new
    # diagnostics require explicit qualification rather than a permissive regex.
    io_errors = {
        2: ("NotFound", "No such file or directory"), 4: ("Interrupted", "Interrupted system call"),
        5: ("Uncategorized", "Input/output error"), 11: ("WouldBlock", "Resource temporarily unavailable"),
        21: ("IsADirectory", "Is a directory"), 36: ("InvalidFilename", "File name too long"),
        40: ("FilesystemLoop", "Too many levels of symbolic links"),
    }

    def constructor(request):
        op, frame = number(request), request[8:]
        if op == 1 and any(frame[at:at + 32] == bytes(32) for at in (0, 32, 64, 96)):
            return None, "payload replay namespace contains a zero identity"
        if op in (2, 3) and len(frame) == 272 and number(frame, 96) in (1, 2):
            if any(frame[at:at + 32] == bytes(32) for at in (0, 32, 64)):
                return "ZeroIdentity", None
            if frame[:32] == frame[32:64]:
                return "SelfPeer", None
            need(number(frame, 224) <= 255, "Original diagnostic bypassed the wire kind check")
            if frame[112:144] == bytes(32) or frame[144:176] == bytes(32):
                return None, "payload replay frame has a zero context digest"
            if frame[176:208] == bytes(32):
                return None, "payload replay frame has a zero session"
            if number(frame, 208) == 0:
                return None, "payload replay generation must be positive"
            if number(frame, 224) == 0:
                return None, "payload replay frame kind must be nonzero"
            if number(frame, 232) <= 8 * 1024 * 1024 and frame[240:272] == bytes(32):
                return None, "payload replay frame fingerprint is zero"
        raise ValueError("Original diagnostic InvalidRequest has no matching constructor or reason")

    def error(code, errno, reason, request):
        if code in fixed:
            need(errno == reason == 0, "Original diagnostic simple error fields changed")
            return fixed[code]
        if code == 10:
            need(errno == 0, "Original diagnostic InvalidRequest has an errno")
            scope, message = (None, reasons[reason]) if reason in reasons else constructor(request)
            need(reason in reasons or reason == 0, "Original diagnostic reason is unknown")
            if scope is not None:
                return scope, None
            return 'InvalidRequest(' + json.dumps(message) + ')', message
        if code == 11 and errno in io_errors:
            need(reason == 0, "Original diagnostic errno has a non-errno reason")
            kind, message = io_errors[errno]
            return ('Io(Os { code: ' + str(errno) + ', kind: ' + kind + ', message: ' + json.dumps(message) + ' })',
                    'payload replay I/O error: ' + message + ' (os error ' + str(errno) + ')')
        if code == 11 and errno == 0 and reason == 21:
            message = "file name contained an unexpected NUL byte"
            return ('Io(Error { kind: InvalidInput, message: ' + json.dumps(message) + ' })',
                    'payload replay I/O error: ' + message)
        raise ValueError("Original diagnostic code/errno is outside the fixed observed corpus")

    expected = []
    line = lambda debug, display: "ORIGINAL_PAYLOAD_ERROR Debug=" + debug + "; Display=" + display + "\n"
    for row, request in zip(rows, inputs, strict=True):
        code = row["code"]
        if code in (0, 100):
            need(row["errno"] == row["reason"] == row["inner"] == 0,
                 "Original diagnostic success/wire fields changed")
            continue
        debug, display = error(row["inner"] if code == 13 else code, row["errno"], row["reason"], request)
        if code == 13:
            need(display is not None and row["inner"] != 13, "Original diagnostic commit nesting changed")
            expected.append(line("CommitAmbiguous(" + debug + ")", "payload replay commit outcome is ambiguous: " + display))
        else:
            need(row["inner"] == 0, "Original diagnostic has an unexpected inner error")
        expected.append("ORIGINAL_SCOPE_ERROR " + debug + "\n" if display is None else line(debug, display))
    need(raw == "".join(expected).encode(), "Original diagnostic events differ from ordered actual responses")


def public_child(directory, executable, inputs, *, trace_argv=None, original=False):
    value = document(directory / "process.json")
    need(value.get("exit_code") == 0 and type(value["exit_code"]) is int and value.get("reaped") is True
         and value.get("timed_out") is False and value.get("failure") is None
         and value.get("cleanup_windows") == 1 and value.get("cleanup_limit_seconds") == 3
         and value.get("family_reaping_observed_by_outer_collector") is True,
         "Public child did not complete under one cleanup window")
    integer(value.get("cleanup_elapsed_ns"), 3_000_000_000)
    integer(value.get("elapsed_ns"), 243_000_000_000)
    need(value.get("argv") == (trace_argv or [str(executable)]) and value.get("cwd") == str(directory)
         and value.get("environment") == {"PATH": ""}
         and value.get("executable_before") == value.get("executable_after") == file_identity(executable),
         "Public child actual image/argv/environment changed")
    raw = framed(inputs)
    need(capture(directory / "stdin.raw") == raw and value["input"] == identity(raw),
         "Public observer omitted or substituted a method request")
    for stream in ("stdout", "stderr"):
        check_identity(directory / (stream + ".raw"), value[stream])
    rows = parse_public(capture(directory / "stdout.raw"), inputs)
    need(document(directory / "responses.json") == rows, "Summarized public responses differ from actual complete raw bytes")
    public_diagnostics(capture(directory / "stderr.raw"), rows, inputs, original=original)
    return rows


def disk_files(base, *, tracee=None):
    result = {}
    for directory, directories, filenames in os.walk(base, followlinks=False):
        for name in sorted([*directories, *filenames]):
            path = Path(directory) / name
            status = path.lstat()
            key = path.relative_to(base).as_posix()
            row = {"mode": stat.S_IMODE(status.st_mode), "uid": status.st_uid,
                   "gid": status.st_gid, "links": status.st_nlink}
            if stat.S_ISREG(status.st_mode): row.update(kind="regular", **file_identity(path))
            elif stat.S_ISDIR(status.st_mode): row["kind"] = "directory"
            elif stat.S_ISLNK(status.st_mode): row.update(kind="symlink", target=os.readlink(path).replace(str(base), "$CASE"))
            elif stat.S_ISFIFO(status.st_mode): row["kind"] = "fifo"
            else: row["kind"] = "other"
            if tracee is not None and key.startswith("..journal.head-v1.tmp-"):
                match = re.fullmatch(r"(\.\.journal\.head-v1\.tmp-)(\d+)-(\d+)-(\d+)", key)
                need(match is not None and type(tracee) is int and int(match[2]) == tracee,
                     "Unbound temporary owner process in disk comparison")
                key = match[1] + "$PID-" + match[3] + "-" + match[4]
            need(key not in result, "Disk path normalization collided")
            result[key] = row
    return result


def public_histories(output, report, group, original, native):
    need(group in {"public", "boundaries"} and report.get("status") == STATUS[group]
         and report.get("failure") is None and report.get("native_runtime_limit_seconds") == 240
         and report.get("cleanup_limit_seconds") == 3
         and report.get("poison_compared_through_subsequent_public_calls") is True,
         "Public history report failed or weakened its deadline")
    integer(report.get("elapsed_ns"))
    roster = history_names(group)
    need([row["name"] for row in report["cases"]] == roster and report["paired_histories"] == len(roster),
         "Public method histories were omitted, reordered or duplicated")
    count = 0
    for name, case in zip(roster, report["cases"], strict=True):
        results = []
        expected_input_count = None
        for label, executable in (("original", original), ("native", native)):
            root = output / (name + "-" + label)
            base = root / "work"
            inputs = requests(group, name, root)
            actual = public_child(root, executable, inputs, original=label == "original")
            rows = [normalize_public(row, base) for row in actual]
            observed = {"responses": rows, "files": disk_files(base)}
            if group == "boundaries":
                observed["nested"] = []
                if name.startswith("simultaneous-owner-"):
                    child_inputs = requests(group, name, root, nested=True)
                    child_rows = public_child(root / "second", executable, child_inputs, original=label == "original")
                    observed["nested"] = [{"directory": "second", "responses": [normalize_public(row, base) for row in child_rows],
                                           "exit_code": 0, "timed_out": False, "reaped": True}]
                if name.startswith("directory-entry-bound-"):
                    entries = int(name.rsplit("-", 1)[1])
                    ordinary = {key for key in observed["files"] if key.startswith("ordinary-")}
                    need(ordinary == {"ordinary-" + str(n).zfill(4) for n in range(entries)},
                         "Namespace entry cap was not physically exercised")
            if name == "constructor-error-priority":
                need([row["code"] for row in actual[1:17]] == [code for code in (100, 100, 100, 100, 100, 100, 10, 100) for _ in range(2)]
                     and all(row["count"] == 1 for row in actual[1:17])
                     and all(row["code"] == 0 for row in actual[17:]), "Public wire error precedence or retry state changed")
            need(document(root / "observed.json") == observed, "Actual public responses or persisted files differ from the report")
            results.append(observed)
            expected_input_count = len(inputs)
        need(results[0] == results[1] and case == {"name": name, "calls": expected_input_count, "status": "PASS"},
             "Original/native public history or filesystem state differs")
        count += expected_input_count
    need(report["paired_calls"] == count and (group != "public" or count == 492), "Public paired-call count changed")
    if group == "public":
        need(report.get("observer_path_controls") == 2, "Path spelling distinction controls missing")
    return count


def trace_rows(path):
    rows, counts = [], {}
    for index, line in enumerate(capture(path).decode().splitlines()):
        match = re.match(r"^(?:(\d+)\s+)?([a-z0-9_]+)\(", line)
        if match:
            name = match[2]
            counts[name] = counts.get(name, 0) + 1
            rows.append({"index": index, "pid": int(match[1] or 0), "syscall": name,
                         "line": line, "ordinal": counts[name]})
    need(rows, "Missing actual syscall trace")
    return rows


def syscall_selectors(rows, base):
    writes = [row for row in rows if row["syscall"] == "write" and re.match(r"^\d+\s+write\(1<", row["line"])]
    need(len(writes) >= 2, "Syscall probe did not return open and admit")
    phases = {"open": [row for row in rows if row["index"] < writes[0]["index"]],
              "admit": [row for row in rows if writes[0]["index"] < row["index"] < writes[1]["index"]]}
    result = {}

    def pick(phase, name, syscalls, predicate, last=False):
        choices = [row for row in phases[phase] if row["syscall"] in syscalls and predicate(row["line"])]
        need(choices, "Actual required syscall target is absent")
        result[phase + "-" + name] = choices[-1 if last else 0]

    journal, head, lock = map(str, (base / "journal", base / ".journal.head-v1", base / ".journal.lock-v1"))
    stats = ("fstat", "newfstatat", "statx")
    descriptor = lambda path: lambda line: path + ">" in line
    temporary = lambda line: "..journal.head-v1.tmp-" in line
    for phase in ("open", "admit"):
        pick(phase, "journal-write", ("write",), descriptor(journal))
        pick(phase, "journal-fsync", ("fsync",), descriptor(journal))
        pick(phase, "directory-fsync", ("fsync",), descriptor(str(base)))
        pick(phase, "head-open", ("openat", "open"), temporary)
        pick(phase, "head-write", ("write",), temporary)
        pick(phase, "head-fsync", ("fsync",), temporary)
        pick(phase, "head-metadata", stats, temporary)
        pick(phase, "head-rename", ("rename", "renameat", "renameat2"), temporary)
        pick(phase, "published-head-metadata", stats, lambda line: head in line, True)
        pick(phase, "published-directory-fsync", ("fsync",), descriptor(str(base)), True)
    pick("open", "directory-open", ("openat", "open"), lambda line: '"' + str(base) + '"' in line)
    pick("open", "lock-open", ("openat", "open"), lambda line: lock in line)
    pick("open", "lock-flock", ("flock",), descriptor(lock))
    pick("open", "journal-open", ("openat", "open"), lambda line: journal in line)
    pick("open", "journal-fchmod", ("fchmod",), descriptor(journal))
    pick("open", "journal-flock", ("flock",), descriptor(journal))
    pick("admit", "journal-metadata", stats, descriptor(journal))
    pick("admit", "journal-seek", ("lseek",), descriptor(journal))
    pick("admit", "journal-read", ("read",), descriptor(journal))
    pick("admit", "head-read", ("read",), descriptor(head))
    need(len(result) == 30, "Actual syscall probe roster changed")
    return result


def syscall_storage_target(phase, base, line):
    suffix = phase.removeprefix("open-").removeprefix("admit-")
    if suffix.startswith("journal-"): expected_path = str(base / "journal")
    elif suffix.startswith("lock-"): expected_path = str(base / ".journal.lock-v1")
    elif "directory" in suffix: expected_path = str(base)
    elif suffix in {"published-head-metadata", "head-read"}: expected_path = str(base / ".journal.head-v1")
    else:
        need(suffix.startswith("head-"), "Unknown syscall target")
        expected_path = "..journal.head-v1.tmp-"
    need(expected_path in line, "Actual fault is unbound from the intended storage object")


def syscall_histories(output, report, original, native):
    need(report.get("status") == STATUS["syscalls"] and report.get("paired_histories") == 61
         and report.get("actual_fault_pairs") == 60 and report.get("paired_calls") == 488
         and report.get("actual_strace_error_injection") is True and report.get("failure") is None
         and report.get("native_runtime_limit_seconds") == 240 and report.get("cleanup_limit_seconds") == 3,
         "Real syscall failure coverage is incomplete")
    integer(report.get("elapsed_ns"))
    roster = history_names("syscalls")
    need([row["name"] for row in report["cases"]] == roster, "Syscall histories were omitted or reordered")
    probes = {}
    for name, case in zip(roster, report["cases"], strict=True):
        need(case["status"] == "PASS" and case.get("failure") is None, "Actual syscall pair failed")
        answers = []
        for label, executable in (("original", original), ("native", native)):
            directory = output / (name + "-" + label)
            base = directory / "work"
            rows = trace_rows(directory / "syscalls.raw")
            need(document(directory / "trace-calls.json") == rows, "Syscall table does not equal actual raw trace")
            execs = [row for row in rows if row["syscall"] == "execve" and str(executable) in row["line"]]
            need(len(execs) == 1 and execs[0]["pid"] > 0 and execs[0]["line"].endswith("= 0"),
                 "Strace did not execute the selected actual original/native image")
            tracee = execs[0]["pid"]
            argv = ["/usr/bin/strace", "-f", "-qq", "-yy", "-s", "4096", "-o", str(directory / "syscalls.raw")]
            injected = [row for row in rows if "(INJECTED)" in row["line"]]
            if name == "probe":
                need(case["phase"] is None and case["errno"] is None and not injected,
                     "Baseline probe included a synthetic failure")
                probes[label] = syscall_selectors(rows, base)
                need(document(directory / "selectors.json") == probes[label], "Syscall selector does not match the complete probe")
            else:
                phase, error = name.rsplit("-", 1)
                need(case["phase"] == phase and case["errno"] == error and error in {"EIO", "EINTR"},
                     "Syscall phase/error changed")
                target = probes[label][phase]
                specification = target["syscall"] + ":error=" + error + ":when=" + str(target["ordinal"])
                argv += ["--inject=" + specification]
                need(len(injected) == 1, "The selected syscall fault was never injected exactly once")
                actual = injected[0]
                need(actual["syscall"] == target["syscall"] and actual["ordinal"] == target["ordinal"]
                     and "= -1 " + error + " " in actual["line"] and actual["pid"] == tracee,
                     "A different syscall, process or ordinal received the fault")
                syscall_storage_target(phase, base, actual["line"])
                need(document(directory / "injection-selector.json")
                     == {"probe": target, "injection": specification, "actual": actual},
                     "Actual fault is unbound from the intended storage object")
            argv += [str(executable)]
            requests_ = requests("syscalls", name, directory)
            responses = public_child(directory, executable, requests_, trace_argv=argv, original=label == "original")
            answer = {"responses": [normalize_public(row, base) for row in responses],
                      "files": disk_files(base, tracee=tracee)}
            need(document(directory / "observed.json") == answer and case[label] == answer,
                 "Syscall failure response/files were replaced after execution")
            answers.append(answer)
        need(answers[0] == answers[1], "Original/native syscall failure semantics differ")
    return 488


def crash_trace(directory, executable, storage, target, payload):
    value = document(directory / "trace.json")
    image = file_identity(executable)
    need(value.get("schema") == "trnm.payload-owned-process-trace.v1" and value.get("status") == "PASS"
         and value.get("failure") is None and value.get("fault_injected") is False
         and value.get("power_failure_claimed") is False and value.get("target") == target
         and value.get("storage") == str(storage) and value.get("executable") == str(executable)
         and value.get("executable_before") == value.get("executable_after") == image
         and value.get("input") == identity(payload) and capture(directory / "stdin.raw") == payload
         and value.get("exit_code") is None and value.get("signal") == signal.SIGKILL
         and value.get("supervisor_cleanup") is None, "Actual crash trace failed or claims a synthetic/power cut")
    integer(value.get("elapsed_ns"), 30_000_000_000)
    for stream in ("stdout", "stderr"):
        check_identity(directory / (stream + ".raw"), value[stream])
    need(capture(directory / "stderr.raw") == b"", "Crash child produced unexpected diagnostics")
    events = value["events"]
    need(type(value.get("pid")) is int and value["pid"] > 0 and events
         and [row["sequence"] for row in events] == list(range(1, len(events) + 1)),
         "Crash trace is incomplete or reordered")
    executed = [row for row in events if row["kind"] == "exec"]
    need(len(executed) == 1 and executed[0]["actual"] == str(Path(executable).resolve(strict=True)),
         "Ptrace did not observe the selected image")
    actions = value["actions"]
    need(len(actions) == 1, "Missing or duplicate actual durability cut")
    action = actions[0]
    need(action.get("kind") == "SIGKILL-after-real-syscall" and action.get("stage") == target,
         "Crash was not after a real kernel operation")
    lookup = {row["sequence"]: row for row in events}
    enter, leave = lookup[action["entry"]], lookup[action["exit"]]
    need(enter["kind"] == "entry" and leave["kind"] == "exit" and leave["entry"] == enter["sequence"]
         and enter["storage_stage"] == leave["storage_stage"] == target
         and type(leave["kernel_result"]) is int and leave["kernel_result"] == leave["result"] >= 0,
         "Cut followed an injected/failed/unrelated syscall")
    suffix = target.removeprefix("open-").removeprefix("admit-")
    if suffix == "journal-write":
        need(enter["nr"] == 1 and enter["fd_path"] == str(storage / "journal")
             and enter["args"][2] == 380 and enter["record_index"] == int(target.startswith("admit-")),
             "Cut did not follow a full real WAL write")
    elif suffix == "journal-fsync":
        need(enter["nr"] == 74 and enter["fd_path"] == str(storage / "journal"), "Wrong WAL fsync cut")
    elif suffix in {"directory-fsync", "published-directory-fsync"}:
        need(enter["nr"] == 74 and enter["fd_path"] == str(storage), "Wrong directory fsync cut")
    elif suffix == "head-rename":
        need(enter["nr"] == 82 and enter["to"] == str(storage / ".journal.head-v1"), "Wrong published-head cut")
    else:
        need(suffix in {"head-write", "head-fsync"} and enter["nr"] == (1 if suffix == "head-write" else 74)
             and "..journal.head-v1.tmp-" in enter["fd_path"], "Wrong temporary head cut")
    need(events[-1]["kind"] == "terminal" and events[-1]["signal"] == signal.SIGKILL
         and events[-1]["exit_code"] is None, "Actual killed child was not waited")
    return value


def crash_histories(output, report, original, native):
    need(report.get("status") == STATUS["crash"] and report.get("paired_histories") == 14
         and report.get("actual_successful_syscall_cuts") == 28 and report.get("power_failure_claimed") is False
         and report.get("failure") is None and report.get("native_runtime_limit_seconds") == 240
         and report.get("cleanup_limit_seconds") == 3, "Actual crash/reopen roster failed")
    integer(report.get("elapsed_ns"))
    roster = history_names("crash")
    need([row["name"] for row in report["cases"]] == roster
         and report["tracer"] == file_identity(HERE / "qualification/owned_trace.py"), "Crash tracer/phase roster changed")
    ns, frame = fixture_values()
    for name, case in zip(roster, report["cases"], strict=True):
        need(case["status"] == "PASS" and case.get("failure") is None, "Crash pair failed")
        answers = []
        for label, executable in (("original", original), ("native", native)):
            root = output / (name + "-" + label)
            base = root / "work"
            path = os.fsencode(base / "journal")
            payload = framed([word(1) + ns + word(len(path)) + path, word(2) + frame, word(3) + frame, word(9)])
            trace = crash_trace(root / "trace", executable, base, name, payload)
            raw = capture(root / "trace/stdout.raw")
            need(len(raw) == (96 if name.startswith("admit-") else 0), "Crash occurred after an unexpected public response")
            if raw:
                opened = parse_public(raw, [word(1) + ns + word(len(path)) + path])[0]
                need(opened["code"] == 0 and opened["count"] == 1, "Admit cut did not follow successful actual open")
            rows = public_child(root / "reopened", executable, requests("crash", name, root), original=label == "original")
            observed = document(root / "observed.json")
            before = observed["before_reopen"]
            saved = document(root / "before-reopen-files.json")
            retained_files = {p.relative_to(root / "before-reopen").as_posix()
                              for p in (root / "before-reopen").rglob("*") if p.is_file()}
            need(retained_files == set(saved), "Pre-reopen raw snapshot members changed")
            normalized_saved = {}
            for key, identity_ in saved.items():
                need(not Path(key).is_absolute() and ".." not in Path(key).parts, "Pre-reopen snapshot traversal")
                check_identity(root / "before-reopen" / key, identity_)
                norm = key
                if key.startswith("..journal.head-v1.tmp-"):
                    match = re.fullmatch(r"(\.\.journal\.head-v1\.tmp-)(\d+)-(\d+)-(\d+)", key)
                    need(match is not None and int(match[2]) == trace["pid"], "Pre-reopen temporary PID is unbound")
                    norm = match[1] + "$PID-" + match[3] + "-" + match[4]
                need(norm not in normalized_saved, "Pre-reopen normalization collision")
                normalized_saved[norm] = identity_
            need({key for key, row in before.items() if row["kind"] == "regular"} == set(normalized_saved),
                 "Pre-reopen raw regular files were omitted")
            for key, identity_ in normalized_saved.items():
                need({field: before[key][field] for field in ("bytes", "sha256")} == identity_,
                     "Pre-reopen disk snapshot was replaced")
            answer = {"crashed_output_hex": raw.hex(), "before_reopen": before,
                      "reopened": [normalize_public(row, base) for row in rows],
                      "after_reopen": disk_files(base, tracee=trace["pid"])}
            need(observed == answer and case[label] == answer, "Crash/reopen actual response or disk state differs")
            answers.append(answer)
        need(answers[0] == answers[1], "Original/native durability boundary behavior differs")


def wal_replay_value(name, value):
    # payload.rs::parse_log rejects reused seen_sessions as Corrupt;
    # preview_replayed_state rejects duplicate sequence positions as Corrupt.
    # The public admit Replay error describes a different operation.
    expected = {"duplicate-sequence": 3, "reused-session": 3, "capacity-79": 102,
        "capacity-zero": 102, "exact-64m-truncated": 2, "over-64m": 8,
        "namespace-before-size": 10}.get(name, 0)
    need(type(value) is int and value == expected, "WAL boundary/error precedence changed")
    return expected


def wal(output, report, *, partition, replay, index, original, maximum_replay=None):
    from .qualification.wal_fixtures import blocks, inspect_tree, names, specification
    need(partition in {"small", "large", "maximum-replay", "maximum-index"}, "Unknown WAL partition")
    large = partition != "small"
    maximum = partition.startswith("maximum-")
    counts = {"small": (11, 18, 9), "large": (14, 21, 12),
              "maximum-replay": (1, 1, 1), "maximum-index": (1, 1, 0)}[partition]
    need(report.get("partition") == partition, "WAL observation partition changed")
    if partition == "maximum-index":
        need(report.get("original_comparison_mode") == "same-round-maximum-replay"
             and type(maximum_replay) is dict and report.get("maximum_replay") == maximum_replay,
             "Maximum index lacks its same-round replay and Rust binding")
        for row in maximum_replay.values():
            check_identity(row["path"], row["identity"])
        prior = document(maximum_replay["report"]["path"])
        need(prior.get("status") == "PASS" and prior.get("partition") == "maximum-replay"
             and prior.get("native_calls") == prior.get("original_cases") == 1
             and prior.get("original_comparison_mode") == "actual-fresh-original-invocation",
             "Maximum replay is incomplete or borrowed from a different partition")
    else:
        need(maximum_replay is None and report.get("maximum_replay") is None
             and report.get("original_comparison_mode") == "actual-fresh-original-invocation",
             "Fresh original WAL invocation was replaced by a reference")
    need(report.get("status") == "PASS" and report.get("source_inputs_stable") is True
         and report.get("fresh_original_comparison_complete") is True
         and report.get("full_four_tree_invariants") is True and report.get("failure") is None
         and type(report.get("original_cases")) is int and type(report.get("native_calls")) is int
         and report.get("original_cases") == counts[2]
         and report.get("native_calls") == counts[1]
         and report.get("maximum_record_count") == (176602 if large else 1281),
         "Complete WAL/index original comparison is absent")
    integer(report.get("elapsed_ns"))
    expected_names = (["maximal-aligned-sorted"] if maximum else
                      [name for name in names(large) if name != "maximal-aligned-sorted"])
    need([row["name"] for row in report["cases"]] == expected_names, "WAL fixture roster changed")
    process_rows = report["processes"]
    expected_processes = []
    original_rows, original_hash, original_size = [], hashlib.sha256(), 0
    original_header = word(counts[2])
    original_hash.update(original_header)
    original_size += len(original_header)
    native_stream = bytearray(original_header)
    for case in report["cases"]:
        name = case["name"]
        required = specification(name, large)
        need(all(case[key] == value for key, value in required.items())
             and case.get("status") == "PASS_NATIVE_AND_INDEX", "WAL case specification changed")
        source = output / "fixtures" / (name + ".input.raw")
        need(case["input"] == str(source), "WAL fixture path escaped its case")
        expected_hash, expected_size = hashlib.sha256(), 0
        for block in blocks(name, large):
            expected_hash.update(block)
            expected_size += len(block)
        input_identity = {"bytes": expected_size, "sha256": expected_hash.hexdigest()}
        need(case["input_identity"] == input_identity and file_identity(source) == input_identity,
             "Retained WAL differs from the complete deterministic authenticated fixture")
        if maximum_replay is not None:
            need(input_identity == maximum_replay["input"]["identity"],
                 "Maximum index/replay fixtures do not have identical complete bytes")
        modes = ((partition.removeprefix("maximum-"),) if maximum else
                 ("replay", "index") if required["observe_index"] else ("replay",))
        need([row["mode"] for row in case["observations"]] == list(modes), "WAL index observations were omitted")
        for mode, observed in zip(modes, case["observations"], strict=True):
            label = name + "-" + mode
            expected_processes.append(label)
            artifact = replay if mode == "replay" else index
            result = output / "results" / label
            request_path = output / "requests" / (label + ".json")
            request = {"input": str(source), "input_identity": input_identity,
                       "output_size": required["output_size"], "mode": mode, "output": str(result),
                       "library": str(artifact), "library_identity": file_identity(artifact)}
            need(document(request_path) == request, "Actual private WAL call request changed")
            child = next(row for row in process_rows if row["name"] == label)
            child_success(output / "processes" / label, child,
                [sys.executable, "-I", "-S", "-B", HERE / "qualification/wal_worker.py", request_path], cwd=output)
            need(child.get("stdin_path") == "/dev/null" and child.get("stdin") == identity(b""),
                 "Native WAL worker received an unexpected standard input")
            value = document(result / "report.json")
            check_identity(result / "report.json", observed["report"])
            need(value.get("status") == "ACTUAL_NATIVE_RETURNED" and value.get("mode") == mode
                 and value.get("request") == file_identity(request_path)
                 and value.get("library") == file_identity(artifact) and value.get("input") == input_identity
                 and value.get("abi_status") == 0 and type(value["abi_status"]) is int
                 and value.get("guards_preserved") is True and value.get("read_only_argument_unchanged") is True
                 and value.get("host_compiler_modules_loaded") == []
                 and value.get("whole_payload_owner_qualified") is False
                 and value.get("original_service_budget_qualified") is False and value.get("error") is None,
                 "Private WAL call failed its exact guards or loaded host compiler logic")
            need(json.loads(capture(output / "processes" / label / "stdout.raw")) == value,
                 "Private WAL worker stdout differs from its retained result")
            integer(value["native_elapsed_ns"])
            need(observed["native_elapsed_ns"] == value["native_elapsed_ns"]
                 and observed["value"] == value["value"] and observed["output"] == value["output"],
                 "WAL observation summary was replaced")
            check_identity(result / "output.raw", value["output"])
            raw = capture(result / "output.raw")
            need(len(raw) == required["output_size"], "WAL output extent changed")
            if mode == "replay":
                need(value["input_argument_bytes"] == expected_size
                     and value["input_argument_sha256"] == input_identity["sha256"]
                     and value["initial_work_bytes"] == 137
                     and value["initial_work_sha256"] == identity(b"\x73" * 137)["sha256"],
                     "Replay private arguments differ from the recorded fixture")
                expected_code = wal_replay_value(name, value["value"])
                if expected_code:
                    need(raw == b"\xa5" * len(raw), "Rejected WAL call wrote public output")
                else:
                    need(number(raw) == 72 and raw[80:] == b"\xa5" * (len(raw) - 80),
                         "Successful WAL call wrote beyond the summary")
                if required["output_size"] == 256:
                    header = word(8, expected_size - 8)
                    original_hash.update(header)
                    original_size += len(header)
                    with source.open("rb") as stream:
                        need(stream.read(8) == word(1), "Replay private opcode changed")
                        while chunk := stream.read(1 << 20):
                            original_hash.update(chunk)
                            original_size += len(chunk)
                    answer = b"" if expected_code else raw[8:80]
                    native_stream.extend(word(expected_code, len(answer)) + answer)
                    original_rows.append((expected_code, answer))
            else:
                count, wal_size = (expected_size - 144) // 380, expected_size - 144
                need(value["value"] == 0 and value["input_argument_bytes"] == 8
                     and value["input_argument_sha256"] == identity(word(count))["sha256"]
                     and value["initial_work_bytes"] == 8192 + wal_size + count * 128
                     and raw == b"\xa5" * len(raw), "Private index entry shape or result changed")
                check_identity(result / "work.raw", value["work"])
                header = bytearray(8192)
                with source.open("rb") as stream:
                    need(stream.read(8) == word(1), "Index private opcode changed")
                    header[2048:2184] = stream.read(136)
                    struct.pack_into("<Q", header, 1544, count)
                    for mode_ in range(4):
                        struct.pack_into("<Q", header, 1552 + mode_ * 8, 8192 + wal_size + mode_ * count * 32)
                    initial_hash = hashlib.sha256(header)
                    while chunk := stream.read(1 << 20): initial_hash.update(chunk)
                remaining = count * 128
                while remaining:
                    amount = min(remaining, 1 << 20)
                    initial_hash.update(bytes(amount)); remaining -= amount
                need(value["initial_work_sha256"] == initial_hash.hexdigest(), "Index input arena was substituted")
                tree = inspect_tree(result / "work.raw", source)
                need(observed["index"] == tree and tree["whole_tree_invariants"] is True
                     and tree["summary_hex"] == capture(Path(maximum_replay["output"]["path"]) if maximum_replay else
                         output / "results" / (name + "-replay") / "output.raw")[8:80].hex(),
                     "Actual complete four-index state is inconsistent with native replay")
    if maximum_replay is not None:
        need([row["name"] for row in process_rows] == expected_processes
             and len(original_rows) == 0
             and all(report.get(key) is None for key in ("original_input", "original_output", "native_output"))
             and not (output / "processes/original-parser").exists()
             and not (output / "original-input.raw").exists(),
             "Maximum index falsely claims a new original invocation")
        actual_original = capture(Path(maximum_replay["original_output"]["path"]))
        need(actual_original == word(1, 0, 72) + capture(Path(maximum_replay["output"]["path"]))[8:80],
             "Maximum index summary is not bound to actual same-round Rust output")
        return {"cases": 1, "native_calls": 1, "original_cases": 0}
    expected_processes.append("original-parser")
    need([row["name"] for row in process_rows] == expected_processes, "WAL child process roster changed")
    need(len(original_rows) == counts[2], "Original WAL parser was not run on every applicable case")
    input_identity = {"bytes": original_size, "sha256": original_hash.hexdigest()}
    need(report["original_input"] == input_identity and file_identity(output / "original-input.raw") == input_identity
         and capture(output / "native-output.raw") == bytes(native_stream)
         and report["native_output"] == identity(bytes(native_stream)), "WAL original/native stream binding changed")
    child = process_rows[-1]
    directory = output / "processes/original-parser"
    child_success(directory, child, [original, output / "original-private-store"], cwd=output)
    need(child.get("stdin_path") == str(output / "original-input.raw")
         and child.get("stdin") == input_identity, "Original parser received different stdin")
    need(capture(directory / "stdout.raw") == bytes(native_stream)
         and report["original_output"] == identity(bytes(native_stream))
         and private_outputs(bytes(native_stream), len(original_rows)) == original_rows,
         "Fresh original parser disagrees with the complete native WAL outputs")
    return {"cases": len(expected_names), "native_calls": report["native_calls"], "original_cases": len(original_rows)}
