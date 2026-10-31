#!/usr/bin/env python3
"""Read bounded actor cost sidecars without changing the historical v3 verdict.

CPU readings are local observations, not authentic work or fairness proofs. The
outer actor-thread interval includes setup and discarded preparations; nested
stage readings must never be added to that interval a second time.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import time

import check_pure_pon_pressure_v2 as pressure

SCHEMA = "pon-pure-attacker-cost-v1"
REPORT_SCHEMA = "pon-pure-attacker-cost-observation-v1"
FILE = "attacker-cost-v1.json"
BINDING_SCHEMA = "pon-pure-attacker-cost-binding-v1"
BINDING_FILE = "attacker-cost-binding-v1.json"
CPU_WALL_TOLERANCE = 1_000_000
CAPTURE_BUDGET = 5_000_000_000
REPORT_LIMIT = 64 * 1024 * 1024
COST_LIMIT = 2 * 1024 * 1024
BINDING_LIMIT = 1024 * 1024
BINDING_SCOPE = ("Parent capture of fixed actor file bytes after original joins and service stop; "
                 "independent SHA256/length/terminal/count binding, not hostile-host authenticity or CPU "
                 "attestation. Read deadline is cooperative between bounded filesystem reads.")
SCOPE = ("Observed actor test-thread CPU from attack entry through loop exit, including setup, "
         "diagnostic generation/rejection, waiting, all preparations, calls and in-loop evidence work. "
         "Nested preparation/call observations are not additional CPU. Excludes process startup, "
         "job loading, other threads and final evidence serialization/writes; not whole-process or "
         "receiver-owner CPU.")
require = pressure.require


def natural(value):
    return pressure.natural(value) and value <= pressure.U64_MAX


def cpu(value):
    require(value is None or natural(value), "CPU observation must be integer or null")
    return value


def cpu_sum(values):
    values = [cpu(v) for v in values]
    known = sum(v for v in values if v is not None)
    missing = sum(v is None for v in values)
    return {"known_ns": known, "unknown_count": missing,
            "total_ns": None if missing else known}


def boundary(value):
    require(type(value) is dict and all(natural(value[k]) for k in
            ("started_monotonic_ns", "ended_monotonic_ns")), "cost boundary clock")
    require(value["started_monotonic_ns"] <= value["ended_monotonic_ns"], "cost sample reversed")
    cpu(value["thread_cpu_ns"])


def interval(start, end):
    require(start["ended_monotonic_ns"] <= end["started_monotonic_ns"], "cost interval reversed")
    a, b = cpu(start["thread_cpu_ns"]), cpu(end["thread_cpu_ns"])
    if a is None or b is None:
        return None
    require(a <= b, "actor CPU counter regressed")
    # The CPU read lies inside each retained monotonic sample bracket. A single
    # actor thread cannot consume more than one CPU at once. The fixed 1ms
    # cross-clock tolerance is only an inconsistency diagnostic, not physical
    # clock authenticity or evidence of kernel scheduling isolation.
    span = end["ended_monotonic_ns"] - start["started_monotonic_ns"]
    require(b - a <= span + CPU_WALL_TOLERANCE, "single-thread CPU exceeds acquisition brackets")
    return b - a


def diagnostic_trials(actor, cost, business):
    trials = cost["diagnostic_generation_trials"]
    require(type(trials) is int and 1 <= trials <= 4096, "diagnostic target trial cap")
    nonce = 10_000_000 + actor["actor"] * 1_000_000
    header = business[0]["header"][:310] + struct.pack("<Q", nonce)
    challenge = pressure.wire_hash(b"challenge", header)
    for trial in range(trials):
        trace = pressure.wire_hash(b"pure-pressure-false-trace-v2", challenge, bytes(8), struct.pack("<Q", trial))
        hit = pressure.wire_hash(b"ticket", challenge, trace) <= header[118:150]
        require(hit is (trial == trials - 1), "omitted diagnostic target trial")
    return trials


def preparation_packet(row, actor, business):
    """Recompute every target trial, including preparations never sent to TCP."""
    sequence = row["sequence"]
    header = pressure.raw_hex(row["header"], 318)
    nonce = 10_000_000 + actor["actor"] * 1_000_000
    if actor["mode"] != "from-zero":
        nonce += sequence
    require(header == business[0]["header"][:310] + struct.pack("<Q", nonce),
            "prepared challenge stream changed")
    challenge, trace = pressure.wire_hash(b"challenge", header), pressure.raw_hex(row["trace"], 32)
    trials = row["generation_trials"]
    require(type(trials) is int and 1 <= trials <= 4096, "prepared target trial cap")
    for trial in range(trials):
        candidate = pressure.wire_hash(b"pure-pressure-false-trace-v2", challenge,
                                       struct.pack("<Q", sequence), struct.pack("<Q", trial))
        hit = pressure.wire_hash(b"ticket", challenge, candidate) <= header[118:150]
        require(hit is (trial == trials - 1), "omitted prepared target trial")
    require(candidate == trace, "invented prepared trace")
    prefix = pressure.raw_hex(actor["acquisition"]["proof_prefix"], pressure.PREFIX_BYTES)
    transactions = business[0]["transactions"]
    packet = header + struct.pack("<H", len(transactions)) + b"".join(
        struct.pack("<H", len(tx)) + tx for tx in transactions) + prefix + trace
    digest = hashlib.sha256(packet).hexdigest()
    require(row["packet_sha256"] == digest, "unbound prepared packet")
    return digest, pressure.body_digest({"op": "submit", "packet": packet.hex()})


def check_actor(actor, cost, epoch, business, seen_packets):
    require(cost["schema"] == SCHEMA and cost["scope"] == SCOPE, "attacker cost namespace or scope")
    require(type(cost["actor"]) is int and cost["actor"] == actor["actor"]
            and natural(cost["pid"]) and cost["pid"] > 0 and cost["pid"] == actor["pid"],
            "attacker cost owner binding")
    require(type(cost["owner_thread"]) is str and len(cost["owner_thread"]) <= 64
            and re.fullmatch(r"ThreadId\([0-9]+\)", cost["owner_thread"]), "actor thread label")
    require(cost["mode"] == actor["mode"] and cost["policy"] == actor["policy"]
            and natural(cost["epoch_monotonic_ns"]) and cost["epoch_monotonic_ns"] == epoch,
            "attacker cost phase binding")
    require(type(cost["window_ns"]) is int and cost["window_ns"] == pressure.WINDOW
            and type(cost["actor_call_cap"]) is int and cost["actor_call_cap"] == pressure.CALL_CAP,
            "attacker cost envelope")
    require(type(cost["cpu_wall_bracket_tolerance_ns"]) is int
            and cost["cpu_wall_bracket_tolerance_ns"] == CPU_WALL_TOLERANCE
            and cost["physical_cpu_authentication"] is False, "CPU bracket scope or tolerance")
    require(cost["template_acquisition_search_trials"] is None
            and cost["template_acquisition_search_trials_observed"] is False,
            "unobserved template acquisition searches cannot become known zero")
    diagnostic = diagnostic_trials(actor, cost, business)
    require(all(cost[k] is False for k in
            ("public_fairness_qualified", "work_hardness_qualified", "production_qualified")),
            "cost observation claimed authority")
    entry, start, end = (cost[k] for k in ("entry", "loop_entry", "loop_exit"))
    for sample in (entry, start, end):
        boundary(sample)
    require(entry["ended_monotonic_ns"] <= epoch <= start["started_monotonic_ns"]
            and end["ended_monotonic_ns"] <= epoch + actor["finished_ns"], "actor cost epoch order")
    before_loop, loop_cpu, outer_cpu = interval(entry, start), interval(start, end), interval(entry, end)
    rows, calls = cost["preparations"], actor["calls"]
    require(type(rows) is list and len(rows) <= pressure.CALL_CAP, "preparation evidence cap")
    ordered = [entry, start]
    previous_clock = start["ended_monotonic_ns"]
    issued, unissued, trials = 0, 0, 0
    preparation_cpu, inner_cpu = [], []
    for sequence, row in enumerate(rows):
        require(natural(row["sequence"]) and row["sequence"] == sequence, "missing or duplicate preparation")
        begin, finish = row["begin"], row["end"]
        boundary(begin)
        boundary(finish)
        ordered.extend((begin, finish))
        gate, phase_gate = row["iteration_gate_monotonic_ns"], row["phase_gate_monotonic_ns"]
        require(natural(gate) and natural(phase_gate)
                and epoch <= gate < epoch + pressure.WINDOW
                and previous_clock <= gate <= begin["started_monotonic_ns"]
                and finish["ended_monotonic_ns"] <= phase_gate,
                "preparation original gate order")
        measured = interval(begin, finish)
        require(cpu(row["preparation_thread_cpu_ns"]) == measured, "invented preparation CPU")
        inner = cpu(row["inner_preparation_thread_cpu_ns"])
        require(measured is None or inner is None or inner <= measured, "nested preparation CPU exceeds outer")
        preparation_cpu.append(measured)
        inner_cpu.append(inner)
        digest, body = preparation_packet(row, actor, business)
        require(digest not in seen_packets, "duplicate prepared packet")
        seen_packets.add(digest)
        trials += row["generation_trials"]
        disposition, call_entry = row["disposition"], row["call_entry_monotonic_ns"]
        require(call_entry is None or natural(call_entry), "call-entry observation")
        if disposition == "issued":
            require(not unissued and sequence < len(calls), "unassociated issued preparation")
            call = calls[sequence]
            require(type(row["call_index"]) is int and row["call_index"] == sequence
                    and row["call_body_digest"] == body == call["body_digest"], "prepared call association")
            require(call_entry is not None and phase_gate < epoch + pressure.WINDOW
                    and phase_gate <= call_entry == epoch + call["started_ns"] < epoch + pressure.WINDOW,
                    "issued call crossed original gate")
            require(all(row[k] == call[k] for k in
                    ("sequence", "header", "trace", "generation_trials", "packet_sha256"))
                    and inner == cpu(call["preparation_thread_cpu_ns"]), "issued preparation changed")
            previous_clock = epoch + call["ended_ns"]
            require(previous_clock >= call_entry, "issued call clock reversed")
            issued += 1
        else:
            require(sequence == len(rows) - 1 == len(calls) and not unissued
                    and row["call_index"] is None and row["call_body_digest"] is None,
                    "unissued preparation must be final and cannot invent a call")
            if disposition == "phase_closed_after_preparation":
                require(call_entry is None and phase_gate >= epoch + pressure.WINDOW,
                        "invented post-preparation phase closure")
                previous_clock = phase_gate
            else:
                require(disposition == "phase_closed_at_call_entry"
                        and phase_gate < epoch + pressure.WINDOW and call_entry is not None
                        and call_entry >= epoch + pressure.WINDOW and call_entry >= phase_gate,
                        "invented call-entry phase closure")
                previous_clock = call_entry
            unissued += 1
    require(issued == len(calls), "omitted issued preparation")
    terminal = cost["loop_terminal"]
    require(natural(terminal["sequence"]) and natural(terminal["observed_monotonic_ns"]),
            "loop terminal types")
    if unissued:
        last = rows[-1]
        require(terminal == {"reason": last["disposition"], "sequence": last["sequence"],
                             "observed_monotonic_ns": previous_clock}, "omitted final preparation")
    else:
        require(terminal["sequence"] == len(calls) and terminal["observed_monotonic_ns"] >= previous_clock,
                "loop terminal omitted issued call")
        if terminal["reason"] == "call_cap":
            require(len(calls) == pressure.CALL_CAP and terminal["observed_monotonic_ns"] < epoch + pressure.WINDOW,
                    "invented call-cap termination")
        else:
            require(terminal["reason"] == "phase_closed_before_preparation"
                    and terminal["observed_monotonic_ns"] >= epoch + pressure.WINDOW,
                    "loop stopped without original phase or cap gate")
    require(terminal["observed_monotonic_ns"] <= end["started_monotonic_ns"], "loop exited before terminal")
    ordered.append(end)
    last_cpu = None
    for previous, current in zip(ordered, ordered[1:]):
        require(previous["ended_monotonic_ns"] <= current["started_monotonic_ns"], "overlapping actor cost samples")
    for sample in ordered:
        value = sample["thread_cpu_ns"]
        if value is not None:
            require(last_cpu is None or last_cpu <= value, "actor CPU counter regressed")
            last_cpu = value
    prep = cpu_sum(preparation_cpu)
    expected = {"prepared_attempts": len(rows), "issued_calls": issued,
                "unissued_preparations": unissued, "loop_generation_trials": trials,
                "known_preparation_thread_cpu_ns": prep["known_ns"],
                "unknown_preparation_cpu_count": prep["unknown_count"],
                "preparation_thread_cpu_ns": prep["total_ns"]}
    summary = cost["summary"]
    require(type(summary) is dict and set(summary) == set(expected)
            and all(v is None or natural(v) for v in summary.values()) and summary == expected,
            "preparation cost totals contradict retained rows")
    call_cpu = cpu_sum([row["thread_cpu_ns"] for row in calls])
    require(loop_cpu is None or prep["known_ns"] + call_cpu["known_ns"] <= loop_cpu,
            "nested loop observations double-counted or exceed owner interval")
    setup_cpu = cpu_sum([actor["acquisition"]["thread_cpu_ns"], actor["diagnostic_thread_cpu_ns"]])
    require(before_loop is None or setup_cpu["known_ns"] <= before_loop,
            "nested setup observations exceed owner interval")
    complete = (all(s["thread_cpu_ns"] is not None for s in ordered)
                and all(v is not None for v in inner_cpu)
                and call_cpu["unknown_count"] == setup_cpu["unknown_count"] == 0)
    return {"actor": actor["actor"], "pid": actor["pid"], **expected,
            "diagnostic_generation_trials": diagnostic,
            "counted_false_trace_generation_trials": trials + diagnostic,
            "template_acquisition_search_trials": None,
            "template_acquisition_search_trials_observed": False,
            "before_loop_thread_cpu_ns": before_loop, "loop_thread_cpu_ns": loop_cpu,
            "entry_through_loop_exit_thread_cpu_ns": outer_cpu,
            "nested_call_thread_cpu": call_cpu, "nested_setup_thread_cpu": setup_cpu,
            "cpu_observation_complete": bool(complete)}


def parse_raw(raw, limit):
    require(type(raw) is bytes and len(raw) <= limit and raw.endswith(b"\n"), "bounded complete capture bytes")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate captured JSON key")
            value[key] = item
        return value

    def finite(text):
        value = float(text)
        require(math.isfinite(value), "nonfinite captured JSON number")
        return value

    def invalid(_):
        raise ValueError("nonfinite captured JSON number")

    return json.loads(raw, object_pairs_hook=unique, parse_float=finite, parse_constant=invalid)


def check_bindings(phases, sidecars, bindings, captured):
    require(type(bindings) is dict and type(captured) is dict, "parent raw binding capture required")
    require(set(bindings) == set(pressure.PHASES), "parent binding phase coverage")
    expected = set()
    for phase in phases:
        name, wrappers = phase["phase"], phase["actors"]
        binding = bindings[name]
        require(binding["schema"] == BINDING_SCHEMA and binding["scope"] == BINDING_SCOPE
                and binding["phase"] == name and binding["physical_authentication"] is False,
                "parent binding namespace or authority")
        require(binding["capture_complete"] is True, "parent capture explicitly incomplete")
        require(natural(binding["parent_pid"]) and binding["parent_pid"] > 0
                and natural(binding["started_monotonic_ns"]) and natural(binding["ended_monotonic_ns"])
                and phase["epoch_monotonic_ns"] + pressure.WINDOW <= binding["started_monotonic_ns"]
                <= binding["ended_monotonic_ns"], "parent capture clock or owner")
        require(type(binding["read_budget_ns"]) is int and binding["read_budget_ns"] == CAPTURE_BUDGET
                and binding["ended_monotonic_ns"] - binding["started_monotonic_ns"] <= CAPTURE_BUDGET
                and type(binding["actor_report_limit"]) is int and binding["actor_report_limit"] == REPORT_LIMIT
                and type(binding["actor_cost_limit"]) is int and binding["actor_cost_limit"] == COST_LIMIT,
                "parent capture resource bounds")
        population = 0 if name == "baseline" else pressure.ATTACKERS
        rows = binding["actors"]
        require(type(binding["expected_actors"]) is int and binding["expected_actors"] == population
                and type(rows) is list and len(rows) == len(wrappers) == population, "parent binding actor coverage")
        for index, (wrapper, row) in enumerate(zip(wrappers, rows)):
            key = (name, index)
            require(key in sidecars and key in captured, "missing parent-bound actor evidence")
            expected.add(key)
            require(type(row["actor"]) is int and row["actor"] == index
                    and row["actor_directory"] == f"actor-{index}"
                    and natural(row["pid"]) and row["pid"] == wrapper["pid"]
                    and row["pid"] != binding["parent_pid"], "parent binding fixed actor path or pid")
            require(row["capture_complete"] is True and row["actor_report_matches_phase"] is True
                    and row["exit_success"] is wrapper["exit_success"] is True
                    and row["parent_forced_kill"] is wrapper["parent_forced_kill"] is False,
                    "parent actor capture incomplete")
            require(set(row["files"]) == {"report.json", FILE}
                    and set(captured[key]) == {"report.json", FILE}, "parent file binding coverage")
            parsed = {}
            for filename, limit in (("report.json", REPORT_LIMIT), (FILE, COST_LIMIT)):
                raw, identity = captured[key][filename], row["files"][filename]
                require(type(raw) is bytes and natural(identity["bytes"])
                        and identity["bytes"] == len(raw) <= limit and identity["error"] is None,
                        "parent-bound raw file length or error")
                require(identity["sha256"] == hashlib.sha256(raw).hexdigest(), "parent-bound raw SHA256 mismatch")
                parsed[filename] = parse_raw(raw, limit)
            require(parsed["report.json"] == wrapper["report"] and parsed[FILE] == sidecars[key],
                    "parsed evidence differs from parent-bound raw bytes")
            actor, cost = parsed["report.json"]["result"], sidecars[key]
            require(actor["actor"] == index and actor["pid"] == row["pid"]
                    and natural(row["report_issued_calls"]) and row["report_issued_calls"] == len(actor["calls"])
                    and natural(row["report_finished_ns"]) and row["report_finished_ns"] == actor["finished_ns"]
                    and phase["epoch_monotonic_ns"] + actor["finished_ns"] <= binding["started_monotonic_ns"],
                    "parent report terminal or count binding")
            require(row["sidecar_summary"] == cost["summary"] and row["sidecar_terminal"] == cost["loop_terminal"],
                    "parent sidecar terminal or count binding")
    require(set(sidecars) == set(captured) == expected, "unassociated parent-bound actor evidence")


def check(manifest, prepared, phases, sidecars, bindings=None, captured=None):
    # Verify the parent's independently captured exact bytes before interpreting
    # the actor's self-reported rows, counts or terminal. This is provenance
    # binding only: a hostile host could rewrite the actor, parent and phase files.
    check_bindings(phases, sidecars, bindings, captured)
    # Preserve the old reader and all its service/failure predicates verbatim.
    original = pressure.check(manifest, prepared, phases)
    business = pressure.preparation(prepared)
    expected, reports = set(), []
    for phase in phases:
        name, actors, seen_packets = phase["phase"], [], set()
        for wrapper in phase["actors"]:
            require(wrapper["exit_success"] is True and wrapper["parent_forced_kill"] is False
                    and wrapper["report"] is not None and wrapper["report"]["error"] is None,
                    "actor did not complete; complete cost evidence unavailable")
            actor = wrapper["report"]["result"]
            require(natural(wrapper["pid"]) and wrapper["pid"] == actor["pid"], "actor process binding")
            key = (name, actor["actor"])
            require(key not in expected and key in sidecars, "missing or duplicate actor cost sidecar")
            expected.add(key)
            actors.append(check_actor(actor, sidecars[key], phase["epoch_monotonic_ns"], business, seen_packets))
        reports.append({"phase": name, "actors": actors,
                        "prepared_attempts": sum(a["prepared_attempts"] for a in actors),
                        "issued_calls": sum(a["issued_calls"] for a in actors),
                        "unissued_preparations": sum(a["unissued_preparations"] for a in actors),
                        "loop_generation_trials": sum(a["loop_generation_trials"] for a in actors),
                        "diagnostic_generation_trials": sum(a["diagnostic_generation_trials"] for a in actors),
                        "counted_false_trace_generation_trials": sum(a["counted_false_trace_generation_trials"] for a in actors),
                        "actor_entry_through_loop_exit_thread_cpu": cpu_sum(
                            [a["entry_through_loop_exit_thread_cpu_ns"] for a in actors]),
                        "cpu_observation_complete": all(a["cpu_observation_complete"] for a in actors)})
    require(set(sidecars) == expected, "unassociated actor cost sidecar")
    return {"schema": REPORT_SCHEMA, "input_consistent": True,
            "parent_byte_bindings_verified": True, "physical_cpu_authentication": False,
            "cpu_wall_bracket_tolerance_ns": CPU_WALL_TOLERANCE,
            "template_acquisition_search_trials": None, "template_acquisition_search_trials_observed": False,
            "all_hash_search_attempts_observed": False,
            "preparation_coverage_complete": True,
            "cpu_observation_complete": all(p["cpu_observation_complete"] for p in reports),
            "original_pressure_finite_qualification": original["finite_qualification"],
            "phases": reports, "scope": SCOPE,
            "public_fairness_qualified": False, "work_hardness_qualified": False,
            "production_qualified": False, "installation_authorized": False}


def open_directory(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    held = os.open("/" if path.is_absolute() else ".", flags)
    try:
        for component in path.parts:
            if component in ("/", "."):
                continue
            require(component not in ("", "..") and "/" not in component, "capture directory traversal")
            child = os.open(component, flags, dir_fd=held)
            os.close(held)
            held = child
        return held
    except BaseException:
        os.close(held)
        raise


def safe_read(directory, parts, limit, deadline):
    held, file = os.dup(directory), None
    try:
        for component in parts[:-1]:
            require(component not in ("", ".", "..") and "/" not in component, "fixed capture basename")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
            os.close(held)
            held = child
        require(parts[-1] not in ("", ".", "..") and "/" not in parts[-1], "fixed capture basename")
        require(time.monotonic() < deadline, "capture read deadline")
        file = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=held)
        before = os.fstat(file)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "capture file type or byte limit")
        raw = bytearray()
        while True:
            require(time.monotonic() < deadline, "capture read deadline")
            chunk = os.read(file, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            require(len(raw) <= limit, "capture file byte limit")
        after = os.fstat(file)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(time.monotonic() < deadline and len(raw) == before.st_size
                and identity(before) == identity(after), "capture file changed or deadline elapsed")
        return bytes(raw)
    finally:
        if file is not None:
            os.close(file)
        os.close(held)


def check_directory(directory):
    held = open_directory(directory)
    try:
        # This reader's cooperative local I/O budget does not modify any actor
        # request window. Arithmetic/association checks happen after bounded reads.
        deadline = time.monotonic() + 30
        load = lambda parts, limit=REPORT_LIMIT: parse_raw(safe_read(held, parts, limit, deadline), limit)
        manifest, prepared = load(("campaign.json",)), load(("preparation.json",))
        phases = [load((p + ".json",)) for p in pressure.PHASES]
        sidecars, bindings, captured = {}, {}, {}
        for name in pressure.PHASES:
            bindings[name] = load((name, BINDING_FILE), BINDING_LIMIT)
            population = 0 if name == "baseline" else pressure.ATTACKERS
            phase_dir = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
            try:
                actor_paths = {entry for entry in os.listdir(phase_dir) if entry.startswith("actor-")}
                require(actor_paths == {f"actor-{i}" for i in range(population)}, "sidecar path binding or population")
            finally:
                os.close(phase_dir)
            for index in range(population):
                key = (name, index)
                captured[key] = {filename: safe_read(held, (name, f"actor-{index}", filename), limit, deadline)
                                 for filename, limit in (("report.json", REPORT_LIMIT), (FILE, COST_LIMIT))}
                sidecars[key] = parse_raw(captured[key][FILE], COST_LIMIT)
        return check(manifest, prepared, phases, sidecars, bindings, captured)
    finally:
        os.close(held)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-observed-cpu", action="store_true")
    args = parser.parse_args()
    try:
        result = check_directory(args.directory)
    except (ValueError, KeyError, TypeError, OSError, RecursionError) as error:
        result = {"schema": REPORT_SCHEMA, "input_consistent": False,
                  "preparation_coverage_complete": False, "cpu_observation_complete": False,
                  "parent_byte_bindings_verified": False, "physical_cpu_authentication": False,
                  "error": str(error), "public_fairness_qualified": False,
                  "work_hardness_qualified": False, "production_qualified": False,
                  "installation_authorized": False}
    raw = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
    print(raw, end="")
    return 0 if result["input_consistent"] and (
        not args.require_observed_cpu or result["cpu_observation_complete"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
