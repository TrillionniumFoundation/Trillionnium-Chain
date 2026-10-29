#!/usr/bin/env python3
"""Read exact-parent wait4 costs without changing the original service verdict."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import time

import check_pure_pon_attacker_cost_v1 as thread_cost

require = thread_cost.require
natural = thread_cost.natural
FILE = "attacker-process-cost-v1.json"
SCHEMA = "pon-pure-attacker-process-cost-v1"
RESULT_SCHEMA = "pon-pure-process-cost-observation-v2"
LOG_LIMIT = 1024 * 1024
SCOPE = ("Parent single-reap wait4 observations for each original actor PID, bound to complete report, "
         "thread-cost sidecar and final log bytes after original cleanup. Whole actor process costs are "
         "separate from receiver costs; nested CPU is not added twice.")
WAIT_SCOPE = ("Linux wait4 resource usage for the exact reaped child, including startup, all child threads, "
              "final output and process teardown, and any waited-descendant usage included by the kernel. "
              "Excludes parent and unrelated sibling processes; nested thread observations are not added "
              "to this enclosing total.")
CPU_TOLERANCE_NS = 1_000_000
FAMILY_FILE = "actor-family-observation-v1.json"
FAMILY_SCOPE = ("Bounded Linux per-thread child census and actual RUSAGE_SELF/RUSAGE_CHILDREN after owned work. "
                "A stable empty census is an observation, not an authenticated proof of absence; waited-child "
                "CPU is nested inside Linux wait4 totals and must not be added twice.")
PROBE_SCOPE = ("One non-reaping Linux waitid(P_ALL, WEXITED|WNOHANG|WNOWAIT|__WALL) with unchanged SIG_DFL and no SA_NOCLDWAIT. "
               "ECHILD observes no eligible children at this probe, not CLONE_THREAD joins, CLONE_PARENT causal siblings, "
               "historical cost completeness or physical authentication.")
PROBE_BINDING_SCOPE = ("Parent exact-byte binding of independent non-reaping child-ownership probes after single-reap cost capture; "
                       "not authentication or a replacement for preserved procfs failures.")
PROBE_OPTIONS = 4 | 1 | 0x01000000 | 0x40000000
PROBE_NAMES = ["P_ALL", "WEXITED", "WNOHANG", "WNOWAIT", "__WALL"]


def timeval_ns(seconds, micros):
    require(type(seconds) is int and type(micros) is int, "wait4 raw timeval type")
    if seconds < 0 or not 0 <= micros < 1_000_000:
        return None
    value = seconds * 1_000_000_000 + micros * 1000
    return value if value <= (1 << 64) - 1 else None


def check_wait4(value, pid, parent_pid, capture_started, nested=None):
    require(value["schema"] == "pon-child-wait4-cost-v1" and value["scope"] == WAIT_SCOPE,
            "wait4 schema/scope")
    require(natural(pid) and pid > 0 and natural(parent_pid) and parent_pid > 0
            and type(value["pid"]) is int and type(value["parent_pid"]) is int
            and value["pid"] == pid and value["parent_pid"] == parent_pid and pid != parent_pid,
            "wait4 exact child/parent PID")
    require(type(value["successful_reaps"]) is int and value["successful_reaps"] == 1
            and natural(value["wait4_calls"]) and value["wait4_calls"] >= 1
            and value["error"] is None and value["physical_authentication"] is False,
            "wait4 single successful reap required")
    keys = ("spawn_started_monotonic_ns", "spawn_finished_monotonic_ns",
            "reap_started_monotonic_ns", "reap_finished_monotonic_ns")
    require(all(natural(value[k]) for k in keys) and natural(capture_started), "wait4 clock type")
    a, b, c, d = (value[k] for k in keys)
    require(a <= b <= c <= d <= capture_started, "wait4 lifetime clock order")
    status = value["raw_wait_status"]
    require(type(status) is int and 0 <= status <= 65535 and status & 0x7f != 0x7f,
            "wait4 terminal status")
    require(type(value["exit_success"]) is bool and value["exit_success"] is (status == 0)
            and type(value["parent_forced_kill"]) is bool, "wait4 exit/kill status")
    usage = value["rusage"]
    require(type(usage) is dict, "wait4 resource sample absent")
    user = timeval_ns(usage["user_seconds"], usage["user_microseconds"])
    system = timeval_ns(usage["system_seconds"], usage["system_microseconds"])
    total = None if user is None or system is None or user + system > (1 << 64) - 1 else user + system
    for key, expected in (("user_cpu_ns", user), ("system_cpu_ns", system), ("total_cpu_ns", total)):
        require((usage[key] is None if expected is None else natural(usage[key]) and usage[key] == expected),
                "wait4 CPU conversion/unknown propagation")
    for key in ("max_rss_kib", "minor_faults", "major_faults", "input_blocks", "output_blocks",
                "voluntary_context_switches", "involuntary_context_switches"):
        require(usage[key] is None or natural(usage[key]), "wait4 optional resource type")
    if nested is not None:
        require(a <= nested["entry"]["started_monotonic_ns"]
                <= nested["loop_exit"]["ended_monotonic_ns"] <= d, "thread outside child lifetime")
        cpu = thread_cost.interval(nested["entry"], nested["loop_exit"])
        if cpu is not None and total is not None:
            require(cpu <= total + CPU_TOLERANCE_NS, "nested thread CPU exceeds whole child")
    return {"pid": pid, "total_cpu_ns": total, "user_cpu_ns": user, "system_cpu_ns": system,
            "max_rss_kib": usage["max_rss_kib"], "exit_success": value["exit_success"],
            "parent_forced_kill": value["parent_forced_kill"], "cpu_observed": total is not None}


def check_family(value, wait4, nested=None, require_subreaper=False):
    require(value["schema"] == "pon-process-family-observation-v1" and value["scope"] == FAMILY_SCOPE
            and value["pid"] == wait4["pid"] and type(value["pid"]) is int
            and value["physical_authentication"] is False, "family observation identity/scope")
    begin, end = value["started_monotonic_ns"], value["ended_monotonic_ns"]
    require(natural(begin) and natural(end) and wait4["spawn_started_monotonic_ns"] <= begin <= end
            <= wait4["reap_finished_monotonic_ns"], "family observation lifetime")
    if nested is not None:
        require(nested["loop_exit"]["ended_monotonic_ns"] <= begin, "family observation preceded owned loop")
    require(type(value["capture_complete"]) is bool and type(value["thread_set_stable"]) is bool
            and type(value["no_live_or_unreaped_children_observed"]) is bool
            and (value["child_subreaper"] is None or type(value["child_subreaper"]) is bool)
            and type(value["errors"]) is list, "family observation flag types")
    if not value["capture_complete"]:
        require(value["errors"] and value["no_live_or_unreaped_children_observed"] is False,
                "incomplete family observation relabelled")
        return {"family_observation_complete": False, "descendants_quiescent_observed": False,
                "self_cpu_before_publication_ns": None, "waited_children_cpu_ns": None}
    before, after, rows = value["thread_ids_before"], value["thread_ids_after"], value["thread_children"]
    require(type(before) is list and 0 < len(before) <= 256 and before == after
            and all(natural(t) and t > 0 for t in before) and before == sorted(set(before))
            and value["thread_set_stable"] is True and not value["errors"]
            and [r["tid"] for r in rows] == before, "family stable complete thread census")
    children = []
    for row in rows:
        require(row["error"] is None and type(row["children"]) is list
                and all(natural(p) and p > 0 and p != value["pid"] for p in row["children"]),
                "family child census type")
        children.extend(row["children"])
    require(len(set(children)) == len(children)
            and value["observed_child_pids"] == sorted(children)
            and value["no_live_or_unreaped_children_observed"] is (not children), "family child census association")
    cpus = []
    # Reuse the exact wait4 time-field decoder while retaining distinct scope:
    # these two getrusage snapshots are nested, not additional process costs.
    for key in ("self_rusage", "waited_children_rusage"):
        sample = dict(wait4, rusage=value[key])
        cpus.append(check_wait4(sample, wait4["pid"], wait4["parent_pid"],
                                wait4["reap_finished_monotonic_ns"])["total_cpu_ns"])
    total = wait4["rusage"]["total_cpu_ns"]
    if total is not None and all(v is not None for v in cpus):
        require(sum(cpus) <= total + CPU_TOLERANCE_NS, "self and waited children exceed wait4 total")
    complete = all(v is not None for v in cpus)
    quiet = complete and not children and (not require_subreaper or value["child_subreaper"] is True)
    return {"family_observation_complete": complete, "descendants_quiescent_observed": quiet,
            "self_cpu_before_publication_ns": cpus[0], "waited_children_cpu_ns": cpus[1]}


def bound_bytes(raw, binding):
    require(binding["error"] is None and natural(binding["bytes"]) and binding["bytes"] == len(raw)
            and binding["sha256"] == hashlib.sha256(raw).hexdigest(), "process parent-bound raw SHA256 mismatch")


def check_child_probe(value, wait4, family, require_subreaper=False):
    require(value["schema"] == "pon-child-ownership-probe-v1" and value["scope"] == PROBE_SCOPE
            and type(value["pid"]) is int and value["pid"] == wait4["pid"]
            and value["physical_authentication"] is False, "child ownership probe identity/scope")
    require(type(value["idtype"]) is int and value["idtype"] == 0
            and type(value["id"]) is int and value["id"] == 0
            and type(value["options"]) is int and value["options"] == PROBE_OPTIONS
            and value["option_names"] == PROBE_NAMES
            and type(value["successful_reaps"]) is int and value["successful_reaps"] == 0,
            "exact all-thread non-reaping waitid options")
    start, end = value["started_monotonic_ns"], value["ended_monotonic_ns"]
    require(natural(start) and natural(end) and family["ended_monotonic_ns"] <= start <= end
            <= wait4["reap_finished_monotonic_ns"], "child probe lifetime/order")
    before, after = value["sigchld_before"], value["sigchld_after"]
    for signal in (before, after):
        require(set(signal) == {"disposition", "flags", "no_cld_wait", "error"}, "signal observation coverage")
        if signal["error"] is None:
            require(signal["disposition"] in ("default", "ignored", "handler")
                    and type(signal["flags"]) is int and -(1 << 31) <= signal["flags"] < (1 << 31)
                    and signal["no_cld_wait"] is bool(signal["flags"] & 2), "SIGCHLD disposition/NOCLDWAIT")
        else:
            require(type(signal["error"]) is str and signal["error"]
                    and signal["disposition"] is signal["flags"] is signal["no_cld_wait"] is None,
                    "unavailable signal disposition")
    safe = before == after and before["disposition"] == "default" and before["no_cld_wait"] is False and before["error"] is None
    require(value["safe_signal_disposition_observed"] is safe, "signal guard relabelled")
    returned = value["waitid_return"]
    require(type(returned) is int and returned in (-1, 0), "waitid raw return")
    if returned == -1:
        require(type(value["errno"]) is int and value["errno"] > 0 and value["event"] is None, "failed waitid errno/event")
    else:
        require(value["errno"] is None and type(value["event"]) is dict
                and set(value["event"]) == {"signo", "code", "errno", "pid", "uid", "status"}
                and all(type(v) is int for v in value["event"].values())
                and value["event"]["pid"] >= 0 and value["event"]["uid"] >= 0, "successful waitid raw event")
    echild = returned == -1 and value["errno"] == errno.ECHILD
    absent = echild and safe
    require(value["waitid_echild_observed"] is echild and value["no_eligible_children_at_probe"] is absent,
            "zero-event, error or auto-reap cannot mean no children")
    if value["child_subreaper"] is None:
        require(type(value["subreaper_error"]) is str and value["subreaper_error"], "unknown subreaper observation")
    else:
        require(type(value["child_subreaper"]) is bool and value["subreaper_error"] is None, "subreaper observation type")
    children = family["observed_child_pids"]
    require(type(children) is list and all(natural(pid) and pid > 0 for pid in children)
            and children == sorted(set(children)), "preserved procfs child observations")
    require(not (children and absent), "procfs children contradict kernel ECHILD")
    subreaper = not require_subreaper or value["child_subreaper"] is family["child_subreaper"] is True
    quiet = absent and not children and subreaper
    return {"waitid_echild_observed": echild, "no_eligible_children_at_probe": absent,
            "procfs_capture_complete": family["capture_complete"],
            "procfs_children_observed": children, "descendants_quiescent_observed": quiet,
            "quiescence_basis": "waitid-echild-with-sig-dfl-no-nocldwait" if quiet else "unavailable",
            "child_ownership_scope": PROBE_SCOPE}


def child_probe_bindings(read, kind, phase, parent_pid, pids, parent_raw):
    filename = ("attacker" if kind == "actor" else "receiver") + "-child-ownership-binding-v1.json"
    value = thread_cost.parse_raw(read((filename,), thread_cost.BINDING_LIMIT), thread_cost.BINDING_LIMIT)
    parent_file = "attacker-process-cost-v1.json" if kind == "actor" else "receiver-owner-binding-v1.json"
    require(value["schema"] == "pon-child-ownership-binding-v1" and value["scope"] == PROBE_BINDING_SCOPE
            and value["kind"] == kind and value["phase"] == phase and value["parent_pid"] == parent_pid
            and value["parent_cost_file"] == parent_file and value["capture_complete"] is True
            and value["physical_authentication"] is False, "child probe parent binding scope/identity")
    require(type(value["read_budget_ns"]) is int and value["read_budget_ns"] == thread_cost.CAPTURE_BUDGET
            and type(value["probe_limit"]) is int and value["probe_limit"] == LOG_LIMIT
            and type(value["expected_children"]) is int and value["expected_children"] == len(pids)
            and natural(value["started_monotonic_ns"]) and natural(value["ended_monotonic_ns"])
            and value["started_monotonic_ns"] <= value["ended_monotonic_ns"]
            <= value["started_monotonic_ns"] + thread_cost.CAPTURE_BUDGET,
            "child probe capture bounds")
    bound_bytes(parent_raw, value["parent_cost_binding"])
    parent = thread_cost.parse_raw(parent_raw, thread_cost.BINDING_LIMIT)
    require(parent["ended_monotonic_ns"] <= value["started_monotonic_ns"], "probe binding before parent cost capture")
    require(type(value["children"]) is list and len(value["children"]) == len(pids), "probe child coverage")
    probes = []
    for index, (row, pid) in enumerate(zip(value["children"], pids)):
        directory = f"actor-{index}" if kind == "actor" else None
        file = kind + "-child-ownership-v1.json"
        require(type(row["index"]) is int and row["index"] == index and type(row["pid"]) is int and row["pid"] == pid
                and row["directory"] == directory and row["file"] == file and row["capture_complete"] is True,
                "probe fixed child path/PID")
        raw = read((directory, file) if directory else (file,), LOG_LIMIT)
        bound_bytes(raw, row["binding"])
        probe = thread_cost.parse_raw(raw, LOG_LIMIT)
        require(probe["pid"] == pid and probe["ended_monotonic_ns"] <= value["started_monotonic_ns"], "probe capture clock/PID")
        probes.append(probe)
    return probes


def check_directory(directory):
    # The old reader retains all original service and thread-cost requirements.
    original = thread_cost.check_directory(directory)
    return check_process_directory(directory, original)


def check_process_directory(directory, original, phase_reports=None):
    """Shared cost predicates; a separately named caller must validate its own namespace.

    The independent receiver supplement passes its already validated reports.
    This function grants no service or namespace authority to those reports.
    """
    held = thread_cost.open_directory(directory)
    try:
        deadline = time.monotonic() + 30
        read = lambda parts, limit: thread_cost.safe_read(held, parts, limit, deadline)
        load = lambda parts, limit: thread_cost.parse_raw(read(parts, limit), limit)
        reports = []
        for name in thread_cost.pressure.PHASES:
            phase = (load((name + ".json",), thread_cost.REPORT_LIMIT) if phase_reports is None
                     else phase_reports[name])
            process_raw = read((name, FILE), thread_cost.BINDING_LIMIT)
            process = thread_cost.parse_raw(process_raw, thread_cost.BINDING_LIMIT)
            binding_raw = read((name, thread_cost.BINDING_FILE), thread_cost.BINDING_LIMIT)
            binding = thread_cost.parse_raw(binding_raw, thread_cost.BINDING_LIMIT)
            population = 0 if name == "baseline" else thread_cost.pressure.ATTACKERS
            require(process["schema"] == SCHEMA and process["scope"] == SCOPE
                    and process["phase"] == name and process["epoch_monotonic_ns"] == phase["epoch_monotonic_ns"]
                    and process["physical_authentication"] is False
                    and process["capture_complete"] is True, "process capture namespace/completeness")
            require(type(process["expected_actors"]) is int and process["expected_actors"] == population
                    and natural(process["parent_pid"]) and process["parent_pid"] == binding["parent_pid"],
                    "process phase parent/population")
            require(process["read_budget_ns"] == thread_cost.CAPTURE_BUDGET
                    and process["actor_report_limit"] == thread_cost.REPORT_LIMIT
                    and process["actor_cost_limit"] == thread_cost.COST_LIMIT
                    and process["actor_log_limit"] == LOG_LIMIT,
                    "process capture bounds")
            begin, end = process["started_monotonic_ns"], process["ended_monotonic_ns"]
            require(natural(begin) and natural(end) and binding["ended_monotonic_ns"] <= begin <= end
                    <= begin + thread_cost.CAPTURE_BUDGET, "process capture deadline/order")
            bound_bytes(binding_raw, process["thread_cost_parent_binding"])
            require(len(process["actors"]) == len(phase["actors"]) == population, "process actor coverage")
            probes = child_probe_bindings(lambda parts, limit: read((name, *parts), limit), "actor", name,
                                          process["parent_pid"], [a["pid"] for a in phase["actors"]], process_raw)
            rows, pids = [], set()
            for index, (row, wrapper) in enumerate(zip(process["actors"], phase["actors"])):
                require(type(row["actor"]) is int and row["actor"] == index
                        and row["actor_directory"] == f"actor-{index}" and row["pid"] == wrapper["pid"]
                        and row["capture_complete"] is True, "process actor binding")
                require(row["pid"] not in pids, "duplicate child PID")
                pids.add(row["pid"])
                require(set(row["files"]) == {"report.json", thread_cost.FILE, "actor.log", FAMILY_FILE}, "process raw coverage")
                raw = {}
                for file, limit in (("report.json", thread_cost.REPORT_LIMIT),
                                    (thread_cost.FILE, thread_cost.COST_LIMIT), ("actor.log", LOG_LIMIT),
                                    (FAMILY_FILE, LOG_LIMIT)):
                    raw[file] = read((name, f"actor-{index}", file), limit)
                    bound_bytes(raw[file], row["files"][file])
                require(thread_cost.parse_raw(raw["report.json"], thread_cost.REPORT_LIMIT) == wrapper["report"],
                        "process report/phase association")
                nested = thread_cost.parse_raw(raw[thread_cost.FILE], thread_cost.COST_LIMIT)
                result = check_wait4(row["cost"], row["pid"], process["parent_pid"], begin, nested)
                family = thread_cost.parse_raw(raw[FAMILY_FILE], LOG_LIMIT)
                result.update(check_family(family, row["cost"], nested))
                result["procfs_descendants_quiescent_observed"] = result["descendants_quiescent_observed"]
                result.update(check_child_probe(probes[index], row["cost"], family))
                require(result["exit_success"] is wrapper["exit_success"]
                        and result["parent_forced_kill"] is wrapper["parent_forced_kill"], "process legacy exit binding")
                require(phase["epoch_monotonic_ns"] + wrapper["report"]["result"]["finished_ns"]
                        <= row["cost"]["reap_finished_monotonic_ns"], "child reaped before final actor report")
                rows.append({"actor": index, **result})
            reports.append({"phase": name, "actors": rows,
                            "whole_actor_process_cpu": thread_cost.cpu_sum([r["total_cpu_ns"] for r in rows]),
                            "cpu_observation_complete": all(r["cpu_observed"] for r in rows),
                            "descendants_quiescent_observed": all(r["descendants_quiescent_observed"] for r in rows)})
        return {"schema": RESULT_SCHEMA, "input_consistent": True,
                "process_coverage_complete": True, "parent_byte_bindings_verified": True,
                "cpu_observation_complete": all(r["cpu_observation_complete"] for r in reports),
                "descendants_quiescent_observed": all(r["descendants_quiescent_observed"] for r in reports),
                "original_pressure_finite_qualification": original["original_pressure_finite_qualification"],
                "nested_thread_cpu_observation_complete": original["cpu_observation_complete"],
                "cpu_precision_tolerance_ns": CPU_TOLERANCE_NS, "phases": reports,
                "physical_authentication": False, "receiver_owner_observed": False,
                "public_fairness_qualified": False, "production_qualified": False,
                "work_hardness_qualified": False, "installation_authorized": False}
    finally:
        os.close(held)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-observed-cpu", action="store_true")
    parser.add_argument("--require-quiescent-descendants", action="store_true")
    args = parser.parse_args()
    try:
        result = check_directory(args.directory)
    except (ValueError, KeyError, TypeError, OSError, RecursionError) as error:
        result = {"schema": RESULT_SCHEMA, "input_consistent": False,
                  "process_coverage_complete": False, "cpu_observation_complete": False,
                  "descendants_quiescent_observed": False,
                  "parent_byte_bindings_verified": False, "error": str(error),
                  "physical_authentication": False, "receiver_owner_observed": False,
                  "public_fairness_qualified": False, "production_qualified": False,
                  "work_hardness_qualified": False, "installation_authorized": False}
    raw = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        with args.output.open("x") as out:
            out.write(raw)
    print(raw, end="")
    return 0 if result["input_consistent"] and (not args.require_observed_cpu or result["cpu_observation_complete"]) \
        and (not args.require_quiescent_descendants or result["descendants_quiescent_observed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
