#!/usr/bin/env python3
"""Read the independent receiver-process supplement; never qualify the original campaign."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import time

import check_pure_pon_attacker_cost_v1 as actor
import check_pure_pon_process_cost_v1 as process

pressure = actor.pressure
require, natural = actor.require, actor.natural
CAMPAIGN_SCHEMA = "pon-pure-receiver-owner-campaign-v1"
PHASE_SCHEMA = "pon-pure-receiver-owner-phase-v1"
NODE_SCHEMA = "pon-pure-receiver-node-v1"
RESULT_SCHEMA = "pon-pure-receiver-owner-observation-v2"
FRAME_LIMIT, TRACE_LIMIT = 32 * 1024, 16 * 1024 * 1024
OWNER_SCOPE = ("Independent receiver child lifetime with the real Node, two protected public reactors and their joined worker threads. "
               "Includes startup, seed replay, loopback identities, observation IPC, final publication and teardown. "
               "Parent honest client, sampler and attacker siblings are excluded. Linux waited-descendant usage is nested, "
               "not added again; absence of unobserved descendants is not physically authenticated.")
IPC_SCOPE = ("Private local observation IPC; its receiver-side CPU and publication work are included in receiver wait4. "
             "It grants no live ingress, consensus, credit, deadline or fixed-parent authority.")
KERNEL_SCOPE = ("Existing fixed parent aggregate counters, if eligible; includes other members and is not exclusive receiver CPU.")
FILES = {"receiver-report.json": actor.REPORT_LIMIT, "receiver-family-observation-v1.json": process.LOG_LIMIT,
         "receiver.log": process.LOG_LIMIT, "receiver-wait4.json": process.LOG_LIMIT,
         "receiver-ready.json": process.LOG_LIMIT, "receiver-control-trace.json": actor.REPORT_LIMIT,
         "receiver-job.json": actor.REPORT_LIMIT}
FIXED_PARENT = "/sys/fs/cgroup/trnmponpublic.slice"


def no_authority(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"physical_authentication", "public_fairness_qualified", "production_qualified",
                       "work_hardness_qualified", "installation_authorized", "original_campaign_qualification",
                       "fixed_parent_provisioned", "created_or_modified"}:
                require(item is False, "supplement authority cannot be promoted")
            no_authority(item)
    elif isinstance(value, list):
        for item in value:
            no_authority(item)


def kernel_observation(value):
    require(value["path"] == FIXED_PARENT and value["created_or_modified"] is False
            and value["scope"] == KERNEL_SCOPE, "fixed parent read-only scope")
    if value["open_error"] is not None:
        require(type(value["open_error"]) is str and value["open_error"]
                and value["before"] is value["after"] is value["delta"] is None,
                "unavailable kernel parent cannot have invented counters")
        return {"fixed_parent_interval_observed": False, "fixed_parent_cpu_delta": None}
    samples = []
    for key in ("before", "after"):
        item = value[key]
        require(type(item) is dict and len(item) == 1 and set(item) in ({"Ok"}, {"Err"}), "kernel sample result")
        if "Err" in item:
            require(type(item["Err"]) is str and item["Err"], "kernel sample failure")
            samples.append(None)
            continue
        sample = item["Ok"]
        require(sample["schema"] == "public-host-kernel-bound-resource-sample-v1", "bound kernel namespace")
        binding, resources = sample["binding"], sample["resources"]
        require(binding["schema"] == "public-host-kernel-binding-v1" and binding["parent"] == FIXED_PARENT
                and type(binding["boot_id"]) is str and binding["boot_id"], "kernel parent identity")
        for field in ("device", "inode", "cpu_quota_usec", "cpu_period_usec", "cpu_burst_usec",
                      "memory_max_bytes", "memory_swap_max_bytes", "pids_max"):
            require(natural(binding[field]), "kernel binding integer")
        require(0 < binding["cpu_quota_usec"] * 4 <= binding["cpu_period_usec"]
                and binding["cpu_burst_usec"] == binding["memory_swap_max_bytes"] == 0
                and 0 < binding["memory_max_bytes"] <= 2 * 1024 ** 3
                and 0 < binding["pids_max"] <= 256, "original fixed parent ceilings")
        require(set(resources) == {"cpu_usage_usec", "cpu_nr_periods", "cpu_nr_throttled", "cpu_throttled_usec",
                                   "memory_current_bytes", "pids_current"}
                and all(natural(v) for v in resources.values()), "kernel counter coverage/types")
        samples.append(sample)
    if None in samples:
        require(value["delta"] is None, "unknown kernel endpoint delta")
        return {"fixed_parent_interval_observed": False, "fixed_parent_cpu_delta": None}
    before, after = samples
    delta = value["delta"]
    require(type(delta) is dict and len(delta) == 1 and set(delta) in ({"Ok"}, {"Err"}), "kernel delta result")
    if "Err" in delta:
        require(type(delta["Err"]) is str and delta["Err"], "kernel delta failure")
        return {"fixed_parent_interval_observed": False, "fixed_parent_cpu_delta": None}
    require(before["binding"] == after["binding"], "kernel parent identity changed")
    expected = {}
    for short, key in (("usage_usec", "cpu_usage_usec"), ("nr_periods", "cpu_nr_periods"),
                       ("nr_throttled", "cpu_nr_throttled"), ("throttled_usec", "cpu_throttled_usec")):
        amount = after["resources"][key] - before["resources"][key]
        require(amount >= 0, "kernel counter rewind")
        expected[short] = amount
    require(delta["Ok"] == expected and all(natural(v) for v in delta["Ok"].values()), "kernel delta arithmetic")
    return {"fixed_parent_interval_observed": True, "fixed_parent_cpu_delta": expected}


def check_control(trace, node, phase, read):
    require(trace["schema"] == "pon-receiver-control-trace-v2" and trace["scope"] == IPC_SCOPE
            and trace["parent_pid"] == phase["parent_pid"] and trace["receiver_pid"] == phase["receiver_pid"]
            and trace["physical_authentication"] is False, "observation IPC owner/scope")
    require(type(trace["frame_limit"]) is int and trace["frame_limit"] == FRAME_LIMIT
            and type(trace["trace_payload_limit"]) is int and trace["trace_payload_limit"] == TRACE_LIMIT,
            "IPC observation bounds")
    rows, receipts = trace["exchanges"], node["control_receipts"]
    require(type(rows) is list and 3 <= len(rows) <= 2048 and len(rows) == len(receipts), "IPC complete request coverage")
    size, prior_end, samples, hostile, closed = 0, 0, [], [], 0
    for sequence, (row, receipt) in enumerate(zip(rows, receipts)):
        require(natural(row["sequence"]) and row["sequence"] == sequence
                and natural(row["started_monotonic_ns"]) and natural(row["ended_monotonic_ns"])
                and prior_end <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"]
                and row["error"] is None, "IPC sequence, incomplete receive or clock")
        prior_end = row["ended_monotonic_ns"]
        request_raw, response_raw = pressure.raw_hex(row["request_hex"]), pressure.raw_hex(row["response_hex"])
        require(0 < len(request_raw) <= FRAME_LIMIT and 0 < len(response_raw) <= FRAME_LIMIT, "IPC raw frame size")
        require(type(row["sent_frame_bytes"]) is int and row["sent_frame_bytes"] == len(request_raw) + 4
                and pressure.raw_hex(row["response_prefix_hex"]) == len(response_raw).to_bytes(4, "big")
                and pressure.raw_hex(row["response_payload_hex"]) == response_raw,
                "partial frame cannot be relabelled complete")
        require(row["ended_monotonic_ns"] <= phase["epoch_monotonic_ns"] + pressure.WINDOW + 5_000_000_000,
                "IPC crossed original absolute cleanup deadline")
        size += len(request_raw) + len(response_raw)
        # parse_raw requires complete file bytes; these framed payloads have no
        # newline on the stream. Add only the parser delimiter, never a field.
        request = actor.parse_raw(request_raw + b"\n", FRAME_LIMIT + 1)
        response = actor.parse_raw(response_raw + b"\n", FRAME_LIMIT + 1)
        operation = row["operation"]
        require(request == {"schema": "pon-receiver-control-request-v1", "sequence": sequence, "operation": operation}
                and type(request["sequence"]) is int
                and set(response) == {"schema", "pid", "sequence", "operation", "value"}
                and response["schema"] == "pon-receiver-control-response-v1"
                and type(response["pid"]) is int and response["pid"] == phase["receiver_pid"]
                and type(response["sequence"]) is int and response["sequence"] == sequence
                and response["operation"] == operation, "IPC raw request/response binding")
        request_sha, response_sha = hashlib.sha256(request_raw).hexdigest(), hashlib.sha256(response_raw).hexdigest()
        require(row["request_sha256"] == request_sha and row["response_sha256"] == response_sha
                and receipt == {"sequence": sequence, "operation": operation, "request_sha256": request_sha,
                                "response_sha256": None if operation == "stop" else response_sha},
                "receiver and parent IPC receipt mismatch")
        value = response["value"]
        require(type(receipt["sequence"]) is int, "receiver receipt integer sequence")
        if sequence == 0:
            require(operation == "arm" and value == {"epoch_monotonic_ns": phase["epoch_monotonic_ns"]}
                    and row["started_monotonic_ns"] <= phase["epoch_monotonic_ns"] <= row["ended_monotonic_ns"],
                    "cold arm receipt clock bracket")
        elif sequence == len(rows) - 1:
            require(operation == "stop" and row["started_monotonic_ns"] >= phase["epoch_monotonic_ns"] + pressure.WINDOW,
                    "receiver stop before original window")
            process.bound_bytes(read("receiver-report.json", actor.REPORT_LIMIT), value["report"])
        elif operation == "sample":
            if value.get("phase_closed") is True:
                require(natural(value["started_ns"]) and value["started_ns"] >= pressure.WINDOW, "closed sample gate")
                closed += 1
            else:
                require(phase["epoch_monotonic_ns"] + value["started_ns"] >= row["started_monotonic_ns"]
                        and phase["epoch_monotonic_ns"] + value["ended_ns"] <= row["ended_monotonic_ns"],
                        "sample outside receiver IPC interval")
                samples.append(value)
        elif operation == "hostile":
            require(value["file"] == f"hostile-{sequence}.json", "fixed hostile snapshot path")
            raw = read(value["file"], actor.REPORT_LIMIT)
            process.bound_bytes(raw, value["binding"])
            snapshot = actor.parse_raw(raw, actor.REPORT_LIMIT)
            require(row["started_monotonic_ns"] <= phase["epoch_monotonic_ns"] + snapshot["started_ns"]
                    <= phase["epoch_monotonic_ns"] + snapshot["ended_ns"] <= row["ended_monotonic_ns"], "hostile IPC lifetime")
            hostile.append((value, snapshot))
        else:
            raise ValueError("unassociated receiver control operation")
    require(natural(trace["payload_bytes"]) and trace["payload_bytes"] == size <= TRACE_LIMIT and closed <= 1,
            "complete IPC byte accounting")
    require(samples == phase["samples"], "sample omitted or substituted from actual IPC")
    require([v for v, _ in hostile] == node["hostile_snapshots"]
            and [v for _, v in hostile] == [r[k] for r in phase["rounds"] for k in ("hostile_before", "hostile_after")],
            "hostile progress source binding")
    return {"ipc_exchanges": len(rows), "ipc_payload_bytes": size, "samples": len(samples), "closed_samples": closed,
            "ipc_first_started_ns": rows[0]["started_monotonic_ns"], "ipc_final_started_ns": rows[-1]["started_monotonic_ns"],
            "ipc_final_ended_ns": prior_end}


def check_receiver(phase, prepared, read):
    require(phase["schema"] == PHASE_SCHEMA and phase["scope"] == OWNER_SCOPE
            and phase["experiment"] == "receiver-owner-supplement" and phase["original_campaign_qualification"] is False,
            "receiver supplement namespace")
    for field in ("parent_pid", "receiver_pid"):
        require(natural(phase[field]) and phase[field] > 0, "receiver process identity type")
    require(phase["parent_pid"] != phase["receiver_pid"]
            and all(phase["receiver_pid"] != a["pid"] and phase["parent_pid"] != a["pid"] for a in phase["actors"]),
            "mixed receiver/parent/actor ownership")
    binding_raw = read("receiver-owner-binding-v1.json", actor.BINDING_LIMIT)
    binding = actor.parse_raw(binding_raw, actor.BINDING_LIMIT)
    require(binding["schema"] == "pon-pure-receiver-owner-binding-v1" and binding["scope"] == OWNER_SCOPE
            and binding["parent_pid"] == phase["parent_pid"] and binding["receiver_pid"] == phase["receiver_pid"]
            and binding["capture_complete"] is True and binding["physical_authentication"] is False,
            "receiver parent binding incomplete or wrong owner")
    require(type(binding["read_budget_ns"]) is int and binding["read_budget_ns"] == actor.CAPTURE_BUDGET
            and natural(binding["started_monotonic_ns"]) and natural(binding["ended_monotonic_ns"])
            and binding["started_monotonic_ns"] <= binding["ended_monotonic_ns"]
            <= binding["started_monotonic_ns"] + actor.CAPTURE_BUDGET and set(binding["files"]) == set(FILES),
            "receiver bounded capture coverage")
    raw = {name: read(name, limit) for name, limit in FILES.items()}
    for name in FILES:
        process.bound_bytes(raw[name], binding["files"][name])
    values = {name: actor.parse_raw(data, FILES[name]) for name, data in raw.items() if name != "receiver.log"}
    node, cost = values["receiver-report.json"], values["receiver-wait4.json"]
    require(node["schema"] == NODE_SCHEMA and cost == binding["cost"], "receiver raw report/wait4 association")
    require(all(phase[k] == v for k, v in node.items() if k != "schema")
            and node["pid"] == phase["receiver_pid"], "parent phase changed receiver observations")
    require(node["received_stop"] is True and node["control_error"] is None
            and type(node["owned_reactors_joined"]) is int and node["owned_reactors_joined"] == 2
            and node["node_owner_dropped"] is True, "receiver shutdown incomplete")
    result = process.check_wait4(cost, phase["receiver_pid"], phase["parent_pid"], binding["started_monotonic_ns"])
    require(result["exit_success"] is phase["receiver_exit_success"] is True
            and result["parent_forced_kill"] is phase["receiver_parent_forced_kill"] is False,
            "receiver failure or forced shutdown")
    family = values["receiver-family-observation-v1.json"]
    require(family["started_monotonic_ns"] >= phase["epoch_monotonic_ns"] + pressure.WINDOW, "family census before full phase")
    result.update(process.check_family(family, cost, require_subreaper=True))
    probe = process.child_probe_bindings(lambda parts, limit: read(parts[0], limit), "receiver", phase["phase"],
                                         phase["parent_pid"], [phase["receiver_pid"]], binding_raw)[0]
    result["procfs_descendants_quiescent_observed"] = result["descendants_quiescent_observed"]
    result.update(process.check_child_probe(probe, cost, family, require_subreaper=True))
    ready, job = values["receiver-ready.json"], values["receiver-job.json"]
    require(ready["schema"] == "pon-receiver-ready-v1" and ready["pid"] == phase["receiver_pid"]
            and ready["experiment"] == job["experiment"] == "receiver-owner-supplement"
            and ready["subreaper_enabled"] is True and job["schema"] == "pon-receiver-job-v1"
            and job["phase"] == phase["phase"] and job["seed_packets"] == prepared["seed"], "receiver startup binding")
    require(ready["initial_tip"] == pressure.packet(pressure.raw_hex(prepared["seed"][-1]))["id"]
            and type(ready["initial_height"]) is int and ready["initial_height"] == 4
            and type(ready["initial_generation"]) is int and ready["initial_generation"] == 4,
            "receiver initial chain")
    business = pressure.preparation(prepared)
    require(job["honest_body_digests"] == sorted(p["body"] for p in business), "receiver honest request membership")
    addresses = ready["addresses"]
    require(type(addresses) is list and len(addresses) == 2 and len(set(addresses)) == 2, "receiver two listener addresses")
    for address in addresses:
        host, port = address.rsplit(":", 1)
        require(ipaddress.ip_address(host).is_loopback and port.isdigit() and 0 < int(port) <= 65535, "supplement listener isolation")
    ipc = check_control(values["receiver-control-trace.json"], node, phase, read)
    require(cost["spawn_finished_monotonic_ns"] <= ipc["ipc_first_started_ns"]
            <= ipc["ipc_final_ended_ns"] <= cost["reap_finished_monotonic_ns"]
            <= phase["epoch_monotonic_ns"] + pressure.WINDOW + 5_000_000_000,
            "receiver lifetime exceeded original cleanup deadline")
    require(ipc["ipc_final_started_ns"] <= family["started_monotonic_ns"] <= family["ended_monotonic_ns"]
            <= probe["started_monotonic_ns"] <= probe["ended_monotonic_ns"] <= ipc["ipc_final_ended_ns"],
            "receiver cleanup observation outside final stop publication")
    result.update(ipc)
    result.update(kernel_observation(node["kernel_parent"]))
    no_authority([phase, binding, *values.values()])
    return {"phase": phase["phase"], **result}


def check_directory(directory):
    held = actor.open_directory(directory)
    try:
        deadline = time.monotonic() + 30
        read = lambda parts, limit: actor.safe_read(held, parts, limit, deadline)
        load = lambda parts, limit=actor.REPORT_LIMIT: actor.parse_raw(read(parts, limit), limit)
        manifest, prepared = load(("campaign.json",)), load(("preparation.json",))
        require(manifest["schema"] == CAMPAIGN_SCHEMA and manifest["scope"] == OWNER_SCOPE
                and manifest["original_campaign_qualification"] is False and manifest["fixed_parent_provisioned"] is False,
                "fresh supplemental campaign required")
        no_authority(manifest)
        phases = [load((name + ".json",)) for name in pressure.PHASES]
        reports, sidecars, bindings, captured = [], {}, {}, {}
        for name, phase in zip(pressure.PHASES, phases):
            require(phase["phase"] == name, "supplement phase order")
            reports.append(check_receiver(phase, prepared, lambda file, limit: read((name, file), limit)))
            bindings[name] = load((name, actor.BINDING_FILE), actor.BINDING_LIMIT)
            population = 0 if name == "baseline" else pressure.ATTACKERS
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
            try:
                require({entry for entry in os.listdir(fd) if entry.startswith("actor-")}
                        == {f"actor-{i}" for i in range(population)}, "supplement actor population")
            finally:
                os.close(fd)
            for index in range(population):
                key = (name, index)
                captured[key] = {file: read((name, f"actor-{index}", file), limit)
                                 for file, limit in (("report.json", actor.REPORT_LIMIT), (actor.FILE, actor.COST_LIMIT))}
                sidecars[key] = actor.parse_raw(captured[key][actor.FILE], actor.COST_LIMIT)
        # Pure predicates are deliberately reused after the new namespace and
        # raw ownership checks. These temporary views are never written, never
        # passed to the old directory reader and confer no original-campaign pass.
        view_manifest = dict(manifest, schema=pressure.SCHEMA)
        view_phases = [dict(phase, schema=pressure.SCHEMA) for phase in phases]
        semantics = pressure.check(view_manifest, prepared, view_phases)
        nested = actor.check(view_manifest, prepared, view_phases, sidecars, bindings, captured)
        actor_processes = process.check_process_directory(directory, nested, {p["phase"]: p for p in phases})
        for phase, binding in zip(phases, bindings.values()):
            require(binding["parent_pid"] == phase["parent_pid"], "actor and receiver parent ownership mismatch")
        known = all(p["cpu_observed"] for p in reports)
        quiet = all(p["descendants_quiescent_observed"] for p in reports)
        return {"schema": RESULT_SCHEMA, "input_consistent": True, "parent_byte_bindings_verified": True,
                "receiver_lifetime_cost_observed": known, "receiver_descendants_quiescent_observed": quiet,
                "actor_cpu_observation_complete": actor_processes["cpu_observation_complete"],
                "actor_descendants_quiescent_observed": actor_processes["descendants_quiescent_observed"],
                "nested_actor_thread_cpu_observation_complete": nested["cpu_observation_complete"],
                "supplemental_finite_qualification": semantics["finite_qualification"],
                "original_campaign_qualification": False, "receiver_processes": reports,
                "actor_process_phases": actor_processes["phases"], "service_phases": semantics["phases"],
                "actor_preparation_phases": nested["phases"],
                "physical_authentication": False, "public_fairness_qualified": False,
                "production_qualified": False, "work_hardness_qualified": False, "installation_authorized": False,
                "fixed_parent_provisioned": False, "exclusive_receiver_cgroup_observed": False,
                "scope": OWNER_SCOPE,
                "max_rss_scope": "Linux per-process/wait4 maximum; not a simultaneous aggregate family memory peak.",
                "child_ownership_scope": process.PROBE_SCOPE,
                "kernel_interval_scope": "Fixed-parent samples bracket prepared-node service and shutdown; they exclude early startup/final publication and other members cannot be separated.",
                "cpu_cost_combination": "Receiver and actor sibling totals remain separate; nested actor thread, RUSAGE_SELF and waited-child samples are never added twice."}
    finally:
        os.close(held)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    parser.add_argument("--require-observed-cpu", action="store_true")
    parser.add_argument("--require-quiescent-descendants", action="store_true")
    args = parser.parse_args()
    try:
        result = check_directory(args.directory)
    except (ValueError, KeyError, TypeError, OSError, RecursionError) as failure:
        result = {"schema": RESULT_SCHEMA, "input_consistent": False, "parent_byte_bindings_verified": False,
                  "receiver_lifetime_cost_observed": False, "receiver_descendants_quiescent_observed": False,
                  "actor_cpu_observation_complete": False, "actor_descendants_quiescent_observed": False,
                  "nested_actor_thread_cpu_observation_complete": False, "supplemental_finite_qualification": False,
                  "original_campaign_qualification": False, "error": str(failure), "physical_authentication": False,
                  "public_fairness_qualified": False, "production_qualified": False, "work_hardness_qualified": False,
                  "installation_authorized": False, "fixed_parent_provisioned": False}
    raw = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
    print(raw, end="")
    success = result["input_consistent"]
    success &= not args.require_qualified or result["supplemental_finite_qualification"]
    success &= not args.require_observed_cpu or all(result[k] for k in
        ("receiver_lifetime_cost_observed", "actor_cpu_observation_complete", "nested_actor_thread_cpu_observation_complete"))
    success &= not args.require_quiescent_descendants or all(result[k] for k in
        ("receiver_descendants_quiescent_observed", "actor_descendants_quiescent_observed"))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
