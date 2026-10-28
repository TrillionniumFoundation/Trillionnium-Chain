#!/usr/bin/env python3
"""Read actual CPU batches with one aggregate clock and retained legal packets."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from check_legal_ticket_cost_v3 import (
    ARMS, PHASES as SERIAL_PHASES, RECURRING, hex_value, number, parsed,
    read_rows, require, summed, timing,
)

SCHEMA = "pon-legal-ticket-cpu-batch-cost-v4"
PHASES = (*SERIAL_PHASES, "packet_archival")


def validate(rows):
    require(len(rows) == 14 and all(r.get("schema") == SCHEMA for r in rows),
            "complete 12-cohort CPU batch report required")
    begin, terminal = rows[0], rows[-1]
    require(begin["kind"] == "begin" and terminal["kind"] == "terminal" and
            terminal["status"] == "complete" and terminal["cohorts"] == 12, "terminal")
    for key, expected in {"searches":64, "attempts":8, "rounds":2, "seed":1,
                          "budget_seconds":240, "native_workers":1}.items():
        require(type(begin[key]) is int and begin[key] == expected, "frozen batch plan")
    require(begin["cpu_batch_workers"] == [1,2,4] and begin["cpu_batching_measured"] is True
            and begin["winning_packet_payloads_retained"] is True, "batch/payload scope")
    require(begin["positive_legal_tickets_only"] is True and
            begin["standalone_verifier_added_to_native_admission"] is False, "legal scope")
    for key in ["gpu_measured", "energy_measured", "hardware_batching_measured",
                "hardware_authenticated", "exclusive_host", "global_minimum_proved"]:
        require(begin[key] is False, "unsupported hardware claim")
    for key in ["production_qualified", "global_minimum_proved", "active_chain_rewards_measured"]:
        require(terminal[key] is False, "unsupported qualification")
    require(number(terminal["wall_ns"]) <= 240_000_000_000, "campaign budget")
    groups, seen, paired, all_ids = [], set(), {}, set()
    expected_order = [(r, w, arm) for r in (0,1) for w in ((1,2,4) if r == 0 else (4,2,1))
                      for arm in (ARMS if r == 0 else ARMS[::-1])]
    for row, expected in zip(rows[1:-1], expected_order):
        key = (row["round"], row["batch_workers"], row["strategy"])
        require(type(row["round"]) is int and type(row["batch_workers"]) is int and
                key == expected and key not in seen, "complete counterbalanced batch grid")
        seen.add(key)
        r, workers, arm = key
        require(row["kind"] == "cohort" and row["status"] == "complete", "cohort")
        require(row["order"] == (ARMS.index(arm) if r == 0 else 1-ARMS.index(arm)), "arm order")
        require(row["reuse"] is True and row["producer_setup_calls"] == 1 and
                row["batch_process_clock_intervals"] == 1 and
                row["overlapping_trial_times_added_to_batch"] is False and
                row["batch_includes_spawn_join_and_trial_records"] is True, "exclusive batch clock")
        require(row["fresh_store"] is True and row["template_seed_admitted"] is False and
                row["standalone_verifier_added_to_native_admission"] is False and
                row["explicit_activation_calls"] == 0, "native first admission")
        require(row["search_horizon"] == 64 and row["attempt_budget"] == 8, "search bounds")
        for key_name in ["parent", "target", "task", "stream_sha256"]:
            hex_value(row[key_name],64)
        hex_value(row["native_template_header"],636)
        require(set(row["phases"]) == set(PHASES), "phase inventory")
        phases = {name: timing(row["phases"][name]) for name in PHASES}
        require(summed(phases.values()) == timing(row["all_exclusive_phases"]), "phase total")
        require(summed(phases[k] for k in RECURRING) == timing(row["recurring_producer_encode_admission"]), "recurring total")
        outer = timing(row["observed_outer"])
        for clock in ["wall_ns","process_cpu_ns"]:
            part = row["all_exclusive_phases"][clock]
            require(part is None or outer[clock] is None or outer[clock] >= part, "overlapping phases")
        observations = row["worker_observations"]
        require(len(observations) == workers, "missing worker terminal")
        thread_ids, events = set(), []
        for i, obs in enumerate(observations):
            require(obs["worker"] == i and obs["searches"] == 64//workers, "worker search ownership")
            require(re.fullmatch(r"ThreadId\([0-9]+\)", obs["thread_id"]) and
                    obs["thread_id"] not in thread_ids, "distinct actual worker threads")
            thread_ids.add(obs["thread_id"])
            start, finish = number(obs["started_offset_ns"]), number(obs["finished_offset_ns"])
            require(start < finish <= phases["all_attempt_generation"]["wall_ns"], "worker interval")
            events.extend([(start,1),(finish,-1)])
        live = maximum = 0
        for _, delta in sorted(events):
            live += delta
            maximum = max(maximum, live)
        require(live == 0, "unclosed worker intervals")
        ids, attempts, wins, admissions, packet_sizes, trace = set(), 0, 0, [], {}, []
        stream = hashlib.sha256(b"TRNM-LEGAL-CPU-BATCH-STREAM-V4\0")
        require(len(row["searches"]) == 64, "missing searches")
        for i, search in enumerate(row["searches"]):
            require(search["search"] == i and search["worker"] == i % workers and
                    type(search["won"]) is bool, "search partition")
            stream.update(i.to_bytes(8,"little"))
            stream.update(bytes.fromhex(hex_value(search["search_stream_sha256"],64)))
            trials = search["trials"]
            require(1 <= len(trials) <= 8 and (search["won"] or len(trials) == 8), "omitted exhausted attempts")
            attempts += len(trials)
            for j, trial in enumerate(trials):
                require(trial["trial"] == j and trial["nonce"] == (1<<32)+r*(1<<24)+i*8+j, "nonce range")
                for name in ["challenge","proof_sha256","ticket"]:
                    hex_value(trial[name],64)
                hit = bytes.fromhex(trial["ticket"]) <= bytes.fromhex(row["target"])
                require(trial["target_hit"] is hit and hit == (search["won"] and j == len(trials)-1), "original ticket predicate")
                number(trial["overlapping_kernel_wall_ns"])
                require("generation" not in trial, "per-trial process clock would overlap")
                trace.append(tuple(trial[k] for k in ["nonce","challenge","proof_sha256","ticket"]))
                if hit:
                    pid = hex_value(trial["packet_id"],64)
                    require(pid not in ids, "duplicate admission")
                    ids.add(pid)
                    packet_sizes[pid] = number(trial["packet_bytes"])
                    admissions.append(timing(trial["native_admission"]))
                    wins += 1
                else:
                    require("packet_id" not in trial and "native_admission" not in trial, "miss credited")
        require(stream.hexdigest() == row["stream_sha256"], "full ordered search stream")
        identity = (row["parent"],row["target"],row["task"],row["native_template_header"],row["stream_sha256"],trace)
        require(r not in paired or paired[r] == identity, "paired workload changed")
        paired[r] = identity
        require(summed(admissions) == phases["first_native_admission"], "admission cost total")
        require(row["attempts"] == attempts and row["winners"] == wins and
                row["exhausted"] == 64-wins and row["first_native_admissions"] == wins and
                row["cold_packet_readbacks"] == wins, "first-admission denominator")
        retained = row["retained_packets"]
        require(len(retained) == wins and {x["id"] for x in retained} == ids, "cold readback coverage")
        for packet in retained:
            hex_value(packet["sha256"],64)
            label = f"round-{r}-workers-{workers}-{'limb' if arm == ARMS[1] else 'general'}"
            require(packet["file"] == f"{label}/{packet['id']}.packet" and
                    packet["bytes"] == packet_sizes[packet["id"]], "bounded retained packet identity")
        require(row["hot_active_before_close"]["id"] == row["parent"] and
                row["cold_recovery_active"]["id"] == (min(ids) if ids else row["parent"]) and
                row["cold_recovery_selected_height"] == int(bool(ids)), "ordinary cold recovery")
        all_ids.update(ids)
        groups.append({"round":r,"workers":workers,"strategy":arm,"attempts":attempts,"winners":wins,
                       "phases":phases,"recurring":row["recurring_producer_encode_admission"],
                       "all_phases":row["all_exclusive_phases"],"outer":outer,
                       "maximum_observed_overlapping_worker_intervals":maximum})
    comparisons = []
    for arm in ARMS:
        for workers in [1,2,4]:
            chosen = [r for r in groups if r["strategy"] == arm and r["workers"] == workers]
            wins = sum(r["winners"] for r in chosen)
            scopes = {key: summed(r[key] for r in chosen) for key in ["recurring","all_phases","outer"]}
            scopes["batch_generation"] = summed(r["phases"]["all_attempt_generation"] for r in chosen)
            comparisons.append({"strategy":arm,"workers":workers,"first_admissions":wins,
                "attempts":sum(r["attempts"] for r in chosen),"ms_per_first_admission":{
                    scope:{k.replace("_ns","_ms"):(v/wins/1e6 if wins and v is not None else None) for k,v in cost.items()}
                    for scope,cost in scopes.items()}})
    return {"schema":"pon-legal-ticket-cpu-batch-summary-v4","cohorts":12,"groups":groups,
            "first_admission_calls":sum(r["winners"] for r in groups),
            "distinct_fixture_packet_ids_across_paired_cohorts":len(all_ids),"comparisons":comparisons,
            "settings_setup":timing(begin["settings_setup"]),"packet_archive_setup":timing(begin["packet_archive_setup"]),
            "cpu_batching_measured":True,"gpu_measured":False,"energy_measured":False,
            "global_minimum_proved":False,"active_chain_rewards_measured":False,"production_qualified":False,
            "scope":"actual 1/2/4-thread CPU batches; all failed attempts and one shared preparation; aggregate process clock counted once; serialized native admission/cold readback and separate payload archive cost"}


def verify_payloads(rows, root):
    require(root.is_dir() and not root.is_symlink(), "packet directory")
    expected = {p["file"]:p for row in rows[1:-1] for p in row["retained_packets"]}
    files = {str(p.relative_to(root)):p for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    require(set(files) == set(expected), "packet archive inventory")
    for name,p in files.items():
        require(not p.is_symlink() and not p.parent.is_symlink() and p.stat().st_size == expected[name]["bytes"]
                and p.stat().st_size <= 2*1024*1024, "packet archive shape")
        require(hashlib.sha256(p.read_bytes()).hexdigest() == expected[name]["sha256"], "packet bytes changed")
    return {"files":len(files),"bytes":sum(p.stat().st_size for p in files.values()),
            "all_sha256_verified":True,"cryptographic_admission_repeated_by_reader":False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ["capture","source-before","source-after","packets","output"]:
        p.add_argument("--"+flag,type=Path,required=True)
    p.add_argument("--expected-head",required=True)
    args = p.parse_args()
    capture = parsed(args.capture.read_bytes())
    raw = args.capture.parent/"stdout.jsonl.gz"
    rows,count,digest = read_rows(raw)
    require(capture["exit_code"] == 0 and capture["timed_out"] is False and capture["stable_binary"] is True
            and capture["stdout_within_bound"] is True and capture["timeout_seconds"] == 250
            and capture["elapsed_ns"] <= 250_000_000_000, "bounded capture terminal")
    require(capture["binary_sha256_before"] == capture["binary_sha256_after"] and
            capture["stdout_bytes"] == count and capture["stdout_uncompressed_sha256"] == digest and
            capture["stdout_gzip_sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest(), "raw/binary identity")
    before,after = parsed(args.source_before.read_bytes()),parsed(args.source_after.read_bytes())
    require(before == after and before["tested_commit"] == args.expected_head and
            before["tracked_worktree_verified"] is True and before["kind"] == "head", "full source identity")
    require(capture["source"]["commit"] == args.expected_head and capture["source"]["tree"] == before["tested_tree"] and
            capture["source"]["example_sha256"] == rows[0]["compiled_driver_sha256"] and
            capture["source"]["lock_sha256"] == rows[0]["compiled_cargo_lock_sha256"], "compiled source binding")
    require(len(capture["argv"]) == 2 and Path(capture["argv"][1]) == args.packets, "packet destination binding")
    result = validate(rows)
    result.update(payload_archive=verify_payloads(rows,args.packets),source=before,native_capture=capture,raw_uncompressed_sha256=digest)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:result[k] for k in ["schema","cohorts","first_admission_calls","distinct_fixture_packet_ids_across_paired_cohorts","payload_archive"]}))


if __name__ == "__main__":
    main()
