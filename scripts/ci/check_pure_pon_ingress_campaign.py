#!/usr/bin/env python3
"""Check finite ingress accounting; never infer public fairness or CPU authenticity."""
import argparse
import collections
import gzip
import hashlib
import json
import math
from pathlib import Path

SCHEMA = "pon-pure-ingress-campaign-v1"
PHASES = ("honest-cold", "attack-cold-reopen", "attack-second-reopen")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value):
    return type(value) is int and value >= 0


def optional_sum(values):
    values = list(values)
    require(all(value is None or natural(value) for value in values), "invalid CPU observation")
    return None if any(value is None for value in values) else sum(values)


def percentile(values, percent):
    return sorted(values)[(len(values) * percent + 99) // 100 - 1] if values else None


def indexed(rows, keys):
    result = {}
    for row in rows:
        key = tuple(row[k] for k in keys)
        require(key not in result, "duplicate observation identity")
        result[key] = row
    return result


def check(rows):
    require(bool(rows) and all(row.get("schema") == SCHEMA for row in rows), "schema")
    first, last = rows[0], rows[-1]
    require(first["kind"] == "begin" and last["kind"] == "terminal"
            and last["status"] == "complete", "incomplete campaign")
    require(sum(r["kind"] == "begin" for r in rows) == sum(r["kind"] == "terminal" for r in rows) == 1,
            "multiple campaign boundaries")
    require(last["production_qualified"] is False and last["work_hardness_qualified"] is False
            and last["public_fairness_qualified"] is False, "unearned qualification")
    receivers = first["receivers"]
    require(type(receivers) is int and 1 <= receivers <= 2 and first["listeners_per_receiver"] == 2,
            "receiver limits")
    require(first["seed_acquired_once"] is True and first["model_useful_output_credit"] == 0,
            "seed or model scope")
    require({r["phase"] for r in rows if "phase" in r} == set(PHASES), "phase coverage")
    previous_states = {}
    reports, all_packets = [], set()
    all_attack_preparation = []
    all_attack_transport = []
    all_attack_dispatch = []
    for phase in PHASES:
        group = [r for r in rows if r.get("phase") == phase]
        of = lambda kind: [r for r in group if r["kind"] == kind]
        terminals = of("phase_terminal")
        require(len(terminals) == 1, "phase terminal")
        terminal = terminals[0]
        require(terminal["work_hardness_qualified"] is False and terminal["public_fairness_qualified"] is False,
                "phase qualification")
        elapsed = terminal["elapsed_including_client_tails_ns"]
        require(natural(elapsed) and elapsed > 0, "phase clock")
        expected_seconds = first["baseline_seconds"] if phase == PHASES[0] else first["attack_seconds_per_phase"]
        require(terminal["requested_seconds"] == expected_seconds, "phase duration")
        require(terminal["group_bound_reached"] or elapsed >= expected_seconds * 1_000_000_000,
                "short phase hidden")
        prepared = indexed(of("prepared_packet"), ("sequence",))
        require(len(prepared) == terminal["generated_unique_packets"], "missing prepared packet")
        calls = of("client_call")
        call_index = indexed(calls, ("sequence", "receiver"))
        require(len(calls) == len(prepared) * receivers, "missing fanout call")
        body_index = {}
        for (seq,), packet in prepared.items():
            require(packet["packet_sha256"] not in all_packets, "reused complete packet")
            all_packets.add(packet["packet_sha256"])
            require(type(packet["honest"]) is bool and packet["receiver_fanout"] == receivers
                    and packet["transport_hash_trials"] == 0, "prepared packet scope")
            require(natural(packet["generation_trials"]) and 1 <= packet["generation_trials"] <= 4096,
                    "generation trials")
            require(natural(packet["preparation_wall_ns"]), "preparation wall")
            for receiver in range(receivers):
                call = call_index.get((seq, receiver))
                require(call is not None and call["body_digest"] == packet["body_digest"]
                        and call["honest"] == packet["honest"], "unmatched fanout")
                require((receiver, call["body_digest"]) not in body_index, "receiver cache hit")
                body_index[(receiver, call["body_digest"])] = call
                require(type(call["accepted"]) is bool and (call["honest"] or not call["accepted"]),
                        "invalid work accepted")
                require(call["metrics"]["solution_trials"] == 0 and natural(call["latency_ns"]),
                        "hashcash or invalid client clock")
        require(sum(p["preparation_wall_ns"] for p in prepared.values()) == terminal["packet_preparation_wall_ns"],
                "preparation wall accounting")
        require(optional_sum(p["preparation_thread_cpu_ns"] for p in prepared.values())
                == terminal["packet_preparation_thread_cpu_ns"], "preparation CPU accounting")
        summaries = indexed(of("class_summary"), ("honest",))
        require(set(summaries) == {(True,), (False,)}, "class summary coverage")
        classes = []
        observations = of("receiver_observation")
        indexed_observations = indexed([r for r in observations if r["sequence"] is not None], ("sequence", "receiver"))
        for observation in observations:
            if observation["sequence"] is None:
                continue
            call = call_index.get((observation["sequence"], observation["receiver"]))
            require(call is not None and observation["body_digest"] == call["body_digest"]
                    and observation["honest"] == call["honest"], "receiver association")
        for honest in (True, False):
            selected = [c for c in calls if c["honest"] == honest]
            accepted = [c for c in selected if c["accepted"]]
            summary = summaries[(honest,)]
            require(summary["calls"] == len(selected) and summary["accepted_receiver_calls"] == len(accepted),
                    "class outcomes")
            require(summary["errors"] == dict(collections.Counter(c["error"] for c in selected if not c["accepted"])),
                    "omitted refusal")
            require(summary["elapsed_including_client_tails_ns"] == elapsed
                    and summary["all_call_p50_ns"] == percentile([c["latency_ns"] for c in selected], 50)
                    and summary["all_call_p99_ns"] == percentile([c["latency_ns"] for c in selected], 99)
                    and summary["accepted_p99_ns"] == percentile([c["latency_ns"] for c in accepted], 99),
                    "latency denominator or percentile")
            require(math.isclose(summary["accepted_receiver_calls_per_second"], len(accepted) * 1e9 / elapsed,
                                 rel_tol=1e-12, abs_tol=1e-12), "goodput denominator")
            transport = optional_sum(c["thread_cpu_ns"] for c in selected)
            require(transport == summary["client_transport_thread_cpu_ns"], "transport CPU accounting")
            selected_observations = [indexed_observations.get((c["sequence"], c["receiver"])) for c in selected]
            dispatch = optional_sum(o["dispatch_thread_cpu_ns"] if o else None for o in selected_observations)
            class_prepared = [p for p in prepared.values() if p["honest"] == honest]
            preparation = optional_sum(p["preparation_thread_cpu_ns"] for p in class_prepared)
            full_work = [o for o in selected_observations if o and o["full_work_started"]]
            classes.append({**summary, "prepared_unique_packets": len(class_prepared),
                            "preparation_thread_cpu_ns": preparation,
                            "receiver_dispatch_thread_cpu_ns": dispatch,
                            "full_work_started": len(full_work),
                            "receiver_full_work_thread_cpu_ns": optional_sum(o["full_work_thread_cpu_ns"] for o in full_work),
                            "missing_receiver_observations": sum(o is None for o in selected_observations),
                            "unknown_dispatch_cpu_observations": sum(o is None or o["dispatch_thread_cpu_ns"] is None for o in selected_observations)})
            if not honest:
                all_attack_preparation.append(preparation)
                all_attack_transport.append(transport)
                all_attack_dispatch.append(dispatch)
        accepted_all = sum(all(call_index[(seq, receiver)]["accepted"] for receiver in range(receivers))
                           for (seq,), packet in prepared.items() if packet["honest"])
        require(terminal["honest_unique_packets_accepted_by_all_receivers"] == accepted_all,
                "shared honest acceptance")
        starts, ends = indexed(of("receiver_start"), ("receiver",)), indexed(of("receiver_end"), ("receiver",))
        require(set(starts) == set(ends) == {(r,) for r in range(receivers)}, "receiver epoch coverage")
        for receiver in range(receivers):
            start, end = starts[(receiver,)], ends[(receiver,)]
            require(start["budget"]["stored_credit_ns"] == 0 and start["budget"]["in_flight"] == 0,
                    "restart minted budget")
            if receiver in previous_states:
                require(start["state"] == previous_states[receiver], "cold replay differs")
            flow = end["flow"]
            require(flow["balance_identity_verified"] is True and flow["initial_credit_ns"] == 0
                    and flow["live_owners"] == flow["booked_reservation_ns"] == flow["unsettled_known_live_cpu_ns"] == 0,
                    "incomplete global settlement")
            require(flow["paid_cpu_debit_ns"] == flow["live_debited_cpu_ns"] + flow["settlement_residual_cpu_ns"]
                    == flow["settled_full_cpu_ns"], "CPU debit double count or missing tail")
            require(flow["credited_refill_ns"] - flow["paid_cpu_debit_ns"] - flow["settlement_discard_ns"]
                    == flow["remaining_paid_credit_ns"] == flow["stored_credit_ns"]
                    == end["budget"]["stored_credit_ns"], "global credit conservation")
            require(end["completion_work"]["repeated_identity_skips"] == 0, "completion cache reuse")
            honest_accepted = sum(c["honest"] and c["accepted"] for c in calls if c["receiver"] == receiver)
            require(end["state"]["stored_blocks"] - start["state"]["stored_blocks"] == honest_accepted,
                    "native admission delta")
            require(end["state"]["height"] <= 1, "fixed-parent candidate scope changed")
            previous_states[receiver] = end["state"]
        coverage = indexed(of("observation_coverage"), ("receiver", "listener"))
        listeners = indexed(of("listener_end"), ("receiver", "listener"))
        require(set(coverage) == set(listeners) == {(r, l) for r in range(receivers) for l in range(2)},
                "listener observation coverage")
        reports.append({"phase": phase, "classes": classes, "epoch_end": list(ends.values()),
                        "observation_coverage": list(coverage.values()), "phase_terminal": terminal})
    sender = optional_sum([first["seed_acquisition_thread_cpu_ns"], *all_attack_preparation, *all_attack_transport])
    receiver = optional_sum(all_attack_dispatch)
    return {"schema": "pon-pure-ingress-consistency-v1", "phases": reports,
            "attack_sender_seed_once_plus_preparation_and_client_cpu_ns": sender,
            "attack_receiver_dispatch_cpu_ns": receiver,
            "observed_attack_dispatch_to_sender_cpu_ratio": receiver / sender if receiver is not None and sender else None,
            "scope": "one nonexclusive host; fixed-parent empty candidates, not chain growth or TPS; local diagnostic CPU, no hardware authenticity; dispatch excludes reactor and must not be added to nested full-work CPU; bounded observations prove neither arbitrary-Sybil fairness nor work hardness",
            "production_qualified": False, "hardness_proved": False, "public_fairness_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    opener = gzip.open if args.input.suffix == ".gz" else open
    with opener(args.input, "rb") as stream:
        raw = stream.read(64 * 1024 * 1024 + 1)
    require(len(raw) <= 64 * 1024 * 1024 and raw.endswith(b"\n"), "bounded complete input")
    result = check([json.loads(line) for line in raw.splitlines()])
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    if args.output:
        with args.output.open("x") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
    else:
        print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise SystemExit(f"ingress consistency rejected: {error}") from error
