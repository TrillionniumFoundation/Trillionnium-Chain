#!/usr/bin/env python3
"""Read bounded, source-bound first-admission costs; never infer mining rewards."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

SCHEMA = "pon-legal-ticket-first-admission-cost-v3"
ARMS = ("prepared-general", "maintenance-split-limb")
PHASES = ("directory", "node_open", "bootstrap_material", "template_acquisition",
          "matrix_material", "producer_setup", "all_attempt_generation", "packet_encoding",
          "first_native_admission", "node_close", "cold_node_open", "cold_packet_readback",
          "cold_node_close")
RECURRING = ("producer_setup", "all_attempt_generation", "packet_encoding", "first_native_admission")


def require(value, message):
    if not value:
        raise ValueError(message)


def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, "duplicate JSON field")
        out[key] = value
    return out


def parsed(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def number(value):
    require(type(value) is int and value >= 0, "invalid integer observation")
    return value


def timing(value):
    require(set(value) == {"wall_ns", "process_cpu_ns"}, "timing fields")
    number(value["wall_ns"])
    if value["process_cpu_ns"] is not None:
        number(value["process_cpu_ns"])
    return value


def summed(values):
    values = [timing(v) for v in values]
    return {"wall_ns": sum(v["wall_ns"] for v in values),
            "process_cpu_ns": (sum(v["process_cpu_ns"] for v in values)
                               if all(v["process_cpu_ns"] is not None for v in values) else None)}


def hex_value(value, length):
    require(isinstance(value, str) and len(value) == length and
            all(c in "0123456789abcdef" for c in value), "hex identity")
    return value


def read_rows(path):
    rows, total, digest = [], 0, hashlib.sha256()
    require(path.stat().st_size <= 32 * 1024 * 1024, "compressed report bound")
    with gzip.open(path, "rb") as stream:
        while raw := stream.readline(2 * 1024 * 1024 + 2):
            require(len(raw) <= 2 * 1024 * 1024 + 1 and raw.endswith(b"\n"), "row bound/truncation")
            total += len(raw)
            require(total <= 32 * 1024 * 1024 and len(rows) < 16, "report bound")
            digest.update(raw)
            rows.append(parsed(raw))
    return rows, total, digest.hexdigest()


def validate(rows):
    require(len(rows) == 10, "exact complete 8-cohort report required")
    require(all(r.get("schema") == SCHEMA for r in rows), "report schema")
    begin, terminal = rows[0], rows[-1]
    require(begin["kind"] == "begin" and terminal["kind"] == "terminal" and
            terminal["status"] == "complete" and terminal["cohorts"] == 8, "terminal")
    for key, expected in {"searches": 64, "attempts": 8, "rounds": 2, "seed": 1,
                          "budget_seconds": 240, "native_workers": 1}.items():
        require(type(begin[key]) is int and begin[key] == expected, "frozen run plan")
    require(begin["positive_legal_tickets_only"] is True and
            begin["standalone_verifier_added_to_native_admission"] is False, "cost scope")
    require(number(terminal["wall_ns"]) <= 240_000_000_000, "late campaign terminal")
    for flag in ("gpu_measured", "energy_measured", "hardware_batching_measured",
                 "hardware_authenticated", "exclusive_host", "global_minimum_proved"):
        require(begin[flag] is False, "unsupported qualification")
    for flag in ("production_qualified", "global_minimum_proved", "active_chain_rewards_measured"):
        require(terminal[flag] is False, "unsupported terminal qualification")
    groups, observed, paired, global_ids = [], set(), {}, set()
    for row in rows[1:-1]:
        require(row["kind"] == "cohort" and row["status"] == "complete", "cohort status")
        key = (row["round"], row["reuse"], row["strategy"])
        require(type(row["round"]) is int and row["round"] in (0, 1) and
                type(row["reuse"]) is bool and row["strategy"] in ARMS and key not in observed,
                "cohort identity")
        observed.add(key)
        require(row["order"] == (ARMS.index(row["strategy"]) if row["round"] == 0
                                 else 1 - ARMS.index(row["strategy"])), "paired arm order")
        require(row["fresh_store"] is True and row["template_seed_admitted"] is False and
                row["standalone_verifier_added_to_native_admission"] is False and
                row["explicit_activation_calls"] == 0, "first admission/reward scope")
        require(row["search_horizon"] == 64 and row["attempt_budget"] == 8 and
                row["producer_setup_calls"] == (1 if row["reuse"] else 64), "setup/search plan")
        for name in ("parent", "target", "task", "stream_sha256"):
            hex_value(row[name], 64)
        hex_value(row["native_template_header"], 636)
        identity = (row["parent"], row["target"], row["task"], row["native_template_header"], row["stream_sha256"])
        require(row["round"] not in paired or paired[row["round"]] == identity, "paired source stream")
        paired[row["round"]] = identity
        require(set(row["phases"]) == set(PHASES), "exclusive phase inventory")
        phases = {name: timing(row["phases"][name]) for name in PHASES}
        require(summed(phases.values()) == timing(row["all_exclusive_phases"]), "exclusive totals")
        require(summed(phases[name] for name in RECURRING) == timing(row["recurring_producer_encode_admission"]), "recurring totals")
        outer = timing(row["observed_outer"])
        for clock in ("wall_ns", "process_cpu_ns"):
            part = row["all_exclusive_phases"][clock]
            require(part is None or outer[clock] is None or outer[clock] >= part, "overlapping phase accounting")
        require(len(row["searches"]) == 64, "all searches retained")
        ids, attempts, wins, generation, admission, admitted_bytes = set(), 0, 0, [], [], {}
        for i, search in enumerate(row["searches"]):
            require(search["search"] == i and type(search["won"]) is bool, "search order")
            trials = search["trials"]
            require(1 <= len(trials) <= 8 and (search["won"] or len(trials) == 8), "exhausted search omitted")
            attempts += len(trials)
            for j, trial in enumerate(trials):
                require(trial["trial"] == j and trial["nonce"] == (1 << 32) + row["round"] * (1 << 24) + i * 8 + j,
                        "disjoint fixed nonce window")
                for name in ("challenge", "proof_sha256", "ticket"):
                    hex_value(trial[name], 64)
                hit = bytes.fromhex(trial["ticket"]) <= bytes.fromhex(row["target"])
                require(type(trial["target_hit"]) is bool and trial["target_hit"] == hit and
                        hit == (search["won"] and j == len(trials) - 1), "original ticket predicate")
                generation.append(timing(trial["generation"]))
                if hit:
                    packet = hex_value(trial["packet_id"], 64)
                    require(packet not in ids, "duplicate fast-path admission")
                    ids.add(packet)
                    admitted_bytes[packet] = number(trial["packet_bytes"])
                    admission.append(timing(trial["native_admission"]))
                    wins += 1
                else:
                    require("packet_id" not in trial and "native_admission" not in trial, "miss credited")
        require(attempts == row["attempts"] and wins == row["winners"] and
                row["exhausted"] == 64 - wins and row["first_native_admissions"] == wins and
                row["cold_packet_readbacks"] == wins, "effective ticket denominator")
        require(summed(generation) == phases["all_attempt_generation"] and
                summed(admission) == phases["first_native_admission"], "actual call phase totals")
        retained = row["retained_packets"]
        require(len(retained) == wins and {hex_value(p["id"], 64) for p in retained} == ids, "cold retained coverage")
        for packet in retained:
            hex_value(packet["sha256"], 64)
            require(number(packet["bytes"]) == admitted_bytes[packet["id"]], "cold packet size changed")
        require(row["hot_active_before_close"]["id"] == row["parent"] and
                row["cold_recovery_active"]["id"] == (min(ids) if ids else row["parent"]) and
                row["cold_recovery_selected_height"] == int(bool(ids)), "ordinary cold recovery selection")
        number(row["hot_active_before_close"]["generation"])
        number(row["cold_recovery_active"]["generation"])
        global_ids.update(ids)
        groups.append({"round": row["round"], "reuse": row["reuse"], "strategy": row["strategy"],
                       "attempts": attempts, "winners": wins, "exhausted": 64 - wins,
                       "phases": phases, "recurring": row["recurring_producer_encode_admission"],
                       "all_phases": row["all_exclusive_phases"], "outer": outer,
                       "milliseconds_per_first_admitted_ticket": {
                           scope: {clock.replace("_ns", "_ms"): (value / wins / 1_000_000 if wins and value is not None else None)
                                   for clock, value in row[field].items()}
                           for scope, field in (("recurring", "recurring_producer_encode_admission"),
                                                ("all_phases", "all_exclusive_phases"), ("outer", "observed_outer"))}})
    comparisons = []
    for reuse in (False, True):
        arms = {}
        for arm in ARMS:
            selected = [r for r in groups if r["reuse"] == reuse and r["strategy"] == arm]
            wins = sum(r["winners"] for r in selected)
            arms[arm] = {"winning_first_admissions": wins, "attempts": sum(r["attempts"] for r in selected)}
            for scope in ("recurring", "all_phases", "outer"):
                value = summed(r[scope] for r in selected)
                arms[arm][scope] = {clock.replace("_ns", "_ms"): (n / wins / 1_000_000 if wins and n is not None else None)
                                   for clock, n in value.items()}
        ratios = {scope: {clock: (arms[ARMS[1]][scope][clock] / arms[ARMS[0]][scope][clock]
                                  if arms[ARMS[0]][scope][clock] and arms[ARMS[1]][scope][clock] is not None else None)
                           for clock in ("wall_ms", "process_cpu_ms")}
                  for scope in ("recurring", "all_phases", "outer")}
        comparisons.append({"reuse": reuse, "arms_ms_per_first_admission": arms, "limb_over_general": ratios})
    return {"schema": "pon-legal-ticket-first-admission-summary-v3", "cohorts": 8,
            "fresh_stores": 8, "first_admission_calls": sum(r["winners"] for r in groups),
            "distinct_fixture_packet_ids_across_paired_cohorts": len(global_ids),
            "groups": groups, "comparisons": comparisons, "settings_setup": timing(begin["settings_setup"]),
            "standalone_verifier_double_counted": False, "physical_power_loss_qualified": False,
            "native_independent_hardware_qualified": False, "production_qualified": False,
            "global_minimum_proved": False, "hardware_batching_measured": False,
            "scope": "distinct native tickets within each fresh store; paired fixture bytes repeat across cohorts; no active-chain rewards; all setup and failed attempts retained"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument("--expected-head", required=True)
    p.add_argument("--source-before", type=Path, required=True)
    p.add_argument("--source-after", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    capture = parsed(args.capture.read_bytes())
    raw = args.capture.parent / "stdout.jsonl.gz"
    rows, count, digest = read_rows(raw)
    require(capture["exit_code"] == 0 and capture["timed_out"] is False and
            capture["stable_binary"] is True and capture["stdout_within_bound"] is True and
            capture["timeout_seconds"] == 250 and capture["elapsed_ns"] <= 250_000_000_000,
            "native capture did not close within original budget")
    require(capture["binary_sha256_before"] == capture["binary_sha256_after"], "binary changed")
    require(capture["stdout_bytes"] == count and capture["stdout_uncompressed_sha256"] == digest and
            capture["stdout_gzip_sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest(), "raw evidence identity")
    before, after = parsed(args.source_before.read_bytes()), parsed(args.source_after.read_bytes())
    require(before == after and before["tested_commit"] == args.expected_head and
            before["tracked_worktree_verified"] is True and before["kind"] == "head", "full source identity")
    require(capture["source"]["commit"] == args.expected_head and
            capture["source"]["tree"] == before["tested_tree"] and
            capture["source"]["example_sha256"] == rows[0]["compiled_driver_sha256"] and
            capture["source"]["lock_sha256"] == rows[0]["compiled_cargo_lock_sha256"], "compiled source binding")
    result = validate(rows)
    result.update(source=before, native_capture=capture, raw_uncompressed_sha256=digest)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("schema", "cohorts", "first_admission_calls",
                                            "distinct_fixture_packet_ids_across_paired_cohorts")}))


if __name__ == "__main__":
    main()
