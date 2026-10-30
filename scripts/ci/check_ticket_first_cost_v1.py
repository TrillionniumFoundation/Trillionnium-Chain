#!/usr/bin/env python3
"""Read the separate native ticket-first experiment without certifying hardness.

The original bounded V5 reader supplies JSON, gzip and clock handling. The
existing Python wire/material oracles reconstruct every challenge, ticket,
canonical proof digest and retained packet. Trace values are checked for paired
consistency, not independently recomputed W1 arithmetic on every failed nonce.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from check_legal_ticket_cost_v5 import (
    HORIZONS, PHASES, RECURRING, hex_value, number, parsed, read_rows,
    require, summed, timing,
)
from capture_pure_pon_campaign import digest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from contract_wire import H, PARAMS, header_decode, header_encode, sequence_root
from pon_w1_cost_matrix_reader import PROOF_BYTES, material
from read_original_native_campaign import cost_ratio

SCHEMA = "pon-ticket-first-native-cost-v1"
ARMS = ("generic-legacy", "generic-candidate-all", "generic-ticket-first",
        "limb-legacy", "limb-candidate-all", "limb-ticket-first")
COHORTS = 2 * len(HORIZONS) * 2 * len(ARMS)
STREAM_DOMAIN = b"TRNM-TICKET-FIRST-NATIVE-STREAM-V1\0"
CLOCKS = ("wall_ns", "process_cpu_ns")
SCOPES = ("generation", "recurring", "all_phases", "outer")
JOURNAL_SCHEMA = "pon-ticket-first-progress-v1"
JOURNAL_LIMIT = 64 * 1024 * 1024
JOURNAL_LINE_LIMIT = 16 * 1024


def exact(value, names, label):
    require(type(value) is dict and set(value) == set(names), label + " fields")


def hash_bytes(value):
    return bytes.fromhex(hex_value(value, 64))


def complete_sum(values):
    values = list(values)
    return sum(values) if all(value is not None for value in values) else None


def difference(alternative, reference):
    return alternative - reference if alternative is not None and reference is not None else None


def paired_costs(reference, alternative):
    """Compare complete fixed arms, preserving both rounds and all misses."""
    rounds = []
    for left, right in zip(reference, alternative):
        require((left["round"], left["attempts"], left["winners"], left["exhausted"]) ==
                (right["round"], right["attempts"], right["winners"], right["exhausted"]),
                "paired cost denominators")
        rounds.append({
            "round": left["round"], "attempts": left["attempts"], "winners": left["winners"],
            "exhausted": left["exhausted"],
            "reference_proof_materializations": left["proof_materializations"],
            "alternative_proof_materializations": right["proof_materializations"],
            "alternative_minus_reference_ns": {
                scope: {clock: difference(right[scope][clock], left[scope][clock]) for clock in CLOCKS}
                for scope in SCOPES},
            "reference_costs": {scope: left[scope] for scope in SCOPES},
            "alternative_costs": {scope: right[scope] for scope in SCOPES},
        })
    winners = sum(row["winners"] for row in reference)
    aggregate = {}
    for scope in SCOPES:
        aggregate[scope] = {}
        for clock in CLOCKS:
            left = complete_sum(row[scope][clock] for row in reference)
            right = complete_sum(row[scope][clock] for row in alternative)
            deltas = [row["alternative_minus_reference_ns"][scope][clock] for row in rounds]
            known = all(value is not None for value in deltas)
            aggregate[scope][clock] = {
                "reference_total_ns": left, "alternative_total_ns": right,
                "reference_ns_per_first_admission": cost_ratio(left, winners),
                "alternative_ns_per_first_admission": cost_ratio(right, winners),
                "reference_over_alternative_complete_cost": cost_ratio(left, right) if winners else None,
                "paired_alternative_minus_reference_ns": deltas,
                "observed_sign_reversal": min(deltas) < 0 < max(deltas) if known else None,
                "alternative_lower_in_both_rounds": all(value < 0 for value in deltas) if known else None,
                "population_confidence_interval": None,
            }
    return {"paired_rounds": rounds, "attempts": sum(row["attempts"] for row in reference),
            "winning_first_admissions": winners, "exhausted": sum(row["exhausted"] for row in reference),
            "aggregate": aggregate}


def validate(rows):
    require(len(rows) == COHORTS + 2 and all(row.get("schema") == SCHEMA for row in rows),
            "exact complete 96-cohort ticket-first grid")
    begin, terminal = rows[0], rows[-1]
    require(begin["kind"] == "begin" and terminal["kind"] == "terminal" and
            terminal["status"] == "complete" and number(terminal["cohorts"]) == COHORTS,
            "complete campaign terminal")
    for name, expected in {"attempts": 8, "rounds": 2, "seed": 2,
                           "budget_seconds": 600, "native_workers": 1}.items():
        require(number(begin[name]) == expected, "frozen native experiment plan")
    require(begin["horizons"] == list(HORIZONS) and all(type(value) is int for value in begin["horizons"])
            and begin["arms"] == list(ARMS), "all original horizons and six arms")
    for name in ("old_v3_v4_v5_experiments_unchanged", "failed_proof_materialization_is_not_required_work",
                 "winning_only_still_computes_all_transcript_tiles"):
        require(begin[name] is True, "ticket-first scope")
    for name in ("gpu_measured", "energy_measured", "hardware_authenticated", "exclusive_host",
                 "global_minimum_proved", "production_qualified", "debug_assertions"):
        require(begin[name] is False, "unsupported beginning qualification")
    for name in ("global_minimum_proved", "public_fairness_qualified", "active_chain_rewards_measured",
                 "production_qualified"):
        require(terminal[name] is False, "unsupported terminal qualification")
    require(number(terminal["wall_ns"]) <= 600_000_000_000, "late native terminal")
    timing(begin["settings_setup"])
    for name in ("compiled_driver_sha256", "compiled_cargo_lock_sha256"):
        hash_bytes(begin[name])
    expected_order = []
    for round_id in (0, 1):
        for horizon_index, horizon in enumerate(HORIZONS):
            for reuse in (False, True):
                arms = list(ARMS if round_id == 0 else ARMS[::-1])
                rotation = (horizon_index + int(reuse)) % len(ARMS)
                arms = arms[rotation:] + arms[:rotation]
                expected_order.extend((round_id, horizon, reuse, arm) for arm in arms)
    _, _, task, prefix = material("continuity-maintenance-v1")
    require(len(prefix) + 32 == PROOF_BYTES, "original complete proof length")
    prefix_sha = hashlib.sha256(prefix).hexdigest()
    paired, groups, global_ids = {}, [], set()
    proof_digests, wire_cache = {}, {}
    for position, row in enumerate(rows[1:-1]):
        require(row["kind"] == "cohort" and row["status"] == "complete", "completed cohort")
        round_id, horizon, reuse, arm = row["round"], row["search_horizon"], row["reuse"], row["arm"]
        require(type(round_id) is int and type(horizon) is int and type(reuse) is bool and
                (round_id, horizon, reuse, arm) == expected_order[position], "frozen cohort order/identity")
        require(number(row["arm_index"]) == ARMS.index(arm) and number(row["order"]) == position % len(ARMS),
                "counterbalanced arm identity")
        require(row["fresh_store"] is True and row["template_seed_admitted"] is False and
                number(row["explicit_activation_calls"]) == 0, "first-admission scope")
        require(number(row["attempt_budget"]) == 8 and
                number(row["producer_setup_calls"]) == (1 if reuse else horizon), "actual setup/search plan")
        template_raw = bytes.fromhex(hex_value(row["native_template_header"], 636))
        template = header_decode(template_raw)
        require(header_encode(template) == template_raw, "canonical original header")
        require(hash_bytes(row["parent"]) == template["parent"] and hash_bytes(row["target"]) == template["target"]
                and hash_bytes(row["task"]) == task == template["work_task"], "actual header/task/target binding")
        require(template["target"].hex() == PARAMS["initial_target_hex"] and template["height"] == 1
                and template["timestamp"] == 1_800_010_011 and
                template["transactions"] == sequence_root("transactions", []), "fixed fresh native template context")
        require(row["proof_prefix_sha256"] == prefix_sha, "independently reconstructed maintenance prefix")
        exact(row["phases"], PHASES, "exclusive phases")
        phases = {name: timing(row["phases"][name]) for name in PHASES}
        require(summed(phases.values()) == timing(row["all_exclusive_phases"]), "exclusive phase accounting")
        require(summed(phases[name] for name in RECURRING) == timing(row["recurring_producer_encode_admission"]),
                "recurring phase accounting")
        outer = timing(row["observed_outer"])
        for clock in CLOCKS:
            part = row["all_exclusive_phases"][clock]
            require(part is None or outer[clock] is None or outer[clock] >= part, "nested/overlapping cost scopes")
        require(type(row["searches"]) is list and len(row["searches"]) == horizon, "every actual search retained")
        stream = hashlib.sha256(STREAM_DOMAIN)
        ids, retained, projection = set(), [], []
        generation, admission = [], []
        partitions = {name: [] for name in ("winning_trials", "misses_before_winner", "exhausted_search_trials")}
        attempts = winners = materialized = 0
        for search_id, search in enumerate(row["searches"]):
            exact(search, ("search", "won", "trials"), "search")
            require(number(search["search"]) == search_id and type(search["won"]) is bool, "search identity")
            trials = search["trials"]
            require(type(trials) is list and 1 <= len(trials) <= 8 and (search["won"] or len(trials) == 8),
                    "complete bounded search including exhaustion")
            observed_trials = []
            for trial_id, trial in enumerate(trials):
                fields = {"trial", "nonce", "challenge", "trace", "ticket", "canonical_proof_sha256",
                          "target_hit", "proof_materialized", "generation"}
                require(type(trial["target_hit"]) is bool, "boolean target result")
                if trial["target_hit"]:
                    fields.update(("native_admission", "packet_id", "packet_bytes"))
                exact(trial, fields, "trial")
                nonce = (2 << 32) + round_id * (1 << 24) + horizon * 4096 + search_id * 8 + trial_id
                require(number(trial["trial"]) == trial_id and number(trial["nonce"]) == nonce,
                        "fixed disjoint complete nonce windows")
                trace = hash_bytes(trial["trace"])
                cache_key = (template_raw, nonce)
                if cache_key not in wire_cache:
                    header = header_encode(dict(template, nonce=nonce))
                    wire_cache[cache_key] = (header, H("challenge", header))
                header, challenge = wire_cache[cache_key]
                ticket = H("ticket", challenge, trace)
                if trace not in proof_digests:
                    proof_digests[trace] = hashlib.sha256(prefix + trace).digest()
                proof_sha = proof_digests[trace]
                require(hash_bytes(trial["challenge"]) == challenge, "nonce/header challenge mismatch")
                require(hash_bytes(trial["ticket"]) == ticket, "original complete ticket hash")
                require(hash_bytes(trial["canonical_proof_sha256"]) == proof_sha,
                        "canonical full prefix/trace proof digest")
                hit = ticket <= template["target"]
                require(trial["target_hit"] is hit and hit == (search["won"] and trial_id == len(trials) - 1),
                        "original predicate and first-hit termination")
                assembly = not arm.endswith("-ticket-first") or hit
                require(type(trial["proof_materialized"]) is bool and trial["proof_materialized"] is assembly,
                        "winning-only/always-materialized assembly contract")
                materialized += int(assembly)
                attempts += 1
                observed = timing(trial["generation"])
                generation.append(observed)
                partition = "winning_trials" if hit else "misses_before_winner" if search["won"] else "exhausted_search_trials"
                partitions[partition].append(observed)
                stream.update(header)
                stream.update(trace)
                stream.update(ticket)
                stream.update(proof_sha)
                observed_trials.append((nonce, challenge.hex(), trace.hex(), ticket.hex(), proof_sha.hex(), hit))
                if hit:
                    packet_id = H("block", header, trace).hex()
                    require(hex_value(trial["packet_id"], 64) == packet_id and packet_id not in ids,
                            "distinct original first-admission packet id")
                    packet = header + b"\0\0" + prefix + trace
                    require(number(trial["packet_bytes"]) == len(packet), "complete empty-transaction packet length")
                    retained.append({"id": packet_id, "sha256": hashlib.sha256(packet).hexdigest(), "bytes": len(packet)})
                    ids.add(packet_id)
                    winners += 1
                    admission.append(timing(trial["native_admission"]))
            projection.append((search_id, search["won"], tuple(observed_trials)))
        for name, expected in {"attempts": attempts, "winners": winners, "exhausted": horizon - winners,
                               "proof_materializations": materialized, "proof_bytes_materialized": materialized * PROOF_BYTES,
                               "first_native_admissions": winners, "cold_packet_readbacks": winners}.items():
            require(number(row[name]) == expected, "complete attempt/admission/materialization denominators")
        require(summed(generation) == phases["all_attempt_generation"] and
                summed(admission) == phases["first_native_admission"], "actual call timing sums")
        require(type(row["retained_packets"]) is list and row["retained_packets"] == retained,
                "complete original cold packet bytes/hash/readback coverage")
        require(hash_bytes(row["stream_sha256"]) == stream.digest(), "recomputed complete native stream")
        identity = (template_raw, tuple(projection), tuple((p["id"], p["sha256"], p["bytes"]) for p in retained))
        pair_key = (round_id, horizon)
        require(pair_key not in paired or paired[pair_key] == identity, "all six arms/reuse must retain identical full streams")
        paired[pair_key] = identity
        for name in ("hot_active_before_close", "cold_recovery_active"):
            exact(row[name], ("id", "generation"), name)
            number(row[name]["generation"])
        require(row["hot_active_before_close"]["id"] == row["parent"] and
                row["cold_recovery_active"]["id"] == (min(ids) if ids else row["parent"]), "ordinary hot/cold selection")
        global_ids.update(ids)
        groups.append({
            "round": round_id, "horizon": horizon, "reuse": reuse, "arm": arm,
            "attempts": attempts, "winners": winners, "exhausted": horizon - winners,
            "producer_setup_calls": row["producer_setup_calls"], "proof_materializations": materialized,
            "proof_bytes_materialized": row["proof_bytes_materialized"],
            "generation_partition": {name: {"attempts": len(values), "timing": summed(values)}
                                     for name, values in partitions.items()},
            "phases": phases, "generation": phases["all_attempt_generation"],
            "recurring": row["recurring_producer_encode_admission"],
            "all_phases": row["all_exclusive_phases"], "outer": outer,
            "outer_residual": {clock: difference(outer[clock], row["all_exclusive_phases"][clock])
                               for clock in CLOCKS},
        })
    require(sum(row["outer"]["wall_ns"] for row in groups) + begin["settings_setup"]["wall_ns"] <= terminal["wall_ns"],
            "sequential outer cohorts exceed full native terminal")
    comparisons = []
    for horizon in HORIZONS:
        for reuse in (False, True):
            for producer in ("generic", "limb"):
                for label, before, after in (("candidate-allocation-path", "legacy", "candidate-all"),
                                             ("omit-failed-proof-assembly", "candidate-all", "ticket-first")):
                    reference = [row for row in groups if (row["horizon"], row["reuse"], row["arm"]) ==
                                 (horizon, reuse, producer + "-" + before)]
                    alternative = [row for row in groups if (row["horizon"], row["reuse"], row["arm"]) ==
                                   (horizon, reuse, producer + "-" + after)]
                    comparisons.append({"horizon": horizon, "reuse": reuse, "producer": producer,
                                        "comparison": label, "reference_arm": producer + "-" + before,
                                        "alternative_arm": producer + "-" + after,
                                        **paired_costs(reference, alternative)})
    return {
        "schema": "pon-ticket-first-native-cost-summary-v1", "raw_schema": SCHEMA,
        "cohorts": COHORTS, "groups": groups, "fixed_paired_comparisons": comparisons,
        "attempts_including_paired_repetitions": sum(row["attempts"] for row in groups),
        "first_admission_calls": sum(row["winners"] for row in groups),
        "distinct_fixture_packet_ids_across_paired_cohorts": len(global_ids),
        "settings_setup": begin["settings_setup"],
        "boundaries": {
            "all_failed_attempts_and_exhausted_searches_retained": True,
            "header_challenge_ticket_stream_recomputed": True,
            "canonical_proof_and_packet_bytes_reconstructed": True,
            "every_w1_transcript_independently_replayed": False,
            "proof_materialization_counts_include_template_bootstrap": False,
            "two_paired_rounds_are_independent_host_samples": False,
            "population_confidence_interval_qualified": False,
            "fresh_native_execution_by_reader": False,
            "source_capture_is_physical_attestation": False,
            "global_minimum_proved": False, "public_fairness_qualified": False,
            "throughput_qualified": False, "quantum_cost_bound": False, "production_qualified": False,
        },
        "scope": [
            "Legacy versus candidate-all isolates the changed candidate/allocation path; candidate-all versus ticket-first isolates skipped failed-proof materialization within that path. Both still recompute the full transcript.",
            "All setup, failed trials, exhausted searches, native admission and cold readback remain. The generation partition is disjoint; recurring, exclusive phases and outer clocks are nested and must not be added together.",
            "Per-trial audit hashing, journal I/O and recording are outside generation but inside outer cohorts. Outer residual is outer minus the disjoint phases, not an extra cost to add. Stream finalization, cohort JSON construction, final serialization, directory cleanup and final producer drop are outside observed_outer and remain in the complete process capture. Template bootstrap work is charged separately and is not a counted trial materialization.",
            "Pairwise ratios use complete costs of the same fixed implementation across both rounds, including misses. A missing clock remains unknown and zero winners supply no per-winner ratio. No cherry-picked fastest-round strategy is constructed.",
            "Wire hashes and paired traces do not independently prove each W1 transcript or authenticate hardware. Finite shared-host observations are not a global cost lower bound, network work share, fairness or TPS qualification.",
        ],
    }


def validate_journal(rows, path):
    """Match a successful write-ahead stream without losing event order/types.

    Incomplete or failed runs keep their original stderr; this function grants
    no success to a prefix. Journal-only encoding/readback timers reconcile the
    existing phase totals and are not a second cost denominator.
    """
    require(path.stat().st_size <= JOURNAL_LIMIT, "journal total bound")
    counts, hasher, byte_count = Counter(), hashlib.sha256(), 0
    with path.open("rb") as stream:
        def event(kind, cohort, clock_field=None, **fields):
            nonlocal byte_count
            raw = stream.readline(JOURNAL_LINE_LIMIT + 2)
            require(raw and len(raw) <= JOURNAL_LINE_LIMIT + 1 and raw.endswith(b"\n"),
                    "journal missing/truncated/oversized line")
            byte_count += len(raw)
            require(byte_count <= JOURNAL_LIMIT, "journal total bound")
            hasher.update(raw)
            observed = parsed(raw)
            require(type(observed) is dict, "journal record object")
            if clock_field is not None:
                fields[clock_field] = timing(observed[clock_field])
            expected = {"schema": JOURNAL_SCHEMA, "kind": kind, "cohort": cohort, **fields}
            # JSON's separate bool/number/null types must remain separate;
            # Python equality alone would accept False in place of integer 0.
            require(json.dumps(observed, sort_keys=True, separators=(",", ":"), allow_nan=False) ==
                    json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False),
                    "journal " + kind + " fields/order/observation mismatch")
            counts[kind] += 1
            return observed

        for row in rows[1:-1]:
            cohort = {"round": row["round"], "horizon": row["search_horizon"],
                      "reuse": row["reuse"], "arm": row["arm"]}
            event("cohort-start", cohort)
            encodings, readbacks = [], []
            for search in row["searches"]:
                for trial in search["trials"]:
                    event("trial-start", cohort, search=search["search"], trial=trial["trial"], nonce=trial["nonce"])
                    generated = {key: value for key, value in trial.items()
                                 if key not in ("native_admission", "packet_id", "packet_bytes")}
                    event("trial-generated", cohort, search=search["search"], observation=generated)
                    if trial["target_hit"]:
                        encoded = event("admission-start", cohort, clock_field="packet_encoding",
                                        search=search["search"], trial=trial["trial"], packet_id=trial["packet_id"])
                        encodings.append(encoded["packet_encoding"])
                        event("admission-result", cohort, search=search["search"], trial=trial["trial"],
                              packet_id=trial["packet_id"], timing=trial["native_admission"],
                              accepted_id=trial["packet_id"], error=None)
            event("generation-complete", cohort, attempts=row["attempts"], winners=row["winners"],
                  all_attempt_generation=row["phases"]["all_attempt_generation"],
                  first_native_admission=row["phases"]["first_native_admission"])
            require(summed(encodings) == row["phases"]["packet_encoding"], "journal packet encoding phase total")
            for packet in row["retained_packets"]:
                event("cold-read-start", cohort, packet_id=packet["id"])
                observed = event("cold-read-result", cohort, clock_field="timing", packet_id=packet["id"],
                                 sha256=packet["sha256"], bytes=packet["bytes"])
                readbacks.append(observed["timing"])
            require(summed(readbacks) == row["phases"]["cold_packet_readback"], "journal cold readback phase total")
            event("cohort-complete", cohort, stream_sha256=row["stream_sha256"])
        require(stream.read(1) == b"", "extra journal event or trailing bytes")
    return {"schema": JOURNAL_SCHEMA, "sha256": hasher.hexdigest(), "bytes": byte_count,
            "events": sum(counts.values()), "event_counts": dict(sorted(counts.items())),
            "complete_cohorts": COHORTS, "stdout_observations_matched": True,
            "journal_only_timings_reconcile_existing_phases": True,
            "journal_timings_added_to_existing_cost_totals": False,
            "physical_execution_attested": False}


def bound_capture(capture_path, expected_head, source_before, source_after):
    """Use the existing collector, bounded raw reader and exact-source contract."""
    for path in (capture_path, source_before, source_after):
        require(path.stat().st_size <= 1024 * 1024, "bounded capture/source JSON")
    capture = parsed(capture_path.read_bytes())
    raw = capture_path.parent / "stdout.jsonl.gz"
    stderr = capture_path.parent / "stderr.log"
    require(stderr.stat().st_size <= JOURNAL_LIMIT, "journal total bound")
    require(hash_bytes(capture["stderr_sha256"]).hex() == digest(stderr), "original stderr identity")
    require(capture["schema"] == "pon-ticket-first-release-capture-v1" and
            capture["build_profile"] == "cargo --release; original repository release defaults" and
            capture["package_opt_levels"] == {"trnm-pon-node": 3, "trnm-crypto-primitives": 3, "trnm-mvcc-fee": 3} and
            number(capture["debug_info"]) == 0 and capture["incremental"] is False and
            number(capture["build_jobs"]) > 0 and capture["build_environment_overrides"] == {},
            "explicit original release build contract")
    for name in ("exclusive_host", "host_contention_controlled", "production_qualified", "hardness_proved"):
        require(capture[name] is False, "unsupported physical/source capture qualification")
    require(
            type(capture["exit_code"]) is int and capture["exit_code"] == 0 and capture["timed_out"] is False and
            capture["stable_binary"] is True and capture["stdout_within_bound"] is True and
            number(capture["timeout_seconds"]) == 610 and number(capture["elapsed_ns"]) <= 610_000_000_000,
            "native capture did not close within original budget")
    rows, count, raw_digest = read_rows(raw)
    require(capture["binary_sha256_before"] == capture["binary_sha256_after"] and
            number(capture["stdout_bytes"]) == count and capture["stdout_uncompressed_sha256"] == raw_digest and
            capture["stdout_gzip_sha256"] == digest(raw), "raw/binary identity")
    hash_bytes(capture["binary_sha256_before"])
    before, after = parsed(source_before.read_bytes()), parsed(source_after.read_bytes())
    require(before == after and before["tested_commit"] == expected_head and
            before["tracked_worktree_verified"] is True and before["kind"] == "head", "full source identity")
    require(capture["source"]["commit"] == expected_head and capture["source"]["tree"] == before["tested_tree"] and
            capture["source"]["example_sha256"] == rows[0]["compiled_driver_sha256"] and
            capture["source"]["lock_sha256"] == rows[0]["compiled_cargo_lock_sha256"], "compiled source binding")
    require(type(capture["argv"]) is list and len(capture["argv"]) == 1 and
            Path(capture["argv"][0]).name == "pon_ticket_first_cost_v1", "original native driver without runtime overrides")
    result = validate(rows)
    journal = validate_journal(rows, stderr)
    require(journal["sha256"] == capture["stderr_sha256"], "stderr changed during journal validation")
    result.update(source=before, native_capture=capture, raw_uncompressed_sha256=raw_digest, journal=journal)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--source-before", type=Path, required=True)
    parser.add_argument("--source-after", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = bound_capture(args.capture, args.expected_head, args.source_before, args.source_after)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({name: result[name] for name in
                      ("schema", "cohorts", "first_admission_calls", "distinct_fixture_packet_ids_across_paired_cohorts")}))


if __name__ == "__main__":
    main()
