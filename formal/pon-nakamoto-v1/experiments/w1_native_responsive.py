#!/usr/bin/env python3
"""Freeze responsive native experiments and independently read their evidence.

The native harness owns Node production, admission and authenticated reopen.
Python verifies exact plan/clock/source/packet bytes and event causality. Native
execution uses a declared logical event clock and eager CPU observer proofs;
it is not physically timed quantum mining. The separate reduced Bellman model
does not certify the native honest miner's unenumerated W1 probabilities.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

import contract_wire as wire
import work_oracle
import w1_native_bridge as bridge
from reference import timestamp_state, work
from w1_finite_consensus import _metadata, _required
from w1_machine_architecture import build_service_architecture, declared_architectures
from w1_machine_envelope import build_machine_envelope, machine_action_clock
from w1_marked_domain import enumerate_domain
from w1_quantum_oracle import canonical, template_from_spec
import w1_responsive_consensus as responsive

SCHEMA = "trnm-w1-native-responsive-execution-v1"
PLAN_SCHEMA = "trnm-w1-native-responsive-plan-v1"
CLOCK_SCHEMA = "trnm-w1-native-responsive-clock-records-v1"
READBACK_SCHEMA = "trnm-w1-native-responsive-readback-v1"
PLAN_FILE = "responsive-plan.json"
CLOCK_FILE = "responsive-clock-records.json"
REPORT_FILE = "native-responsive-execution.json"
SEEDS = (9, 17, 41, 73)
HONEST_NONCE_DOMAIN = "trnm-w1-native-responsive-honest-nonce-v1"
PRIVATE_NONCE_DOMAIN = "trnm-w1-native-responsive-private-nonce-v1"
FIXED_POLICY = "fixed-causal-private-then-publish-v1"
ADVICE_POLICY = "observer-advice-private-winning-path-v1"
CLAIMS = {
    "logical_event_clock": True, "physical_clock_calibrated": False,
    "eager_cpu_proof_generation_is_observer_work": True,
    "eager_results_visible_before_candidate_completion": False,
    "cancelled_eager_cpu_proof_costs_retained": True,
    "model_elapsed_ticks_are_interrupted_cpu_measurements": False,
    "honest_parent_reacts_to_delivered_selection": True,
    "completed_stale_packets_survive_rebind": True,
    "all_started_attempts_retained": True,
    "ancestor_includes_tip": True,
    "native_public_network_executed": False,
    "native_honest_probabilities_exhaustively_enumerated": False,
    "quantum_hardware_executed": False, "quantum_mining_qualified": False,
    "long_horizon_settlement_security_proved": False, "production_activation": False,
}
require, sha, read = bridge.require, bridge.sha, bridge.read
strict_load, json_bytes, write_new = bridge.strict_load, bridge.json_bytes, bridge.write_new
ratio, rational, integer = responsive.ratio, responsive.rational, responsive.integer


def sources():
    result = bridge.sources()
    for name in ("formal/pon-nakamoto-v1/w1_responsive_consensus.py",
                 "formal/pon-nakamoto-v1/w1_machine_architecture.py",
                 "formal/pon-nakamoto-v1/experiments/w1_native_responsive.py"):
        result["source_sha256"][name] = sha(read(ROOT / name))
    result["source_sha256"] = dict(sorted(result["source_sha256"].items()))
    return result


def ceil_ticks(seconds, tick=Fraction(1, 4)):
    require(seconds >= 0 and tick > 0, "RESPONSIVE_CLOCK_RANGE")
    value = seconds / tick
    return (value.numerator + value.denominator - 1) // value.denominator


def seeded_nonce(seed, attempt_index, parent_id, owner):
    integer(seed, "RESPONSIVE_SEED", 0, (1 << 64) - 1)
    integer(attempt_index, "RESPONSIVE_ATTEMPT_INDEX", 0, (1 << 64) - 1)
    require(owner in ("honest", "private"), "RESPONSIVE_NONCE_OWNER")
    require(type(parent_id) is str and len(parent_id) == 64
            and bytes.fromhex(parent_id).hex() == parent_id, "RESPONSIVE_NONCE_PARENT")
    domain = HONEST_NONCE_DOMAIN if owner == "honest" else PRIVATE_NONCE_DOMAIN
    raw = domain.encode() + b"\0" + struct.pack("<QQ", seed, attempt_index) + bytes.fromhex(parent_id)
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "little") % 8


def clock_records(fixture):
    """The entire fixed allocation precedes clock projection; no hardware credit.

    Maximum per-context phase clocks are safe for any declared private branch.
    Fresh setup is paid on each attempt, including a repeated context. This is
    an explicit implementation choice, not a minimum-cost attacker bound.
    """
    classical, physical, lifecycle = bridge.declared_models()
    domains = tuple(enumerate_domain(template_from_spec(row["template_spec"]))
                    for row in fixture["contexts"])
    costs = (classical,) * len(domains)
    schedule = tuple((index, 1) for index in range(len(domains)) for _ in range(2))
    serial = build_machine_envelope(domains, schedule, 1, costs, physical, lifecycle,
        10**16, "4", predicate="full", reserved_maximum_winners=2)
    parallel = build_service_architecture(domains, schedule, 1, costs, physical, lifecycle,
        declared_architectures()[2], 10**16, "4", predicate="full", reserved_maximum_winners=2)
    records = {}
    for architecture, machine, allocation in (
            ("classical-host", None, {"classical_costs_ns": asdict(classical),
             "quantum_resources": None, "physical_clock_calibrated": False}),
            ("serial-lifecycle", serial, serial),
            ("declared-reset-65536-readout-64-v1", parallel["machine_record"], parallel)):
        for count in ((0,) if machine is None else (0, 1)):
            phases = []
            for index, context in enumerate(fixture["contexts"]):
                if machine is None:
                    check = Fraction(classical.task_preprocessing_ns + classical.per_search_setup_ns
                                     + classical.per_trial_reset_readout_ns
                                     + classical.per_completed_trial_candidate_check_ns, 10**9)
                    proof, propagation = Fraction(classical.per_winner_proof_ns, 10**9), Fraction(classical.per_winner_propagation_ns, 10**9)
                    raw_clock = None
                else:
                    raw_clock = machine_action_clock(machine, index, count, resident_setup=True)
                    check = rational(raw_clock["search_seconds_exact"])
                    proof = rational(raw_clock["classical_phase_seconds_exact"]["winner_proof"])
                    propagation = rational(raw_clock["classical_phase_seconds_exact"]["winner_propagation"])
                phases.append({"context_id": context["context_id"],
                    "candidate_check_seconds_exact": ratio(check), "winner_proof_seconds_exact": ratio(proof),
                    "per_block_propagation_seconds_exact": ratio(propagation), "full_clock": raw_clock})
            key = architecture + "-q" + str(count)
            record = {"architecture": architecture, "iterations": count, "allocation": allocation,
                      "per_context_clocks": phases,
                      "execution_kind": "classical-uniform-q0" if machine is None else "constructed-quantum"}
            clock = {"clock_record_sha256": responsive.digest(record),
                     "candidate_check_seconds_exact": ratio(max(rational(row["candidate_check_seconds_exact"]) for row in phases)),
                     "winner_proof_seconds_exact": ratio(max(rational(row["winner_proof_seconds_exact"]) for row in phases)),
                     "per_block_propagation_seconds_exact": ratio(max(rational(row["per_block_propagation_seconds_exact"]) for row in phases))}
            for label in ("candidate_check", "winner_proof", "per_block_propagation"):
                clock[label + "_ticks"] = ceil_ticks(rational(clock[label + "_seconds_exact"]))
                require(clock[label + "_ticks"] > 0, "RESPONSIVE_POSITIVE_PHASE_CLOCK")
            if count:
                require(clock["candidate_check_ticks"] > 16, "QUANTUM_SAMPLER_UNIMPLEMENTED")
            records[key] = {"record": record, "projected_clock": clock}
    return {"schema": CLOCK_SCHEMA, "source": sources(), "records": records,
            "projection": "ceil each positive exact phase separately to 1/4s; no deadline extension; fresh setup every attempt",
            "whole_quantum_schedule": "each retained private context reserves two qmax=1 trials and two winner services; one code distance per complete allocation",
            "q_positive_execution": "pre-candidate deadline censor only; no fabricated Grover sample",
            "quantum_mining_qualified": False, "physical_clock_calibrated": False}


def build_plan(fixture, fixture_sha256, clocks, clocks_sha256):
    runs = []
    def add(name, policy, seed, key):
        record = clocks["records"][key]
        runs.append({"run_id": name, "policy": policy, "seed": seed,
            "execution_kind": record["record"]["execution_kind"],
            "iterations": record["record"]["iterations"], "architecture": record["record"]["architecture"],
            "clock_key": key, "private_clock": record["projected_clock"]})
    for seed in SEEDS:
        add("classical-fixed-seed" + str(seed), FIXED_POLICY, seed, "classical-host-q0")
    for architecture in ("serial-lifecycle", "declared-reset-65536-readout-64-v1"):
        for count in (0, 1):
            add(architecture + "-q" + str(count) + "-seed9", FIXED_POLICY, 9,
                architecture + "-q" + str(count))
    for seed in SEEDS:
        add("classical-observer-advice-seed" + str(seed), ADVICE_POLICY, seed, "classical-host-q0")
    return {"schema": PLAN_SCHEMA, "source": sources(),
        "base_fixture_file_sha256": fixture_sha256,
        "clock_records_file": CLOCK_FILE, "clock_records_file_sha256": clocks_sha256,
        "horizon_seconds": "4", "tick_seconds": ratio(Fraction(1, 4)), "horizon_ticks": 16,
        "honest_attempt_ticks": 3, "honest_delivery_ticks": 1, "honest_tip_notification_ticks": 1,
        "max_honest_attempts": 6, "max_private_attempts": 2, "nonce_bits": 3,
        "clock_origin_timestamp": fixture["clock_origin_timestamp"],
        "honest_timestamp_rule": "max(parent.timestamp+1,clock_origin+floor(start_tick/4)+1)",
        "private_timestamp_rule": "genesis_timestamp+height; original private fixture domain",
        "private_phase_policy": "separate-candidate-and-winner-proof-v1",
        "private_publication_policy": "parent-first serial publication after attempt budget exhaustion; no free delivery at horizon",
        "nonce_rule": {"algorithm": "sha256-first8-little-mod8", "attempt_index_origin": 0,
            "input": "domain-utf8 || 00 || seed-le64 || attempt-index-le64 || parent-id32",
            "honest_domain": HONEST_NONCE_DOMAIN, "private_domain": PRIVATE_NONCE_DOMAIN},
        "equal_time_order": "honest-completion; honest-before-private-delivery; notices; private-completion; honest-restart",
        "notification_rule": "each selected-tip change queues a generation-bound notification; only newer generations change view",
        "cancellation_rule": "on changed delivered view cancel in-flight honest attempt; charge elapsed ticks and full eager CPU costs; completed queued packets survive",
        "eager_cpu_rule": "producer may generate and verify full proof at start as observer computation; controller sees verdict only at candidate completion",
        "q_positive_execution": "pre-candidate deadline censor only; finishing candidate check requires unimplemented quantum sampler and must fail",
        "runs": runs, "claims": dict(CLAIMS)}


def make_plan(directory):
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    require(not (directory / PLAN_FILE).exists() and not (directory / CLOCK_FILE).exists(), "RESPONSIVE_OUTPUT_EXISTS")
    before = sources()
    fixture, fixture_sha, checked = bridge.load_fixture(directory)
    clocks = clock_records(fixture)
    clock_raw = json_bytes(clocks)
    plan = build_plan(fixture, fixture_sha, clocks, sha(clock_raw))
    require(sources() == before, "RESPONSIVE_SOURCE_CHANGED")
    write_new(directory / CLOCK_FILE, clocks)
    write_new(directory / PLAN_FILE, plan)
    write_new(directory / "responsive-plan-observer-clock.json", {
        "schema": "trnm-w1-responsive-plan-observer-clock-v1", "wall_ns": time.perf_counter_ns() - wall,
        "cpu_ns": time.process_time_ns() - cpu, "scope": "offline source/fixture checks and machine construction; excludes native execution",
        "charged_to_four_second_miner": False, "physical_clock_calibrated": False})
    return {"schema": PLAN_SCHEMA, "status": "PREPARED", "runs": len(plan["runs"]),
            "plan_sha256": sha(read(directory / PLAN_FILE)), "checked_packet_records": checked,
            "private_clocks": {key: value["projected_clock"] for key, value in clocks["records"].items()}}


def load_plan(directory):
    before = sources()
    fixture, fixture_sha, checked = bridge.load_fixture(directory)
    clocks_raw, plan_raw = read(directory / CLOCK_FILE), read(directory / PLAN_FILE)
    clocks, plan = strict_load(clocks_raw), strict_load(plan_raw)
    require(canonical(clocks) == canonical(clock_records(fixture)), "RESPONSIVE_CLOCK_RECORD_CHANGED")
    require(canonical(plan) == canonical(build_plan(fixture, fixture_sha, clocks, sha(clocks_raw))),
            "RESPONSIVE_PLAN_CHANGED")
    hashes = {"native-fixture.json": fixture_sha, CLOCK_FILE: sha(clocks_raw), PLAN_FILE: sha(plan_raw)}
    require(sources() == before, "RESPONSIVE_SOURCE_CHANGED")
    return fixture, plan, hashes, checked


def verify_plan(directory):
    fixture, plan, hashes, checked = load_plan(directory)
    return {"schema": "trnm-w1-native-responsive-plan-check-v1", "status": "VERIFIED",
            "runs": len(plan["runs"]), "verified_inputs": hashes, "source_snapshot": sources(),
            "native_source": fixture["native_source"], "checked_packet_records": checked,
            "runtime_identity": {"executable": sys.executable, "version": sys.version,
                                 "implementation": sys.implementation.name},
            "native_blocks_admitted_by_python_reader": 0, "quantum_hardware_executed": False}


def _packet(directory, row, cache):
    key = row.get("packet_sha256")
    if key in cache:
        header, proof, expected = cache[key]
        require(canonical(expected) == canonical(row), "RESPONSIVE_PACKET_RECORD_CHANGED")
        return header, proof
    raw, proof = bridge.check_packet(directory, row, full_verify=False)
    header = wire.header_decode(raw)
    values = struct.unpack("<" + "I" * (3 * work_oracle.CELLS), proof[4:-32])
    a, b = list(values[:work_oracle.CELLS]), list(values[work_oracle.CELLS:2 * work_oracle.CELLS])
    require(work_oracle.task_id(a, b) == header["work_task"], "RESPONSIVE_TASK_BINDING")
    require(work_oracle.prove(wire.H("challenge", raw), a, b) == proof, "RESPONSIVE_FULL_PROOF_REPLAY")
    winner = wire.H("ticket", wire.H("challenge", raw), proof[-32:]) <= header["target"]
    require(row.get("native_winner", winner) is winner, "RESPONSIVE_TARGET_VERDICT")
    cache[key] = (header, proof, row)
    return header, proof


NATIVE_CLAIMS = {
    "responsive_honest_view_executed": True, "complete_native_candidate_proofs": True,
    "all_canceled_observer_cpu_costs_retained": True,
    "native_daa_timestamps_work_and_reopen_checked": True,
    "model_time_is_physical_time": False, "live_public_network_executed": False,
    "physical_hardware_calibrated": False,
    "native_probabilities_certified_by_reduced_model": False,
    "quantum_hardware_executed": False, "quantum_mining_qualified": False,
    "production_activation": False,
}
STAGE_CLOCKS = ("preparation_elapsed_ns", "proof_elapsed_ns", "verification_elapsed_ns",
                "preparation_cpu_ns", "proof_cpu_ns", "verification_cpu_ns")


def _initial_history(fixture):
    blocks, histories = {}, {}
    rows = [*reversed(fixture["prefix"]["parent_first_headers"]), fixture["public_tip"]]
    for row in rows:
        block = _metadata(row)
        identifier, parent = block["block_id"], block["parent_id"]
        require(identifier not in blocks, "RESPONSIVE_INITIAL_DUPLICATE")
        if block["height"] == 0:
            require(not blocks and parent is None and block["chainwork"] == 0,
                    "RESPONSIVE_INITIAL_GENESIS")
            history = []
        else:
            require(parent in blocks, "RESPONSIVE_INITIAL_PARENT")
            history = histories[parent]
            require(block["height"] == blocks[parent]["height"] + 1
                    and block["target"] == _required(blocks[parent], history)
                    and block["chainwork"] == blocks[parent]["chainwork"] + work(block["target"]),
                    "RESPONSIVE_INITIAL_DAA_WORK")
            require(timestamp_state(block["timestamp"], [b["timestamp"] for b in reversed(history[:11])],
                                    fixture["clock_origin_timestamp"] + 1, 120) == "admissible",
                    "RESPONSIVE_INITIAL_TIMESTAMP")
        blocks[identifier], histories[identifier] = block, [block] + history
    require(fixture["prefix"]["tip_id"] in blocks and rows[-1]["parent_id"] == fixture["prefix"]["tip_id"],
            "RESPONSIVE_INITIAL_FORK_POINT")
    return blocks, histories


def _packet_metadata(row, blocks, histories, fixture, header):
    block = _metadata(row)
    parent = block["parent_id"]
    require(parent in blocks, "RESPONSIVE_PACKET_PARENT")
    history = histories[parent]
    require(block["height"] == blocks[parent]["height"] + 1
            and block["target"] == _required(blocks[parent], history)
            and block["chainwork"] == blocks[parent]["chainwork"] + work(block["target"]),
            "RESPONSIVE_PACKET_DAA_WORK")
    public = wire.header_decode(bytes.fromhex(fixture["public_tip"]["header_hex"]))
    require(all(header[field] == public[field] for field in ("network", "parameters")),
            "RESPONSIVE_PACKET_NETWORK")
    require(row.get("complete_native_proof_generated") is True
            and type(row.get("native_winner")) is bool
            and row.get("native_verifier_error") == (None if row["native_winner"] else "Target"),
            "RESPONSIVE_COMPLETE_NATIVE_PROOF")
    return block, [block] + history


def validate_attempt_inventory(directory, fixture, run, config, cache):
    inventory = run.get("attempt_inventory")
    require(type(inventory) is list and len(inventory) <= 8, "RESPONSIVE_ATTEMPT_INVENTORY")
    blocks, histories = _initial_history(fixture)
    attempts, owner_index, payloads = {}, {"honest": 0, "private": 0}, {}
    for row in inventory:
        require(type(row) is dict and row.get("owner") in owner_index, "RESPONSIVE_ATTEMPT_OWNER")
        owner = row["owner"]
        identifier = owner + "-" + str(owner_index[owner])
        owner_index[owner] += 1
        require(row.get("attempt_id") == identifier and identifier not in attempts,
                "RESPONSIVE_CONTIGUOUS_ATTEMPT_INVENTORY")
        generated = row.get("observer_candidate_generated")
        require(type(generated) is bool, "RESPONSIVE_GENERATED_FLAG")
        for field in STAGE_CLOCKS:
            integer(row.get(field), "RESPONSIVE_STAGE_CLOCK", 1 if generated else 0, (1 << 128) - 1)
        if not generated:
            require(owner == "private" and set(row) == {"attempt_id", "owner", "observer_candidate_generated",
                    "reason", *STAGE_CLOCKS} and all(row[field] == 0 for field in STAGE_CLOCKS)
                    and row["reason"] == "candidate check cannot complete within the declared horizon",
                    "RESPONSIVE_OPAQUE_ATTEMPT")
        else:
            require(set(row) == {"attempt_id", "owner", "observer_candidate_generated", "packet",
                    "outcome_hidden_until_candidate_due", "observer_advice", *STAGE_CLOCKS},
                    "RESPONSIVE_ATTEMPT_FIELDS")
            require(row["outcome_hidden_until_candidate_due"] is True
                    and row["observer_advice"] is (owner == "private" and config["policy"] == ADVICE_POLICY),
                    "RESPONSIVE_ADVICE_VISIBILITY")
            packet = row["packet"]
            header, _ = _packet(directory, packet, cache)
            block, history = _packet_metadata(packet, blocks, histories, fixture, header)
            if packet["native_winner"]:
                if block["block_id"] in blocks:
                    require(blocks[block["block_id"]] == block, "RESPONSIVE_REUSED_BLOCK_METADATA")
                blocks[block["block_id"]], histories[block["block_id"]] = block, history
            name, value = packet["packet_file"], packet["packet_sha256"]
            require(name not in payloads or payloads[name] == value, "RESPONSIVE_PAYLOAD_ALIAS")
            payloads[name] = value
        attempts[identifier] = row
    require(owner_index["honest"] <= 6 and owner_index["private"] <= 2, "RESPONSIVE_START_BUDGET")
    return attempts, blocks, histories, payloads


def replay_run_events(fixture, plan, run, config, attempts, blocks, histories):
    """Independently execute the declared controller using retained proof outcomes.

    Outcomes are looked up only when a modeled completion fires. Offline packet
    validation knows all bytes; the policy below never uses a future verdict.
    Every event is consumed exactly once and every started attempt terminates
    by completion, cancellation or horizon censoring, without dropping cost.
    """
    events = run.get("events")
    require(type(events) is list and 1 <= len(events) <= 10000, "RESPONSIVE_EVENT_INVENTORY")
    require(run.get("configuration") == config and run.get("run_id") == config["run_id"]
            and run.get("policy") == config["policy"] and run.get("seed") == config["seed"],
            "RESPONSIVE_RUN_BINDING")
    selected = fixture["public_tip"]["block_id"]
    initial = selected
    require(run.get("initial_tip") == selected and run.get("initial_public_block_id") == selected,
            "RESPONSIVE_INITIAL_TIP")
    view, private_parent = selected, fixture["prefix"]["tip_id"]
    cursor = 0
    honest_active = private_active = None
    started = {"honest": 0, "private": 0}
    completed, cancelled, censored, used = set(), set(), set(), []
    private_ids, held = set(), []
    deliveries, notices, visible = [], [], []
    visible_count, generation, sequence, published = 0, 0, 0, False
    ever = False
    model_elapsed = {"honest": 0, "private": 0}
    cancelled_ticks = 0
    event_cpu = event_wall = 0
    clock = config["private_clock"]
    horizon = plan["horizon_ticks"]
    if config["execution_kind"] == "constructed-quantum" and config["iterations"] > 0:
        require(clock["candidate_check_ticks"] > horizon, "QUANTUM_SAMPLER_UNIMPLEMENTED")

    def consume(tick, kind, expected, *, cost=False):
        nonlocal cursor, event_cpu, event_wall
        require(cursor < len(events), "RESPONSIVE_OMITTED_EVENT:" + kind)
        actual = events[cursor]
        base = {"event_index": cursor, "tick": tick, "kind": kind, **expected}
        if cost:
            for label in ("admit_activate_elapsed_ns", "admit_activate_cpu_ns"):
                integer(actual.get(label), "RESPONSIVE_ADMISSION_COST", 1, (1 << 128) - 1)
                base[label] = actual[label]
            event_wall += actual["admit_activate_elapsed_ns"]
            event_cpu += actual["admit_activate_cpu_ns"]
        require(canonical(actual) == canonical(base), "RESPONSIVE_EVENT_MISMATCH:" + kind)
        cursor += 1

    def start(owner, parent, tick, duration):
        index = started[owner]
        identifier = owner + "-" + str(index)
        require(identifier in attempts and identifier not in used, "RESPONSIVE_MISSING_STARTED_ATTEMPT")
        attempt = attempts[identifier]
        opaque = owner == "private" and duration > horizon - tick
        require(attempt["observer_candidate_generated"] is (not opaque), "RESPONSIVE_EAGER_CENSOR_RULE")
        nonce = None
        if not opaque:
            packet = attempt["packet"]
            nonce = seeded_nonce(config["seed"], index, parent, owner)
            if owner == "private" and config["policy"] == ADVICE_POLICY:
                context = next((row for row in fixture["contexts"] if row["parent_id"] == parent), None)
                require(context is not None, "RESPONSIVE_ADVICE_CONTEXT")
                if context["winner_children"]:
                    nonce = context["winner_children"][0]["nonce"]
            require(packet["nonce"] == nonce and packet["parent_id"] == parent,
                    "RESPONSIVE_CAUSAL_NONCE_OR_PARENT")
            expected_timestamp = (fixture["genesis_timestamp"] + packet["height"] if owner == "private"
                                  else max(blocks[parent]["timestamp"] + 1,
                                           fixture["clock_origin_timestamp"] + tick // 4 + 1))
            require(packet["timestamp"] == expected_timestamp, "RESPONSIVE_FIXED_TIMESTAMP_RULE")
            require(timestamp_state(packet["timestamp"], [b["timestamp"] for b in reversed(histories[parent][:11])],
                                    fixture["clock_origin_timestamp"] + tick // 4 + 1, 120) == "admissible",
                    "RESPONSIVE_CANDIDATE_TIME")
        consume(tick, owner + "-start", {"attempt_id": identifier, "owner": owner,
            "parent_id": parent, "nonce": nonce, "start_tick": tick, "due_tick": tick + duration,
            "observer_candidate_generated": not opaque})
        used.append(identifier)
        started[owner] += 1
        return {"id": identifier, "owner": owner, "parent": parent, "start": tick,
                "due": tick + duration, "proof_stage": False}

    def completion(active, tick, kind):
        attempt = attempts[active["id"]]
        require(attempt["observer_candidate_generated"] is True, "RESPONSIVE_OPAQUE_COMPLETION")
        packet = attempt["packet"]
        consume(tick, kind, {"attempt_id": active["id"], "owner": active["owner"], "packet": packet,
            "native_winner": packet["native_winner"], "proof_elapsed_ns": attempt["proof_elapsed_ns"],
            "verification_elapsed_ns": attempt["verification_elapsed_ns"],
            "actual_cost_reference": active["id"], "actual_cost_counted_once_in_attempt_inventory": True})
        return packet

    def queue(owner, packet, tick, due, attempt_id=None):
        nonlocal sequence
        sequence += 1
        row = {"owner": owner, "block_id": packet["block_id"], "due_tick": due}
        if owner == "honest":
            row["attempt_id"] = attempt_id
        else:
            row["publication_policy"] = "after-two-attempts-parent-first"
        consume(tick, "delivery-queued", row)
        deliveries.append({"owner": owner, "packet": packet, "due_tick": due, "sequence": sequence})

    for tick in range(horizon + 1):
        if honest_active is not None and honest_active["due"] == tick:
            packet = completion(honest_active, tick, "honest-complete")
            completed.add(honest_active["id"])
            model_elapsed["honest"] += tick - honest_active["start"]
            if packet["native_winner"]:
                queue("honest", packet, tick, tick + plan["honest_delivery_ticks"], honest_active["id"])
            honest_active = None

        deliveries.sort(key=lambda row: (row["due_tick"], row["owner"] != "honest", row["sequence"]))
        while deliveries and deliveries[0]["due_tick"] == tick:
            delivery = deliveries.pop(0)
            packet, owner = delivery["packet"], delivery["owner"]
            identifier = packet["block_id"]
            require(packet["native_winner"] is True and identifier in blocks, "RESPONSIVE_NONWINNER_DELIVERY")
            # A complete parent chain must have reached this receiver already.
            parent_ids = {row["block_id"] for row in visible} | set(
                row["block_id"] for row in fixture["prefix"]["parent_first_headers"]) | {initial}
            require(packet["parent_id"] in parent_ids, "RESPONSIVE_DELIVERY_PARENT_ORDER")
            old = selected
            if blocks[identifier]["chainwork"] > blocks[selected]["chainwork"]:
                selected = identifier
            replacement = owner == "private" and selected == identifier and old not in private_ids
            ever |= replacement
            require(timestamp_state(packet["timestamp"], [b["timestamp"] for b in reversed(histories[packet["parent_id"]][:11])],
                                    fixture["clock_origin_timestamp"] + tick // 4 + 1, 120) == "admissible",
                    "RESPONSIVE_NATIVE_ARRIVAL_TIME")
            consume(tick, "receiver-admit", {"owner": owner, "packet": packet,
                "selected_before": old, "selected_after": selected,
                "selected_work_before_hex": f"{blocks[old]['chainwork']:0128x}",
                "selected_work_after_hex": f"{blocks[selected]['chainwork']:0128x}",
                "private_replacement": replacement,
                "logical_observed_now": fixture["clock_origin_timestamp"] + tick // 4 + 1}, cost=True)
            visible.append(packet)
            if old != selected:
                generation += 1
                due = tick + plan["honest_tip_notification_ticks"]
                notice = {"generation": generation, "selected_tip": selected,
                          "due_tick": due, "visible_packet_count": len(visible)}
                notices.append(notice)
                consume(tick, "honest-notification-queued", notice)

        while notices and notices[0]["due_tick"] == tick:
            notice = notices.pop(0)
            old = view
            delivered = visible[visible_count:notice["visible_packet_count"]]
            for packet in delivered:
                if blocks[packet["block_id"]]["chainwork"] > blocks[view]["chainwork"]:
                    view = packet["block_id"]
            visible_count = notice["visible_packet_count"]
            require(view == notice["selected_tip"], "RESPONSIVE_RECEIVER_FOLLOWING_VIEW")
            consume(tick, "honest-notify", {"generation": notice["generation"], "selected_tip": view,
                "old_view_tip": old, "new_view_tip": view,
                "delivered_packet_ids": [packet["block_id"] for packet in delivered]}, cost=True)
            if honest_active is not None and honest_active["parent"] != view:
                attempt = attempts[honest_active["id"]]
                elapsed = tick - honest_active["start"]
                consume(tick, "honest-cancel", {"attempt_id": honest_active["id"], "owner": "honest",
                    "old_parent_id": honest_active["parent"], "new_parent_id": view,
                    "start_tick": honest_active["start"], "cancel_tick": tick, "due_tick": honest_active["due"],
                    "charged_elapsed_ticks": elapsed, "reserved_ticks": honest_active["due"] - honest_active["start"],
                    "packet": attempt["packet"], "proof_elapsed_ns": attempt["proof_elapsed_ns"],
                    "verification_elapsed_ns": attempt["verification_elapsed_ns"],
                    "actual_cost_reference": honest_active["id"], "actual_eager_cost_charged_in_full": True})
                cancelled.add(honest_active["id"])
                cancelled_ticks += elapsed
                model_elapsed["honest"] += elapsed
                honest_active = None

        if private_active is not None and private_active["due"] == tick:
            packet = completion(private_active, tick, "private-complete" if private_active["proof_stage"] else "private-check")
            if private_active["proof_stage"]:
                identifier = packet["block_id"]
                require(packet["native_winner"] is True, "RESPONSIVE_LOSER_PROOF_COMPLETION")
                consume(tick, "private-producer-admit", {"owner": "private", "block_id": identifier}, cost=True)
                private_parent = identifier
                private_ids.add(identifier)
                held.append(packet)
                completed.add(private_active["id"])
                model_elapsed["private"] += tick - private_active["start"]
                private_active = None
            elif packet["native_winner"]:
                private_active["proof_stage"] = True
                private_active["due"] = tick + clock["winner_proof_ticks"]
                consume(tick, "private-proof-start", {"owner": "private", "attempt_id": private_active["id"],
                    "start_tick": tick, "due_tick": private_active["due"], "model_phase_only": True})
            else:
                completed.add(private_active["id"])
                model_elapsed["private"] += tick - private_active["start"]
                private_active = None
        if private_active is None and started["private"] == plan["max_private_attempts"] and not published:
            published = True
            for index, packet in enumerate(held, 1):
                queue("private", packet, tick, tick + index * clock["per_block_propagation_ticks"])
            held = []
        if tick == horizon:
            break
        if private_active is None and started["private"] < plan["max_private_attempts"]:
            private_active = start("private", private_parent, tick, clock["candidate_check_ticks"])
        if honest_active is None and started["honest"] < plan["max_honest_attempts"]:
            honest_active = start("honest", view, tick, plan["honest_attempt_ticks"])

    for active in (honest_active, private_active):
        if active is None:
            continue
        attempt = attempts[active["id"]]
        elapsed = horizon - active["start"]
        consume(horizon, "attempt-censored", {"owner": active["owner"], "attempt_id": active["id"],
            "start_tick": active["start"], "due_tick": active["due"],
            "phase": "winner-proof" if active["proof_stage"] else "candidate",
            "charged_elapsed_ticks": elapsed, "packet": attempt.get("packet"),
            "actual_cost_reference": active["id"], "all_observed_cpu_costs_retained": True})
        model_elapsed[active["owner"]] += elapsed
        censored.add(active["id"])
    require(cursor == len(events), "RESPONSIVE_EXTRA_EVENT")
    require(used == list(attempts) and set(used) == completed | cancelled | censored
            and not (completed & cancelled or completed & censored or cancelled & censored),
            "RESPONSIVE_COMPLETE_ATTEMPT_DENOMINATOR")
    require(run.get("honest_attempts_started") == started["honest"]
            and run.get("private_attempts_started") == started["private"], "RESPONSIVE_STARTED_TOTALS")
    expected_pending = [{key: row[key] for key in ("owner", "due_tick", "packet")} for row in deliveries]
    require(run.get("pending_deliveries") == expected_pending and run.get("pending_notifications") == notices,
            "RESPONSIVE_PENDING_EVENT_INVENTORY")
    ancestry, tip = [], selected
    while tip is not None:
        require(tip in blocks and tip not in ancestry, "RESPONSIVE_FINAL_ANCESTRY")
        ancestry.append(tip)
        tip = blocks[tip]["parent_id"]
    metrics = {"ever_private_replacement": ever, "private_tip_at_horizon": selected in private_ids,
        "private_ancestor_at_horizon": any(key in private_ids for key in ancestry), "ancestor_includes_tip": True,
        "initial_public_block_orphaned_at_horizon": initial not in ancestry}
    require(run.get("metrics") == metrics and run.get("private_winning_block_ids") == sorted(private_ids),
            "RESPONSIVE_FINAL_METRICS")
    require(run.get("final_tip") == selected and run.get("reopened_tip") == selected
            and run.get("final_chainwork_hex") == f"{blocks[selected]['chainwork']:0128x}"
            and run.get("final_ancestry_ids") == ancestry and run.get("reopened_ancestry_ids") == ancestry,
            "RESPONSIVE_REOPEN_OR_TIP")
    receipt = run.get("cpu_receipt")
    require(type(receipt) is dict and receipt.get("eager_observer_work_is_literal_interrupted_miner") is False
            and receipt.get("exclusive_machine_calibration") is False
            and type(receipt.get("scope")) is str and receipt["scope"], "RESPONSIVE_CPU_SCOPE")
    for key in ("process_cpu_ns", "wall_ns"):
        integer(receipt.get(key), "RESPONSIVE_PIPELINE_CLOCK", 1, (1 << 128) - 1)
    history = run.get("history_replay")
    require(type(history) is dict and set(history) == {"receiver_elapsed_ns", "honest_elapsed_ns", "private_elapsed_ns"},
            "RESPONSIVE_HISTORY_COST")
    for value in history.values():
        integer(value, "RESPONSIVE_HISTORY_CLOCK", 0, (1 << 128) - 1)
    stage_cpu = sum(sum(row[field] for field in STAGE_CLOCKS if field.endswith("cpu_ns")) for row in attempts.values())
    stage_wall = sum(sum(row[field] for field in STAGE_CLOCKS if field.endswith("elapsed_ns")) for row in attempts.values())
    require(stage_cpu + event_cpu <= receipt["process_cpu_ns"], "RESPONSIVE_CPU_COST_SUM")
    require(stage_wall + event_wall + sum(history.values()) <= receipt["wall_ns"], "RESPONSIVE_WALL_COST_SUM")
    return {"run_id": run["run_id"], "metrics": metrics, "events_checked": cursor,
            "started_attempts": len(attempts), "completed_attempts": len(completed),
            "cancelled_attempts": len(cancelled), "censored_attempts": len(censored),
            "honest_cancelled_elapsed_ticks": cancelled_ticks, "modeled_mining_elapsed_ticks": model_elapsed,
            "actual_attempt_cpu_ns": stage_cpu, "actual_event_cpu_ns": event_cpu,
            "actual_process_cpu_ns": receipt["process_cpu_ns"],
            "other_process_cpu_ns": receipt["process_cpu_ns"] - stage_cpu - event_cpu,
            "retained_pending_deliveries": len(deliveries), "retained_pending_notifications": len(notices)}


def verify(directory):
    before = sources()
    fixture, plan, hashes, checked = load_plan(directory)
    raw = read(directory / REPORT_FILE)
    report = strict_load(raw)
    require(type(report) is dict and report.get("schema") == SCHEMA, "RESPONSIVE_EXECUTION_SCHEMA")
    require(report.get("plan") == plan and report.get("plan_sha256") == hashes[PLAN_FILE]
            and report.get("base_fixture_file_sha256") == hashes["native-fixture.json"],
            "RESPONSIVE_REPORT_INPUT_BINDING")
    require(report.get("native_source") == fixture["native_source"]
            and report.get("claims") == NATIVE_CLAIMS, "RESPONSIVE_EXECUTION_SOURCE_OR_CLAIMS")
    runs = report.get("runs")
    require(type(runs) is list and [row.get("run_id") for row in runs] == [row["run_id"] for row in plan["runs"]],
            "RESPONSIVE_COMPLETE_RUN_INVENTORY")
    cache, summaries, payloads = {}, [], {}
    for index, (run, config) in enumerate(zip(runs, plan["runs"])):
        attempts, blocks, histories, packets = validate_attempt_inventory(directory, fixture, run, config, cache)
        summaries.append(replay_run_events(fixture, plan, run, config, attempts, blocks, histories))
        name = "responsive-run-" + str(index) + ".jsonl"
        require(run.get("event_journal_file") == name, "RESPONSIVE_JOURNAL_PATH")
        journal = read(directory / name)
        require(journal.endswith(b"\n") and b"\n\n" not in journal
                and len(journal) == run.get("event_journal_bytes") and sha(journal) == run.get("event_journal_sha256"),
                "RESPONSIVE_JOURNAL_DIGEST")
        require([strict_load(line) for line in journal.splitlines()] == run["events"], "RESPONSIVE_FULL_EVENT_JOURNAL")
        packets[name] = sha(journal)
        for path, value in packets.items():
            require(path not in payloads or payloads[path] == value, "RESPONSIVE_CROSS_RUN_PAYLOAD_ALIAS")
            payloads[path] = value
    hashes[REPORT_FILE] = sha(raw)
    require(sources() == before and bridge.native_source_inventory() == fixture["native_source"]["source_sha256"],
            "RESPONSIVE_SOURCE_CHANGED")
    require(all(sha(read(directory / name)) == value for name, value in {**hashes, **payloads}.items()),
            "RESPONSIVE_INPUT_CHANGED_DURING_READBACK")
    return {"schema": READBACK_SCHEMA, "status": "VERIFIED", "runs": len(runs), "run_summaries": summaries,
            "verified_inputs": hashes, "verified_payloads": dict(sorted(payloads.items())),
            "source_snapshot": before, "checked_original_packet_records": checked,
            "independently_checked_responsive_packet_identities": len(cache),
            "runtime_identity": {"executable": sys.executable, "version": sys.version,
                                 "implementation": sys.implementation.name},
            "receiver_following_honest_policy": "honest view advances only on receiver selection notification; no immediate own-block extension",
            "native_blocks_admitted_by_python_reader": 0, "native_node_executed_by_python_reader": False,
            "native_probabilities_certified_by_reduced_model": False,
            "quantum_hardware_executed": False, "quantum_mining_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", type=Path)
    group.add_argument("--verify-plan", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    result = make_plan(args.plan) if args.plan else verify_plan(args.verify_plan) if args.verify_plan else verify(args.verify)
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
