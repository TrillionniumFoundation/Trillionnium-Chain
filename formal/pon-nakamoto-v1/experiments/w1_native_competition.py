#!/usr/bin/env python3
"""Check source-bound W1 races against a continuing, conditional public branch.

Rust owns production and native admission. All failed honest proof attempts and
all private lifecycle charges are retained. Declared arrival times are not
calibrated honest mining/network delays. Temporary and horizon wins differ.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
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
import w1_competing_consensus as competing
from w1_quantum_oracle import canonical

SCHEMA = "trnm-w1-native-competition-samples-v1"
CERTIFICATES_SCHEMA = "trnm-w1-native-competition-certificates-v1"
SCENARIOS = ("honest-before-private-publication", "honest-after-private-publication")
EXECUTIONS = ("constructed-quantum", "classical-uniform-q0")
OUTPUTS = ("competition-certificates.json", "competition-samples.json", "competition-observer-clock.json")
INPUTS = ("native-fixture.json", "native-competition-plan.json", "native-competition-fixture.json",
          "competition-certificates.json", "competition-samples.json")
require, sha, read = bridge.require, bridge.sha, bridge.read
strict_load, json_bytes, write_new = bridge.strict_load, bridge.json_bytes, bridge.write_new
ratio, integer = competing.ratio, competing.integer

FIXTURE_CLAIMS = {
    "complete_native_honest_proofs_generated": True,
    "all_failed_honest_attempts_retained": True,
    "offline_native_honest_chain_admitted": True,
    "conditional_arrivals_are_measured_mining_or_network_times": False,
    "honest_producer_receives_private_publications_before_horizon": False,
    "native_public_ingress_executed": False,
    "quantum_hardware_executed": False,
    "quantum_mining_qualified": False,
    "production_activation": False,
}
CLAIMS = {
    "complete_honest_packet_attempts_scalar_replayed": True,
    "all_declared_fixed_seed_runs_retained": True,
    "observer_selected_controls_are_random_samples": False,
    "honest_arrivals_continue_after_private_termination": True,
    "temporary_replacement_distinct_from_horizon_selection": True,
    "equal_time_order_is_honest_first": True,
    "native_blocks_admitted_by_python_reader": 0,
    "native_node_executed_by_python_reader": False,
    "physical_clock_calibrated": False,
    "whole_network_machine_error_bound_composed": False,
    "stochastic_continuing_honest_mining_covered": False,
    "long_horizon_settlement_security_proved": False,
    "quantum_hardware_executed": False,
    "quantum_mining_qualified": False,
    "production_activation": False,
}


def fixed_plan(origin):
    return {"schema": "trnm-w1-native-competition-plan-v1", "horizon_seconds": "4",
            "max_private_attempts": 2, "sample_seed": 9,
            "honest_heights": [17, 18], "honest_timestamps": [origin + 1, origin + 2],
            "max_honest_attempts_per_block": 4096,
            "public_producer_view": "isolated-public-branch-until-horizon",
            "equal_time_order": "honest-before-private-parent-first",
            "scenario_times": {SCENARIOS[0]: [ratio(Fraction(1)), ratio(Fraction(3))],
                               SCENARIOS[1]: [ratio(Fraction(5, 2)), ratio(Fraction(7, 2))]},
            "selection": "source-declared schedule before honest packet generation; no external timestamp attestation",
            "native_honest_production_wall_time_is_arrival_time": False}


def sources():
    result = bridge.sources()
    for name in ("formal/pon-nakamoto-v1/w1_competing_consensus.py",
                 "formal/pon-nakamoto-v1/experiments/w1_native_competition.py"):
        result["source_sha256"][name] = sha(read(ROOT / name))
    result["source_sha256"] = dict(sorted(result["source_sha256"].items()))
    return result


def check_honest_attempt(directory, row, *, expected_nonce, parent, height):
    require(row.get("nonce") == expected_nonce and type(row.get("nonce")) is int,
            "HONEST_CONTIGUOUS_ATTEMPTS")
    require(row.get("parent_id") == parent and row.get("height") == height, "HONEST_ATTEMPT_CONTEXT")
    header, proof = bridge.check_packet(directory, row, full_verify=False)
    values = struct.unpack("<" + "I" * (3 * work_oracle.CELLS), proof[4:-32])
    a, b = list(values[:work_oracle.CELLS]), list(values[work_oracle.CELLS:2 * work_oracle.CELLS])
    decoded = wire.header_decode(header)
    require(work_oracle.task_id(a, b) == decoded["work_task"], "HONEST_TASK_BINDING")
    challenge = wire.H("challenge", header)
    # TARGET failure alone is not evidence of a complete correct transcript.
    require(work_oracle.prove(challenge, a, b) == proof, "HONEST_COMPLETE_PROOF_REPLAY")
    ticket = wire.H("ticket", challenge, proof[-32:])
    winner = decoded["target"] != bytes(32) and ticket <= decoded["target"]
    require(row.get("native_winner") is winner
            and row.get("native_verifier_error") == (None if winner else "Target")
            and row.get("complete_native_proof_generated") is True, "HONEST_NATIVE_VERDICT")
    for field in ("proof_elapsed_ns", "verification_elapsed_ns"):
        integer(row.get(field), "HONEST_CLOCK_RECEIPT", maximum=(1 << 128) - 1)
    return winner


def check_honest_inventory(directory, fixture, competition):
    blocks, production = competition.get("honest_blocks"), competition.get("honest_production")
    require(type(blocks) is list and len(blocks) == 2 and type(production) is list and len(production) == 2,
            "HONEST_PRODUCTION_INVENTORY")
    parent, checked = fixture["public_tip"]["block_id"], 0
    for index, (block, receipt) in enumerate(zip(blocks, production), start=1):
        height = 16 + index
        require(receipt.get("parent_id") == parent and receipt.get("height") == height
                and receipt.get("selected_block_id") == block.get("block_id")
                and receipt.get("max_attempts") == 4096, "HONEST_PRODUCTION_BINDING")
        require(block.get("timestamp") == fixture["clock_origin_timestamp"] + index,
                "HONEST_DECLARED_TIMESTAMP")
        attempts = receipt.get("attempts")
        require(type(attempts) is list and 1 <= len(attempts) <= 4096, "HONEST_ATTEMPT_BOUND")
        winners = [check_honest_attempt(directory, row, expected_nonce=nonce, parent=parent, height=height)
                   for nonce, row in enumerate(attempts)]
        require(winners == [False] * (len(attempts) - 1) + [True], "HONEST_FIRST_SUCCESS_RULE")
        selected = {key: value for key, value in attempts[-1].items()
                    if key not in ("proof_elapsed_ns", "verification_elapsed_ns")}
        require(canonical(block) == canonical(selected), "HONEST_WINNER_ROW_BINDING")
        for field in ("prepare_elapsed_ns", "admit_activate_elapsed_ns", "complete_pipeline_elapsed_ns"):
            integer(receipt.get(field), "HONEST_PIPELINE_CLOCK", maximum=(1 << 128) - 1)
        require(receipt.get("native_producer_admitted") is True
                and receipt.get("logical_observed_now") == fixture["clock_origin_timestamp"] + index,
                "HONEST_PRODUCER_ADMISSION")
        ledger_name = f"honest-production-fixture-h{height}.jsonl"
        require(receipt.get("ledger_file") == ledger_name, "HONEST_LEDGER_PATH")
        ledger = read(directory / ledger_name)
        require(len(ledger) == receipt.get("ledger_bytes") and sha(ledger) == receipt.get("ledger_sha256"),
                "HONEST_LEDGER_DIGEST")
        require(ledger.endswith(b"\n") and b"\n\n" not in ledger, "HONEST_LEDGER_LINES")
        expected_ledger = [{"event": "started", "parent_id": parent, "height": height,
                            "logical_observed_now": receipt["logical_observed_now"], "max_attempts": 4096},
                           {"event": "prepared", "prepare_elapsed_ns": receipt["prepare_elapsed_ns"]},
                           *({"event": "attempt", "outcome": row} for row in attempts),
                           {"event": "admitted", "selected_block_id": block["block_id"],
                            "admit_activate_elapsed_ns": receipt["admit_activate_elapsed_ns"]}]
        require(canonical([strict_load(line) for line in ledger.splitlines()]) == canonical(expected_ledger),
                "HONEST_LEDGER_COMPLETE_ATTEMPTS")
        stages = receipt["prepare_elapsed_ns"] + receipt["admit_activate_elapsed_ns"] + sum(
            row["proof_elapsed_ns"] + row["verification_elapsed_ns"] for row in attempts)
        require(stages <= receipt["complete_pipeline_elapsed_ns"], "HONEST_PIPELINE_CLOCK_SUM")
        parent, checked = block["block_id"], checked + len(attempts)
    return checked


def payload_hashes(fixture, competition):
    """Bind every packet consumed by either scalar reader plus honest ledgers."""
    result = {}
    packets = [*fixture["prefix"]["packets"], fixture["public_tip"]]
    packets += [row for context in fixture["contexts"] for row in context["all_nonce_outcomes"]]
    packets += [row for receipt in competition["honest_production"] for row in receipt["attempts"]]
    for row in packets:
        name, value = row["packet_file"], row["packet_sha256"]
        require(name not in result or result[name] == value, "COMPETITION_PAYLOAD_CONFLICT")
        result[name] = value
    for row in competition["honest_production"]:
        name, value = row["ledger_file"], row["ledger_sha256"]
        require(name not in result, "COMPETITION_PAYLOAD_DUPLICATE")
        result[name] = value
    return dict(sorted(result.items()))


def check_payloads(directory, expected):
    require(all(sha(read(directory / name)) == value for name, value in expected.items()),
            "COMPETITION_PAYLOAD_CHANGED")


def load_fixture(directory):
    fixture, base_raw_sha256, checked = bridge.load_fixture(directory)
    require(fixture.get("genesis_timestamp") == 1_750_000_000
            and fixture.get("clock_origin_timestamp") == 1_750_000_160,
            "COMPETITION_DECLARED_NATIVE_CLOCK")
    raw = read(directory / "native-competition-fixture.json")
    competition = strict_load(raw)
    require(competition.get("schema") == competing.FIXTURE_SCHEMA, "COMPETITION_FIXTURE_SCHEMA")
    require(competition.get("native_source") == fixture["native_source"], "COMPETITION_NATIVE_SOURCE")
    require(competition.get("base_fixture_file_sha256") == base_raw_sha256
            and competition.get("base_fixture_canonical_sha256") == competing.digest(fixture),
            "COMPETITION_BASE_BINDING")
    plan_raw = read(directory / "native-competition-plan.json")
    plan = strict_load(plan_raw)
    require(canonical(plan) == canonical(fixed_plan(fixture["clock_origin_timestamp"]))
            and competition.get("plan_file_sha256") == sha(plan_raw)
            and canonical(competition.get("fixed_plan")) == canonical(plan), "COMPETITION_FIXED_PLAN_CHANGED")
    require(canonical(competition.get("claims")) == canonical(FIXTURE_CLAIMS), "COMPETITION_FIXTURE_CLAIMS")
    expected_scenarios = [{"scenario_id": name, "arrivals": [
        {"block_id": block["block_id"], "at_seconds": at}
        for block, at in zip(competition["honest_blocks"], plan["scenario_times"][name])]}
        for name in SCENARIOS]
    require(competition.get("scenarios") == expected_scenarios, "COMPETITION_DECLARED_SCENARIOS")
    checked += check_honest_inventory(directory, fixture, competition)
    return fixture, competition, {"native-fixture.json": base_raw_sha256,
                                 "native-competition-plan.json": sha(plan_raw),
                                 "native-competition-fixture.json": sha(raw)}, checked


def certificate_key(scenario, execution, event):
    return "/".join((scenario, execution, event))


def parameters(fixture, scenario, execution, event):
    return {**bridge.cost_premises(fixture, execution)[3], "scenario_id": scenario, "risk_event": event}


def verify_certificates(bundle, fixture, competition):
    require(type(bundle) is dict and set(bundle) == {"schema", "source", "certificates"}
            and bundle["schema"] == CERTIFICATES_SCHEMA and bundle["source"] == sources(),
            "COMPETITION_CERTIFICATE_BUNDLE")
    expected = {certificate_key(scenario, execution, event)
                for scenario in SCENARIOS for execution in EXECUTIONS for event in competing.RISK_EVENTS}
    records = bundle["certificates"]
    require(type(records) is dict and set(records) == expected, "COMPETITION_CERTIFICATE_INVENTORY")
    for scenario in SCENARIOS:
        for execution in EXECUTIONS:
            for event in competing.RISK_EVENTS:
                record = records[certificate_key(scenario, execution, event)]
                require(canonical(record.get("parameters")) == canonical(parameters(fixture, scenario, execution, event)),
                        "COMPETITION_COST_PREMISES_CHANGED")
                require(competing.verify_competing_certificate(record, fixture, competition)["status"] == "COMPLETE",
                        "COMPETITION_INCOMPLETE_CERTIFICATE")


def normalize_run(fixture, name, kind, observation):
    run = bridge.normalize_run(fixture, name, kind, observation["trajectory"], observation)
    terminal = observation["trajectory"][-1]["edge"]["observation"]
    run.update(expected_reorganization=terminal["ever_private_replacement"],
               expected_ever_private_replacement=terminal["ever_private_replacement"],
               expected_private_active_at_horizon=terminal["private_active_at_horizon"],
               expected_selected_tip_at_horizon=terminal["selected_tip_at_horizon"],
               expected_selected_chainwork_at_horizon_hex=terminal["selected_chainwork_at_horizon_hex"],
               receiver_events=terminal["receiver_events"],
               receiver_observed_until_seconds=terminal["receiver_observed_until_seconds"])
    return run


def sample_report(fixture, competition, input_hashes, bundle, bundle_file_sha256, checked):
    runs, controls, risks = [], {}, {}
    records = bundle["certificates"]
    for scenario in SCENARIOS:
        for execution in EXECUTIONS:
            key = certificate_key(scenario, execution, competing.RISK_EVENTS[0])
            record = records[key]
            for count in record["parameters"]["iterations"]:
                sample = competing.sample_competing_policy(record, fixture, competition, iterations=count, seed=9)
                name = f"{scenario}/{'classical' if execution == 'classical-uniform-q0' else 'quantum'}-q{count}-seed9"
                run = normalize_run(fixture, name, "fixed-seed-conditional-competition-sample", sample)
                run.update(scenario_id=scenario, execution_kind=execution)
                runs.append(run)
            for event in competing.RISK_EVENTS:
                other = records[certificate_key(scenario, execution, event)]
                risks[certificate_key(scenario, execution, event)] = {
                    "ideal_risk_upper": other["risk_upper"], "fixed_policy_risks": other["fixed_policy_risks"],
                    "conditional_private_machine_bounds": other["conditional_machine_risk_bounds"],
                    "external_honest_schedule_is_exact_condition": True}
            if execution == "classical-uniform-q0":
                witness = competing.observer_selected_path(record, fixture, competition)
                controls[scenario] = "NO_PROOF_COMPLETE_SELECTED_PATH" if witness is None else "RETAINED"
                if witness is not None:
                    run = normalize_run(fixture, f"{scenario}/observer-advice-classical-path",
                                        "observer-selected-classical-path-control-not-random-sample", witness)
                    run.update(scenario_id=scenario, execution_kind=execution)
                    runs.append(run)
    return {"schema": SCHEMA, "source": sources(), "fixture_inputs": input_hashes,
            "certificate_bundle_file_sha256": bundle_file_sha256,
            "independently_checked_packet_records": checked,
            "declared_seeded_run_count": 6, "observer_controls": controls,
            "risk_summaries": risks, "runs": runs, "claims": dict(CLAIMS)}


def observe(directory):
    for name in OUTPUTS:
        require(not (directory / name).exists(), "OUTPUT_ALREADY_EXISTS")
    before, wall, cpu = sources(), time.perf_counter_ns(), time.process_time_ns()
    fixture, competition, hashes, checked = load_fixture(directory)
    records = {}
    for scenario in SCENARIOS:
        for execution in EXECUTIONS:
            for event in competing.RISK_EVENTS:
                records[certificate_key(scenario, execution, event)] = competing.analyze_competing_consensus(
                    fixture, competition, parameters(fixture, scenario, execution, event))
    bundle = {"schema": CERTIFICATES_SCHEMA, "source": before, "certificates": records}
    verify_certificates(bundle, fixture, competition)
    report = sample_report(fixture, competition, hashes, bundle, sha(json_bytes(bundle)), checked)
    require(sources() == before, "COMPETITION_SOURCE_CHANGED")
    require(all(sha(read(directory / name)) == value for name, value in hashes.items()),
            "COMPETITION_FIXTURE_CHANGED")
    check_payloads(directory, payload_hashes(fixture, competition))
    write_new(directory / OUTPUTS[0], bundle)
    write_new(directory / OUTPUTS[1], report)
    write_new(directory / OUTPUTS[2], {"schema": "trnm-w1-native-competition-observer-clock-v1",
              "elapsed_wall_ns": time.perf_counter_ns() - wall, "process_cpu_ns": time.process_time_ns() - cpu,
              "scope": "offline Python complete packet, finite certificate and sample replay",
              "charged_to_four_second_private_miner": False, "hardware_calibration": False})
    return {"schema": SCHEMA, "status": "OBSERVED", "runs": len(report["runs"]),
            "certificates": len(records), "risk_summaries": report["risk_summaries"],
            "quantum_hardware_executed": False}


def verify(directory):
    before = sources()
    fixture, competition, hashes, checked = load_fixture(directory)
    bundle_raw = read(directory / OUTPUTS[0])
    bundle = strict_load(bundle_raw)
    verify_certificates(bundle, fixture, competition)
    expected = sample_report(fixture, competition, hashes, bundle, sha(bundle_raw), checked)
    samples_raw = read(directory / OUTPUTS[1])
    require(canonical(strict_load(samples_raw)) == canonical(expected), "COMPETITION_SAMPLE_REPLAY_MISMATCH")
    hashes.update({OUTPUTS[0]: sha(bundle_raw), OUTPUTS[1]: sha(samples_raw)})
    require(set(hashes) == set(INPUTS), "COMPETITION_VERIFIED_INPUT_INVENTORY")
    require(sources() == before and bridge.native_source_inventory() == fixture["native_source"]["source_sha256"],
            "COMPETITION_SOURCE_CHANGED")
    require(all(sha(read(directory / name)) == expected_hash for name, expected_hash in hashes.items()),
            "COMPETITION_INPUT_CHANGED_DURING_VERIFY")
    payloads = payload_hashes(fixture, competition)
    check_payloads(directory, payloads)
    return {"schema": SCHEMA, "status": "VERIFIED", "runs": len(expected["runs"]),
            "verified_inputs": hashes, "source_snapshot": before,
            "verified_payloads": payloads,
            "runtime_identity": {"executable": sys.executable, "version": sys.version,
                                 "implementation": sys.implementation.name},
            "native_blocks_admitted_by_python_reader": 0, "quantum_hardware_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--observe", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    print(json.dumps(observe(args.observe) if args.observe else verify(args.verify), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
