#!/usr/bin/env python3
"""Bind finite-search observations to a separately executed native Node DAG.

The Rust exporter generates the prefix, public tip and complete bounded DAG.
This reader independently checks every retained complete PNW1 packet and the
literal domains, then emits fixed-seed samples and a separately named advice
witness. Only the Rust replay harness can report fresh Node admission/reorg.
All quantum clocks remain premises; q=0 is the no-Grover baseline.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

import contract_wire as wire
import work_oracle
from quantum_oracle_resources import example
from w1_constructed_search import SOURCES
from w1_finite_consensus import (
    analyze_finite_consensus, sample_finite_policy, verify_finite_certificate,
)
from w1_marked_domain import enumerate_domain
from w1_machine_envelope import illustrative_lifecycle_model
from w1_quantum_oracle import canonical, template_from_spec

SCHEMA = "trnm-w1-native-bridge-samples-v1"
NATIVE_PREFIXES = ("trillionnium", "config", "rust-toolchain.toml",
                   "scripts/project-preflight.sh")
PYTHON_SOURCES = tuple(sorted(set(SOURCES) | {
    "formal/pon-nakamoto-v1/w1_finite_consensus.py",
    "formal/pon-nakamoto-v1/reference.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "formal/pon-nakamoto-v1/w1_machine_envelope.py",
    "formal/pon-nakamoto-v1/w1_search_probability.py",
    "formal/pon-nakamoto-v1/experiments/w1_native_bridge.py",
}))
FIXTURE_CLAIMS = {
    "full_native_W1_proofs_generated": True,
    "offline_native_dag_admitted": True,
    "online_search_sample_executed": False,
    "native_public_ingress_executed": False,
    "prefix_and_census_are_conditional_advice": True,
    "logical_validation_clock": True,
    "wall_clock_consensus_cadence_measured": False,
    "quantum_hardware_executed": False,
    "original_service_profile_requalified": False,
    "mining_profitability_proved": False,
    "quantum_mining_qualified": False,
    "production_activation": False,
}
CLAIMS = {
    "native_packet_bytes_independently_scalar_replayed": True,
    "full_nonce_inventory_checked": True,
    "conditional_existing_prefix_and_public_tip": True,
    "native_node_executed_by_python_reader": False,
    "native_blocks_admitted_by_python_reader": 0,
    "fixed_seed_selected_before_census": True,
    "external_precommitment_attested": False,
    "q0_is_no_grover_baseline": True,
    "positive_path_is_advice_selected_not_sampled": True,
    "same_declared_lifecycle_envelope_within_each_execution_kind": True,
    "physical_fault_probability_bounds_are_assumptions": True,
    "all_competing_classical_algorithms_covered": False,
    "physical_clock_calibrated": False,
    "quantum_hardware_executed": False,
    "original_service_profile_requalified": False,
    "mining_profitability_proved": False,
    "quantum_mining_qualified": False,
    "production_activation": False,
}
OUTPUTS = ("finite-certificate.json", "classical-certificate.json", "bridge-samples.json", "bridge-observer-clock.json")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_load(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, "DUPLICATE_JSON_KEY")
            result[name] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("NONFINITE_JSON")))


def read(path, limit=32_000_000):
    require(path.is_file() and not path.is_symlink(), "REGULAR_FILE_REQUIRED")
    require(path.stat().st_size <= limit, "FILE_SIZE_BOUND")
    return path.read_bytes()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def write_new(path, value):
    with path.open("xb") as stream:
        stream.write(json_bytes(value))
        stream.flush()


def native_source_inventory():
    raw = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--",
         *NATIVE_PREFIXES], cwd=ROOT)
    names = {value.decode() for value in raw.split(b"\0") if value}
    return {name: sha(read(ROOT / name, 100_000_000)) for name in sorted(names)}


def sources():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    kind = subprocess.check_output(["git", "cat-file", "-t", head], cwd=ROOT, text=True).strip()
    require(kind == "commit", "SOURCE_HEAD_NOT_COMMIT")
    return {"git_head": head,
            "source_sha256": {name: sha(read(ROOT / name)) for name in PYTHON_SOURCES}}


def check_fixture_claims(fixture):
    require(canonical(fixture.get("claims")) == canonical(FIXTURE_CLAIMS), "NATIVE_FIXTURE_CLAIMS")
    initial = fixture.get("initial_resources")
    require(type(initial) is dict and initial.get("coherent_quantum_state_supplied") is False
            and initial.get("winner_advice_available_to_fixed_policy_sampler") is False
            and initial.get("observer_has_full_census") is True, "INITIAL_ADVICE_SCOPE")
    require(fixture.get("fixed_plan") == {
        "nonce_bits": 3, "private_miner": 1,
        "root_timestamp": fixture["genesis_timestamp"] + 16,
        "child_timestamp": fixture["genesis_timestamp"] + 17,
        "sample_seed": 9, "horizon_seconds": "4", "max_attempts": 2,
    }, "NATIVE_FIXED_PLAN_CHANGED")


def check_packet(directory, row, *, full_verify=True):
    name = row["packet_file"]
    require(type(name) is str and re.fullmatch(r"packets/[0-9a-f]{64}\.pnk", name) is not None,
            "PACKET_PATH")
    raw = read(directory / name, 100_000)
    require(sha(raw) == row["packet_sha256"], "PACKET_DIGEST")
    require(len(raw) == 320 + work_oracle.PROOF_BYTES and raw[318:320] == b"\0\0",
            "EMPTY_TRANSACTION_NATIVE_PACKET")
    header, proof = raw[:318], raw[320:]
    decoded = wire.header_decode(header)
    require(wire.header_encode(decoded) == header, "PACKET_HEADER_CANONICAL")
    require(header.hex() == row["header_hex"] and sha(proof) == row["proof_sha256"],
            "PACKET_COMPONENT_BINDING")
    require(proof[-32:].hex() == row["trace"] and decoded["nonce"] == row["nonce"],
            "PACKET_NONCE_TRACE_BINDING")
    require(wire.H("block", header, proof[-32:]).hex() == row["block_id"], "PACKET_ID")
    require(decoded["parent"].hex() == row["parent_id"]
            and decoded["height"] == row["height"] and decoded["timestamp"] == row["timestamp"]
            and decoded["target"].hex() == row["target_hex"], "PACKET_METADATA")
    if full_verify:
        work_oracle.verify(wire.H("challenge", header), decoded["work_task"], decoded["target"], proof)
    return header, proof


def check_outcome_inventory(context, domain):
    outcomes = context.get("all_nonce_outcomes")
    require(type(outcomes) is list and [row.get("nonce") for row in outcomes] == list(range(domain["domain_size"])),
            "COMPLETE_NONCE_INVENTORY_REQUIRED")
    require([row["nonce"] for row in outcomes if row.get("native_winner") is True] == domain["marked_nonces"],
            "NATIVE_WINNER_INVENTORY")
    require([row["nonce"] for row in context["winner_children"]] == domain["marked_nonces"],
            "COMPLETE_WINNER_INVENTORY_REQUIRED")
    for row, expected in zip(outcomes, domain["outcomes"]):
        require(row.get("complete_native_proof_generated") is True
                and row.get("native_fixture_admitted") is expected["winner"]
                and row.get("native_verifier_error") == (None if expected["winner"] else "Target"),
                "NATIVE_OUTCOME_DISAGREEMENT")
    by_nonce = {row["nonce"]: row for row in outcomes}
    for child in context["winner_children"]:
        require(set(child) == set(by_nonce[child["nonce"]]) | {"child_context_id"}
                and canonical({key: value for key, value in child.items() if key != "child_context_id"})
                == canonical(by_nonce[child["nonce"]]), "WINNER_PACKET_RECORD_BINDING")
    return outcomes


def load_fixture(directory):
    raw = read(directory / "native-fixture.json")
    fixture = strict_load(raw)
    require(type(fixture) is dict and fixture.get("schema") == "trnm-w1-native-finite-dag-v1",
            "NATIVE_FIXTURE_SCHEMA")
    check_fixture_claims(fixture)
    current = sources()
    source = fixture.get("native_source")
    require(type(source) is dict and source.get("git_head") == current["git_head"]
            and source.get("source_sha256") == native_source_inventory(), "NATIVE_SOURCE_CHANGED")
    require(type(source.get("binary_sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", source["binary_sha256"]) is not None,
            "NATIVE_BINARY_IDENTITY")
    checked = 0
    for row in [*fixture["prefix"]["packets"], fixture["public_tip"]]:
        check_packet(directory, row)
        checked += 1
    require(len(fixture["prefix"]["packets"]) == 15, "PREFIX_PACKET_INVENTORY")
    for context in fixture["contexts"]:
        template = template_from_spec(context["template_spec"])
        require(template.shape.native and template.profile == "PNH1" and template.nonce_bits == 3,
                "NATIVE_DOMAIN_PROFILE")
        domain = enumerate_domain(template)
        outcomes = check_outcome_inventory(context, domain)
        product = work_oracle.mm(template.a, template.b, 64, 64, 64)
        proof_prefix = b"PNW1" + work_oracle.field_bytes(template.a) + work_oracle.field_bytes(template.b) + work_oracle.field_bytes(product)
        for row, expected in zip(outcomes, domain["outcomes"]):
            header, proof = check_packet(directory, row, full_verify=expected["winner"])
            require(header == template.header_for(row["nonce"])
                    and proof == proof_prefix + bytes.fromhex(expected["trace"]),
                    "FULL_LITERAL_PROOF_BINDING")
            checked += 1
    return fixture, sha(raw), checked


def rational(value):
    require(type(value) is dict and set(value) == {"numerator", "denominator"}
            and type(value["numerator"]) is int and type(value["denominator"]) is int
            and value["denominator"] > 0, "EXACT_TIME")
    return Fraction(value["numerator"], value["denominator"])


def normalize_run(fixture, name, kind, trajectory, raw_observation):
    require(type(trajectory) is list and trajectory, "EMPTY_TRAJECTORY")
    terminal = trajectory[-1]["edge"]["observation"]
    elapsed = rational(terminal["time"])
    require(0 <= elapsed <= 4, "ORIGINAL_HORIZON")
    published = terminal.get("publication_complete", False)
    chain = terminal.get("private_chain", []) if published else []
    lookup = {row["block_id"]: (context, row)
              for context in fixture["contexts"] for row in context["winner_children"]}
    parent, selected = fixture["prefix"]["tip_id"], []
    completed = {item["edge"]["observation"].get("block_id") for item in trajectory
                 if item["edge"]["observation"].get("proof_complete") is True}
    for identifier in chain:
        require(identifier in lookup and identifier in completed, "UNPROVED_SELECTED_BLOCK")
        context, row = lookup[identifier]
        require(context["parent_id"] == parent, "SELECTED_PARENT_BINDING")
        selected.append({"context_id": context["context_id"], "nonce": row["nonce"],
                         "block_id": identifier, "parent_id": parent})
        parent = identifier
    return {"name": name, "observation_kind": kind,
            "native_observed_now": fixture["clock_origin_timestamp"] + elapsed.numerator // elapsed.denominator,
            "packets_to_submit": selected, "publication_complete": published,
            "expected_reorganization": trajectory[-1]["edge"]["terminal_risk"] == 1,
            "logical_elapsed_seconds_exact": terminal["time"],
            "raw_observation": raw_observation,
            "native_replay_is_cpu_execution_not_quantum_execution": True}


def sample_report(fixture, fixture_sha256, certificate, certificate_file_sha256,
                  classical_certificate, classical_certificate_file_sha256, checked_packets):
    require(certificate.get("status") == "COMPLETE", "INCOMPLETE_FINITE_CERTIFICATE")
    runs = []
    for iterations in (0, 1):
        sample = sample_finite_policy(certificate, fixture, iterations=iterations, seed=9)
        runs.append(normalize_run(fixture, f"fixed-q{iterations}-seed9",
                                  "seeded-no-Grover-baseline" if iterations == 0 else "seeded-conditional-Grover-model",
                                  sample["trajectory"], sample))
    positive = certificate.get("positive_path")
    if positive is not None:
        runs.append(normalize_run(fixture, "observer-advice-quantum-positive-path", "advice-selected-conditional-quantum-witness",
                                  positive["trajectory"], positive))
    require(classical_certificate.get("status") == "COMPLETE", "INCOMPLETE_CLASSICAL_CERTIFICATE")
    classical = sample_finite_policy(classical_certificate, fixture, iterations=0, seed=9)
    runs.append(normalize_run(fixture, "classical-q0-seed9", "seeded-classical-uniform-nonce-baseline",
                              classical["trajectory"], classical))
    positive = classical_certificate.get("positive_path")
    if positive is not None:
        runs.append(normalize_run(fixture, "observer-advice-classical-positive-path", "advice-selected-classical-existential-witness",
                                  positive["trajectory"], positive))
    return {"schema": SCHEMA, "source": sources(), "fixture_sha256": fixture_sha256,
            "certificate_file_sha256": certificate_file_sha256,
            "certificate_sha256": certificate["certificate_sha256"],
            "classical_certificate_file_sha256": classical_certificate_file_sha256,
            "classical_certificate_sha256": classical_certificate["certificate_sha256"],
            "independently_checked_packet_records": checked_packets,
            "declared_sample_inventory": ["fixed-q0-seed9", "fixed-q1-seed9", "classical-q0-seed9"],
            "runs": runs, "claims": dict(CLAIMS)}


def declared_models():
    """Public fixed campaign premises, selected without inspecting its census.

    The serial lifecycle is a deliberately explicit illustrative strategy.
    A failed four-second delivery never establishes a minimum attacker time.
    """
    baseline = example()
    physical = replace(baseline.physical_models[1], name="illustrative-w1-bounded-schedule", magic_state_error="1e-30")
    return baseline.classical, physical, illustrative_lifecycle_model()


def cost_premises(fixture, execution_kind="constructed-quantum"):
    require(execution_kind in ("constructed-quantum", "classical-uniform-q0"), "BRIDGE_EXECUTION_KIND")
    classical_model, physical, lifecycle = declared_models()
    classical = (classical_model,) * len(fixture["contexts"])
    parameters = {"classical_costs": [asdict(row) for row in classical],
                  "physical_model": asdict(physical), "physical_qubit_budget": 10**16,
                  "horizon_seconds": "4", "iterations": [0, 1] if execution_kind == "constructed-quantum" else [0], "max_attempts": 2,
                  "predicate": "full", "max_states": 10000,
                  "lifecycle_model": asdict(lifecycle), "execution_kind": execution_kind}
    return classical, physical, lifecycle, parameters


def check_cost_premises(certificate, fixture, execution_kind="constructed-quantum"):
    require(canonical(certificate.get("parameters")) == canonical(cost_premises(fixture, execution_kind)[3]),
            "BRIDGE_COST_PREMISES_CHANGED")


def observe(directory):
    for name in OUTPUTS:
        require(not (directory / name).exists(), "OUTPUT_ALREADY_EXISTS")
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    before = sources()
    fixture, fixture_sha256, checked = load_fixture(directory)
    classical, physical, lifecycle, _ = cost_premises(fixture)
    certificate = analyze_finite_consensus(
        fixture, classical, physical, 10**16,
        horizon_seconds="4", iterations=(0, 1), max_attempts=2, predicate="full", max_states=10000,
        lifecycle_model=lifecycle, execution_kind="constructed-quantum")
    check_cost_premises(certificate, fixture)
    verify_finite_certificate(certificate, fixture)
    classical_certificate = analyze_finite_consensus(
        fixture, classical, physical, 10**16,
        horizon_seconds="4", iterations=(0,), max_attempts=2, predicate="full", max_states=10000,
        lifecycle_model=lifecycle, execution_kind="classical-uniform-q0")
    check_cost_premises(classical_certificate, fixture, "classical-uniform-q0")
    verify_finite_certificate(classical_certificate, fixture)
    report = sample_report(fixture, fixture_sha256, certificate, sha(json_bytes(certificate)),
                           classical_certificate, sha(json_bytes(classical_certificate)), checked)
    require(sources() == before, "BRIDGE_SOURCE_CHANGED")
    clock = {"schema": "trnm-w1-native-bridge-offline-observer-clock-v1",
             "elapsed_wall_ns": time.perf_counter_ns() - wall,
             "process_cpu_ns": time.process_time_ns() - cpu,
             "scope": "Python offline scalar packet/census/certificate replay and sampling; excludes Rust and quantum hardware",
             "charged_to_four_second_modeled_miner": False, "hardware_calibration": False}
    write_new(directory / "finite-certificate.json", certificate)
    write_new(directory / "classical-certificate.json", classical_certificate)
    write_new(directory / "bridge-samples.json", report)
    write_new(directory / "bridge-observer-clock.json", clock)
    return {"schema": SCHEMA, "status": "OBSERVED", "runs": len(report["runs"]),
            "fixed_policy_risks": certificate["fixed_policy_risks"],
            "classical_fixed_policy_risks": classical_certificate["fixed_policy_risks"],
            "quantum_hardware_executed": False}


def verify(directory):
    before = sources()
    fixture, fixture_sha256, checked = load_fixture(directory)
    certificate_raw = read(directory / "finite-certificate.json")
    certificate = strict_load(certificate_raw)
    check_cost_premises(certificate, fixture)
    verify_finite_certificate(certificate, fixture)
    classical_raw = read(directory / "classical-certificate.json")
    classical_certificate = strict_load(classical_raw)
    check_cost_premises(classical_certificate, fixture, "classical-uniform-q0")
    verify_finite_certificate(classical_certificate, fixture)
    expected = sample_report(fixture, fixture_sha256, certificate, sha(certificate_raw),
                             classical_certificate, sha(classical_raw), checked)
    observed_raw = read(directory / "bridge-samples.json")
    observed = strict_load(observed_raw)
    require(canonical(observed) == canonical(expected), "BRIDGE_SAMPLE_REPLAY_MISMATCH")
    verified_inputs = {"native-fixture.json": fixture_sha256,
                       "finite-certificate.json": sha(certificate_raw),
                       "classical-certificate.json": sha(classical_raw),
                       "bridge-samples.json": sha(observed_raw)}
    require(sources() == before, "BRIDGE_SOURCE_CHANGED")
    require(native_source_inventory() == fixture["native_source"]["source_sha256"],
            "NATIVE_SOURCE_CHANGED")
    require(all(sha(read(directory / name)) == expected_hash
                for name, expected_hash in verified_inputs.items()), "BRIDGE_INPUT_CHANGED_DURING_VERIFY")
    return {"schema": SCHEMA, "status": "VERIFIED", "runs": len(expected["runs"]),
            "verified_inputs": verified_inputs, "source_snapshot": before,
            "runtime_identity": {"executable": sys.executable, "version": sys.version,
                                 "implementation": sys.implementation.name},
            "native_blocks_admitted_by_python_reader": 0, "quantum_hardware_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--observe", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    result = observe(args.observe) if args.observe else verify(args.verify)
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
