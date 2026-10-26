#!/usr/bin/env python3
"""P2 joint economic triage on two already-versioned read-only research oracles.

No hardware attestation, public V3 mutation, W1 work verifier, full-server
benchmark, difficulty change, reward, chainwork or production activation.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "formal/pon-nakamoto-v1"))
import pon_admission_price_model as v3
import w2c_cost_verdict as w2c

SCHEMA = "trnm-pon-p2-joint-triage-v1"
MAX_INPUT_BYTES = 1024 * 1024


def analyze(bundle):
    if type(bundle) is not dict or set(bundle) != {"schema", "v3_model", "w2c_cost", "binding"}:
        raise ValueError("JOINT_SCHEMA")
    if bundle["schema"] != SCHEMA:
        raise ValueError("JOINT_SCHEMA")
    identity = bundle["binding"]
    required = {"source_commit", "challenge", "task", "target", "host_receipt_sha256"}
    if type(identity) is not dict or set(identity) != required:
        raise ValueError("JOINT_BINDING")
    def hex_string(value, n, label):
        if type(value) is not str or len(value) != n or any(c not in "0123456789abcdef" for c in value):
            raise ValueError(label)
        return value
    for name in ("challenge", "task", "target", "host_receipt_sha256"):
        hex_string(identity[name], 64, name)
    hex_string(identity["source_commit"], 40, "SOURCE")
    model = bundle["v3_model"]
    if type(model) is not dict or type(model.get("measurement_identity")) is not dict:
        raise ValueError("V3_IDENTITY")
    if model["measurement_identity"].get("source_commit") != identity["source_commit"]:
        raise ValueError("SOURCE_MISMATCH")
    # Run the unaltered separate source and never reinterpret its truth flags.
    v = v3.evaluate(model)
    w = w2c.decide(bundle["w2c_cost"])
    if v.get("production_activation") is not False or w.get("production_qualified") is not False:
        raise ValueError("SOURCE_AUTHORITY_PROMOTION")
    blockers = []
    if not v["model_has_solution"]:
        blockers.append("NO_COMMON_BIT_LEVEL_MEETS_MODELED_HONEST_LATENCY_AND_COST")
    if w["status"] == "UNKNOWN":
        blockers.append("W2C_ACCELERATOR_OR_TRANSPORT_UNOBSERVED")
    elif w["status"] == "OBSERVED_AMPLIFICATION":
        blockers.append("W2C_RECEIVER_CPU_AMPLIFICATION_OBSERVED")
    elif w["status"] == "NO_OBSERVED_AMPLIFICATION":
        blockers.append("FINITE_W2C_SAMPLE_IS_NOT_A_HARDNESS_LOWER_BOUND")
    else:
        raise ValueError("W2C_UNEXPECTED_VERDICT")
    if bundle["w2c_cost"]["ticket_scope"] == "globally-replayable":
        blockers.append("GLOBAL_TICKET_CROSS_RECEIVER_REPLAY")
    if model["measurement_identity"]["independent_operator"] is not True:
        blockers.append("INDEPENDENT_OPERATOR_UNATTESTED")
    if model["measurement_identity"]["measured_on_real_hardware"] is not True:
        blockers.append("REAL_HARDWARE_UNATTESTED")
    # A digest supplied by the caller only checks internal linkage. It does
    # not prove that receipt bytes belong to a host or to these measurements.
    blockers.append("SOURCE_HOST_RECEIPT_NOT_INDEPENDENTLY_VERIFIED")
    blockers.extend((
        "ORIGINAL_NATIVE_V3_AND_W1_END_TO_END_UNMEASURED",
        "A03_THREE_MODES_THREE_RUNS_THREE_CONFIRMATIONS_UNQUALIFIED",
        "W2_SOUNDNESS_AND_EXTERNAL_CRYPTO_REVIEW_UNQUALIFIED",
    ))
    return {
        "schema": SCHEMA,
        "binding_claims_only": identity,
        "v3_modeled_feasible_bits": v["model_feasible_bits"],
        "v3_honest_p95_deadline_model": True,
        "w2c_observation_status": w["status"],
        "w2c_sender_scope": bundle["w2c_cost"]["ticket_scope"],
        "w2c_receiver_count": bundle["w2c_cost"]["receiver_count"],
        "unclosed_gates": sorted(set(blockers)),
        "native_work_verified_by_joint_reader": False,
        "source_and_host_attested_by_joint_reader": False,
        "gpu_test_executed_by_joint_reader": False,
        "public_network_ready": False,
        "independent_accepted": False,
        "production_activation": False,
        "verdict": "HOLD_NO_GO",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("--out")
    options = parser.parse_args()
    source = Path(options.input)
    if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_INPUT_BYTES:
        raise SystemExit("INPUT_LIMIT")
    with source.open("r", encoding="utf-8") as stream:
        data = json.load(stream, parse_constant=lambda s: (_ for _ in ()).throw(ValueError("NONFINITE")))
    result = analyze(data)
    raw = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if options.out:
        with open(options.out, "x", encoding="utf-8") as stream:
            stream.write(raw)
    else:
        print(raw, end="")


if __name__ == "__main__":
    main()
