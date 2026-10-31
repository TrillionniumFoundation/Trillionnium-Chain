#!/usr/bin/env python3
"""Bounded, actual W1 scalar reference experiment; NEVER a work-hardness certificate.

Uses the existing byte-exact W1 oracle, frozen devnet target and real full
transcript verification. Its scalar valid-prover cost is NOT a cheapest legal
solver bound, nor a GPU/ASIC/quantum measurement. No consensus rules change.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE.parents[1]))

from contract_wire import H, PARAMS, WORK_PROFILE  # noqa: E402
import work_oracle as w1  # noqa: E402

FAMILIES = ("zero", "diagonal", "rank-one", "dense")
MAX_TRIALS = 3
MAX_GUESSES = 512


def matrices(name: str) -> tuple[list[int], list[int]]:
    n = w1.N
    if name == "zero":
        return [0] * w1.CELLS, [0] * w1.CELLS
    if name == "diagonal":
        a = [0] * w1.CELLS
        b = [0] * w1.CELLS
        for i in range(n):
            a[i * n + i] = (i + 1) % w1.Q
            b[i * n + i] = (3 * i + 1) % w1.Q
        return a, b
    if name == "rank-one":
        return (
            [(i + 1) * (j + 2) % w1.Q for i in range(n) for j in range(n)],
            [(i + 3) * (j + 1) % w1.Q for i in range(n) for j in range(n)],
        )
    if name == "dense":
        return (
            [(i * 1297 + j * 431 + i * j * 7 + 1) % w1.Q
             for i in range(n) for j in range(n)],
            [(i * 179 + j * 1031 + i * j * 11 + 3) % w1.Q
             for i in range(n) for j in range(n)],
        )
    raise ValueError("unknown work family")


def forge_ticket_only(challenge: bytes, target: bytes, legitimate_trace: bytes):
    """Find only a cheap ticket-qualified digest; it is NOT a W1 transcript."""
    for counter in range(MAX_GUESSES):
        candidate = hashlib.sha256(
            b"TRNM-W1-INVALID-TRANSCRIPT-RESEARCH-V1\0"
            + challenge + counter.to_bytes(4, "little")
        ).digest()
        if candidate != legitimate_trace and H("ticket", challenge, candidate) <= target:
            return candidate, counter + 1
    raise AssertionError("bounded half-range ticket search unexpectedly failed")


def one_case(name: str, trial: int, target: bytes) -> dict:
    a, b = matrices(name)
    challenge = H("adversarial-work-cost-v1", name.encode("ascii"),
                  trial.to_bytes(4, "little"))
    task = w1.task_id(a, b)

    start = time.process_time_ns()
    proof = w1.prove(challenge, a, b)
    honest_ns = time.process_time_ns() - start
    if len(proof) != WORK_PROFILE["proof_bytes"] or len(proof) != w1.PROOF_BYTES:
        raise ValueError("unexpected W1 proof byte length")

    start = time.process_time_ns()
    _ticket, actual_product = w1.verify(challenge, task, b"\xff" * 32, proof)
    valid_verify_ns = time.process_time_ns() - start

    # Independently check selected output coordinates instead of accepting only
    # the prover's claimed C. This does not establish a cost lower bound.
    for i, j in ((0, 0), (0, w1.N - 1), (w1.N // 2, w1.N // 2),
                 (w1.N - 1, w1.N - 1)):
        independent = sum(
            a[i * w1.N + k] * b[k * w1.N + j]
            for k in range(w1.N)
        ) % w1.Q
        if actual_product[i * w1.N + j] != independent:
            raise ValueError("independent output-coordinate mismatch")

    start = time.process_time_ns()
    forged_trace, guesses = forge_ticket_only(challenge, target, proof[-32:])
    cheap_ns = time.process_time_ns() - start
    invalid = proof[:-32] + forged_trace
    if H("ticket", challenge, forged_trace) > target:
        raise ValueError("ticket-only input did not qualify")
    start = time.process_time_ns()
    rejection = None
    try:
        w1.verify(challenge, task, target, invalid)
    except ValueError as error:
        rejection = str(error)
    invalid_verify_ns = time.process_time_ns() - start
    if rejection != "TRANSCRIPT":
        raise AssertionError("ticket-qualified forged W1 trace not rejected by full replay")

    return {
        "family": name,
        "trial": trial,
        "work_task": task.hex(),
        "challenge": challenge.hex(),
        "ticket_qualified_invalid_digest_guesses": guesses,
        "valid_scalar_prover_cpu_ns": honest_ns,
        "valid_full_verify_cpu_ns": valid_verify_ns,
        "invalid_full_verify_cpu_ns": invalid_verify_ns,
        "ticket_only_forgery_cpu_ns": cheap_ns,
        "invalid_to_forgery_ratio_observed": invalid_verify_ns / max(1, cheap_ns),
        "forged_full_replay_error": rejection,
        "valid_winning_ticket_at_devnet_target":
            H("ticket", challenge, proof[-32:]) <= target,
    }


def run(trials: int = 1) -> dict:
    if type(trials) is not int or not 1 <= trials <= MAX_TRIALS:
        raise ValueError("trial limit")
    if WORK_PROFILE["id"] != "pon-matmul-transcript-64-v1" \
            or WORK_PROFILE["production_eligible"] is not False:
        raise ValueError("unreviewed W1 profile")
    target = bytes.fromhex(PARAMS["initial_target_hex"])
    if len(target) != 32 or target == b"\0" * 32:
        raise ValueError("invalid devnet target")
    inputs = [
        "config/pon/work-profile-v1.json",
        "config/pon/devnet-v1.json",
        "formal/pon-nakamoto-v1/work_oracle.py",
        "formal/pon-nakamoto-v1/contract_wire.py",
        "formal/pon-nakamoto-v1/experiments/w1_valid_invalid_cost_v1.py",
    ]
    hashes = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in inputs
    }
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                         capture_output=True, check=False)
    observations = [
        one_case(name, trial, target)
        for name in FAMILIES for trial in range(trials)
    ]
    return {
        "schema": "w1-valid-invalid-structured-cost-v1",
        "source_head": git.stdout.strip() if git.returncode == 0 else None,
        "source_sha256": hashes,
        "profile": WORK_PROFILE["id"],
        "target": target.hex(),
        "environment": {"python": platform.python_version(),
                        "platform": platform.platform(),
                        "clock": "process_time_ns",
                        "gpu_or_asic_measured": False,
                        "quantum_oracle_measured": False},
        "observations": observations,
        "all_ticket_qualified_invalid_rejected":
            all(x["forged_full_replay_error"] == "TRANSCRIPT"
                for x in observations),
        "valid_work_accepted_only_with_full_replay": True,
        "fastest_adversarial_valid_solver_qualified": False,
        "hardness_lower_bound_proven": False,
        "pq128_security_qualified": False,
        "sybil_safe_public_admission": False,
        "production_activation": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=1)
    args = parser.parse_args()
    report = run(args.trials)
    output = args.output.resolve()
    output.mkdir(parents=False, exist_ok=False)
    with (output / "report.json").open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2, sort_keys=True)
        file.write("\n")
    print(json.dumps({"schema": report["schema"],
                      "observations": len(report["observations"]),
                      "source_head": report["source_head"],
                      "public_or_pq_security_accepted": False}))


if __name__ == "__main__":
    main()
