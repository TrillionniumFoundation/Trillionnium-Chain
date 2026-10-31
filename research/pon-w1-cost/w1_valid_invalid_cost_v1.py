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
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))

from contract_wire import H, PARAMS, WORK_PROFILE  # noqa: E402
import work_oracle as w1  # noqa: E402

FAMILIES = ("zero", "diagonal", "rank-one", "dense")
MAX_TRIALS = 3
MAX_GUESSES = 512


# These are the complete direct and configuration imports used by this
# controlled scalar W1 runner. HEAD labels alone are not evidence of bytes.
AUDITED_INPUTS = (
    "config/pon/work-profile-v1.json",
    "config/pon/devnet-v1.json",
    "config/pon/ledger-v1.json",
    "config/pon/model-family-v1.json",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "research/pon-w1-cost/w1_valid_invalid_cost_v1.py",
)


def _git_bytes(root: Path, *args: str) -> bytes:
    """Read a bounded, explicit Git identity or committed source blob."""
    try:
        command = subprocess.run(
            ["git", *args], cwd=root, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("source Git verification unavailable") from error
    if command.returncode != 0:
        raise ValueError("source Git verification failed")
    return command.stdout


def audit_source_inputs(root: Path, inputs: tuple[str, ...]) -> tuple[str, str, dict[str, str]]:
    """Fail closed on a dirty or substituted source, even assume-unchanged.

    Every file is compared byte-for-byte with its *committed* HEAD blob;
    a clean-looking index/status is not enough. No missing Git fallback.
    """
    actual_root = Path(_git_bytes(root, "rev-parse", "--show-toplevel").decode().strip())
    if actual_root.resolve() != root.resolve():
        raise ValueError("unexpected source repository root")
    head = _git_bytes(root, "rev-parse", "--verify", "HEAD").decode().strip()
    tree = _git_bytes(root, "rev-parse", "--verify", "HEAD^{tree}").decode().strip()
    if any(len(item) != 40 or any(ch not in "0123456789abcdef" for ch in item)
           for item in (head, tree)):
        raise ValueError("invalid source object identity")
    if _git_bytes(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("source checkout not clean")
    fingerprints = {}
    for relative in inputs:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source is missing or redirected: {relative}")
        current = path.read_bytes()
        committed = _git_bytes(root, "show", f"HEAD:{relative}")
        if current != committed:
            raise ValueError(f"tracked source differs from HEAD: {relative}")
        fingerprints[relative] = hashlib.sha256(current).hexdigest()
    return head, tree, fingerprints



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


# A real, eligible W1 solver can derive the true C=A*B for these structures
# without the generic correction term. The challenge-noised transcript is
# still constructed in full. This is an upper-cost candidate, NOT a lower bound
# on the cheapest valid miner or a post-quantum security qualification.
STRUCTURED_LEGAL_FAMILIES = ("zero", "diagonal", "rank-one")


def legal_structured_product(name: str) -> list[int]:
    if name == "zero":
        return [0] * w1.CELLS
    if name == "diagonal":
        out = [0] * w1.CELLS
        for i in range(w1.N):
            out[i * w1.N + i] = (i + 1) * (3 * i + 1) % w1.Q
        return out
    if name == "rank-one":
        inner = sum((k + 2) * (k + 3) for k in range(w1.N)) % w1.Q
        return [(i + 1) * (j + 1) * inner % w1.Q
                for i in range(w1.N) for j in range(w1.N)]
    raise ValueError("unknown legal structure")


def prove_legal_structured(
    challenge: bytes, a: list[int], b: list[int], name: str,
) -> bytes:
    """Emit a full, lawful W1 proof, never a fabricated cheap ticket.

    Input matrices must exactly match a known legal structural identity;
    a family label alone cannot authorize an incorrect product. All
    challenge-derived noise and 512 cumulative trace tiles remain included.
    """
    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise ValueError("invalid challenge")
    if name not in STRUCTURED_LEGAL_FAMILIES or (a, b) != matrices(name):
        raise ValueError("unreviewed structured matrices")
    product = legal_structured_product(name)
    el, er, fl, fr = [
        w1.expand(challenge, x, w1.N * w1.R) for x in range(4)
    ]
    e = w1.mm(el, er, w1.N, w1.R, w1.N)
    f = w1.mm(fl, fr, w1.N, w1.R, w1.N)
    aa = [(x + y) % w1.Q for x, y in zip(a, e)]
    bb = [(x + y) % w1.Q for x, y in zip(b, f)]
    cp = [0] * w1.CELLS
    trace = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    for i0 in range(0, w1.N, w1.R):
        for j0 in range(0, w1.N, w1.R):
            for k0 in range(0, w1.N, w1.R):
                tile = []
                for i in range(i0, i0 + w1.R):
                    for j in range(j0, j0 + w1.R):
                        pos = i * w1.N + j
                        cp[pos] = (cp[pos] + sum(
                            aa[i * w1.N + k] * bb[k * w1.N + j]
                            for k in range(k0, k0 + w1.R)
                        )) % w1.Q
                        tile.append(cp[pos])
                trace.update(w1.field_bytes(tile))
    return (b"PNW1" + w1.field_bytes(a) + w1.field_bytes(b)
            + w1.field_bytes(product) + trace.digest())

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

    # Same challenge/task; do not award a fabricated digest as valid work.
    legal_structured_cpu_ns = None
    if name in STRUCTURED_LEGAL_FAMILIES:
        start = time.process_time_ns()
        legal_proof = prove_legal_structured(challenge, a, b, name)
        legal_structured_cpu_ns = time.process_time_ns() - start
        if legal_proof != proof or len(legal_proof) != w1.PROOF_BYTES:
            raise AssertionError("legal structured proof differs from W1 oracle")
        if H("ticket", challenge, legal_proof[-32:]) != H(
            "ticket", challenge, proof[-32:]
        ):
            raise AssertionError("structured valid ticket differs from W1")


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
        "legal_structured_prover_cpu_ns": legal_structured_cpu_ns,
        "legal_structured_proof_byte_identical": (
            True if legal_structured_cpu_ns is not None else None),
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
    source_head, source_tree, hashes = audit_source_inputs(ROOT, AUDITED_INPUTS)
    observations = [
        one_case(name, trial, target)
        for name in FAMILIES for trial in range(trials)
    ]
    after_head, after_tree, after_hashes = audit_source_inputs(ROOT, AUDITED_INPUTS)
    if (source_head, source_tree, hashes) != (after_head, after_tree, after_hashes):
        raise ValueError("W1 source changed during measurement")
    return {
        "schema": "w1-valid-invalid-structured-cost-v1",
        "source_head": source_head,
        "source_tree": source_tree,
        "source_sha256": hashes,
        "profile": WORK_PROFILE["id"],
        "target": target.hex(),
        "environment": {"python": platform.python_version(),
                        "platform": platform.platform(),
                        "clock": "process_time_ns",
                        "gpu_or_asic_measured": False,
                        "quantum_oracle_measured": False},
        "observations": observations,
        # Actual valid transcript work at the frozen target: record honest
        # eligible attempts and winner denominators; forged tickets never count.
        "sampled_valid_proof_attempts": len(observations),
        "sampled_valid_devnet_winners": sum(
            x["valid_winning_ticket_at_devnet_target"] for x in observations),
        "sampled_structured_proof_attempts": sum(
            x["legal_structured_proof_byte_identical"] is True for x in observations),
        "sampled_structured_devnet_winners": sum(
            x["legal_structured_proof_byte_identical"] is True
            and x["valid_winning_ticket_at_devnet_target"] for x in observations),
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
