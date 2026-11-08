#!/usr/bin/env python3
"""Exercise complete native W1 unit witnesses through existing Rust bridges.

This is a bridge-level probe, not the MU1 outer relation or its lottery.  The
mandatory-units relation has its own context encoding, unit challenge derivation,
aggregate ticket, and admission rules.  This probe gives it an actually executed
native full-relation backend and rejects representative malformed unit witnesses.
No reference implementation is substituted if a native subprocess fails.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time


FORMAL = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(FORMAL))
import work_oracle as independent  # noqa: E402


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


class NativeCalls:
    def __init__(self, out: Path):
        self.out = out
        self.rows: list[dict] = []

    def run(self, name: str, executable: Path, mode: str, raw: bytes,
            expected_exit: int = 0, expected_error: str | None = None) -> bytes:
        require(name.replace("-", "").isalnum(), "CALL_NAME")
        prefix = self.out / name
        prefix.with_suffix(".input.bin").write_bytes(raw)
        started = time.monotonic_ns()
        result = subprocess.run([str(executable), mode], input=raw,
                                capture_output=True, check=False, timeout=60)
        elapsed = time.monotonic_ns() - started
        prefix.with_suffix(".stdout.bin").write_bytes(result.stdout)
        prefix.with_suffix(".stderr.txt").write_bytes(result.stderr)
        row = {
            "name": name, "binary": executable.name, "mode": mode,
            "exit_code": result.returncode, "expected_exit": expected_exit,
            "wall_ns_observed_including_process_start": elapsed,
            "input_bytes": len(raw), "input_sha256": digest(raw),
            "stdout_bytes": len(result.stdout), "stdout_sha256": digest(result.stdout),
            "stderr_sha256": digest(result.stderr),
            "expected_error": expected_error,
            "pass": result.returncode == expected_exit and (
                expected_error is None or result.stderr.strip() == expected_error.encode()),
        }
        self.rows.append(row)
        (self.out / "calls.json").write_text(json.dumps(self.rows, indent=2) + "\n")
        require(row["pass"], "NATIVE_CALL_FAILED:" + name)
        return result.stdout


def produce_payload(challenge: bytes, a: list[int], b: list[int]) -> bytes:
    return challenge + independent.field_bytes(a) + independent.field_bytes(b)


def verify_payload(challenge: bytes, task: bytes, proof: bytes) -> bytes:
    # All-ff means only the complete inner W1 relation is being checked here.
    # MU1 has exactly one separate fixed-target aggregate lottery.
    return challenge + task + bytes([255]) * 32 + proof


def source_binding() -> dict:
    paths = [
        "trillionnium/Cargo.lock",
        "trillionnium/crates/trnm-crypto-primitives/Cargo.toml",
        "trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs",
        "trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_io.rs",
        "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
        "formal/pon-nakamoto-v1/work_oracle.py",
        "formal/pon-nakamoto-v1/contract_wire.py",
        "formal/pon-nakamoto-v1/native_w1_units_probe/probe.py",
    ]
    paths += sorted(str(path.relative_to(REPO)) for path in (
        REPO / "trillionnium/crates/trnm-crypto-primitives/src/pon_work").rglob("*.rs"))
    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                          capture_output=True, check=True, text=True).stdout.strip()
    return {"repository_head_observed": head,
            "files": [{"path": path, "sha256": digest((REPO / path).read_bytes())}
                      for path in paths]}


def run(native: Path, prepared: Path, out: Path) -> dict:
    require(native.is_file() and prepared.is_file(), "NATIVE_BINARY_REQUIRED")
    out.mkdir(parents=True, exist_ok=False)
    calls = NativeCalls(out)
    result = {
        "schema": "pon-native-w1-unit-bridge-probe-v1",
        "source": source_binding(),
        "binaries": {path.name: {"sha256": digest(path.read_bytes()),
                                 "bytes": path.stat().st_size}
                     for path in (native, prepared)},
        "inner_target_hex": "ff" * 32,
        "unit_sets": [], "controls": [],
        "scope": {
            "complete_native_w1_producer_executed": True,
            "complete_native_w1_verifier_executed": True,
            "independent_python_proof_bytes_compared": True,
            "mu1_outer_context_and_aggregate_lottery_checked": False,
            "native_chain_admission_executed": False,
            "minimum_classical_or_quantum_cost_proved": False,
            "strategy_uniform_resource_tail_proved": False,
            "consensus_or_six_confirmation_risk_qualified": False,
            "production_activation": False,
        },
    }
    a = [(17 * index + 3) % independent.Q for index in range(independent.CELLS)]
    b = [(11 * index * index + 7) % independent.Q for index in range(independent.CELLS)]
    task = independent.task_id(a, b)
    context = hashlib.sha256(b"TRNM-MU1-NATIVE-BRIDGE-PROBE-V1\0").digest()
    retained: dict[int, list[tuple[bytes, bytes]]] = {}
    for units in (1, 2):
        row = {"units": units, "task_id_hex": task.hex(), "witnesses": []}
        retained[units] = []
        for index in range(units):
            # A separate probe namespace deliberately makes no assertion that
            # this is MU1's outer context serialization or challenge domain.
            challenge = independent.H("mandatory-unit-native-bridge-probe-v1", context,
                                      struct.pack("<II", units, index), task)
            request = produce_payload(challenge, a, b)
            prefix = f"u{units}-unit{index}"
            proof = calls.run(prefix + "-scalar", native, "prove", request)
            require(len(proof) == independent.PROOF_BYTES, "COMPLETE_PROOF_LENGTH")
            prepared_proof = calls.run(prefix + "-prepared", prepared, "generic", request)
            require(proof == prepared_proof, "NATIVE_PRODUCER_DIFFERENTIAL")
            require(proof == independent.prove(challenge, a, b), "PYTHON_DIFFERENTIAL")
            verification = verify_payload(challenge, task, proof)
            receipt = calls.run(prefix + "-verify", native, "verify", verification)
            require(receipt == independent.H("native-work-verification", verification),
                    "NATIVE_VERIFICATION_RECEIPT")
            retained[units].append((challenge, proof))
            row["witnesses"].append({"index": index, "challenge_hex": challenge.hex(),
                                     "proof_sha256": digest(proof),
                                     "trace_hex": proof[-32:].hex(),
                                     "proof_bytes": len(proof),
                                     "native_full_verification_receipt_hex": receipt.hex()})
        result["unit_sets"].append(row)

    challenge, proof = retained[2][0]
    next_challenge, next_proof = retained[2][1]
    require(challenge != next_challenge, "DISTINCT_INDEX_CHALLENGES")

    def reject(name: str, raw: bytes, expected_error: str = "WORK",
               cheap_filter_passed: bool | None = None) -> None:
        calls.run(name, native, "verify", raw, 2, expected_error)
        result["controls"].append({"name": name, "native_rejected": True,
                                   "independent_cheap_filter_passed": cheap_filter_passed})

    false_trace = proof[:-1] + bytes([proof[-1] ^ 1])
    independent.precheck(challenge, task, bytes([255]) * 32, false_trace)
    reject("correct-product-false-trace", verify_payload(challenge, task, false_trace),
           cheap_filter_passed=True)
    product_offset = 4 + 2 * independent.CELLS * 4
    value, = struct.unpack_from("<I", proof, product_offset)
    false_product = (proof[:product_offset] + struct.pack("<I", (value + 1) % independent.Q)
                     + proof[product_offset + 4:])
    independent.precheck(challenge, task, bytes([255]) * 32, false_product)
    reject("correct-trace-false-product", verify_payload(challenge, task, false_product),
           cheap_filter_passed=True)
    reject("wrong-task", verify_payload(challenge, bytes([task[0] ^ 1]) + task[1:], proof))
    reject("duplicate-unit-at-new-index", verify_payload(next_challenge, task, proof))
    reject("reordered-unit-at-index-zero", verify_payload(challenge, task, next_proof))
    reject("cross-unit-count-transplant", verify_payload(retained[1][0][0], task, proof))
    reject("truncated-proof", verify_payload(challenge, task, proof[:-1]), "LENGTH")
    reject("trailing-proof-bytes", verify_payload(challenge, task, proof + b"\0"), "LENGTH")

    zeros = [0] * independent.CELLS
    zero_task = independent.task_id(zeros, zeros)
    zero_challenge = independent.H("mandatory-unit-native-bridge-zero-v1", context, zero_task)
    zero_input = produce_payload(zero_challenge, zeros, zeros)
    zero_generic = calls.run("zero-generic", prepared, "generic", zero_input)
    zero_blocked = calls.run("zero-blocked", prepared, "blocked-zero", zero_input)
    require(zero_generic == zero_blocked == independent.prove(zero_challenge, zeros, zeros),
            "VALID_STRUCTURED_PRODUCER_DIFFERENTIAL")
    calls.run("zero-complete-verify", native, "verify",
              verify_payload(zero_challenge, zero_task, zero_blocked))
    calls.run("zero-only-refuses-nonzero", prepared, "blocked-zero",
              produce_payload(challenge, a, b), 2, "UNSUPPORTED")
    result["controls"].append({"name": "legal-structured-producer-same-full-proof",
                               "same_complete_proof": True,
                               "native_full_verification_passed": True,
                               "cheapest_cost_claim": False})
    result["controls"].append({"name": "zero-only-refuses-nonzero",
                               "unsupported_is_not_silently_replaced": True})
    result["calls"] = calls.rows
    result["pass"] = all(row["pass"] for row in calls.rows)
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-bin", type=Path, required=True)
    parser.add_argument("--zero-bin", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.native_bin.resolve(), args.zero_bin.resolve(), args.out.resolve())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"pass": False, "error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps({"pass": result["pass"], "native_calls": len(result["calls"]),
                      "unit_sets": [row["units"] for row in result["unit_sets"]],
                      "controls": len(result["controls"]), "out": str(args.out)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
