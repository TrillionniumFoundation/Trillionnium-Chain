#!/usr/bin/env python3
"""Pinned, complete scalar MU1 control for reusing u-1 full unit proofs.

Default/--check emits JSON after every check. --out NEW_DIR also writes the
original and hybrid packets, their independent contexts, and report.json.
The output directory must not exist. No Cargo or native process is invoked.

The original packet and the separately loaded expected context are pinned to
previously recorded MU1 fixture bytes. A pinned input does not substitute for
complete verification: both original units are verified, and the hybrid's
valid final unit and stale first unit are checked separately. An outer-winning
hybrid must be rejected by full MU1 verification and add no research credit.

This rejects one literal proof-reuse strategy in this fixture. Legal AB
preparation reuse is observed; costs of other preprocessing, batching, faster
algorithms, and quantum strategies remain open. No minimum-cost, native
consensus, attack-profitability, or resource-tail qualification is issued.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Callable

import mandatory_units_relation as mu


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "pon-fixed-probability-reuse-probe-v1"
FIXTURE_BASE = (
    "evidence/pon-work-native-certificates-20261107/mandatory_units/run-02-final"
)
CONTEXT_FILE = FIXTURE_BASE + "/dense-repeat-u2.pmh1"
PACKET_FILE = FIXTURE_BASE + "/dense-repeat-u2.pmu1"
CONTEXT_SHA256 = "290a8724dee47e23a9ae258157361cedc8e19b0a7e6b6a0701be1e05d2bc0403"
PACKET_SHA256 = "711643c498353dc1a2cdd450ff5b2fdb37e998617ec752418035e382654b4647"
HYBRID_SHA256 = "04d5b00f0e2b73c88a8a5674041077014c322a4021ba9083d43d6f1377256443"
ORIGINAL_NONCE = 24
HYBRID_NONCE = 26
QUALIFICATIONS = {
    "all_algorithm_cost_qualified": False,
    "quantum_cost_qualified": False,
    "native_consensus_qualified": False,
    "tail_qualified": False,
    "production_qualified": False,
    "attack_profitability_established": False,
}


class ProbeError(ValueError):
    """A failed check cannot produce a passing probe receipt."""


def _need(condition: bool, code: str) -> None:
    # Explicit checks remain active when Python is invoked with -O.
    if not condition:
        raise ProbeError(code)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pinned_fixture(relative: str, expected_sha256: str, expected_length: int) -> bytes:
    raw = (ROOT / relative).read_bytes()
    _need(len(raw) == expected_length, "FIXTURE_LENGTH_MISMATCH:" + relative)
    _need(_sha256(raw) == expected_sha256, "FIXTURE_SHA256_MISMATCH:" + relative)
    return raw


def _rejection(operation: Callable[[], object], kind: type[Exception], code: str) -> str:
    try:
        operation()
    except kind as error:
        _need(str(error) == code, "WRONG_REJECTION:" + str(error))
        return str(error)
    raise ProbeError("INVALID_REUSE_ACCEPTED:" + code)


def run_probe() -> tuple[dict[str, object], dict[str, bytes]]:
    """Run real scalar relation checks; return report and reproducible bytes."""
    context_bytes = _pinned_fixture(CONTEXT_FILE, CONTEXT_SHA256, 432)
    packet = _pinned_fixture(PACKET_FILE, PACKET_SHA256, 98882)
    # The verifier's expected context is an independent, pinned PMH1 input,
    # never a context obtained by trusting the submitted PMU1 packet.
    context = mu.decode_context(context_bytes)
    _need(context.units == 2 and context.nonce == ORIGINAL_NONCE, "FIXTURE_PROFILE")
    original = mu.verify_packet(packet, context, backend="scalar")
    parsed = mu.inspect_packet(packet, context)

    a, b, _, _ = mu.w1.precheck(mu.unit_challenge(context, 1), context.tasks[1],
                                mu.UNIT_TARGET, parsed.proofs[1])
    prepared = mu.PreparedMatrices(tuple(a), tuple(b))
    regenerated_last = prepared.prove(mu.unit_challenge(context, 1))
    repeated_packet = mu.encode_packet(context, (parsed.proofs[0], regenerated_last))
    repeated = mu.inspect_packet(repeated_packet, context)

    book = mu.UniqueWorkCounter()
    initial_credit = book.admit(packet, context, backend="scalar")
    duplicate_credit = book.admit(repeated_packet, context, backend="scalar")
    credit_before_hybrid = book.total_credit

    # Fixed public control nonce. It is never assumed to win: the actual
    # aggregate hash is tested below before any rejection is called a pass.
    changed = replace(context, nonce=HYBRID_NONCE)
    new_last = prepared.prove(mu.unit_challenge(changed, 1))
    hybrid = mu.encode_packet(changed, (parsed.proofs[0], new_last))
    inspected = mu.inspect_packet(hybrid, changed)
    _need(inspected.ticket <= mu.T0, "HYBRID_OUTER_LOTTERY_DID_NOT_WIN")
    new_unit_ticket, new_unit_product = mu.w1.verify(
        mu.unit_challenge(changed, 1), changed.tasks[1], mu.UNIT_TARGET, new_last)

    stale_unit_error = _rejection(
        lambda: mu.w1.verify(mu.unit_challenge(changed, 0), changed.tasks[0],
                             mu.UNIT_TARGET, parsed.proofs[0]),
        ValueError, "TRANSCRIPT")
    full_error = _rejection(
        lambda: mu.verify_packet(hybrid, changed, backend="scalar"),
        mu.RelationError, "W1_TRANSCRIPT")
    counter_error = _rejection(
        lambda: book.admit(hybrid, changed, backend="scalar"),
        mu.RelationError, "W1_TRANSCRIPT")

    checks = {
        "independent_context_pin_matches": _sha256(context_bytes) == CONTEXT_SHA256,
        "original_packet_pin_matches": _sha256(packet) == PACKET_SHA256,
        "original_complete_scalar_verification": (
            original.identity == parsed.identity and original.ticket == parsed.ticket
            and original.outputs_root == parsed.outputs_root and original.units == 2
            and original.credit == 32 and original.packet_bytes == len(packet)),
        "fixed_context_last_proof_byte_identical": regenerated_last == parsed.proofs[1],
        "fixed_context_packet_byte_identical": repeated_packet == packet,
        "fixed_context_ticket_and_identity_unchanged": (
            repeated.ticket == parsed.ticket and repeated.identity == parsed.identity),
        "first_admission_credit_32": initial_credit == 32,
        "fixed_context_duplicate_credit_zero": duplicate_credit == 0,
        "counter_credit_before_hybrid_32": credit_before_hybrid == 32,
        "both_unit_challenges_changed": all(
            mu.unit_challenge(context, index) != mu.unit_challenge(changed, index)
            for index in range(context.units)),
        "hybrid_keeps_unit_0_byte_for_byte": inspected.proofs[0] == parsed.proofs[0],
        "hybrid_unit_1_matches_constructed_full_proof": inspected.proofs[1] == new_last,
        "hybrid_unit_1_complete_scalar_verification": (
            new_unit_product == list(prepared.product)
            and len(new_unit_ticket) == 32 and new_unit_ticket <= mu.UNIT_TARGET),
        "prepared_AB_prefix_actually_reused": (
            prepared.prefix == parsed.proofs[1][:-32]
            and new_last[:-32] == parsed.proofs[1][:-32]),
        "new_unit_trace_changed": new_last[-32:] != parsed.proofs[1][-32:],
        "hybrid_outer_target_passes": inspected.ticket <= mu.T0,
        "hybrid_reproduces_recorded_bytes": _sha256(hybrid) == HYBRID_SHA256,
        "stale_unit_rejected_at_transcript": stale_unit_error == "TRANSCRIPT",
        "complete_MU1_rejected_at_transcript": full_error == "W1_TRANSCRIPT",
        "counter_rejected_at_transcript": counter_error == "W1_TRANSCRIPT",
        "counter_credit_did_not_increase": book.total_credit == credit_before_hybrid == 32,
    }
    failed = [name for name, passed in checks.items() if not passed]
    _need(not failed, "CHECKS_FAILED:" + ",".join(failed))

    artifacts = {
        "original-nonce24.pmh1": context_bytes,
        "original-nonce24.pmu1": packet,
        "hybrid-nonce26.pmh1": mu.encode_context(changed),
        "hybrid-nonce26.pmu1": hybrid,
    }
    sources = (
        "formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py",
        "formal/pon-nakamoto-v1/mandatory_units_relation.py",
        "formal/pon-nakamoto-v1/work_oracle.py",
        "formal/pon-nakamoto-v1/contract_wire.py",
    )
    report = {
        "schema": SCHEMA,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "fixture_provenance": {
            "context_path": CONTEXT_FILE,
            "context_sha256": CONTEXT_SHA256,
            "packet_path": PACKET_FILE,
            "packet_sha256": PACKET_SHA256,
            "expected_context_origin": "separate pinned PMH1 fixture, not untrusted packet metadata",
            "pin_scope": "previously recorded fixture identity; full scalar verification reruns here",
        },
        "profile": mu.PROFILE.decode("ascii"),
        "relation_parameters": mu.RELATION_PARAMETERS.hex(),
        "original": {
            "nonce": context.nonce, "units": original.units,
            "ticket": original.ticket.hex(), "identity": original.identity.hex(),
            "credit": original.credit, "duplicate_added_credit": duplicate_credit,
        },
        "hybrid": {
            "nonce": changed.nonce, "unit_0_source_nonce": context.nonce,
            "unit_1_source_nonce": changed.nonce,
            "packet_sha256": _sha256(hybrid), "ticket": inspected.ticket.hex(),
            "outputs_root": inspected.outputs_root.hex(), "identity": inspected.identity.hex(),
            "stale_unit_rejection": stale_unit_error, "complete_rejection": full_error,
            "counter_rejection": counter_error, "counter_credit_after_rejection": book.total_credit,
            "nonce_selection": "fixed reproducible control; actual outer predicate must pass",
        },
        "source_sha256": {name: _sha256((ROOT / name).read_bytes()) for name in sources},
        "artifact_manifest": {
            name: {"sha256": _sha256(raw), "bytes": len(raw)}
            for name, raw in artifacts.items()
        },
        "interpretation": {
            "observed": "same-context regeneration is identical; changing the global nonce invalidates the retained full unit proof",
            "legal_prepared_AB_reuse": "observed and permitted",
            "other_preprocessing_batching_or_quantum_costs": "open; no minimum-cost conclusion",
            "whole_context_nonce_bank": "prior preparation for each different context must remain in lifecycle accounting",
            "hash_binding": "assumed for generalization; not proved by fixture checks",
            "native_backend": "not executed; this probe explicitly uses the complete scalar MU1 verifier",
            "synthetic_MDP_mapping": "none claimed",
        },
        **QUALIFICATIONS,
    }
    return report, artifacts


def write_evidence(output: Path, report: dict[str, object], artifacts: dict[str, bytes]) -> None:
    """Exclusive creation preserves previous observations and refuses reruns."""
    _need(not output.exists() and not output.is_symlink(), "OUTPUT_DIRECTORY_MUST_BE_NEW")
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in artifacts.items():
        with (output / name).open("xb") as handle:
            handle.write(raw)
    with (output / "report.json").open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="explicit full verification mode (also the default; exports always check)")
    parser.add_argument("--out", type=Path, metavar="NEW_DIR",
                        help="also save verified inputs, rejected hybrid, contexts and report in a new directory")
    args = parser.parse_args()
    try:
        if args.out is not None:
            _need(not args.out.exists() and not args.out.is_symlink(), "OUTPUT_DIRECTORY_MUST_BE_NEW")
        # --check explicitly names the default mode. Evidence export always
        # executes exactly the same complete checks; there is no unchecked mode.
        report, artifacts = run_probe()
        if args.out is not None:
            write_evidence(args.out, report, artifacts)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"schema": SCHEMA, "result": "FAIL",
                          "error_type": type(error).__name__, "error": str(error),
                          **QUALIFICATIONS}, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
