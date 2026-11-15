"""Required native LQC1 experiment; missing native executables are errors.

The deterministic experiment is a dispatch/cache binding check. It does not
estimate p, prove global query coverage, or instantiate a physical work tail.
Every candidate, losing ticket, native invocation and negative is retained.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
from fractions import Fraction
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

from bounded_process import ProcessFailure
import mandatory_units_relation as mu
from mandatory_units_query import QueryBudget, quantum_weight_bound
from mandatory_units_vectors import dense_values, label, make_context
from lifecycle_query_bound import (LifetimeCaps, UNATTESTED,
                                  continuation_given_complete_prefix,
                                  global_lifecycle_weight_bound)
from lifecycle_query_runtime import ReferenceQueryOwner, terminal_address_without_ticket
import lifecycle_query_tests


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SOURCE_FILES = (
    "lifecycle_query_bound.py", "lifecycle_query_runtime.py", "lifecycle_query_tests.py",
    "lifecycle_query_evidence.py", "lifecycle_query_charging_v1.md",
    "mandatory_units_relation.py", "mandatory_units_query.py", "mandatory_units_vectors.py",
    "work_oracle.py", "contract_wire.py", "bounded_process.py",
)


def public(value):
    if type(value) is Fraction:
        return {"numerator": value.numerator, "denominator": value.denominator}
    if type(value) is dict:
        return {key: public(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [public(item) for item in value]
    return value


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(public(value), sort_keys=True, indent=2, allow_nan=False) + "\n")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@contextmanager
def native_recording(out: Path):
    original = mu.run_bounded
    calls = []

    def recorded(argv, payload, **kwargs):
        index = len(calls) + 1
        directory = out / "native-calls" / f"{index:04d}"
        directory.mkdir(parents=True, exist_ok=False)
        (directory / "stdin.bin").write_bytes(payload)
        row = {"index": index, "binary": str(argv[0]), "mode": argv[1],
               "stdin_sha256": hashlib.sha256(payload).hexdigest(), "stdin_bytes": len(payload)}
        calls.append(row)
        started = time.monotonic_ns()
        try:
            result = original(argv, payload, **kwargs)
            (directory / "stdout.bin").write_bytes(result.stdout)
            (directory / "stderr.bin").write_bytes(result.stderr)
            row.update(returncode=result.returncode, stdout_bytes=len(result.stdout),
                       stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                       stderr_sha256=hashlib.sha256(result.stderr).hexdigest(),
                       exchange_status="COMPLETE" if result.returncode == 0 else "COMPLETE_REJECTION")
            return result
        except ProcessFailure as error:
            (directory / "stdout.bin").write_bytes(error.stdout)
            (directory / "stderr.bin").write_bytes(error.stderr)
            row.update(exception=type(error).__name__, error=str(error), exchange_status="FAILED",
                       returncode=error.returncode, stdin_written=error.stdin_written,
                       stdout_bytes=len(error.stdout), stdout_truncated=error.stdout_truncated,
                       stderr_truncated=error.stderr_truncated,
                       stdout_sha256=hashlib.sha256(error.stdout).hexdigest(),
                       stderr_sha256=hashlib.sha256(error.stderr).hexdigest())
            raise
        except Exception as error:
            row.update(exception=type(error).__name__, error=str(error), exchange_status="FAILED")
            raise
        finally:
            row["elapsed_ns_observed_not_a_lower_bound"] = time.monotonic_ns() - started
            write_json(directory / "observation.json", row)

    mu.run_bounded = recorded
    try:
        yield calls
    finally:
        mu.run_bounded = original
        write_json(out / "native-calls.json", calls)


def expected_refusal(name: str, action, code: str) -> dict:
    try:
        action()
    except ValueError as error:
        if str(error) != code:
            raise AssertionError((name, str(error), code)) from error
        return {"name": name, "observed_refusal": code, "passed": True}
    raise AssertionError("NEGATIVE_ACCEPTED: " + name)


@contextmanager
def preserve_reference_observations(out: Path, owner, attempts, controls):
    try:
        yield
    finally:
        # Preserve partial state even if a native call or later assertion fails.
        write_json(out / "attempts.json", attempts)
        write_json(out / "controls.json", controls)
        write_json(out / "reference-events.json", owner.events)
        write_json(out / "reference-emissions.json", owner.emissions)
        write_json(out / "reference-report.json", owner.report())


def run(out: Path) -> dict:
    binaries = {}
    for env in ("LQC_NATIVE_WORK", "LQC_NATIVE_PREPARED"):
        value = os.environ.get(env)
        if not value or not Path(value).is_file() or not os.access(value, os.X_OK):
            raise ValueError("REQUIRED_NATIVE_EXECUTABLE: " + env)
        binaries[env] = Path(value).resolve()
    binaries_before = {key: {"path": str(path), "sha256": digest(path)}
                       for key, path in binaries.items()}
    write_json(out / "native-binaries-before.json", binaries_before)
    source_before = {str((HERE / name).relative_to(ROOT)): digest(HERE / name) for name in SOURCE_FILES}
    write_json(out / "source-manifest-before.json", source_before)

    test_log = io.StringIO()
    tests = unittest.TextTestRunner(stream=test_log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(lifecycle_query_tests))
    (out / "tests.log").write_text(test_log.getvalue())
    if not tests.wasSuccessful():
        raise AssertionError("FINITE_TEST_FAILURE")

    material = mu.PreparedMatrices(dense_values("A"), dense_values("B"))
    base = make_context((material.task,))
    caps = LifetimeCaps(8, 1, 10)
    owner = ReferenceQueryOwner("lqc1-fixed-mu1-native-prefix-cache-example", caps)
    work, prepared = str(binaries["LQC_NATIVE_WORK"]), str(binaries["LQC_NATIVE_PREPARED"])
    attempts, stored, controls = [], [], []
    packets_dir = out / "packets"
    packets_dir.mkdir()

    def candidate(nonce: int):
        context = replace(base, nonce=nonce)
        row = {"nonce": nonce, "reference_phase": owner.phase, "status": "started"}
        attempts.append(row)
        write_json(out / "attempts.json", attempts)
        (packets_dir / f"nonce-{nonce:02d}.context").write_bytes(mu.encode_context(context))
        packet = mu.produce_packet(context, (material,), backend="native-prepared",
                                   native_prover=prepared)
        (packets_dir / f"nonce-{nonce:02d}.pmu1").write_bytes(packet)
        address = terminal_address_without_ticket(packet, context)
        with owner.intercept_frozen_terminal("producer-terminal-query"):
            inspected = mu.inspect_packet(packet, context)
        if (address.context_digest, address.ordered_root, address.identity) != (
                inspected.context_hash, inspected.outputs_root, inspected.identity):
            raise AssertionError("FROZEN_EXTRACTOR_DISAGREES")
        emission = owner.emit_native(packet, context, work)
        if emission["reason"] not in ("VALID_MU1", "AGGREGATE_TARGET"):
            raise AssertionError("FULL_NATIVE_UNIT_FAILURE: " + repr(emission))
        row.update({"status": "completed",
               "packet_sha256": hashlib.sha256(packet).hexdigest(),
               "context_digest": address.context_digest.hex(),
               "ordered_root": address.ordered_root.hex(), "identity": address.identity.hex(),
               "ticket": inspected.ticket.hex(), "winner": inspected.ticket <= mu.T0,
               "constructed_complete_native_units": 1, "emission": emission})
        stored.append((context, packet, address, row))
        write_json(out / "attempts.json", attempts)

    with native_recording(out) as calls, preserve_reference_observations(out, owner, attempts, controls):
        # Fixed before this reference execution; no stopping at the first hit.
        for nonce in range(8):
            candidate(nonce)
        winners = [item for item in stored if item[3]["winner"]]
        if not winners or winners[0][0].nonce != 6:
            raise AssertionError("FROZEN_DENSE_U1_VECTOR_CHANGED")
        winner_context, winner_packet, winner_address, _ = winners[0]
        owner.begin_post_prefix()
        ref = owner.reference(winner_address.context_digest, winner_address.ordered_root)
        before = owner.total_credit
        owner.read_reference(ref, "public-helper-cache-transfer")
        duplicate = owner.emit_native(winner_packet, winner_context, work, "helper-republication")
        if not duplicate["accepted"] or duplicate["credit_added"] != 0 or owner.total_credit != before:
            raise AssertionError("DUPLICATE_CREDIT")
        controls.append({"name": "helper-republication-keeps-paid-origin-adds-zero-credit",
                         "passed": True, "emission": duplicate})
        # All later callers, including a newly joined helper, share Q.
        candidate(8)
        fresh = mu.produce_packet(winner_context, (material,), backend="native-fresh",
                                 native_prover=work)
        if fresh != winner_packet:
            raise AssertionError("NATIVE_FRESH_PREPARED_BYTE_DIVERGENCE")
        controls.append({"name": "native-fresh-equals-native-prepared-complete-packet",
                         "passed": True, "packet_sha256": hashlib.sha256(fresh).hexdigest()})

        # Separate, explicitly invalid fixture scope; never added to a fresh
        # lifetime probability assertion or merged into the main owner's C.
        bad_proof = winner_packet[-mu.w1.PROOF_BYTES:]
        bad_proof = bad_proof[:-1] + bytes([bad_proof[-1] ^ 1])
        bad_packet = mu.encode_packet(winner_context, (bad_proof,))
        invalid_owner = ReferenceQueryOwner("lqc1-invalid-full-trace-control", LifetimeCaps(1, 0, 1))
        invalid = invalid_owner.emit_native(bad_packet, winner_context, work)
        (packets_dir / "invalid-trace.pmu1").write_bytes(bad_packet)
        if invalid["accepted"] or invalid["reason"] != "NATIVE_W1_INVALID":
            raise AssertionError("INVALID_FULL_TRACE_ACCEPTED")
        controls.append({"name": "complete-native-transcript-mutation-rejected",
                         "passed": True, "emission": invalid})
        write_json(out / "invalid-control-events.json", invalid_owner.events)

        before_hashes = owner.hash_evaluations
        controls.append(expected_refusal("post-cap-before-hash",
            lambda: owner.query(label("unseen-after-Q-cap"), label("root"), "late-helper"), "QUERY_CAP"))
        if owner.hash_evaluations != before_hashes:
            raise AssertionError("DENIED_QUERY_EXECUTED")
        controls.append(expected_refusal("global-output-cap-includes-duplicate",
            lambda: owner.emit_native(winner_packet, winner_context, work), "OUTPUT_CAP"))
        controls.append(expected_refusal("phase-cannot-reset", owner.begin_post_prefix,
                                         "PREFIX_ALREADY_CLOSED"))
        other = ReferenceQueryOwner("other-owner-control", LifetimeCaps(1, 0, 1))
        controls.append(expected_refusal("foreign-paid-cache-refused",
            lambda: other.read_reference(ref), "FOREIGN_CACHE_SCOPE"))
        restarted = ReferenceQueryOwner(owner.scope, LifetimeCaps(1, 0, 1))
        controls.append(expected_refusal("new-owner-cannot-claim-prior-cache-origin",
            lambda: restarted.read_reference(ref), "UNOBSERVED_OR_CHANGED_CACHE_ORIGIN"))
        controls.append(expected_refusal("changed-cache-ticket-refused",
            lambda: owner.read_reference(replace(ref, ticket=bytes(32))), "UNOBSERVED_OR_CHANGED_CACHE_ORIGIN"))
        controls.append(expected_refusal("observed-dispatch-is-not-global-query-certificate",
            owner.global_budget_certificate, "GLOBAL_QUERY_CLOSURE_AND_JOINT_INITIAL_STATE_UNATTESTED"))

    report = owner.report()
    if (report["reference_prefix_distinct_calls"], report["reference_post_prefix_calls"],
            report["reference_sha256_evaluations"], report["complete_emissions_including_duplicates"]) != (8, 1, 9, 10):
        raise AssertionError("REFERENCE_COUNTERS")
    write_json(out / "reference-events.json", owner.events)
    write_json(out / "reference-emissions.json", owner.emissions)
    write_json(out / "reference-report.json", report)
    write_json(out / "controls.json", controls)

    comparisons = []
    for c, q, m in ((0, 1, 32), (8, 1, 32), (8, 1, 64), (25, 1, 64), (64, 1, 64)):
        threshold = 128 * m
        new = global_lifecycle_weight_bound(LifetimeCaps(c, q, m), threshold)
        old = quantum_weight_bound(QueryBudget(c + q, m, True, True), threshold)
        comparisons.append({"C": c, "Q": q, "M": m, "credit_threshold": threshold,
                            "new": new, "older_virtual_check_bound": old["bound"],
                            "actual_native_risk": False})
    write_json(out / "ideal-model-comparisons.json", comparisons)
    global_one = global_lifecycle_weight_bound(LifetimeCaps(1, 0, 1), 128)
    conditional_hit = continuation_given_complete_prefix(
        distinct_seen=1, marked_seen=1, post_queries=0, output_slots=1, credit=128)
    write_json(out / "global-vs-conditional-negative.json", {
        "global_bound": global_one, "conditional_at_observed_hit": conditional_hit,
        "incorrect_global_bound_as_selected_start_risk_rejected": True})
    manifest = {str((HERE / name).relative_to(ROOT)): digest(HERE / name) for name in SOURCE_FILES}
    write_json(out / "source-manifest.json", manifest)
    binaries_after = {key: {"path": str(path), "sha256": digest(path)}
                      for key, path in binaries.items()}
    write_json(out / "native-binaries-after.json", binaries_after)
    if manifest != source_before:
        raise AssertionError("SOURCE_CHANGED_DURING_RUN")
    if binaries_after != binaries_before:
        raise AssertionError("NATIVE_BINARY_CHANGED_DURING_RUN")
    baseline = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                              text=True, capture_output=True).stdout.strip()
    return {"schema": "pon-lifecycle-query-native-evidence-v1", "result": "PASS",
            "baseline_git_anchor_not_a_claim_all_new_files_are_committed": baseline,
            "source_manifest_sha256": digest(out / "source-manifest.json"),
            "python": sys.version, "native_binaries": binaries_before,
            "native_binary_hashes_before_after_match": True,
            "source_hashes_before_after_match": True,
            "hash_samples_are_not_execution_attestation": True,
            "finite_tests_run": tests.testsRun, "finite_test_failures": len(tests.failures),
            "finite_test_errors": len(tests.errors),
            "complete_candidates": len(attempts),
            "winning_candidates": sum(row["winner"] for row in attempts),
            "losing_candidates_retained": sum(not row["winner"] for row in attempts),
            "native_calls": len(calls), "native_successes": sum(row.get("returncode") == 0 for row in calls),
            "native_expected_invalid_calls": sum(row.get("returncode") == 2 for row in calls),
            "native_modes": {mode: sum(row["mode"] == mode for row in calls)
                             for mode in sorted({row["mode"] for row in calls})},
            "controls_passed": len(controls), "reference_report": report,
            "full_frozen_MU1_bytes_unchanged": True,
            "empirical_hit_rate_is_not_p_or_a_risk_estimate": True,
            "all_failed_and_nonwinning_attempts_retained": True,
            **UNATTESTED}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New directory; existing evidence is never overwritten.")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    try:
        result = run(args.out)
    except Exception as error:
        write_json(args.out / "summary.json", {"result": "FAIL", "error_type": type(error).__name__,
                   "error": str(error), "retained_partial_observations": True, **UNATTESTED})
        raise
    write_json(args.out / "summary.json", result)
    print(json.dumps({"result": result["result"], "finite_tests": result["finite_tests_run"],
                      "native_calls": result["native_calls"], "controls": result["controls_passed"],
                      "summary": str(args.out / "summary.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
