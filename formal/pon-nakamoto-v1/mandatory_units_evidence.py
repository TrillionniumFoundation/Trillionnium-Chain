"""Reproduce complete MU1 evidence using required, real existing native examples.

The runner retains every nonce attempt and every native child exchange.  It
never substitutes a successful Python receipt for an unavailable native child.
Output files are created exclusively so a rerun cannot erase observations.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import time
import traceback

import mandatory_units_query as query
import mandatory_units_relation as mu
import mandatory_units_vectors as vectors


ROOT = Path(__file__).resolve().parents[2]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_value(value):
    if isinstance(value, Fraction):
        return {"numerator": value.numerator, "denominator": value.denominator,
                "decimal_approximation": float(value)}
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    return value


def save_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(json_value(value), handle, indent=2, sort_keys=True)
        handle.write("\n")


def save_bytes(path: Path, value: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(value)


def source_manifest() -> dict[str, str]:
    files = [
        "formal/pon-nakamoto-v1/MANDATORY_UNITS_RELATION_V1.md",
        "formal/pon-nakamoto-v1/mandatory_units_relation.py",
        "formal/pon-nakamoto-v1/mandatory_units_query.py",
        "formal/pon-nakamoto-v1/mandatory_units_vectors.py",
        "formal/pon-nakamoto-v1/mandatory_units_tests.py",
        "formal/pon-nakamoto-v1/mandatory_units_evidence.py",
        "formal/pon-nakamoto-v1/work_oracle.py",
        "formal/pon-nakamoto-v1/contract_wire.py",
        "formal/pon-nakamoto-v1/bounded_process.py",
        "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
        "trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs",
        "trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_io.rs",
    ]
    return {name: digest((ROOT / name).read_bytes()) for name in files}


def expect_rejection(raw: bytes, context: mu.Context, backend: str,
                     native: Path, expected: str) -> str:
    try:
        mu.verify_packet(raw, context, backend=backend, native_verifier=native)
    except mu.RelationError as error:
        if str(error) != expected:
            raise AssertionError((backend, str(error), expected)) from error
        return str(error)
    raise AssertionError("INVALID_PACKET_ACCEPTED: " + backend)


def run(native: Path, prepared: Path, output: Path) -> dict[str, object]:
    if not native.is_file() or not prepared.is_file():
        raise ValueError("REQUIRED_NATIVE_BRIDGE_UNAVAILABLE")
    output.mkdir(parents=True, exist_ok=True)
    calls, phase = [], "initial"
    original = mu.run_bounded
    with (output / "native_calls.jsonl").open("x", encoding="utf-8") as call_log:
        def observe(argv, data, **options):
            record = {"index": len(calls), "phase": phase, "argv": argv,
                      "stdin_length": len(data), "stdin_sha256": digest(data)}
            start = time.monotonic_ns()
            try:
                result = original(argv, data, **options)
            except Exception as error:
                record.update(exception_type=type(error).__name__, exception=str(error),
                              elapsed_ns_observation=time.monotonic_ns() - start)
                calls.append(record)
                call_log.write(json.dumps(record, sort_keys=True) + "\n")
                call_log.flush()
                raise
            record.update(returncode=result.returncode, stdout_length=len(result.stdout),
                          stdout_sha256=digest(result.stdout), stderr_length=len(result.stderr),
                          stderr_utf8=result.stderr.decode("utf-8", "replace"),
                          elapsed_ns_observation=time.monotonic_ns() - start)
            calls.append(record)
            call_log.write(json.dumps(record, sort_keys=True) + "\n")
            call_log.flush()
            return result

        mu.run_bounded = observe
        try:
            material = vectors.materials()
            definitions = [(f"dense-repeat-u{u}", (material["dense"],) * u)
                           for u in (1, 2, 4, 8)]
            definitions.append(("mixed-dense-zero-u2", (material["dense"], material["zero"])))
            rows, positives, unit_tickets = [], [], []
            for name, items in definitions:
                phase = "nonce-search/" + name
                vector = vectors.mine_vector(name, items, native_prepared=prepared)
                rows.append(vector)
                save_json(output / (name + "-nonce-attempts.json"), {
                    "stopping_rule": "first aggregate winner, at most 256 sequential nonces",
                    "statistical_estimate_of_sha_success_probability": False,
                    "attempts": vector.attempts,
                })
                save_bytes(output / (name + ".pmu1"), vector.packet)
                save_bytes(output / (name + ".pmh1"), mu.encode_context(vector.context))
                parsed = mu.inspect_packet(vector.packet, vector.context)
                phase = "verify-winning-envelope/" + name
                scalar = mu.verify_packet(vector.packet, vector.context)
                native_result = mu.verify_packet(vector.packet, vector.context,
                                                 backend="native", native_verifier=native)
                if scalar != native_result:
                    raise AssertionError("SCALAR_NATIVE_ACCEPTANCE_DISAGREEMENT")
                encodings = {}
                for backend, path in (("scalar-fresh", None), ("scalar-prepared", None),
                                      ("native-fresh", native), ("native-prepared", prepared)):
                    phase = backend + "/" + name
                    raw = mu.produce_packet(vector.context, vector.material, backend=backend,
                                             native_prover=path)
                    if raw != vector.packet:
                        raise AssertionError("NONUNIQUE_PRODUCER_ENCODING: " + name + "/" + backend)
                    encodings[backend] = digest(raw)
                positives.append({
                    "name": name, "units": vector.context.units, "credit": scalar.credit,
                    "packet_length": len(vector.packet), "packet_sha256": digest(vector.packet),
                    "context_hex": mu.encode_context(vector.context).hex(),
                    "context_hash": parsed.context_hash.hex(),
                    "outputs_root": parsed.outputs_root.hex(), "ticket": parsed.ticket.hex(),
                    "identity": parsed.identity.hex(), "winning_nonce": vector.context.nonce,
                    "attempt_count": len(vector.attempts),
                    "scalar_and_native_full_relation_verified": True,
                    "four_producer_encodings": encodings,
                })
                for index, proof in enumerate(parsed.proofs):
                    ticket = mu.w1_hash("ticket", mu.unit_challenge(vector.context, index), proof[-32:])
                    unit_tickets.append({"vector": name, "index": index, "ticket": ticket.hex(),
                                         "would_fail_if_unit_had_aggregate_target": ticket > mu.T0})

            controls = []
            for name, context, raw, scalar_reason in vectors.mutations(rows[1]):
                phase = "negative-control/" + name
                native_reason = "NATIVE_W1_INVALID" if scalar_reason.startswith("W1_") else scalar_reason
                controls.append({
                    "name": name, "packet_sha256": digest(raw),
                    "scalar_refusal": expect_rejection(raw, context, "scalar", native, scalar_reason),
                    "native_refusal": expect_rejection(raw, context, "native", native, native_reason),
                })

            # Rebind both expected context and on-wire context to avoid getting
            # a cheap expected-context refusal instead of testing the W1 trace.
            for name, vector, context, proofs in (
                ("u8-prefix-rebound-as-u4", rows[3], replace(rows[3].context, tasks=rows[3].context.tasks[:4]),
                 mu.inspect_packet(rows[3].packet, rows[3].context).proofs[:4]),
                ("task-order-rebound", rows[4], replace(rows[4].context, tasks=tuple(reversed(rows[4].context.tasks))),
                 tuple(reversed(mu.inspect_packet(rows[4].packet, rows[4].context).proofs))),
            ):
                phase = "negative-control/" + name
                raw = mu.encode_packet(context, proofs)
                controls.append({"name": name, "packet_sha256": digest(raw),
                                 "scalar_refusal": expect_rejection(raw, context, "scalar", native, "W1_TRANSCRIPT"),
                                 "native_refusal": expect_rejection(raw, context, "native", native, "NATIVE_W1_INVALID")})

            phase = "negative-control/outer-winning-false-transcript"
            vector = rows[1]
            original_proof = mu.inspect_packet(vector.packet, vector.context).proofs[0]
            forged_attempts, forged = [], None
            for attempt in range(4096):
                fake_trace = mu.mu_hash(b"negative-control-false-trace", struct.pack("<I", attempt))
                raw = vectors.replace_proof(vector.packet, vector.context, 0, original_proof[:-32] + fake_trace)
                parsed = mu.inspect_packet(raw, vector.context)
                winner = parsed.ticket <= mu.T0
                forged_attempts.append({"attempt": attempt, "trace": fake_trace.hex(),
                                        "ticket": parsed.ticket.hex(), "outer_winner": winner,
                                        "packet_sha256": digest(raw)})
                if winner:
                    forged = raw
                    break
            save_json(output / "false-trace-search.json", forged_attempts)
            if forged is None:
                raise AssertionError("BOUNDED_NEGATIVE_SEARCH_EXHAUSTED")
            controls.append({"name": "outer-winning-false-transcript", "packet_sha256": digest(forged),
                             "outer_ticket_passes": True,
                             "scalar_refusal": expect_rejection(forged, vector.context, "scalar", native, "W1_TRANSCRIPT"),
                             "native_refusal": expect_rejection(forged, vector.context, "native", native, "NATIVE_W1_INVALID")})

            phase = "negative-control/complete-units-losing-aggregate"
            missed = next(row for row in vector.attempts if not row["winner"])
            context = replace(vector.context, nonce=missed["nonce"])
            loser = mu.produce_packet(context, vector.material, backend="native-prepared", native_prover=prepared)
            if digest(loser) != missed["packet_sha256"]:
                raise AssertionError("NONCE_REPLAY_BYTES_CHANGED")
            controls.append({"name": "complete-units-losing-aggregate", "packet_sha256": digest(loser),
                             "all_units_verified_before_aggregate_refusal": True,
                             "scalar_refusal": expect_rejection(loser, context, "scalar", native, "AGGREGATE_TARGET"),
                             "native_refusal": expect_rejection(loser, context, "native", native, "AGGREGATE_TARGET")})

            phase = "all-branch-unique-counter"
            book = mu.UniqueWorkCounter()
            increments = [book.admit(rows[index].packet, rows[index].context) for index in (1, 1, 0)]
            if increments != [32, 0, 16] or book.total_credit != 48:
                raise AssertionError("DUPLICATE_CREDIT")
            parsed = mu.inspect_packet(rows[1].packet, rows[1].context)
            preparation = {
                "same_prepared_object_reused": rows[1].material[0] is rows[1].material[1],
                "A_B_product_prefix_byte_identical": parsed.proofs[0][:-32] == parsed.proofs[1][:-32],
                "challenge_specific_full_traces_distinct": parsed.proofs[0][-32:] != parsed.proofs[1][-32:],
                "minimum_cost_inferred": False,
            }
            examples = [query.quantum_weight_bound(query.QueryBudget(q, m, True, True), credit)
                        for q, m, credit in ((0, 0, 0), (0, 1, 128), (0, 8, 1024),
                                             (1, 32, 4096), (1, 3, 385))]
            residual = {
                "fresh_32": query.residual_bernoulli_bound(34, 32, (Fraction(1),) + (Fraction(0),) * 32),
                "unrestricted_32": query.residual_bernoulli_bound(34, 32, (Fraction(1),) * 33),
                "known_winner_zero_online_queries": query.residual_bernoulli_bound(
                    0, 1, (Fraction(1), Fraction(15, 16))),
            }
            save_json(output / "query_bounds.json", {"fresh_examples": examples, "residual_interfaces": residual})
            save_json(output / "positive_vectors.json", positives)
            save_json(output / "negative_controls.json", controls)
            save_json(output / "unit_ticket_controls.json", unit_tickets)
            summary = {
                "result": "PASS", "profile": mu.PROFILE.decode("ascii"),
                "relation_parameters": mu.RELATION_PARAMETERS.hex(),
                "source_sha256": source_manifest(),
                "native_binary_sha256": {str(native): digest(native.read_bytes()), str(prepared): digest(prepared.read_bytes())},
                "actual_native_child_exchanges_this_evidence_run": len(calls),
                "native_child_successes": sum(row.get("returncode") == 0 for row in calls),
                "native_child_expected_nonzero_rejections": sum(row.get("returncode", 0) != 0 for row in calls),
                "native_calls_by_mode": {mode: sum(row["argv"][1] == mode for row in calls)
                                         for mode in ("prove", "generic", "verify")},
                "whole_MU1_winning_positive_vectors": len(rows),
                "whole_envelope_negative_controls": len(controls),
                "nonce_attempts_including_all_losses": sum(len(row.attempts) for row in rows),
                "nonce_search_complete_units_constructed": sum(len(row.attempts) * row.context.units for row in rows),
                "aggregate_winners": len(rows),
                "observed_stopped_fixture_fraction": Fraction(len(rows), sum(len(row.attempts) for row in rows)),
                "statistical_probability_or_independence_estimate": False,
                "subunit_tickets_above_T0_in_valid_envelopes": sum(row["would_fail_if_unit_had_aggregate_target"] for row in unit_tickets),
                "dedup_increments": increments, "dedup_total": book.total_credit,
                "preparation_reuse": preparation, "claims": mu.CLAIMS,
                "query_initial_state_certificate_for_actual_W1": False,
                "elapsed_native_ns_are_minimum_cost_certificate": False,
                "test_execution_count_not_included_in_child_exchange_count": True,
            }
            save_json(output / "summary.json", summary)
            return summary
        except Exception as error:
            save_json(output / "failure.json", {"result": "FAIL", "phase": phase,
                                                "error": str(error), "type": type(error).__name__,
                                                "traceback": traceback.format_exc(),
                                                "native_calls_observed": len(calls)})
            raise
        finally:
            mu.run_bounded = original


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-work", type=Path, required=True)
    parser.add_argument("--native-prepared", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary = run(args.native_work.resolve(), args.native_prepared.resolve(), args.out)
    print(json.dumps({key: summary[key] for key in (
        "result", "actual_native_child_exchanges_this_evidence_run",
        "whole_MU1_winning_positive_vectors", "whole_envelope_negative_controls",
        "nonce_attempts_including_all_losses", "nonce_search_complete_units_constructed")}, sort_keys=True))


if __name__ == "__main__":
    main()
