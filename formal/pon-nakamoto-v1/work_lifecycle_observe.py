"""Actual W1 observations and public-receipt counterexamples for WLC1.

This records real existing native child calls and imports real frozen MU1
packets.  It never records a native call for the public-digest counterexample.
Private ML-DSA keys are generated in memory and never serialized or exported.
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

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from bounded_process import run_bounded
import mandatory_units_relation as mu
import work_lifecycle_certificate as wlc
from work_lifecycle_help import HelpPolicy, HelpSlot, finite_help_weight_bound


ROOT = Path(__file__).resolve().parents[2]
BASE_COMMIT = "f8362822b406463ac3dfcc911a0c3eda1686e32d"
FROZEN_EVIDENCE = ROOT / "evidence/pon-work-native-certificates-20261107/mandatory_units/run-02-final"
SOURCE_FILES = (
    "formal/pon-nakamoto-v1/work_lifecycle_certificate.py",
    "formal/pon-nakamoto-v1/work_lifecycle_help.py",
    "formal/pon-nakamoto-v1/work_lifecycle_observe.py",
    "formal/pon-nakamoto-v1/work_lifecycle_tests.py",
    "formal/pon-nakamoto-v1/WORK_LIFECYCLE_CERTIFICATE_V1.md",
    "formal/pon-nakamoto-v1/mandatory_units_relation.py",
    "formal/pon-nakamoto-v1/mandatory_units_query.py",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "formal/pon-nakamoto-v1/bounded_process.py",
    "trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs",
    "trillionnium/crates/trnm-crypto-primitives/examples/pq_message_oracle.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs",
)


def put(artifacts: dict[str, bytes], raw: bytes) -> str:
    digest = wlc.sha256(raw)
    if digest in artifacts and artifacts[digest] != raw:
        raise ValueError("ARTIFACT_DIGEST_COLLISION")
    artifacts[digest] = raw
    return digest


def public_receipt_without_verification(data: bytes) -> bytes:
    """The existing receipt is public hashing, with NO native/W1 invocation."""
    return mu.w1_hash("native-work-verification", data)


def mu1_observation(context: mu.Context, raw: bytes, artifacts: dict[str, bytes]) -> dict:
    parsed = mu.inspect_packet(raw, context)
    try:
        mu.verify_packet(raw, context)
        result, refusal = "accepted", None
    except mu.RelationError as error:
        result, refusal = "rejected", str(error)
    return {"context_sha256": put(artifacts, mu.encode_context(context)),
            "packet_sha256": put(artifacts, raw), "context_digest": parsed.context_hash.hex(),
            "ordered_root": parsed.outputs_root.hex(), "ticket": parsed.ticket.hex(),
            "identity": parsed.identity.hex(), "units": context.units,
            "result": result, "refusal": refusal}


def capture_call(writer: wlc.ObservationWriter, native: Path, mode: str, data: bytes,
                 artifacts: dict[str, bytes], calls: list[dict], journal=None) -> object:
    wlc.need(native.is_file(), "REQUIRED_NATIVE_W1_UNAVAILABLE")
    start = time.monotonic_ns()
    try:
        result = run_bounded([str(native), mode], data, timeout=30,
                             stdout_limit=mu.w1.PROOF_BYTES, stderr_limit=4096)
    except Exception as error:
        if journal is not None:
            journal({"mode": mode, "input_sha256": put(artifacts, data),
                     "exception": type(error).__name__, "error": str(error)}, artifacts)
        raise
    elapsed = time.monotonic_ns() - start
    body = {"mode": mode, "program_sha256": wlc.sha256(native.read_bytes()),
            "input_sha256": put(artifacts, data), "input_bytes": len(data),
            "output_sha256": put(artifacts, result.stdout), "output_bytes": len(result.stdout),
            "stderr_sha256": put(artifacts, result.stderr), "stderr_bytes": len(result.stderr),
            "returncode": result.returncode}
    event = writer.append("native_call", body)
    writer.append("resource_reading", {"quantity": "elapsed_ns", "value": elapsed,
                                       "bound_direction": "observation_only"})
    record = {"event_hash": event, "body": body, "stderr_utf8": result.stderr.decode("utf-8", "replace"),
              "elapsed_ns_observation": elapsed}
    calls.append(record)
    if journal is not None:
        journal(record, artifacts)
    return result


def collect(native: Path, *, include_document_sources: bool = True, journal=None) -> dict:
    """One pre-existing complete MU1 winner flows through two signed observers.

    The source's imported stock is expressly unmetered.  Actual validation is
    performed and recorded, but cannot turn that stock into fresh generation.
    """
    wlc.need(native.is_file(), "REQUIRED_NATIVE_W1_UNAVAILABLE")
    paths = SOURCE_FILES if include_document_sources else tuple(
        p for p in SOURCE_FILES if (ROOT / p).is_file())
    manifest = {p: wlc.sha256((ROOT / p).read_bytes()) for p in paths}
    manifest["native/pon_work_io"] = wlc.sha256(native.read_bytes())
    raw = (FROZEN_EVIDENCE / "dense-repeat-u2.pmu1").read_bytes()
    context_raw = (FROZEN_EVIDENCE / "dense-repeat-u2.pmh1").read_bytes()
    context = mu.decode_context(context_raw)
    parsed = mu.inspect_packet(raw, context)
    artifacts, calls = {}, []
    packet_digest, context_digest = put(artifacts, raw), put(artifacts, context_raw)
    source_key = MLDSA65PrivateKey.generate()
    receiver_key = MLDSA65PrivateKey.generate()
    source = wlc.ObservationWriter(
        source_key, session=wlc.sha256(b"WLC1 actual-source observation"), source_commit=BASE_COMMIT,
        source_manifest=manifest, help_policy=HelpPolicy(()))
    for digest in (packet_digest, context_digest):
        source.append("unmetered_import", {"source": "frozen-prior-MU1-evidence",
                                           "artifact_sha256": digest, "artifact_bytes": len(artifacts[digest]),
                                           "state_kind": "classical"})
    valid_inputs = []
    for index, proof in enumerate(parsed.proofs):
        data = mu.unit_challenge(context, index) + context.tasks[index] + mu.UNIT_TARGET + proof
        valid_inputs.append(data)
        result = capture_call(source, native, "verify", data, artifacts, calls, journal)
        wlc.need(result.returncode == 0 and result.stdout == public_receipt_without_verification(data),
                 "NATIVE_POSITIVE_CONTROL")
    source.append("mu1_observation", mu1_observation(context, raw, artifacts))
    published = source.append("publish_artifact", {"artifact_sha256": packet_digest,
                                                   "artifact_bytes": len(raw), "role": "complete_mu1_packet"})
    source_doc, source_pin = source.close()

    policy = HelpPolicy((HelpSlot(("public-helper",), 4, len(raw), 2),))
    receiver = wlc.ObservationWriter(
        receiver_key, session=wlc.sha256(b"WLC1 actual-receiver observation"), source_commit=BASE_COMMIT,
        source_manifest=manifest, help_policy=policy)
    receiver.append("help_delivery", {
        "delivery": {"slot": 0, "status": "data", "source": "public-helper", "delivery_bin": 2,
                     "payload_bytes": len(raw), "error_code": None},
        "payload_sha256": packet_digest,
        "source_reference": {"label": "public-helper", "header_digest": source_pin.header_digest,
                             "end_sequence": source_pin.end.sequence, "end_head": source_pin.end.head,
                             "publish_event": published},
    })
    for data in valid_inputs:
        result = capture_call(receiver, native, "verify", data, artifacts, calls, journal)
        wlc.need(result.returncode == 0, "NATIVE_IMPORTED_WORK_CONTROL")
    receiver.append("mu1_observation", mu1_observation(context, raw, artifacts))

    # Public recomputation does not execute the native program or the W1 check.
    before_public_recomputation = len(calls)
    valid_receipt = public_receipt_without_verification(valid_inputs[0])
    invalid = valid_inputs[0][:-1] + bytes([valid_inputs[0][-1] ^ 1])
    forged_invalid_receipt = public_receipt_without_verification(invalid)
    after_public_recomputation = len(calls)
    wlc.need(before_public_recomputation == after_public_recomputation,
             "PUBLIC_RECOMPUTATION_MUST_NOT_CALL_NATIVE")
    rejected = capture_call(receiver, native, "verify", invalid, artifacts, calls, journal)
    wlc.need(rejected.returncode == 2 and rejected.stderr == b"WORK\n", "NATIVE_NEGATIVE_CONTROL")
    put(artifacts, forged_invalid_receipt)
    receiver_doc, receiver_pin = receiver.close()
    documents = {"public-helper": source_doc, "receiver": receiver_doc}
    pins = {"public-helper": source_pin, "receiver": receiver_pin}
    verified = wlc.verify_collection(documents, pins, artifacts, "receiver")

    tag = b"ticket"
    terminal_frame = (mu.DOMAIN + struct.pack("<H", len(tag)) + tag
                      + struct.pack("<I", 32) + parsed.context_hash
                      + struct.pack("<I", 32) + parsed.outputs_root)
    wlc.need(hashlib.sha256(terminal_frame).digest() == parsed.ticket, "ACTUAL_MU1_HASH_FRAME")
    return {
        "documents": documents, "pins": pins, "artifacts": artifacts, "verified": verified,
        "calls": calls, "source_manifest": manifest, "policy": policy,
        "receipt_controls": {
            "valid_native_receipt_hex": valid_receipt.hex(),
            "valid_public_recomputation_matches_real_native_stdout": valid_receipt == artifacts[calls[0]["body"]["output_sha256"]],
            "native_calls_during_public_receipt_recomputation": after_public_recomputation - before_public_recomputation,
            "invalid_input_sha256": put(artifacts, invalid),
            "invalid_input_public_receipt_hex": forged_invalid_receipt.hex(),
            "invalid_public_receipt_is_well_formed": len(forged_invalid_receipt) == 32,
            "real_native_invalid_returncode": rejected.returncode,
            "real_native_invalid_stderr": rejected.stderr.decode("ascii"),
            "receipt_alone_authenticates_execution": False,
        },
        "hash_composition": {
            "MU1_prefix_hex": mu.DOMAIN.hex(), "W1_prefix_hex": b"TRNM-PON1\0".hex(),
            "W1_trace_prefix_hex": b"TRNM-PON-TRACE1\0".hex(),
            "terminal_frame_hex": terminal_frame.hex(), "terminal_frame_bytes": len(terminal_frame),
            "terminal_digest_hex": parsed.ticket.hex(), "actual_sha256_recomputation_matches": True,
            "MU1_domain_tags": ["parameters", "context", "unit", "unit-output", "ordered-units", "ticket", "identity"],
            "W1_domain_tags": ["task", "noise", "ticket", "native-work-verification"],
            "same_public_SHA256_primitive": True,
            "actual_domains_proved_independent_random_functions": False,
            "preprocessing_aware_composition_proved": False,
        },
        "key_handling": {"algorithm": "ML-DSA-65", "private_key_exported": False,
                         "fresh_ephemeral_keys": 2, "real_independent_trust_root": False},
    }


def native_pq_differential(path: Path, collected: dict, evidence_path: Path | None = None) -> dict:
    """Cross-check the real OpenSSL signatures using existing RustCrypto code."""
    wlc.need(path.is_file(), "REQUIRED_NATIVE_PQ_UNAVAILABLE")
    queries, labels, expected = [], [], []
    for name, doc in collected["documents"].items():
        pin = collected["pins"][name]
        for cut in ("start", "end"):
            envelope = doc[cut]
            message = wlc.checkpoint_message(envelope["statement"])
            common = {"mode": "verify", "spki": pin.public_spki.hex(), "key_id": wlc.key_id(pin.public_spki)}
            queries.append({**common, "message": message.hex(), "signature": envelope["signature"]})
            labels.append(name + "/" + cut + "/valid")
            expected.append(True)
            changed = message[:-1] + bytes([message[-1] ^ 1])
            queries.append({**common, "message": changed.hex(), "signature": envelope["signature"]})
            labels.append(name + "/" + cut + "/changed-message")
            expected.append(False)
            queries.append({**common, "message": message.hex(), "signature": bytes(3309).hex()})
            labels.append(name + "/" + cut + "/zero-signature")
            expected.append(False)
    payload = json.dumps(queries, sort_keys=True, separators=(",", ":")).encode("ascii")
    if evidence_path is not None:
        save_json(evidence_path / "native_pq_input.json", queries)
    result = run_bounded([str(path)], payload, timeout=30, stdout_limit=16384, stderr_limit=4096)
    if evidence_path is not None:
        save_json(evidence_path / "native_pq_process.json", {
            "returncode": result.returncode, "stdout_utf8": result.stdout.decode("utf-8", "replace"),
            "stderr_utf8": result.stderr.decode("utf-8", "replace")})
    wlc.need(result.returncode == 0, "NATIVE_PQ_PROCESS")
    decoded = json.loads(result.stdout)
    wlc.need(type(decoded) is list and len(decoded) == len(expected), "NATIVE_PQ_OUTPUT")
    for item, outcome in zip(decoded, expected):
        wlc.need(type(item) is dict and item == {"accepted": outcome}, "NATIVE_PQ_DISAGREEMENT")
    return {"result": "PASS", "binary_sha256": wlc.sha256(path.read_bytes()),
            "actual_native_process_exchanges": 1, "verification_items": len(expected),
            "positive_signatures": sum(expected), "negative_controls": len(expected) - sum(expected),
            "cases": [{"label": label, "accepted": value} for label, value in zip(labels, expected)],
            "stdin_sha256": wlc.sha256(payload), "stdout_sha256": wlc.sha256(result.stdout),
            "stderr_utf8": result.stderr.decode("utf-8", "replace")}


def json_value(value):
    if isinstance(value, Fraction):
        return {"numerator": value.numerator, "denominator": value.denominator,
                "decimal_approximation": float(value)}
    if isinstance(value, dict):
        return {k: json_value(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_value(v) for v in value]
    return value


def save_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as out:
        json.dump(json_value(value), out, indent=2, sort_keys=True)
        out.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-work", type=Path, required=True)
    parser.add_argument("--native-pq", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    artifact_dir = args.out / "artifacts"
    artifact_dir.mkdir()
    observed = None
    try:
        with (args.out / "native_call_journal.jsonl").open("x", encoding="utf-8") as log:
            def persist(record, artifacts):
                for digest, raw in artifacts.items():
                    path = artifact_dir / (digest + ".bin")
                    if path.exists():
                        wlc.need(path.read_bytes() == raw, "ARTIFACT_REWRITE")
                    else:
                        with path.open("xb") as out:
                            out.write(raw)
                log.write(json.dumps(record, sort_keys=True) + "\n")
                log.flush()
            observed = collect(args.native_work.resolve(), journal=persist)
        pq = native_pq_differential(args.native_pq.resolve(), observed, args.out)
        for digest, raw in observed["artifacts"].items():
            path = artifact_dir / (digest + ".bin")
            if not path.exists():
                with path.open("xb") as out:
                    out.write(raw)
        save_json(args.out / "signed_observations.json", observed["documents"])
        save_json(args.out / "supplied_expectation_pins.json", {
            name: wlc.pin_wire(pin) for name, pin in observed["pins"].items()})
        save_json(args.out / "verified_observations.json", observed["verified"])
        save_json(args.out / "actual_native_calls.json", observed["calls"])
        save_json(args.out / "public_receipt_counterexample.json", observed["receipt_controls"])
        save_json(args.out / "actual_hash_composition.json", observed["hash_composition"])
        save_json(args.out / "native_pq_differential.json", pq)
        small = HelpPolicy((HelpSlot(("fixed-source",), 1, 1, 0),))
        help_bounds = {"one_byte_finite_global_help_alphabet": finite_help_weight_bound(1, 64, 8192, small),
                       "actual_imported_packet_alphabet_is_vacuous": finite_help_weight_bound(
                           1, 64, 8192, observed["policy"])}
        save_json(args.out / "finite_help_bounds.json", help_bounds)
        summary = {
            "result": "PASS", "schema": wlc.SCHEMA, "base_commit": BASE_COMMIT,
            "source_sha256": observed["source_manifest"],
            "cryptography_version": cryptography.__version__, "openssl_version": openssl_backend.openssl_version_text(),
            "actual_native_W1_exchanges": len(observed["calls"]),
            "actual_native_W1_successes": sum(c["body"]["returncode"] == 0 for c in observed["calls"]),
            "actual_native_W1_expected_rejections": sum(c["body"]["returncode"] != 0 for c in observed["calls"]),
            "actual_native_PQ_process_exchanges": pq["actual_native_process_exchanges"],
            "native_PQ_verification_items": pq["verification_items"],
            "key_handling": observed["key_handling"],
            "source_ledgers_cryptographically_verified": len(observed["verified"]["verified_sources"]),
            "all_lifecycle_resources_attested": False, "initial_state_attested": False,
            "complete_public_help_mediation_attested": False, "actual_sha_preprocessing_composition": False,
            "physical_resource_tail": False, "native_confirmation_risk": False,
            "production_qualified": False,
        }
        save_json(args.out / "summary.json", summary)
        print(json.dumps({k: summary[k] for k in ("result", "actual_native_W1_exchanges",
                                                "native_PQ_verification_items", "source_ledgers_cryptographically_verified")},
                         sort_keys=True))
    except Exception as error:
        if observed is not None:
            save_json(args.out / "partial_signed_observations.json", observed["documents"])
            save_json(args.out / "partial_supplied_expectation_pins.json", {
                name: wlc.pin_wire(pin) for name, pin in observed["pins"].items()})
        save_json(args.out / "failure.json", {"error": str(error), "traceback": traceback.format_exc()})
        raise


if __name__ == "__main__":
    main()
