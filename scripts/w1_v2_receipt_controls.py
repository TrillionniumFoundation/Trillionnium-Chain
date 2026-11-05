#!/usr/bin/env python3
"""Run actual saved-v2-receipt controls under one 120-second wall budget.

This program never creates a proof. A valid saved receipt must first pass the
explicit independent verifier. Fixed-length journal mutations are located only
after a unique exact domain match, canonical Vec length, and byte bounds. The
critical paired-A/B and canonical-C controls require the verifier's stable
W1_V2_CRYPTO_REJECT context, not merely a nonzero process exit. That context
covers the construction profile and complete receipt verification; it does not
claim that every rejection executes the entire STARK verification algorithm.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1/experiments"))
from w1_stage_measure import Canceled, cancel_on_signals, measure, sha, write_new

SCHEMA = "TRNM-W1-V2-RECEIPT-CONTROLS1"
PROFILE_ID = "trnm-w1-risc0-3.0.6-poseidon2-join-v2"
DOMAIN = b"TRNM-W1-ZK-JOURNAL2\0"
HEADER_BYTES = 318
JOURNAL_BYTES = 16882
TRACE = len(DOMAIN) + HEADER_BYTES
TICKET, WORK_ID = TRACE + 32, TRACE + 64
MODEL, INPUT, PRODUCT = TRACE + 96, TRACE + 128, TRACE + 160
MODULUS = 4294967291
MAX_RECEIPT = 16 * 1024 * 1024
TOTAL_SECONDS = 120
LAYERS = {"wire": "W1_V2_WIRE_REJECT", "public": "W1_V2_PUBLIC_REJECT",
          "crypto": "W1_V2_CRYPTO_REJECT"}
HEADER_FIELDS = (("magic", 0), ("version", 4), ("network", 6), ("parameters", 38),
                 ("parent", 70), ("height", 102), ("timestamp", 110), ("target", 118),
                 ("miner", 150), ("transactions", 182), ("state", 214),
                 ("receipts", 246), ("work_task", 278), ("nonce", 310))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, f"input exceeds declared bound: {path}")
    return data


def write_bytes(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def strict_json(data):
    def pairs(values):
        out = {}
        for key, value in values:
            require(key not in out, f"duplicate JSON key: {key}")
            out[key] = value
        return out

    def invalid(value):
        raise ValueError(f"nonfinite JSON value: {value}")

    def finite(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number

    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite)


def locate_journal(receipt, header, artifacts):
    """Locate exactly the saved journal, never a similar byte run in the seal."""
    require(len(header) == HEADER_BYTES and len(artifacts) == 64, "exact header and external A/B lengths required")
    require(12 <= len(receipt) <= MAX_RECEIPT, "bounded complete receipt required")
    require(receipt[:4] == (1).to_bytes(4, "little"), "baseline must encode Succinct")
    seal_words = int.from_bytes(receipt[4:12], "little")
    seal_end = 12 + 4 * seal_words
    require(0 < seal_words and seal_end <= len(receipt), "baseline seal vector is invalid")
    require(receipt.count(DOMAIN) == 1, "v2 journal domain must occur exactly once")
    start = receipt.index(DOMAIN)
    end = start + JOURNAL_BYTES
    require(start >= seal_end + 8 and end <= len(receipt), "journal overlaps seal or exceeds receipt bounds")
    require(receipt[start - 8:start] == JOURNAL_BYTES.to_bytes(8, "little"),
            "unique domain is not preceded by the exact canonical journal Vec length")
    journal = receipt[start:end]
    require(journal[len(DOMAIN):TRACE] == header, "journal differs from independent header")
    require(journal[MODEL:PRODUCT] == artifacts, "journal differs from independent expected A/B")
    require(all(int.from_bytes(journal[i:i + 4], "little") < MODULUS
                for i in range(PRODUCT, JOURNAL_BYTES, 4)), "baseline C is not canonical")
    return {"journal_start": start, "journal_end": end, "seal_words": seal_words,
            "seal_end": seal_end, "journal_sha256": digest(journal),
            "work_id": journal[WORK_ID:MODEL].hex()}


def plan_controls(receipt, location):
    plans = [{"name": "positive_original_full_v2", "operation": "original", "expect": "accept"}]

    def add(name, operation, *, layer=None, **fields):
        plans.append({"name": name, "operation": operation, "expect": "reject",
                      "required_rejection_layer": layer, **fields})

    for name, tag in (("composite", 0), ("groth16", 2), ("fake", 3), ("unknown", 2**32 - 1)):
        add(f"wire_tag_{name}", "receipt_integer", offset=0, width=4, value=tag, layer="wire")
    for name, value in (("zero", 0), ("overflow_u64", 2**64 - 1),
                        ("multiply_overflow", 2**62), ("beyond_slice", len(receipt) // 4 + 1)):
        add(f"seal_length_{name}", "receipt_integer", offset=4, width=8, value=value, layer="wire")
    for name, length in (("empty", 0), ("tag", 3), ("seal_length", 11),
                         ("seal_body", location["seal_end"] - 1), ("last_byte", len(receipt) - 1)):
        add(f"receipt_truncated_{name}", "truncate", target="receipt", length=length, layer="wire")
    add("receipt_trailing_byte", "append", target="receipt", layer="wire")
    for name, offset in (("first", 12), ("middle", 12 + 4 * (location["seal_words"] // 2)),
                         ("last", location["seal_end"] - 4)):
        add(f"seal_word_{name}", "xor", target="receipt", offset=offset, layer="crypto")
    for name, offset in HEADER_FIELDS:
        add(f"external_header_{name}", "xor", target="header", offset=offset, layer="public")
    for target, length in (("header", HEADER_BYTES - 1), ("artifacts", 63)):
        add(f"external_{target}_truncated", "truncate", target=target, length=length,
            required_error_text="header size" if target == "header" else "expected artifacts must be exactly")
        add(f"external_{target}_trailing", "append", target=target,
            required_error_text="input size bound")
    for name, offset in (("model_first", 0), ("model_last", 31), ("input_first", 32), ("input_last", 63)):
        add(f"external_artifacts_{name}", "xor", target="artifacts", offset=offset, layer="public")
    for name, offset in (("domain", 0), ("embedded_header", len(DOMAIN) + 6),
                         ("trace", TRACE), ("ticket", TICKET), ("work_id", WORK_ID),
                         ("model", MODEL), ("input", INPUT)):
        add(f"journal_{name}", "journal_xor", offset=offset, layer="public")
    for name, offset in (("first", PRODUCT), ("middle", PRODUCT + 4 * 2048), ("last", JOURNAL_BYTES - 4)):
        add(f"journal_C_canonical_{name}", "canonical_product", offset=offset, layer="crypto",
            public_conditions_preserved="only a C word changes to a distinct value in [0,q); the public checker does not replay matrix multiplication")
    for value in range(MODULUS, 2**32):
        add(f"journal_C_noncanonical_{value}", "journal_integer", offset=PRODUCT, value=value, layer="public")
    for name, offsets in (("model", [MODEL]), ("input", [INPUT]), ("both", [MODEL, INPUT])):
        add(f"journal_and_expected_{name}", "paired_artifacts", offsets=offsets, layer="crypto",
            public_conditions_preserved="only journal A/B bytes and corresponding external expected bytes change together; header, trace, ticket, work ID and C remain identical to the accepted baseline")
    require(len({row["name"] for row in plans}) == len(plans), "duplicate control name")
    return plans


def materialize(plan, baseline, location):
    changed = dict(baseline)

    def replace(target, offset, replacement):
        data = changed[target]
        require(0 <= offset and offset + len(replacement) <= len(data), "mutation exceeds its intended field")
        changed[target] = data[:offset] + replacement + data[offset + len(replacement):]

    operation = plan["operation"]
    if operation == "original":
        return changed
    if operation == "receipt_integer":
        replace("receipt", plan["offset"], plan["value"].to_bytes(plan["width"], "little"))
    elif operation == "truncate":
        changed[plan["target"]] = changed[plan["target"]][:plan["length"]]
    elif operation == "append":
        changed[plan["target"]] += b"\0"
    elif operation == "xor":
        target, offset = plan["target"], plan["offset"]
        replace(target, offset, bytes([changed[target][offset] ^ 1]))
    elif operation in ("journal_xor", "journal_integer", "canonical_product"):
        offset = plan["offset"]
        width = 1 if operation == "journal_xor" else 4
        require(0 <= offset and offset + width <= JOURNAL_BYTES, "journal mutation exceeds exact journal bounds")
        absolute = location["journal_start"] + offset
        if operation == "journal_xor":
            replacement = bytes([changed["receipt"][absolute] ^ 1])
        elif operation == "journal_integer":
            replacement = plan["value"].to_bytes(4, "little")
        else:
            old = int.from_bytes(changed["receipt"][absolute:absolute + 4], "little")
            require(PRODUCT <= offset <= JOURNAL_BYTES - 4 and (offset - PRODUCT) % 4 == 0,
                    "canonical C mutation is not an aligned product cell")
            require(old < MODULUS, "baseline product word must be canonical")
            replacement = (1 if old == 0 else 0).to_bytes(4, "little")
        replace("receipt", absolute, replacement)
    elif operation == "paired_artifacts":
        for offset in plan["offsets"]:
            require(offset in (MODEL, INPUT), "paired mutation must target exactly A or B")
            absolute = location["journal_start"] + offset
            replacement = bytes([changed["receipt"][absolute] ^ 1])
            replace("receipt", absolute, replacement)
            replace("artifacts", offset - MODEL, replacement)
    else:
        raise ValueError("unknown control mutation")
    require(any(changed[name] != baseline[name] for name in baseline), "negative control changed no bytes")
    if operation.startswith("journal") or operation in ("canonical_product", "paired_artifacts"):
        start, end = location["journal_start"], location["journal_end"]
        require(len(changed["receipt"]) == len(baseline["receipt"])
                and changed["receipt"][:start] == baseline["receipt"][:start]
                and changed["receipt"][end:] == baseline["receipt"][end:],
                "journal mutation changed seal, encoding, or receipt metadata")
    return changed


def validate_positive(data, baseline, location):
    row = strict_json(data)
    require(type(row) is dict, "positive verifier report must be an object")
    expected = {"schema": "TRNM-W1-V2-FULL-VERIFY1", "profile_id": PROFILE_ID,
                "sdk": "3.0.6", "iterations": 1, "independent_proof_trials": 1,
                "work_id": location["work_id"], "header_sha256": digest(baseline["header"]),
                "receipt_sha256": digest(baseline["receipt"]), "journal_sha256": location["journal_sha256"],
                "expected_artifacts_sha256": digest(baseline["artifacts"]),
                "receipt_bytes": len(baseline["receipt"]),
                "parent_eligibility_checked": False, "admission_authorized": False}
    for key, value in expected.items():
        require(type(row.get(key)) is type(value) and row[key] == value, f"positive report {key} differs")
    samples = row.get("decode_and_verify_ns")
    require(type(samples) is list and len(samples) == 1 and type(samples[0]) is int
            and 0 < samples[0] < 2**63, "positive report lacks its actual verification sample")
    return row


def panic_or_abort(process, output):
    lower = output.lower()
    markers = (b"panicked at", b"fatal runtime error", b"stack overflow",
               b"memory allocation of", b"out of memory", b"core dumped")
    return (process["returncode"] in (101, -signal.SIGABRT, -signal.SIGSEGV, -signal.SIGBUS, -signal.SIGILL)
            or any(marker in lower for marker in markers))


def read_log_prefix(path):
    # The full raw file is retained by the stage observer. Oversized logs must
    # still produce a failed control record instead of erasing the attempt.
    with path.open("rb") as stream:
        data = stream.read(4 * 1024 * 1024 + 1)
    return data, len(data) > 4 * 1024 * 1024


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("verifier", "receipt", "header", "expected-artifacts", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    started, started_unix_ns = time.monotonic(), time.time_ns()
    deadline = started + TOTAL_SECONDS
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    results, plans, baseline, location = [], [], None, None
    positive_report, error = None, None
    verifier_hash = None
    declaration = {"schema": SCHEMA, "started_unix_ns": started_unix_ns,
                   "started_monotonic": started, "deadline_monotonic": deadline,
                   "total_wall_budget_seconds": TOTAL_SECONDS,
                   "termination_settlement_adds_acceptance_budget": False,
                   "runner_sha256": sha(Path(__file__)), "profile_id": PROFILE_ID,
                   "new_proofs_generated": 0, "additional_work_tickets": 0,
                   "scope": "one actual saved full-v2 receipt, explicit independent verifier, local hostile-input observations only",
                   "crypto_context_scope": "construction profile and complete receipt verification; not a guarantee that every rejection executes all STARK checks"}
    write_new(out / "declaration.json", declaration)
    with cancel_on_signals():
        try:
            verifier = args.verifier.resolve(strict=True)
            verifier_hash = sha(verifier)
            baseline = {"receipt": bounded(args.receipt, MAX_RECEIPT),
                        "header": bounded(args.header, HEADER_BYTES),
                        "artifacts": bounded(args.expected_artifacts, 64)}
            location = locate_journal(baseline["receipt"], baseline["header"], baseline["artifacts"])
            assets = out / "original"
            assets.mkdir()
            for name, data in baseline.items():
                write_bytes(assets / f"{name}.bin", data)
            write_new(out / "identity.json", {"verifier_path": str(verifier), "verifier_sha256": verifier_hash,
                      "assets": {name: {"bytes": len(data), "sha256": digest(data)} for name, data in baseline.items()},
                      "journal_location": location,
                      "binary_source_attestation": "executable bytes pinned for this run; this script does not attest compilation"})
            plans = plan_controls(baseline["receipt"], location)
            write_new(out / "plan.json", plans)
            for index, plan in enumerate(plans):
                require(time.monotonic() < deadline, "common 120-second deadline exhausted before next control")
                require(sha(verifier) == verifier_hash, "verifier executable changed during controls")
                case = out / f"{index:03}-{plan['name']}"
                case.mkdir()
                mutated = materialize(plan, baseline, location)
                paths = {}
                for name, data in mutated.items():
                    paths[name] = assets / f"{name}.bin"
                    if data != baseline[name]:
                        paths[name] = case / f"{name}.bin"
                        write_bytes(paths[name], data)
                write_new(case / "mutation.json", {**plan,
                          "assets": {name: {"bytes": len(data), "sha256": digest(data), "path": str(paths[name])}
                                     for name, data in mutated.items()}})
                process = measure([str(verifier), str(paths["receipt"]), str(paths["header"]), str(paths["artifacts"])],
                                  case / "process", TOTAL_SECONDS, deadline=deadline)
                stdout, stdout_scan_truncated = read_log_prefix(case / "process/stdout.log")
                stderr, stderr_scan_truncated = read_log_prefix(case / "process/stderr.log")
                panic = panic_or_abort(process, stdout + stderr)
                layers = [name for name, marker in LAYERS.items() if marker.encode() in stderr]
                clean = (process["completion_observed_before_deadline"]
                         and not process["termination_reasons"] and not panic)
                report_error = None
                if plan["expect"] == "accept":
                    passed = clean and process["returncode"] == 0
                    if passed:
                        try:
                            positive_report = validate_positive(stdout, baseline, location)
                        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as failure:
                            report_error = str(failure)
                            passed = False
                else:
                    passed = (clean and type(process["returncode"]) is int and process["returncode"] > 0
                              and (plan["required_rejection_layer"] is None
                                   or layers == [plan["required_rejection_layer"]])
                              and (not plan.get("required_error_text")
                                   or plan["required_error_text"].encode() in stderr))
                if time.monotonic() >= deadline:
                    passed = False
                    report_error = "control decision was not observed before the common deadline"
                row = {**plan, "passed": passed, "returncode": process["returncode"],
                       "timed_out": process["timed_out"], "panic_or_abort_detected": panic,
                       "stdout_scan_truncated": stdout_scan_truncated,
                       "stderr_scan_truncated": stderr_scan_truncated,
                       "observed_rejection_layers": layers, "report_error": report_error,
                       "process": process, "case_directory": case.name}
                write_new(case / "result.json", row)
                results.append(row)
                print(json.dumps({"case": plan["name"], "passed": passed, "returncode": process["returncode"],
                                  "observed_rejection_layers": layers, "timed_out": process["timed_out"],
                                  "panic_or_abort_detected": panic}), flush=True)
                if plan["expect"] == "accept" and not passed:
                    raise ValueError("original full-v2 receipt did not pass the independent positive control")
                if process["timed_out"] or any(reason.startswith("CANCELED_SIGNAL_") for reason in process["termination_reasons"]):
                    raise ValueError("control process timed out or observer was canceled")
            require(time.monotonic() < deadline, "control summary exceeded common deadline")
        except (Canceled, KeyboardInterrupt, OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as failure:
            error = f"{type(failure).__name__}: {failure}"
    complete = bool(plans) and len(results) == len(plans) and all(row["passed"] for row in results) and error is None
    uncompleted = []
    for index, plan in enumerate(plans[len(results):], start=len(results)):
        case = out / f"{index:03}-{plan['name']}"
        status = "ATTEMPT_WITHOUT_FINAL_CONTROL_RESULT" if (case / "process").exists() else "NOT_RUN"
        uncompleted.append({**plan, "status": status, "case_directory": case.name})
    result = {
        **declaration, "verifier_sha256": verifier_hash, "journal_location": location,
        "planned_controls": len(plans), "completed_controls": len(results),
        "positive_controls_passed": sum(row["expect"] == "accept" and row["passed"] for row in results),
        "negative_controls_passed": sum(row["expect"] == "reject" and row["passed"] for row in results),
        "unexpected_acceptances": sum(row["expect"] == "reject" and row["returncode"] == 0 for row in results),
        "panic_or_abort_count": sum(row["panic_or_abort_detected"] for row in results),
        "timeout_count": sum(row["timed_out"] for row in results),
        "controls": results, "uncompleted_controls": uncompleted,
        "positive_report": positive_report, "error": error,
        "all_controls_passed": complete, "elapsed_wall_seconds": time.monotonic() - started,
        "independent_proof_trials": int(positive_report is not None),
        "quantum_security_qualified": False, "consensus_admission": False,
        "parent_eligibility_checked": False, "production_activation": False,
    }
    if time.monotonic() >= deadline:
        complete = False
        result["all_controls_passed"] = False
        result["error"] = result["error"] or "final summary completed after the common deadline"
    write_new(out / "result.json", result)
    print(json.dumps({"all_controls_passed": complete, "planned_controls": len(plans),
                      "completed_controls": len(results), "error": result["error"]}), flush=True)
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
