#!/usr/bin/env python3
"""Fail-closed P0-P6 admission/work readiness evidence checker (read-only).

Does not run the claimed experiments or verify cryptographic signatures; this
only checks strict evidence *shape and coverage*. A report cannot confer
production consensus authority and always carries production_activation=False.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

PHASES = ("P0", "P1", "P2", "P3", "P4", "P5", "P6")
MODES = ("from-zero-false-trace", "valid-w1-invalid-root", "mixed-honest-hostile")


def check(report: object) -> dict:
    errors: list[str] = []
    if type(report) is not dict or report.get("schema") != "pon-p0-p6-readiness-evidence-v1":
        return {"verdict": "HOLD_NO_GO", "errors": ["SCHEMA"], "phase_pass": {p: False for p in PHASES},
                "production_activation": False}
    exact = report.get("exact_source")
    if (type(exact) is not dict or type(exact.get("chain_sha")) is not str
        or len(exact["chain_sha"]) != 40
        or any(c not in "0123456789abcdef" for c in exact["chain_sha"])):
        errors.append("EXACT_SOURCE")
    evidence = report.get("evidence")
    evidence = evidence if type(evidence) is dict else {}
    phase_pass = {}
    for phase in PHASES:
        item = evidence.get(phase)
        fields = {
            "P0": ("four_w1_full_rejections", "no_verified_work",
                   "unchanged_state_and_chainwork", "native_byte_identity"),
            "P1": ("all_w1_entrypoints_inventoried", "shared_real_host_cpu",
                   "fail_closed_restart", "no_unmetered_external_path"),
            "P2": ("real_signed_cookie_cost", "attacker_cpu", "attacker_gpu",
                   "honest_cost", "invalid_receiver_cost"),
            "P3": ("rotated_keys", "spent_replay", "distinct_false_traces",
                   "wrong_state_root", "mixed_honest_timing"),
            "P4": ("preregistered", "actual_physical_host",
                   "all_attempts_accounted", "honest_confirmations"),
            "P5": ("sound_w2_relation", "no_lottery_grinding",
                   "bounded_generation_and_verification", "measured_hardware"),
            "P6": ("external_independent_reviewer", "blind_cross_language",
                   "adversarial_fork_choice", "signed_review_receipt"),
        }[phase]
        if type(item) is not dict or not all(item.get(field) is True for field in fields):
            errors.append(phase + "_MISSING_EVIDENCE")
            phase_pass[phase] = False
            continue
        if phase == "P4":
            rows = item.get("runs")
            complete = (type(rows) is list and len(rows) == 9
                        and {(x.get("mode"), x.get("run")) for x in rows if type(x) is dict}
                        == {(mode, run) for mode in MODES for run in (1,2,3)}
                        and all(type(x) is dict and x.get("on_time_confirmed") == 3
                                and x.get("required_confirmations") == 3
                                and x.get("timeout_or_busy_excluded") is False
                                and x.get("raw_receipt_sha256") is not None
                                and type(x["raw_receipt_sha256"]) is str
                                and len(x["raw_receipt_sha256"]) == 64
                                and all(c in "0123456789abcdef" for c in x["raw_receipt_sha256"])
                                for x in rows))
            if not complete:
                errors.append("P4_A03_COVERAGE")
                phase_pass[phase] = False
                continue
        phase_pass[phase] = True
    # This is a shape/coverage reader, not external witness authentication.
    # Even all fields marked true cannot authorize production readiness.
    return {"verdict": "HOLD_NO_GO", "errors": errors or ["EXTERNAL_AUTHENTICITY_NOT_VERIFIED"],
            "phase_pass": phase_pass, "source_claim_accepted": False,
            "independent_attestation_verified": False, "production_activation": False}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("report")
    p.add_argument("--out")
    args = p.parse_args()
    raw = Path(args.report).read_bytes()
    if len(raw) > 4 * 1024 * 1024:
        raise SystemExit("EVIDENCE_SIZE")
    evidence = json.loads(raw)
    result = check(evidence)
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    payload = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.out:
        with open(args.out, "x", encoding="utf-8") as output:
            output.write(payload)
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
