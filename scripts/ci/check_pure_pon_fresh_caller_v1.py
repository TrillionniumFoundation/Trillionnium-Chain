#!/usr/bin/env python3
"""Additional finite fresh-caller pressure gate, never unrestricted Sybil fairness.

The new raw namespace is mandatory. Only its top-level namespace is projected
in memory to the original pressure reader: all original deadlines, CPU limits,
service rounds, exhaustion and arithmetic churn predicates remain conjuncts.
Caller keys are independently derived with pinned cryptography, then joined to
the receiver's post-signature observation and the original exact wire body.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

import check_pure_pon_pressure_v2 as pressure

SCHEMA = "pon-pure-pressure-fresh-caller-v1"
RESULT_SCHEMA = "pon-pure-pressure-fresh-caller-qualification-v1"
OBSERVATION_SCHEMA = "public-v3-local-request-resource-observation-v4"
CRYPTOGRAPHY_VERSION = "50.0.2"
KEY_DOMAIN = b"pure-pressure-fresh-caller-v1"
KEY_VECTOR = "b3365953873098069d9cb0ae19cf24704699085bc396ef420c2312dfcf1d8d8a"
MIN_AUTHENTICATED_CALLERS = 65
require = pressure.require


def public_key(secret):
    # Optional lane only; importing the legacy driver/reader does not silently
    # add a dependency or choose a different interpreter.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw().hex()


def caller_key(phase, actor, sequence):
    require(phase in pressure.PHASES[1:] and type(actor) is int and 0 <= actor < pressure.ATTACKERS
            and type(sequence) is int and 0 <= sequence < pressure.CALL_CAP, "caller derivation bounds")
    return public_key(pressure.wire_hash(KEY_DOMAIN, phase.encode(), struct.pack("<Q", actor),
                                       struct.pack("<Q", sequence)))


def check_environment():
    import cryptography
    require(cryptography.__version__ == CRYPTOGRAPHY_VERSION, "pinned cryptography 50.0.2 required")
    require(caller_key("from-zero", 0, 0) == KEY_VECTOR, "independent Ed25519 derivation vector")
    return {"schema": "pon-pure-fresh-caller-reader-environment-v1",
            "interpreter": sys.executable, "python_version": sys.version.split()[0],
            "cryptography_version": cryptography.__version__, "key_vector": KEY_VECTOR,
            "input_consistent": True, "dependency_version_qualified": True,
            "supply_chain_attestation": False}


def original_contract(value):
    require(value["schema"] == SCHEMA, "fresh-caller raw namespace required")
    return dict(value, schema=pressure.SCHEMA)


def check_phase(report, business):
    original_contract(report)
    attack_by_body, issued = {}, set()
    for wrapper in report["actors"]:
        actor_report = wrapper["report"]
        if actor_report is None:
            continue
        require(actor_report["schema"] == SCHEMA, "fresh-caller actor namespace required")
        if actor_report["error"] is not None:
            continue
        actor = actor_report["result"]
        for row in actor["calls"]:
            key = caller_key(report["phase"], actor["actor"], row["sequence"])
            require(row["caller_public_key"] == key and key not in issued,
                    "independently derived fresh caller reused or changed")
            issued.add(key)
            require(row["body_digest"] not in attack_by_body, "duplicate fresh caller body")
            attack_by_body[row["body_digest"]] = key

    honest_key, history_key = public_key(bytes([73]) * 32), public_key(bytes([74]) * 32)
    honest = {item["body"] for item in business}
    offered = {row["body_digest"] for row in report["submissions"]}
    require(offered <= honest, "unplanned honest body")
    histories = {row["body_digest"] for row in report["history"]}
    authenticated, honest_dispatched, honest_accepted = set(), set(), set()
    authenticated_rows, preauthentication_rows = 0, 0
    for capture in report["observations"]:
        require(capture["snapshot"]["schema"] == OBSERVATION_SCHEMA,
                "post-signature v4 observation required")
        for row in capture["snapshot"]["records"]:
            key = row.get("authenticated_caller")
            if key is None:
                require(row.get("dispatch_started") is not True
                        and row["dispatch_accepted"] is None and row["full_work_accepted"] is None,
                        "dispatch without authenticated caller")
                preauthentication_rows += 1
                continue
            pressure.raw_hex(key, 32)
            require(row["body_digest"] is not None, "authenticated caller without bound body")
            digest = bytes(row["body_digest"]).hex()
            if digest in attack_by_body:
                require(key == attack_by_body[digest], "authenticated caller/attack body binding")
                authenticated.add(key)
            elif digest in offered:
                require(key == honest_key, "authenticated caller/honest body binding")
                if row.get("dispatch_started") is True:
                    honest_dispatched.add(digest)
                if row["dispatch_accepted"] is True:
                    honest_accepted.add(digest)
            elif digest in histories:
                require(key == history_key, "authenticated caller/History body binding")
            else:
                raise ValueError("authenticated caller with unoffered body")
            authenticated_rows += 1
    required = 0 if report["phase"] == "baseline" else MIN_AUTHENTICATED_CALLERS
    submissions = report["submissions"]
    return {"phase": report["phase"], "offered_distinct_attack_callers": len(issued),
            "authenticated_distinct_attack_callers": len(authenticated),
            "minimum_authenticated_distinct_attack_callers": required,
            "fresh_caller_coverage_qualified": len(authenticated) >= required,
            "authenticated_connection_rows": authenticated_rows,
            "preauthentication_connection_rows": preauthentication_rows,
            "planned_honest_bodies": len(honest), "offered_honest_bodies": len(offered),
            "unoffered_honest_bodies": len(honest - offered),
            "honest_submission_attempts": len(submissions),
            "honest_submission_retries": len(submissions) - len(offered),
            "honest_submission_outcomes": {status: sum(row["status"] == status for row in submissions)
                                           for status in ("ok", "refused", "error")},
            "on_time_honest_successful_calls": sum(pressure.call(row) for row in submissions),
            "honest_bodies_with_authenticated_dispatch": len(honest_dispatched),
            "honest_bodies_with_authenticated_acceptance": len(honest_accepted)}


def check(manifest, prepared, phases):
    environment = check_environment()
    original = pressure.check(original_contract(manifest), original_contract(prepared),
                              [original_contract(phase) for phase in phases])
    business = pressure.preparation(original_contract(prepared))
    callers = [check_phase(phase, business) for phase in phases]
    return {"schema": RESULT_SCHEMA, "input_consistent": True,
            "finite_qualification": original["finite_qualification"] and all(
                row["fresh_caller_coverage_qualified"] for row in callers),
            "original_pressure_qualification": original, "phases": callers,
            "reader_environment": environment,
            "namespace_projection": "explicit top-level in-memory original-contract projection; original raw bytes retained",
            "public_fairness_qualified": False, "production_qualified": False,
            "work_hardness_qualified": False, "installation_authorized": False,
            "scope": "Finite 24-actor per-call fresh keys in the original 30s/2s cold pressure envelope. At least 65 independently derived actually authenticated hostile identities per attack phase. Signature binding is local receiver evidence, not independent machine attestation, arbitrary-Sybil fairness or minimum attacker resource cost."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--check-environment", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args()
    try:
        if args.check_environment:
            require(args.directory is None and not args.require_qualified, "environment-only invocation")
            result = check_environment()
        else:
            require(args.directory is not None, "fresh-caller directory required")
            result = check(pressure.load(args.directory / "campaign.json"),
                           pressure.load(args.directory / "preparation.json"),
                           [pressure.load(args.directory / (name + ".json")) for name in pressure.PHASES])
    except (ValueError, KeyError, TypeError, OSError, ImportError, IndexError) as error:
        result = {"schema": RESULT_SCHEMA, "input_consistent": False,
                  "finite_qualification": False, "error": str(error),
                  "public_fairness_qualified": False, "production_qualified": False,
                  "work_hardness_qualified": False, "installation_authorized": False}
    raw = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
    print(raw, end="")
    return 0 if result["input_consistent"] and (
        not args.require_qualified or result["finite_qualification"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
