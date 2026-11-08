#!/usr/bin/env python3
"""Audit retained W1 verification ABBA bytes without executing a verifier.

The caller pins every comparison report by SHA-256. Raw row, stage and stdout
records must agree; aggregates are recomputed. ABBA block contrasts are
*descriptive*, and do not add a fresh proof, randomize treatments, qualify
resources, or establish a population tail. Historical evidence is read-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import stat
import sys

SCHEMA = "TRNM-W1-DEPLOYMENT-COMPARISON-AUDIT1"
COMPARISON = "TRNM-W1-DEPLOYMENT-COMPARISON2"
PROFILE = "trnm-w1-risc0-3.0.6-poseidon2-join-v2"
MAX_REPORT = 16 * 1024 * 1024
MAX_RECORD = 256 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def finite(value, positive=False):
    return finite_number(value) and (value > 0 if positive else value >= 0)


def same_json(left, right):
    # Python's == equates False with 0 and True with 1. Evidence types matter.
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(same_json(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def no_cancellation(path):
    # A dangling symlink is still a present cancellation-path entry.
    require(not os.path.lexists(path), "cancellation sidecar present")


def digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def strict_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def validate_numbers(value):
    if type(value) is float:
        require(math.isfinite(value), "nonfinite JSON number")
    elif type(value) is list:
        for item in value:
            validate_numbers(item)
    elif type(value) is dict:
        for item in value.values():
            validate_numbers(item)


def read_record(path, maximum=MAX_RECORD, expected_sha256=None):
    path = Path(path)
    require(not path.is_symlink(), "regular evidence file required")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                "bounded regular evidence file required")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) == before.st_size and len(raw) <= maximum and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "evidence changed during read or exceeds byte limit")
    observed = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None:
        require(digest(expected_sha256) and observed == expected_sha256, "evidence SHA-256 mismatch")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON constant")))
    validate_numbers(value)
    require(type(value) is dict, "evidence JSON object required")
    return value, {"path": str(path), "sha256": observed, "bytes": len(raw)}


def descriptive(values):
    require(values and all(finite_number(v) for v in values),
            "finite nonempty measurement vector required")
    ordered = sorted(values)
    return {"count": len(values), "median": statistics.median(values),
            "minimum": ordered[0], "maximum": ordered[-1],
            "p95_nearest_rank": ordered[math.ceil(.95 * len(ordered)) - 1],
            "p99_nearest_rank": ordered[math.ceil(.99 * len(ordered)) - 1]}


def check_summary(recorded, calculated):
    require(type(recorded) is dict, "retained aggregate missing")
    for key, value in calculated.items():
        if type(value) is dict:
            check_summary(recorded.get(key), value)
        elif type(value) is bool:
            require(recorded.get(key) is value, "retained aggregate boolean mismatch: " + key)
        else:
            observed = recorded.get(key)
            require(key != "count" or type(observed) is int, "retained aggregate count must be an integer")
            require(type(observed) is type(value) or type(observed) in (int, float) and type(value) in (int, float),
                    "retained aggregate numeric type mismatch: " + key)
            require(finite_number(observed)
                    and math.isclose(observed, value, rel_tol=1e-12, abs_tol=1e-12),
                    "retained aggregate value mismatch: " + key)


def audit_comparison(path, expected_sha256):
    require(digest(expected_sha256), "independent comparison SHA-256 required")
    path = Path(path).absolute()
    root = path.parent
    require(path.name == "result.json" and not root.is_symlink(), "comparison result directory required")
    report, pin = read_record(path, MAX_REPORT, expected_sha256)
    no_cancellation(root / "operation-cancellation.json")
    require(report.get("schema") == COMPARISON and report.get("operation_complete") is True
            and report.get("error") is None and report.get("cancellation_event") is None
            and report.get("deadline_exhausted_at_snapshot") is False, "comparison has no eligible terminal snapshot")
    require(type(report.get("fresh_proof_generations")) is int and report["fresh_proof_generations"] == 0
            and type(report.get("independent_receipts")) is int and report["independent_receipts"] == 1,
            "verification repetitions cannot be promoted to fresh proof generation")
    for field in ("admission_authorized", "production_qualified", "cryptographic_security_qualified",
                  "original_business_budget_reproduced"):
        require(report.get(field) is False, "unsupported qualification in comparison: " + field)
    planned, rows = report.get("planned_order"), report.get("rows")
    require(type(planned) is list and 4 <= len(planned) <= 1000 and len(planned) % 4 == 0
            and planned == ["native", "proof", "proof", "native"] * (len(planned) // 4)
            and type(rows) is list and len(rows) == len(planned), "complete declared ABBA order required")
    ids = report.get("identities")
    require(type(ids) is dict, "fixed input identities required")
    for name in ("verifier", "receipt", "input", "header", "expected_artifacts"):
        require(digest(ids.get(name + "_sha256")) and type(ids.get(name + "_bytes")) is int
                and ids[name + "_bytes"] > 0, "invalid fixed input identity: " + name)
    require(ids["header_bytes"] == 318 and ids["expected_artifacts_bytes"] == 64
            and digest(ids.get("journal_sha256")), "full statement identity required")
    resource = report.get("resource_observation")
    require(type(resource) is dict and type(resource.get("cpu_affinity")) is list
            and resource["cpu_affinity"] and all(type(x) is int and x >= 0 for x in resource["cpu_affinity"])
            and resource["cpu_affinity"] == sorted(set(resource["cpu_affinity"]))
            and resource.get("same_supervisor") is True and resource.get("same_verifier_binary") is True
            and resource.get("task_exclusive_resource_ownership_established") is False,
            "recorded supervisor/binary/CPU affinity mismatch")
    boot_id = report.get("original_deadline_clock_boot_id")
    require(type(boot_id) is str and boot_id and resource.get("boot_id") == boot_id,
            "comparison boot clock mismatch")
    started, deadline = report.get("started_monotonic"), report.get("original_deadline_monotonic")
    require(finite(started) and finite(deadline, True) and started < deadline, "finite original comparison deadline required")
    intent, intent_pin = read_record(root / "intent.json")
    require(intent.get("schema") == COMPARISON and intent.get("planned_order") == planned
            and same_json(intent.get("identities"), {k: v for k, v in ids.items() if k != "journal_sha256"})
            and same_json(intent.get("resource_observation"), resource)
            and same_json(intent.get("deadline_monotonic"), deadline) and intent.get("deadline_boot_id") == boot_id,
            "result does not match prior comparison intent")
    reference_work, environment, previous_end = None, None, started
    raw_pins, accepted = [], []
    for index, (kind, row) in enumerate(zip(planned, rows)):
        require(type(row) is dict and type(row.get("index")) is int and row["index"] == index
                and row.get("kind") == kind and row.get("accepted") is True
                and row.get("dispatched") is True and row.get("observation_error") is None,
                "row index/order/acceptance mismatch")
        stage_dir = root / f"row-{index:04d}-{kind}"
        require(stage_dir.is_dir() and not stage_dir.is_symlink(), "regular row directory required")
        no_cancellation(stage_dir / "operation-cancellation.json")
        raw_row, row_pin = read_record(root / f"row-{index:04d}-observation.json")
        stage, stage_pin = read_record(stage_dir / "result.json")
        value, stdout_pin = read_record(stage_dir / "stdout.log")
        require(same_json(raw_row, row) and same_json(stage, row.get("stage"))
                and same_json(value, row.get("verifier_report")),
                "embedded row/stage/stdout differs from retained raw bytes")
        require(stage.get("stdout_sha256") == stdout_pin["sha256"], "stage stdout digest mismatch")
        require(stage.get("schema") == "TRNM-W1-STAGE-MEASUREMENT3"
                and type(stage.get("returncode")) is int and stage["returncode"] == 0
                and stage.get("stage_process_complete") is True and stage.get("error") is None
                and stage.get("canceled_signal") is None and stage.get("cancellation_event") is None
                and stage.get("termination_reasons") == [] and stage.get("timed_out") is False
                and stage.get("deadline_exhausted_at_snapshot") is False
                and stage.get("completion_observed_before_deadline") is True
                and stage.get("owned_session_observation_complete") is True
                and stage.get("process_group_remaining_after_child_exit") is False
                and stage.get("final_owned_session_members") == []
                and type(stage.get("final_known_group_probes")) is list
                and all(type(x) is dict and x.get("state") == "ABSENT" for x in stage["final_known_group_probes"]),
                "row has no complete uncancelled process snapshot")
        when, wall = stage.get("started_monotonic"), stage.get("wall_seconds")
        require(finite(when) and finite(wall, True) and when >= previous_end
                and stage.get("effective_deadline_monotonic") == deadline
                and stage.get("observer_boot_id") == boot_id and when + wall < deadline,
                "row order, deadline or clock mismatch")
        previous_end = when + wall
        env = stage.get("environment")
        require(type(env) is dict and type(env.get("RAYON_NUM_THREADS")) is str
                and env["RAYON_NUM_THREADS"].isdigit() and int(env["RAYON_NUM_THREADS"]) > 0,
                "explicit Rayon width required")
        if environment is None:
            environment = env
        require(same_json(env, environment), "verifier environment changed between ABBA rows")
        require(value.get("schema") == ("TRNM-W1-V2-NATIVE-ONCE1" if kind == "native" else "TRNM-W1-V2-FULL-VERIFY1")
                and value.get("profile_id") == PROFILE and type(value.get("iterations")) is int
                and value["iterations"] == 1 and value.get("admission_authorized") is False,
                "one real independent verification profile required")
        for name in ("header", "expected_artifacts", "journal"):
            require(value.get(name + "_sha256") == ids[name + "_sha256"], "row public statement identity changed")
        work = value.get("work_id")
        require(digest(work) and (reference_work is None or work == reference_work), "row work identity changed")
        reference_work = work
        source, count_key, timing_key = (("input", "full_replay_calls", "full_native_verify_ns") if kind == "native"
                                       else ("receipt", "independent_proof_trials", "decode_and_verify_ns"))
        require(type(value.get(count_key)) is int and value[count_key] == 1
                and value.get(source + "_sha256") == ids[source + "_sha256"]
                and type(value.get(source + "_bytes")) is int and value[source + "_bytes"] == ids[source + "_bytes"],
                "row source bytes or execution count changed")
        timings = value.get(timing_key)
        require(type(timings) is list and len(timings) == 1 and type(timings[0]) is int and timings[0] > 0
                and type(row.get("inner_ns")) is int and row["inner_ns"] == timings[0], "row inner timing mismatch")
        usage = stage.get("rusage")
        require(type(usage) is dict and finite(usage.get("user_seconds")) and finite(usage.get("system_seconds")),
                "finite wait4 CPU observation required")
        accepted.append({"index": index, "kind": kind, "inner_ns": timings[0], "wall_seconds": wall,
                         "wait4_cpu_seconds": usage["user_seconds"] + usage["system_seconds"]})
        raw_pins.append({"index": index, "row": row_pin, "stage": stage_pin, "stdout": stdout_pin})
    cost = {}
    for kind in ("native", "proof"):
        selected = [row for row in accepted if row["kind"] == kind]
        cost[kind] = {"verifier_inner_ns": descriptive([r["inner_ns"] for r in selected]),
                      "cold_process_wall_seconds": descriptive([r["wall_seconds"] for r in selected]),
                      "wait4_cpu_seconds": descriptive([r["wait4_cpu_seconds"] for r in selected])}
    cost["proof_over_native_inner_median"] = cost["proof"]["verifier_inner_ns"]["median"] / cost["native"]["verifier_inner_ns"]["median"]
    cost["proof_over_native_cold_wall_median"] = cost["proof"]["cold_process_wall_seconds"]["median"] / cost["native"]["cold_process_wall_seconds"]["median"]
    cost["receipt_over_native_payload_bytes"] = ids["receipt_bytes"] / ids["input_bytes"]
    for field, ratio in (("verification_inner_benefit_observed", "proof_over_native_inner_median"),
                         ("cold_process_benefit_observed", "proof_over_native_cold_wall_median"),
                         ("payload_byte_benefit_observed", "receipt_over_native_payload_bytes")):
        cost[field] = cost[ratio] < 1
    check_summary(report.get("cost_comparison"), cost)
    blocks = []
    for index in range(0, len(accepted), 4):
        a0, b0, b1, a1 = accepted[index:index + 4]
        native = (a0["inner_ns"] + a1["inner_ns"]) / 2
        proof = (b0["inner_ns"] + b1["inner_ns"]) / 2
        blocks.append({"index": index // 4, "row_indices": list(range(index, index + 4)),
                       "native_mean_ns": native, "proof_mean_ns": proof,
                       "proof_minus_native_mean_ns": proof - native, "proof_over_native_mean": proof / native})
    return {"source": pin, "intent": intent_pin, "accepted_rows": len(accepted), "work_id": reference_work,
            "identities": ids, "resource_observation": resource, "environment": environment,
            "original_deadline_monotonic": deadline, "raw_rows": raw_pins, "recomputed_cost": cost,
            "abba_blocks": blocks, "block_contrasts": {
                "proof_over_native_mean": descriptive([b["proof_over_native_mean"] for b in blocks]),
                "proof_minus_native_mean_ns": descriptive([b["proof_minus_native_mean_ns"] for b in blocks])}}


def audit(comparisons):
    require(1 <= len(comparisons) <= 8, "one to eight pinned comparison reports required")
    require(len({pin for _, pin in comparisons}) == len(comparisons), "duplicate comparison source digest")
    arms = [audit_comparison(path, pin) for path, pin in comparisons]
    first = arms[0]
    for arm in arms[1:]:
        for field in ("work_id", "environment", "resource_observation", "original_deadline_monotonic"):
            require(same_json(arm[field], first[field]), "common verification configuration mismatch: " + field)
        require(same_json({k: v for k, v in arm["identities"].items() if not k.startswith("receipt_")},
                          {k: v for k, v in first["identities"].items() if not k.startswith("receipt_")}),
                "common verification input mismatch")
    # Reconcile every observed pin and cancellation path after reading all arms.
    # This is a bounded closing read, not an atomic snapshot or trusted timestamp.
    for arm in arms:
        root = Path(arm["source"]["path"]).parent
        pins = [arm["source"], arm["intent"]]
        for row in arm["raw_rows"]:
            pins.extend(row[name] for name in ("row", "stage", "stdout"))
        for pin in pins:
            _, current = read_record(pin["path"], pin["bytes"], pin["sha256"])
            require(current["bytes"] == pin["bytes"], "evidence length changed during audit")
        no_cancellation(root / "operation-cancellation.json")
        for row in arm["raw_rows"]:
            no_cancellation(Path(row["stage"]["path"]).parent / "operation-cancellation.json")
    return {"schema": SCHEMA, "audit_complete": True, "error": None, "arms": arms,
            "accepted_verification_rows": sum(a["accepted_rows"] for a in arms),
            "distinct_receipt_byte_identities": len({a["identities"]["receipt_sha256"] for a in arms}),
            "fresh_proof_generations": 0, "generation_schemes_compared": False,
            "causal_speedup_established": False, "population_tail_established": False,
            "full_process_tree_reaping_established": False, "resource_billing_complete": False,
            "gpu_ns": None, "admission_authorized": False, "production_qualified": False,
            "cryptographic_security_qualified": False, "original_business_budget_reproduced": False,
            "actual_controller_exit_qualified": False,
            "scope": "retained verification records and descriptive ABBA block contrasts only",
            "limitations": [
                "Source pins and raw linkage check retained-byte consistency, not trusted timestamping or independent truth.",
                "ABBA blocks are fixed-order within-arm contrasts, not randomized trials or cross-arm generation pairs.",
                "The two receipt arms run consecutively; between-arm drift and generating configuration differences remain.",
                "Recorded environment/affinity agreement does not prove exclusive resources or historical device denial.",
                "Empty sampled sessions or cgroups do not establish reaping of every historical descendant.",
                "wait4 measurements cannot be summed with enclosing cgroup CPU counters without double counting.",
                "No verifier or generator runs during this audit, and existing research deadlines are unchanged.",
                "No controller terminal receipt is supplied; retained snapshots alone do not establish a successful command exit."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparison", nargs=2, action="append", required=True, metavar=("RESULT", "SHA256"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    # Refuse an existing output before processing; never overwrite evidence.
    require(not args.out.exists(), "audit output already exists")
    try:
        result = audit(args.comparison)
        exit_code = 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        result = {"schema": SCHEMA, "audit_complete": False,
                  "error": {"type": type(error).__name__, "message": str(error)},
                  "fresh_proof_generations": 0, "admission_authorized": False,
                  "resource_billing_complete": False, "production_qualified": False}
        exit_code = 1
    with args.out.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k not in {"arms", "limitations"}}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
