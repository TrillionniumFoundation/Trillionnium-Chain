#!/usr/bin/env python3
"""Read retained pon-w1-same-target-budget-v1/v2 JSONL; never run or modify a node.

Usage: python3 scripts/pon_w1_budget_reader.py A.jsonl B.jsonl exhausted.jsonl budget.jsonl
Writes one JSON summary to stdout. Exit 2 means malformed/inconsistent input;
exit 1 means an observed verifier disagreement; exit 0 means the logged records
are internally consistent. None of these exits is a production qualification.
Full proof bytes/native execution are not reconstructed by this reader.
"""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys

sys.dont_write_bytecode = True

SCHEMA = "pon-w1-same-target-budget-v1"
WAIT_SCHEMA = "pon-w1-same-target-budget-v2"
CLASSES = ("dense", "zero", "rank-one", "sparse")
ARMS = ("generic", "structured", "blocked-zero", "from-zero-false-trace")
KERNELS = ("production", "scalar-reference", "limb")
Q, N, R = 4_294_967_291, 64, 8
ORIGINAL_RECEIVER_PARAMETERS = {
    "burst_ns": 2_000_000_000,
    "refill_ns_per_second": 250_000_000,
    "start_reserve_ns": 100_000_000,
    "worker_limit": 2,
}
# One BeforeReplay, four 512-field noise expansions (eight fields per
# hash), two 64-row products and all 8^3 transcript tiles. Rejection
# sampling can add checkpoints, so these are lower bounds, not exact counts.
TRANSCRIPT_CHECKPOINT_MINIMUM = 1 + 4 * (N * R // 8) + 2 * N + (N // R) ** 3
VERIFIED_CHECKPOINT_MINIMUM = TRANSCRIPT_CHECKPOINT_MINIMUM + 1 + 3 * N + R + 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, label, minimum=0, maximum=None):
    require(type(value) is int and value >= minimum, f"{label}: expected integer >= {minimum}")
    require(maximum is None or value <= maximum, f"{label}: above allowed maximum")
    return value


def boolean(value, label):
    require(type(value) is bool, f"{label}: expected boolean")
    return value


def digest(value, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), f"{label}: canonical 32-byte hex required")
    return bytes.fromhex(value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def finite_float(value):
    result = float(value)
    require(math.isfinite(result), f"non-finite JSON number: {value}")
    return result


def pon_hash(tag, *parts):
    h = hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag)
    for part in parts:
        h.update(len(part).to_bytes(4, "little"))
        h.update(part)
    return h.digest()


def u64(value):
    return value.to_bytes(8, "little")


def material(seed, kind):
    a, b = [], []
    for index in range(N * N):
        random = pon_hash(b"pon-w1-budget-material-v1", u64(seed), kind.encode(), u64(index))
        left, right = 0, 0
        if kind == "dense":
            left, right = int.from_bytes(random[:4], "little") % Q, int.from_bytes(random[4:8], "little") % Q
        elif kind == "rank-one":
            left = (index // N + 1) * (index % N + 1)
            right = (index // N + 3) * (index % N + 2)
        elif kind == "sparse":
            left = int.from_bytes(random[:4], "little") % Q if index % 17 == 0 else 0
            right = int.from_bytes(random[4:8], "little") % Q if index % 19 == 0 else 0
        a.append(left)
        b.append(right)
    raw_a = b"".join(x.to_bytes(4, "little") for x in a)
    raw_b = b"".join(x.to_bytes(4, "little") for x in b)
    return a, b, raw_a, raw_b, pon_hash(b"task", raw_a, raw_b)


def rank_one(a):
    pivot = next((i for i, value in enumerate(a) if value), None)
    if pivot is None:
        return False
    row, column = divmod(pivot, N)
    value = a[pivot]
    return all((a[i * N + j] * value - a[i * N + column] * a[row * N + j]) % Q == 0
               for i in range(N) for j in range(N))


def supported(arm, a, b):
    if arm in ("generic", "from-zero-false-trace"):
        return True
    az, bz = not any(a), not any(b)
    if arm == "blocked-zero":
        return az and bz
    identity = lambda m: all(value == int(i // N == i % N) for i, value in enumerate(m))
    diagonal = lambda m: all(i // N == i % N or value == 0 for i, value in enumerate(m))
    return az or bz or identity(a) or identity(b) or (diagonal(a) and diagonal(b)) or (rank_one(a) and rank_one(b))


def timing(row, label):
    require(isinstance(row, dict) and set(row) == {"wall_ns", "cpu_ns"}, f"{label}: timing object required")
    for key, value in row.items():
        if value is not None:
            integer(value, f"{label}.{key}", maximum=2**64 - 1)
    return row


def distribution(values):
    known = [value for value in values if value is not None]
    return {"observations": len(values), "known": len(known), "unavailable": len(values) - len(known),
            "known_sum": sum(known), "all_observations_sum": sum(known) if len(known) == len(values) else None,
            "minimum": min(known) if known else None, "median": statistics.median(known) if known else None,
            "maximum": max(known) if known else None,
            "tail_inference": "none; no p95/p99 or independent-sample confidence claim"}


def state(row, label, parameters=None):
    require(row["schema"] == "public-v3-local-stored-cpu-budget-v1", f"{label}: state schema")
    integer(row["stored_credit_ns"], label + ".stored_credit_ns", minimum=-(2**127))
    require(integer(row["in_flight"], label + ".in_flight") == 0, f"{label}: original sequential operation not settled")
    boolean(row["accounting_unavailable"], label + ".accounting_unavailable")
    constants = {key: integer(row[key], label + "." + key, 1) for key in
                 ("burst_ns", "refill_ns_per_second", "start_reserve_ns", "worker_limit")}
    require(row["stored_credit_ns"] <= constants["burst_ns"], f"{label}: credit exceeds original burst")
    require(parameters is None or constants == parameters, f"{label}: shared budget parameters changed")
    return constants


FLOW_V1 = "public-v3-local-actual-cpu-flow-v1"
FLOW_V2 = "public-v3-local-actual-cpu-flow-reorg-reserve-v2"
FLOW_V3 = "public-v3-local-actual-cpu-flow-admission-wait-v3"
FLOW_COUNTERS = (
    "credited_refill_ns", "discarded_refill_ns", "booked_reservation_ns",
    "live_debited_cpu_ns", "settlement_residual_cpu_ns", "settled_full_cpu_ns",
    "unsettled_known_live_cpu_ns", "paid_cpu_debit_ns", "settlement_discard_ns",
)


def actual_cpu_flow(flow, label="actual flow"):
    """Validate one explicit accounting generation and return already-paid wait CPU.

    Legacy schemas have no wait billing. A v3 snapshot must carry its wait debit,
    including an explicit zero. Phase-observer CpuWait spans are not ledger entries.
    """
    require(isinstance(flow, dict), label + ": known flow object required")
    schema = flow.get("schema")
    require(schema in (FLOW_V1, FLOW_V2, FLOW_V3), label + ": unsupported schema")
    required = {"schema", "balance_identity_verified", "initial_credit_ns",
                "remaining_paid_credit_ns", "stored_credit_ns", "live_owners", *FLOW_COUNTERS}
    if schema == FLOW_V3:
        required.add("admission_wait_cpu_ns")
    require(required <= set(flow) <= required | {"termination_reserved_ns"},
            label + ": missing fields or fields from another accounting generation")
    require(flow["balance_identity_verified"] is True, label + ": balance not verified")
    integer(flow["initial_credit_ns"], label + ".initial_credit_ns", maximum=2**127 - 1)
    for key in ("remaining_paid_credit_ns", "stored_credit_ns"):
        integer(flow[key], label + "." + key, minimum=-(2**127), maximum=2**127 - 1)
    for key in FLOW_COUNTERS:
        integer(flow[key], label + "." + key, maximum=2**64 - 1)
    owners = integer(flow["live_owners"], label + ".live_owners",
                     maximum=ORIGINAL_RECEIVER_PARAMETERS["worker_limit"])
    termination = integer(flow.get("termination_reserved_ns", 0),
                          label + ".termination_reserved_ns", maximum=2**64 - 1)
    require((schema != FLOW_V1 or termination == 0)
            and (schema != FLOW_V2 or termination > 0),
            label + ": termination reserve/schema mismatch")
    wait = (integer(flow["admission_wait_cpu_ns"], label + ".admission_wait_cpu_ns",
                    maximum=2**64 - 1) if schema == FLOW_V3 else 0)
    owner_debit = flow["live_debited_cpu_ns"] + flow["settlement_residual_cpu_ns"]
    require(flow["paid_cpu_debit_ns"] == wait + owner_debit,
            label + ": paid debit double count or missing admission wait")
    require(flow["unsettled_known_live_cpu_ns"] == owner_debit - flow["settled_full_cpu_ns"],
            label + ": already-paid admission wait is not unsettled live CPU")
    require(flow["remaining_paid_credit_ns"] == flow["initial_credit_ns"]
            + flow["credited_refill_ns"] - flow["paid_cpu_debit_ns"]
            - flow["settlement_discard_ns"]
            and flow["booked_reservation_ns"] == owners * ORIGINAL_RECEIVER_PARAMETERS["start_reserve_ns"]
            and flow["stored_credit_ns"] == flow["remaining_paid_credit_ns"]
            - flow["booked_reservation_ns"] - termination,
            label + ": original shared budget conservation mismatch")
    return wait


def settled_owner_cpu(flow, owner_cpu, reported_owner_cpu, service_charged_cpu, *, service_metrics=None):
    """Require a fully settled owner cohort without counting paid wait twice."""
    wait = actual_cpu_flow(flow, "GLOBAL_PAID_SETTLEMENT_REQUIRED")
    for value in (owner_cpu, reported_owner_cpu, service_charged_cpu):
        integer(value, "GLOBAL_PAID_SETTLEMENT_REQUIRED owner CPU", 1, 2**64 - 1)
    require(flow["live_owners"] == flow["booked_reservation_ns"]
            == flow["unsettled_known_live_cpu_ns"] == flow.get("termination_reserved_ns", 0) == 0
            and owner_cpu == flow["settled_full_cpu_ns"] == reported_owner_cpu == service_charged_cpu
            and flow["paid_cpu_debit_ns"] == wait + owner_cpu,
            "GLOBAL_PAID_SETTLEMENT_REQUIRED")
    if flow["schema"] == FLOW_V3:
        require(isinstance(service_metrics, dict)
                and service_metrics.get("mutation_cpu_charged_scope")
                == "owner-and-scoped-workers-excluding-admission-wait",
                "GLOBAL_PAID_SETTLEMENT_REQUIRED explicit service CPU scope")
        for key in ("mutation_cpu_admission_wait_ns", "mutation_cpu_admission_wait_observations",
                    "mutation_cpu_admission_wait_unknown"):
            integer(service_metrics[key], "GLOBAL_PAID_SETTLEMENT_REQUIRED " + key, maximum=2**64 - 1)
        require(service_metrics["mutation_cpu_admission_wait_unknown"] == 0
                and service_metrics["mutation_cpu_admission_wait_observations"] > 0
                and service_metrics["mutation_cpu_admission_wait_ns"] <= wait,
                "GLOBAL_PAID_SETTLEMENT_REQUIRED complete listener admission wait")
        # History and other listeners can share the account: this listener's
        # projection is a subset, never an assumed equality with the global flow.
    return wait


def receiver_flow_snapshot(flow, observed_state, initial_credit, label):
    """Sequential v2 boundaries have no live owner or outstanding reserve."""
    if flow is None:
        return
    actual_cpu_flow(flow, label)
    require(flow["schema"] == FLOW_V3, label + ": v2 campaign requires admission-wait flow")
    require(observed_state["accounting_unavailable"] is False
            and flow["initial_credit_ns"] == initial_credit
            and flow["stored_credit_ns"] == observed_state["stored_credit_ns"],
            label + ": flow/state/epoch mismatch")
    require(flow["live_owners"] == flow["booked_reservation_ns"]
            == flow["unsettled_known_live_cpu_ns"] == flow.get("termination_reserved_ns", 0) == 0,
            label + ": sequential owner/reserve not released")


def receiver_flow_transition(row, initial_credit):
    """Validate this request's actual debit; a final aggregate alone is insufficient."""
    before, after = row["actual_flow_before"], row["actual_flow_after"]
    receiver_flow_snapshot(before, row["before"], initial_credit, "before actual flow")
    receiver_flow_snapshot(after, row["after"], initial_credit, "after actual flow")
    require(before is not None or after is None, "unknown actual flow was reset to known")
    if before is None or after is None:
        return None
    cumulative = ("credited_refill_ns", "discarded_refill_ns", "admission_wait_cpu_ns",
                  "live_debited_cpu_ns", "settlement_residual_cpu_ns", "settled_full_cpu_ns",
                  "settlement_discard_ns", "paid_cpu_debit_ns")
    delta = {key: after[key] - before[key] for key in cumulative}
    require(all(value >= 0 for value in delta.values()), "actual flow cumulative counters reset")
    change = (delta["credited_refill_ns"] - delta["admission_wait_cpu_ns"]
              - delta["live_debited_cpu_ns"] - delta["settlement_residual_cpu_ns"]
              - delta["settlement_discard_ns"]
              - (after["booked_reservation_ns"] - before["booked_reservation_ns"])
              - (after.get("termination_reserved_ns", 0) - before.get("termination_reserved_ns", 0)))
    require(row["after"]["stored_credit_ns"] - row["before"]["stored_credit_ns"] == change,
            "row credit change differs from its own wait/refill/owner/reservation flow")
    if row["status"] == "not-started":
        require(all(delta[key] == 0 for key in
                    ("live_debited_cpu_ns", "settlement_residual_cpu_ns",
                     "settled_full_cpu_ns", "settlement_discard_ns")),
                "refused start fabricated an owner settlement")
    else:
        require(row["status"] == "started", "unknown receiver status")
        settlement = row["settlement"]
        for flow_key, row_key in (("live_debited_cpu_ns", "live_paid_cpu_ns"),
                                  ("settlement_residual_cpu_ns", "residual_cpu_ns"),
                                  ("settled_full_cpu_ns", "total_cpu_ns")):
            require(settlement[row_key] is not None and delta[flow_key] == settlement[row_key],
                    "row actual flow differs from once-settled owner CPU: " + flow_key)
    return delta["admission_wait_cpu_ns"]


def outcome(row, label):
    require(isinstance(row, dict) and set(row) == {"kind", "error"}, f"{label}: outcome object")
    require(row["kind"] in ("verified-work", "relation-error", "local-cancellation"), f"{label}: unknown outcome")
    require((row["error"] is None) if row["kind"] == "verified-work" else
            (isinstance(row["error"], str) and bool(row["error"])), f"{label}: error/outcome mismatch")
    return row["kind"]


def full_verifier_outcome(row, arm, label):
    """Check a completed verdict without turning cancellation into invalidity.

    A false-trace prefix has canonical fields and the right task/ticket. The
    original diagnostic can reject it only after replay with Transcript. A
    different relation error is retained as a semantic disagreement. These
    counters remain host-reported evidence; they do not reverify a proof.
    """
    actual = outcome(row["outcome"], label)
    checkpoints = integer(row["checkpoints"], label + ".checkpoints")
    expected = {"kind": "relation-error", "error": "Transcript"} if arm == ARMS[-1] else {
        "kind": "verified-work", "error": None}
    if row["outcome"] == expected:
        minimum = TRANSCRIPT_CHECKPOINT_MINIMUM if arm == ARMS[-1] else VERIFIED_CHECKPOINT_MINIMUM
        require(checkpoints >= minimum, label + ": completed verdict omits full replay checkpoints")
    return actual, expected


def analyze(path):
    raw = path.read_bytes()
    require(raw and raw.endswith(b"\n"), "empty or truncated JSONL (missing final newline)")
    rows = []
    input_schema = None
    for number, line in enumerate(raw.splitlines(), 1):
        require(line.strip(), f"line {number}: empty record")
        try:
            row = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant, parse_float=finite_float)
        except (ValueError, UnicodeError) as error:
            raise ValueError(f"line {number}: {error}") from error
        require(isinstance(row, dict) and row.get("schema") in (SCHEMA, WAIT_SCHEMA), f"line {number}: schema")
        if input_schema is None:
            input_schema = row["schema"]
        require(row["schema"] == input_schema, f"line {number}: mixed accounting generations")
        rows.append(row)
    position = 0

    def take(kind):
        nonlocal position
        require(position < len(rows), f"missing {kind} record")
        row = rows[position]
        position += 1
        require(row.get("kind") == kind, f"line {position}: expected {kind}, got {row.get('kind')}")
        return row

    campaign = take("campaign")
    samples = integer(campaign["samples"], "samples", 1, 16)
    attempts = integer(campaign["attempt_budget_per_arm"], "attempt budget", 1, 4096)
    replays = integer(campaign["receiver_replays"], "receiver replays", 1, 1024)
    seed = integer(campaign["seed"], "seed", maximum=2**64 - 1)
    target = digest(campaign["target"], "target")
    require(campaign["classes"] == list(CLASSES), "class order/coverage mismatch")
    require(campaign["work_profile"] == "pon-matmul-transcript-64-v1" and campaign["w1_changed"] is False, "W1 scope mismatch")
    candidates, producers, diagnostics, task_rows, alerts = [], [], [], [], []
    for kind in CLASSES:
        a, b, raw_a, raw_b, task = material(seed, kind)
        task_row = take("public-task-material")
        require(task_row["class"] == kind and digest(task_row["task"], "material task") == task, "material recipe/task digest mismatch")
        timing(task_row["timing"], kind + ".material")
        task_rows.append(task_row)
        for sample in range(samples):
            legal_reference = None
            for arm in ARMS:
                case = f"{kind}/{sample}/{arm}"
                row = take("producer")
                require(row["case"] == case and digest(row["task"], case) == task and digest(row["target"], case) == target, case + ": cohort/context mismatch")
                setup, total = timing(row["setup"], case + ".setup"), timing(row["total"], case + ".total")
                require(isinstance(row["attempts"], list), case + ": trials array required")
                producers.append(row)
                if not supported(arm, a, b):
                    require(row["status"] == "unsupported" and row["attempts"] == [], case + ": unsupported arm not retained accurately")
                    continue
                require(row["status"] in ("target-hit-unverified", "exhausted"), case + ": supported status")
                require(integer(row["attempt_budget"], case + ".attempt_budget") == attempts and integer(row["attempts_executed"], case + ".attempts_executed") == len(row["attempts"]), case + ": attempt denominator mismatch")
                require(0 < len(row["attempts"]) <= attempts, case + ": invalid trial count")
                require(row["phase_intervals_nested_in_total"] is True and
                        row["valid_proof_acquisition_used"] is (arm != ARMS[-1]), case + ": cost/acquisition scope mismatch")
                search = timing(row["search"], case + ".search")
                hits = []
                for nonce, trial in enumerate(row["attempts"]):
                    require(integer(trial["nonce"], case + ".nonce") == nonce, case + ": skipped/duplicated trial nonce")
                    context = pon_hash(b"pon-w1-budget-challenge-v1", u64(seed), kind.encode(), u64(sample), u64(0 if arm == ARMS[-1] else nonce))
                    require(digest(trial["challenge"], case) == context, case + ": challenge recipe mismatch")
                    trace, ticket = digest(trial["trace"], case), digest(trial["ticket"], case)
                    require(ticket == pon_hash(b"ticket", context, trace), case + ": ticket digest mismatch")
                    if arm == ARMS[-1]:
                        require(trace == pon_hash(b"public-v3-from-zero-v1", context, u64(nonce)), case + ": false trace recipe mismatch")
                    hit = target != bytes(32) and ticket <= target
                    require(boolean(trial["target_hit_unverified"], case) == hit, case + ": target hit mismatch")
                    hits.append(hit)
                    timing(trial["timing"], case + ".trial")
                won = row["status"] == "target-hit-unverified"
                require(not any(hits[:-1]) and hits[-1] == won, case + ": first-hit/exhaustion mismatch")
                require(won or len(hits) == attempts, case + ": exhaustion must retain the entire attempt budget")
                require((row["candidate_proof_digest"] is not None) == won, case + ": candidate digest mismatch")
                if won:
                    digest(row["candidate_proof_digest"], case)
                    if arm == ARMS[-1]:
                        false_proof = b"PNW1" + raw_a + raw_b + bytes(N * N * 4) + bytes.fromhex(row["attempts"][-1]["trace"])
                        require(row["candidate_proof_digest"] == pon_hash(b"proof", false_proof).hex(), case + ": false candidate bytes/digest mismatch")
                for axis in ("wall_ns", "cpu_ns"):
                    if all(x[axis] is not None for x in (setup, search, total)):
                        require(setup[axis] + search[axis] <= total[axis], case + ": phase intervals exceed full total")
                    times = [trial["timing"][axis] for trial in row["attempts"]]
                    if search[axis] is not None and all(value is not None for value in times):
                        require(sum(times) <= search[axis], case + ": nested trial intervals exceed search")
                if arm != ARMS[-1]:
                    projection = (row["status"], row["candidate_proof_digest"],
                                  [{k: trial[k] for k in ("nonce", "challenge", "trace", "ticket", "target_hit_unverified")} for trial in row["attempts"]])
                    if legal_reference is not None:
                        require(projection == legal_reference, case + ": legal producer exact stream disagrees")
                    legal_reference = projection
                if not won:
                    continue
                candidates.append(case)
                for kernel in KERNELS:
                    diagnostic = take("raw-verifier-diagnostic")
                    require(diagnostic["case"] == case and diagnostic["kernel"] == kernel and digest(diagnostic["task"], case) == task and digest(diagnostic["target"], case) == target, case + ": raw diagnostic context/coverage")
                    _, expected = full_verifier_outcome(diagnostic, arm, case)
                    if diagnostic["outcome"] != expected:
                        alerts.append({"case": case, "kernel": kernel, "expected": expected["kind"],
                                       "expected_error": expected["error"], "observed": diagnostic["outcome"]})
                    timing(diagnostic["timing"], case + ".raw")
                    cpu, producer_cpu = diagnostic["timing"]["cpu_ns"], total["cpu_ns"]
                    ratio = diagnostic["receiver_cpu_over_full_producer_search_cpu"]
                    expected_ratio = cpu / producer_cpu if cpu is not None and producer_cpu else None
                    require((ratio is None) if expected_ratio is None else
                            (type(ratio) in (int, float) and math.isfinite(ratio) and math.isclose(ratio, expected_ratio, rel_tol=1e-12, abs_tol=1e-15)), case + ": ratio does not use full same-arm producer CPU")
                    diagnostics.append(diagnostic)
    domain = take("receiver-domain-start")
    require(integer(domain["domain_count"], "domain_count") == 1, "receiver must use one original domain")
    parameters = state(domain["state"], "initial")
    require(parameters == ORIGINAL_RECEIVER_PARAMETERS, "original receiver budget parameters were substituted")
    require(domain["state"]["stored_credit_ns"] == parameters["burst_ns"] and domain["state"]["accounting_unavailable"] is False, "standalone initial budget mismatch")
    previous = domain["state"]
    wait_billing = input_schema == WAIT_SCHEMA
    wait_samples = []
    if wait_billing:
        previous_flow = domain["actual_flow"]
        receiver_flow_snapshot(previous_flow, previous, previous["stored_credit_ns"], "initial actual flow")
        if previous_flow is not None:
            require(all(previous_flow[key] == 0 for key in (*FLOW_COUNTERS, "admission_wait_cpu_ns")),
                    "initial actual flow is not a fresh standalone epoch")
    else:
        require("actual_flow" not in domain, "legacy campaign cannot carry v2 boundary evidence")
    counts, receiver_by_arm, settlements = Counter(), defaultdict(Counter), []
    refused_errors, cancel_errors = Counter(), Counter()
    first_budget_denial = None
    minimum_credit = previous["stored_credit_ns"]
    for round_number in range(replays):
        for case in candidates:
            row = take("receiver")
            arm = case.split("/")[-1]
            require(row["case"] == case and integer(row["round"], "round") == round_number, "receiver replay order/denominator mismatch")
            require(row["before"] == previous, "shared domain observation changed/reset between sequential requests")
            state(row["before"], "before", parameters)
            state(row["after"], "after", parameters)
            require(not previous["accounting_unavailable"] or row["after"]["accounting_unavailable"], "unavailable original domain was reset")
            previous = row["after"]
            minimum_credit = min(minimum_credit, previous["stored_credit_ns"])
            counts["requested_replays"] += 1
            receiver_by_arm[arm]["requested"] += 1
            status = row["status"]
            if wait_billing:
                require(row["actual_flow_before"] == previous_flow,
                        "actual flow changed/reset between sequential requests")
                wait_samples.append(receiver_flow_transition(row, domain["state"]["stored_credit_ns"]))
                previous_flow = row["actual_flow_after"]
            else:
                require("actual_flow_before" not in row and "actual_flow_after" not in row,
                        "legacy campaign cannot carry v2 boundary evidence")
            if status == "not-started":
                require(isinstance(row["error"], str) and row["error"], "start refusal error missing")
                require("settlement" not in row and "outcome" not in row, "refused request fabricated verification/settlement")
                if not wait_billing:
                    require(row["after"]["stored_credit_ns"] >= row["before"]["stored_credit_ns"], "refused start lost credit without a started operation")
                if row["error"] == "PUBLIC_MUTATION_CPU_BUDGET":
                    require(not row["after"]["accounting_unavailable"] and
                            row["after"]["stored_credit_ns"] < parameters["start_reserve_ns"],
                            "sequential budget refusal has available start credit and no in-flight owner")
                counts["start_refusals"] += 1
                refused_errors[row["error"]] += 1
                receiver_by_arm[arm]["not-started"] += 1
                if row["error"] == "PUBLIC_MUTATION_CPU_BUDGET" and first_budget_denial is None:
                    first_budget_denial = {"request_ordinal": counts["requested_replays"], "case": case, "round": round_number, "status": status,
                                           "before_credit_ns": row["before"]["stored_credit_ns"],
                                           "after_credit_ns": row["after"]["stored_credit_ns"],
                                           "start_reserve_ns": parameters["start_reserve_ns"]}
                continue
            require(status == "started", "unknown receiver status")
            counts["started_replays"] += 1
            actual, expected = full_verifier_outcome(row, arm, case)
            counters = {"verified-work": "verified_work", "relation-error": "relation_errors", "local-cancellation": "local_cancellations"}
            counts[counters[actual]] += 1
            receiver_by_arm[arm][actual] += 1
            if actual == "local-cancellation":
                cancel_errors[row["outcome"]["error"]] += 1
                if row["outcome"]["error"] == "PUBLIC_MUTATION_CPU_BUDGET" and first_budget_denial is None:
                    first_budget_denial = {"request_ordinal": counts["requested_replays"], "case": case, "round": round_number, "status": actual}
            elif row["outcome"] != expected:
                alerts.append({"case": case, "round": round_number, "expected": expected["kind"],
                               "expected_error": expected["error"],
                               "receiver_outcome": row["outcome"]})
            settlement = row["settlement"]
            require(settlement["schema"] == "service-owner-scoped-thread-cpu-settlement-v1", "settlement schema")
            for key in ("owner_cpu_ns", "scoped_worker_cpu_ns", "total_cpu_ns", "live_paid_cpu_ns", "residual_cpu_ns"):
                if settlement[key] is not None:
                    integer(settlement[key], "settlement." + key)
            for key in ("spawned_workers", "started_workers", "finished_workers", "known_workers"):
                require(integer(settlement[key], "settlement." + key) == 0, "raw receiver unexpectedly reports a scoped worker")
            for key in ("live_refused", "accounting_unavailable"):
                boolean(settlement[key], "settlement." + key)
            if all(settlement[key] is not None for key in ("owner_cpu_ns", "scoped_worker_cpu_ns", "total_cpu_ns")):
                require(settlement["owner_cpu_ns"] + settlement["scoped_worker_cpu_ns"] == settlement["total_cpu_ns"], "owner+workers double count/mismatch")
            if all(settlement[key] is not None for key in ("total_cpu_ns", "live_paid_cpu_ns", "residual_cpu_ns")):
                require(settlement["live_paid_cpu_ns"] + settlement["residual_cpu_ns"] == settlement["total_cpu_ns"], "live+residual double count/mismatch")
            settlements.append(settlement)
    summary = take("receiver-summary")
    require(position == len(rows), "extra records or second/reset campaign in same JSONL")
    require(integer(summary["candidate_count"], "candidate_count") == len(candidates) and integer(summary["receiver_replays"], "receiver_replays") == replays, "summary candidates/replays mismatch")
    require(summary["requested_replays"] == len(candidates) * replays, "summary must include every requested replay")
    for key in ("requested_replays", "started_replays", "start_refusals", "verified_work", "relation_errors", "local_cancellations"):
        require(integer(summary[key], "summary." + key) == counts[key], "summary denominator mismatch: " + key)
    require(summary["final_state"] == previous, "summary domain was reset or unsettled")
    require(all(summary[key] is False for key in ("source_proves_w1_hardness", "independent_operators", "production_qualification")), "report overclaims scope")
    if summary["wall_ns"] is not None:
        integer(summary["wall_ns"], "receiver wall")
    flow = summary["actual_flow"]
    known_charge = distribution([settlement["total_cpu_ns"] for settlement in settlements])
    if wait_billing:
        require(flow == previous_flow, "summary actual flow changed/reset after the final request")
    if flow is not None:
        wait = actual_cpu_flow(flow)
        require(flow["schema"] == (FLOW_V3 if wait_billing else FLOW_V1), "campaign/actual flow generation mismatch")
        require(previous["accounting_unavailable"] is False, "known actual flow contradicts unavailable accounting")
        require(flow["initial_credit_ns"] == domain["state"]["stored_credit_ns"], "flow initial epoch mismatch")
        require(flow["booked_reservation_ns"] == flow["live_owners"] == flow.get("termination_reserved_ns", 0) == 0,
                "original reservation/owner not released")
        require(flow["remaining_paid_credit_ns"] == flow["stored_credit_ns"] == previous["stored_credit_ns"],
                "original shared budget conservation mismatch")
        require(flow["unsettled_known_live_cpu_ns"] == 0 and
                flow["settled_full_cpu_ns"] == known_charge["all_observations_sum"] and
                flow["paid_cpu_debit_ns"] == wait + flow["settled_full_cpu_ns"],
                "full actual flow differs from once-settled owner and admission CPU")
        if wait_billing:
            require(distribution(wait_samples)["all_observations_sum"] == wait,
                    "full admission wait differs from this cohort's request deltas")
        for flow_key, row_key in (("live_debited_cpu_ns", "live_paid_cpu_ns"), ("settlement_residual_cpu_ns", "residual_cpu_ns")):
            require(all(s[row_key] is not None for s in settlements) and flow[flow_key] == sum(s[row_key] for s in settlements), "flow settlement cohort mismatch: " + flow_key)
    grouped = defaultdict(list)
    for row in producers:
        kind, _, arm = row["case"].split("/")
        grouped[(kind, arm)].append(row)
    groups = []
    for (kind, arm), values in grouped.items():
        cases = {row["case"] for row in values}
        groups.append({"class": kind, "arm": arm, "offered_arm_cases": len(values),
                       "statuses": dict(Counter(row["status"] for row in values)),
                       "attempts_executed": sum(len(row["attempts"]) for row in values),
                       "full_producer_cpu_ns": distribution([row["total"]["cpu_ns"] for row in values]),
                       "full_producer_wall_ns": distribution([row["total"]["wall_ns"] for row in values]),
                       "raw_full_verify_cpu_over_full_producer_cpu": {kernel: distribution([
                           row["receiver_cpu_over_full_producer_search_cpu"] for row in diagnostics
                           if row["case"] in cases and row["kernel"] == kernel]) for kernel in KERNELS}})
    result = {"input": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "records": len(rows),
            "record_consistency": "PASS", "semantic_alerts": alerts,
            "campaign": campaign, "producer_cases_offered": len(producers),
            "producer_status_counts": dict(Counter(row["status"] for row in producers)),
            "producer_attempts_executed": sum(len(row["attempts"]) for row in producers),
            "target_exhaustion_case_count": sum(row["status"] == "exhausted" for row in producers),
            "unsupported_cases": [row["case"] for row in producers if row["status"] == "unsupported"],
            "raw_verifier_records": len(diagnostics),
            "raw_verifier_outcomes": dict(Counter(row["outcome"]["kind"] for row in diagnostics)),
            "producer_groups": groups,
            "public_material_construction_cpu_ns_separate": distribution([row["timing"]["cpu_ns"] for row in task_rows]),
            "receiver_counts_recomputed": {key: counts[key] for key in ("requested_replays", "started_replays", "start_refusals", "verified_work", "relation_errors", "local_cancellations")},
            "receiver_by_arm": {key: dict(value) for key, value in receiver_by_arm.items()},
            "start_refusal_errors": dict(refused_errors), "local_cancellation_errors": dict(cancel_errors),
            "first_actual_budget_denial": first_budget_denial, "minimum_stored_credit_ns": minimum_credit,
            "receiver_settled_cpu_ns": known_charge, "receiver_wall_ns": summary["wall_ns"],
            "actual_flow": flow, "final_state": previous,
            "cost_scope": "producer total once; setup/search/trials are nested and never added again; public material construction separate; raw diagnostics separate from sequential shared receiver settlements; JSONL output/transport/signature/M06/SQLite not priced",
            "verification_scope": "original record/hash/stream/count/accounting consistency only; native verifier outcome is reported evidence, full native proofs are not reverified here",
            "native_verification_performed_by_reader": False, "unique_confirmed_business_transactions_measured": False,
            "independent_operators": False, "production_qualification": False}

    if wait_billing:
        result["receiver_admission_wait_cpu_ns"] = distribution(wait_samples)
        result["receiver_paid_cpu_ns"] = None if flow is None else flow["paid_cpu_debit_ns"]
        result["receiver_paid_cpu_unavailable_reason"] = (
            "actual flow unavailable; owner settlement totals cannot substitute for admission wait" if flow is None else None)
        result["cost_scope"] = (
            "producer total once; setup/search/trials are nested and never added again; public material construction separate; "
            "raw diagnostics separate; each requested receiver attempt includes its paid admission wait plus once-settled owner CPU; "
            "CpuWait observation spans are not added to these disjoint ledger intervals; JSONL output/transport/signature/M06/SQLite not priced")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()
    results = []
    for path in args.inputs:
        try:
            results.append(analyze(path))
        except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
            results.append({"input": str(path), "record_consistency": "FAIL", "error": str(error)})
    valid = [result for result in results if result["record_consistency"] == "PASS"]
    comparisons = []
    for i, left in enumerate(valid):
        for right in valid[i + 1:]:
            a, b = left["campaign"], right["campaign"]
            equal = {key: a[key] == b[key] for key in ("work_profile", "target", "samples", "attempt_budget_per_arm", "receiver_replays", "classes")}
            comparisons.append({"inputs": [left["input"], right["input"]], "same_declared_parameters": equal,
                                "different_seed": a["seed"] != b["seed"],
                                "same_target_campaign_comparison_eligible": all(equal.values()),
                                "host_and_build_identity_verified": False,
                                "scope": "seed changes dense/sparse material; zero/rank-one task material stays the same; fresh seed changes challenges; source/compiler/host identity requires separately retained run evidence"})
    output_schema = ("pon-w1-readonly-accounting-summary-admission-wait-v2" if any(
        result["campaign"]["schema"] == WAIT_SCHEMA for result in valid) else "pon-w1-readonly-accounting-summary-v1")
    output = {"schema": output_schema, "inputs": results, "comparisons": comparisons,
              "reader_wrote_input_files": False, "reader_ran_native_code": False,
              "result_interpretation": "internally consistent JSONL does not authenticate the producing host or establish hardness, anonymous fairness, independent operators, business throughput or production readiness"}
    print(json.dumps(output, ensure_ascii=False, indent=2, allow_nan=False))
    return 2 if len(valid) != len(results) else (1 if any(result["semantic_alerts"] for result in valid) else 0)


if __name__ == "__main__":
    sys.exit(main())
